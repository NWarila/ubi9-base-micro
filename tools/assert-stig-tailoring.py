#!/usr/bin/env python3
"""Validate the image-scoped RHEL9 STIG tailoring and scope ledger."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"


class TailoringError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TailoringError(message)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def bare_rule(rule_id: str) -> str:
    if rule_id.startswith(RULE_PREFIX):
        return rule_id[len(RULE_PREFIX) :]
    return rule_id


def parse_tailoring(path: Path) -> tuple[str, set[str], set[str]]:
    root = ET.parse(path).getroot()
    profile_id = ""
    selected: set[str] = set()
    unselected: set[str] = set()

    for element in root.iter():
        name = local_name(element.tag)
        if name == "Profile" and not profile_id:
            profile_id = element.get("id") or ""
        if name != "select":
            continue
        idref = element.get("idref") or ""
        selected_attr = (element.get("selected") or "").lower()
        require(idref.startswith(RULE_PREFIX), f"tailoring select idref must use an SSG rule id: {idref}")
        rule = bare_rule(idref)
        if selected_attr == "true":
            selected.add(rule)
        elif selected_attr == "false":
            unselected.add(rule)
        else:
            raise TailoringError(f"tailoring select for {idref} has invalid selected={selected_attr!r}")

    require(profile_id, "tailoring profile id is missing")
    require(selected, "tailoring must select at least one image-scope rule")
    return profile_id, selected, unselected


def parse_controls(path: Path) -> dict[str, list[str]]:
    controls: dict[str, list[str]] = {}
    current_id: str | None = None
    in_controls = False
    in_rules = False

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()
        if re.match(r"^controls:\s*$", line):
            in_controls = True
            current_id = None
            in_rules = False
            continue
        if not in_controls:
            continue
        match = re.match(r"^    - id: (.+)$", line)
        if match:
            current_id = match.group(1).strip().strip("'\"")
            controls[current_id] = []
            in_rules = False
            continue
        if current_id is None:
            continue
        if re.match(r"^      rules:\s*$", line):
            in_rules = True
            continue
        if in_rules:
            rule_match = re.match(r"^          - (.+)$", line)
            if rule_match:
                rule = rule_match.group(1).strip().strip("'\"")
                if "=" not in rule:
                    controls[current_id].append(rule)
                continue
            if line.startswith("      ") and not line.startswith("          "):
                in_rules = False

    require(controls, f"no controls parsed from {path}")
    return controls


def parse_datastream_rules(path: Path) -> set[str]:
    rules: set[str] = set()
    for _event, element in ET.iterparse(path, events=("end",)):
        if local_name(element.tag) == "Rule":
            rule_id = element.get("id") or ""
            if rule_id.startswith(RULE_PREFIX):
                rules.add(bare_rule(rule_id))
        element.clear()
    require(rules, f"no SSG rules parsed from datastream {path}")
    return rules


def load_ledger(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in [
        "tailored_profile",
        "ssg_version",
        "ssg_tarball_sha512",
        "selected_controls",
        "supplemental_selected_rules",
        "omission_groups",
    ]:
        require(key in data, f"justification ledger missing key: {key}")
    require(re.fullmatch(r"[0-9a-f]{128}", data["ssg_tarball_sha512"]), "SSG SHA512 pin must be 128 lowercase hex characters")
    return data


def validate(args: argparse.Namespace) -> dict[str, int]:
    profile_id, selected_rules, unselected_rules = parse_tailoring(args.tailoring)
    ledger = load_ledger(args.justifications)
    controls = parse_controls(args.controls_yaml)

    require(profile_id == ledger["tailored_profile"], "tailoring profile id does not match justification ledger")

    selected_controls = ledger["selected_controls"]
    supplemental = ledger["supplemental_selected_rules"]
    omission_groups = ledger["omission_groups"]
    require(isinstance(selected_controls, dict) and selected_controls, "selected_controls must be a non-empty object")
    require(isinstance(supplemental, dict), "supplemental_selected_rules must be an object")
    require(isinstance(omission_groups, list) and omission_groups, "omission_groups must be a non-empty list")

    selected_from_controls: set[str] = set()
    for control_id, entry in selected_controls.items():
        require(control_id in controls, f"selected control not present in pinned STIG source: {control_id}")
        rules = entry.get("rules")
        scope = entry.get("scope")
        require(isinstance(rules, list) and rules, f"selected control {control_id} must list selected rules")
        require(isinstance(scope, str) and scope.strip(), f"selected control {control_id} must document scope")
        for rule in rules:
            require(rule in controls[control_id], f"rule {rule} is not listed under selected STIG control {control_id}")
            selected_from_controls.add(rule)

    supplemental_rules = set(supplemental)
    for rule, entry in supplemental.items():
        require(isinstance(entry, dict), f"supplemental rule {rule} must have an object entry")
        require(isinstance(entry.get("scope"), str) and entry["scope"].strip(), f"supplemental rule {rule} must document scope")

    expected_selected = selected_from_controls | supplemental_rules
    require(selected_rules == expected_selected, "tailoring selected rules do not match the reviewed ledger")

    for rule in unselected_rules:
        require(rule in supplemental_rules or rule in selected_from_controls, f"explicitly unselected rule lacks a reviewed ledger entry: {rule}")

    compiled_groups: list[tuple[str, list[re.Pattern[str]], str]] = []
    for group in omission_groups:
        group_id = group.get("id")
        patterns = group.get("control_id_patterns")
        justification = group.get("justification")
        require(isinstance(group_id, str) and group_id.strip(), "omission group must have an id")
        require(isinstance(justification, str) and justification.strip(), f"omission group {group_id} must have a justification")
        require(isinstance(patterns, list) and patterns, f"omission group {group_id} must list control_id_patterns")
        compiled_groups.append((group_id, [re.compile(pattern) for pattern in patterns], justification))

    selected_control_ids = set(selected_controls)
    uncovered: list[str] = []
    for control_id in sorted(controls):
        if control_id in selected_control_ids:
            continue
        matched = [group_id for group_id, patterns, _ in compiled_groups if any(pattern.search(control_id) for pattern in patterns)]
        if not matched:
            uncovered.append(control_id)

    require(not uncovered, "STIG controls missing omission justification: " + ", ".join(uncovered))

    if args.datastream:
        available_rules = parse_datastream_rules(args.datastream)
        missing_rules = sorted(rule for rule in selected_rules if rule not in available_rules)
        require(not missing_rules, "selected rules missing from generated datastream: " + ", ".join(missing_rules))

    summary = {
        "stig_controls": len(controls),
        "selected_controls": len(selected_control_ids),
        "selected_rules": len(selected_rules),
        "supplemental_selected_rules": len(supplemental_rules),
        "omitted_controls_with_justification": len(controls) - len(selected_control_ids),
        "omission_groups": len(compiled_groups),
    }
    print(
        "STIG tailoring guard: "
        f"controls={summary['stig_controls']} selected_controls={summary['selected_controls']} "
        f"selected_rules={summary['selected_rules']} supplemental_rules={summary['supplemental_selected_rules']} "
        f"omitted_controls_with_justification={summary['omitted_controls_with_justification']} "
        f"omission_groups={summary['omission_groups']}"
    )
    return summary


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        controls = root / "controls.yml"
        tailoring = root / "tailoring.xml"
        ledger = root / "ledger.json"
        datastream = root / "ds.xml"

        controls.write_text(
            """
controls:
    - id: RHEL-09-111111
      rules:
          - selected_rule
    - id: RHEL-09-222222
      rules:
          - omitted_rule
""".lstrip(),
            encoding="utf-8",
        )
        tailoring.write_text(
            f"""<?xml version="1.0" encoding="UTF-8"?>
<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <xccdf:Profile id="tailored">
    <xccdf:select idref="{RULE_PREFIX}selected_rule" selected="true"/>
    <xccdf:select idref="{RULE_PREFIX}supplemental_rule" selected="true"/>
  </xccdf:Profile>
</xccdf:Tailoring>
""",
            encoding="utf-8",
        )
        ledger.write_text(
            json.dumps(
                {
                    "tailored_profile": "tailored",
                    "ssg_version": "0.0.0",
                    "ssg_tarball_sha512": "a" * 128,
                    "selected_controls": {
                        "RHEL-09-111111": {
                            "rules": ["selected_rule"],
                            "scope": "selected for the image",
                        }
                    },
                    "supplemental_selected_rules": {
                        "supplemental_rule": {"scope": "extra image-rootfs rule"}
                    },
                    "omission_groups": [
                        {
                            "id": "omitted",
                            "control_id_patterns": ["^RHEL-09-222222$"],
                            "justification": "not image-rootfs scope",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        datastream.write_text(
            f"""<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <Rule id="{RULE_PREFIX}selected_rule"/>
  <Rule id="{RULE_PREFIX}supplemental_rule"/>
</Benchmark>
""",
            encoding="utf-8",
        )
        validate(
            argparse.Namespace(
                tailoring=tailoring,
                justifications=ledger,
                controls_yaml=controls,
                datastream=datastream,
            )
        )

        broken = json.loads(ledger.read_text(encoding="utf-8"))
        broken["omission_groups"] = []
        ledger.write_text(json.dumps(broken), encoding="utf-8")
        try:
            validate(
                argparse.Namespace(
                    tailoring=tailoring,
                    justifications=ledger,
                    controls_yaml=controls,
                    datastream=datastream,
                )
            )
        except TailoringError:
            pass
        else:
            raise AssertionError("self-test failed to reject missing omission justification")

    print("STIG tailoring guard self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tailoring", type=Path, default=Path("stig/rhel9-base-micro-tailoring.xml"))
    parser.add_argument("--justifications", type=Path, default=Path("stig/tailoring-justifications.json"))
    parser.add_argument("--controls-yaml", type=Path, help="Pinned ComplianceAsCode products/rhel9/controls/stig_rhel9.yml")
    parser.add_argument("--datastream", type=Path, help="Generated ssg-rhel9-ds.xml to validate selected rule IDs")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_test:
            self_test()
            return 0
        require(args.controls_yaml is not None, "--controls-yaml is required unless --self-test is used")
        validate(args)
        return 0
    except TailoringError as exc:
        print(f"STIG tailoring guard failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
