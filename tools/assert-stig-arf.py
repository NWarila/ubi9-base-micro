#!/usr/bin/env python3
"""Fail closed on tailored OpenSCAP ARF results."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, cast

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
MUST_ACTUALLY_EVALUATE = {
    "accounts_no_uid_except_zero",
    "file_permissions_ungroupowned",
    "no_files_unowned_by_user",
}


class ArfError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise ArfError(message)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def bare_rule(rule_id: str) -> str:
    if rule_id.startswith(RULE_PREFIX):
        return rule_id[len(RULE_PREFIX) :]
    return rule_id


def load_equivalent_assertions(paths: list[Path]) -> tuple[set[str], dict[str, list[str]], list[dict[str, Any]]]:
    covered_rules: set[str] = set()
    covered_by: dict[str, list[str]] = {}
    reports: list[dict[str, Any]] = []
    for path in paths:
        require(path.is_file() and path.stat().st_size > 0, f"equivalent assertion report is missing or empty: {path}")
        loaded = json.loads(path.read_text(encoding="utf-8"))
        require(isinstance(loaded, dict), f"equivalent assertion report must be a JSON object: {path}")
        report = cast(dict[str, Any], loaded)
        rules = report.get("coveredRules")
        if not isinstance(rules, list) or not rules:
            raise ArfError(f"equivalent assertion report has no coveredRules: {path}")
        assertions = report.get("assertions")
        if not isinstance(assertions, dict) or not assertions:
            raise ArfError(f"equivalent assertion report has no assertions: {path}")
        for assertion_id, assertion in assertions.items():
            require(isinstance(assertion, dict), f"equivalent assertion {assertion_id} must be an object")
            require(assertion.get("result") == "pass", f"equivalent assertion {assertion_id} did not pass")
            assertion_rules = assertion.get("coveredRules")
            require(
                isinstance(assertion_rules, list) and assertion_rules,
                f"equivalent assertion {assertion_id} has no coveredRules",
            )
            for rule in assertion_rules:
                covered_by.setdefault(str(rule), []).append(str(assertion_id))
        covered_rules.update(str(rule) for rule in rules)
        reports.append(
            {
                "path": str(path).replace("\\", "/"),
                "coveredRules": sorted(str(rule) for rule in rules),
                "assertions": assertions,
                "checked": report.get("checked", {}),
            }
        )
    return covered_rules, covered_by, reports


def parse_arf(path: Path, fail_on: str, equivalent_assertion_paths: list[Path] | None = None) -> dict[str, Any]:
    equivalent_assertion_paths = equivalent_assertion_paths or []
    covered_rules, covered_by, equivalent_reports = load_equivalent_assertions(equivalent_assertion_paths)
    threshold = SEVERITY_ORDER.get(fail_on.lower())
    if threshold is None:
        raise ArfError(f"invalid fail threshold: {fail_on}")
    require(path.is_file() and path.stat().st_size > 0, f"ARF is missing or empty: {path}")

    tree = ET.parse(path)
    counts: dict[str, int] = {}
    blocking: list[dict[str, str]] = []
    rule_results: list[dict[str, str]] = []
    covered_notapplicable: list[dict[str, str | list[str]]] = []
    uncovered_notapplicable: list[dict[str, str]] = []

    for element in tree.iter():
        if local_name(element.tag) != "rule-result":
            continue
        rule_id = element.get("idref") or "unknown"
        severity = (element.get("severity") or "unknown").strip().lower()
        result = "unknown"
        for child in element:
            if local_name(child.tag) == "result":
                result = (child.text or "unknown").strip().lower()
                break
        counts[result] = counts.get(result, 0) + 1
        record = {"idref": rule_id, "severity": severity, "result": result}
        rule_results.append(record)

        if result == "fail":
            severity_rank = SEVERITY_ORDER.get(severity)
            if severity_rank is None or severity_rank >= threshold:
                blocking.append(record)
        elif result in {"error", "unknown"}:
            blocking.append(record)
        elif result == "notapplicable" and bare_rule(rule_id) in MUST_ACTUALLY_EVALUATE:
            rule = bare_rule(rule_id)
            if rule in covered_rules:
                covered_notapplicable.append({**record, "coveredBy": sorted(covered_by.get(rule, []))})
            else:
                uncovered_notapplicable.append(record)

    require(rule_results, "ARF contains no rule-result elements")
    summary = {
        "profile": find_profile(tree),
        "fail_on": fail_on.lower(),
        "total_rule_results": len(rule_results),
        "counts": counts,
        "rule_results": rule_results,
        "blocking_results": blocking,
        "must_actually_evaluate_rules": sorted(MUST_ACTUALLY_EVALUATE),
        "equivalent_assertions": equivalent_reports,
        "covered_notapplicable_results": covered_notapplicable,
        "uncovered_notapplicable_results": uncovered_notapplicable,
    }

    print(
        "OpenSCAP STIG ARF results: "
        f"total={summary['total_rule_results']} " + " ".join(f"{key}={counts.get(key, 0)}" for key in sorted(counts))
    )
    require(
        not blocking,
        "blocking STIG rule results: "
        + ", ".join(f"{item['idref']}={item['result']}:{item['severity']}" for item in blocking),
    )
    require(
        not uncovered_notapplicable,
        "must-verify STIG rule(s) returned notapplicable without an equivalent deterministic assertion: "
        + ", ".join(item["idref"] for item in uncovered_notapplicable),
    )
    return summary


def find_profile(tree: ET.ElementTree[ET.Element[str]]) -> str:
    for element in tree.iter():
        if local_name(element.tag) == "profile":
            return (element.text or "").strip()
    return "unknown"


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        passing = root / "passing.arf.xml"
        covered_na = root / "covered-na.arf.xml"
        uncovered_na = root / "uncovered-na.arf.xml"
        failing = root / "failing.arf.xml"
        erroring = root / "error.arf.xml"
        equivalent = root / "equivalent.json"

        passing.write_text(
            """<arf xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <xccdf:TestResult>
    <xccdf:profile>tailored</xccdf:profile>
    <xccdf:rule-result idref="rule_ok" severity="low">
      <xccdf:result>pass</xccdf:result>
    </xccdf:rule-result>
    <xccdf:rule-result idref="rule_na" severity="medium">
      <xccdf:result>notapplicable</xccdf:result>
    </xccdf:rule-result>
  </xccdf:TestResult>
</arf>
""",
            encoding="utf-8",
        )
        covered_na.write_text(
            f"""<arf xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <xccdf:TestResult>
    <xccdf:rule-result idref="{RULE_PREFIX}accounts_no_uid_except_zero" severity="medium">
      <xccdf:result>notapplicable</xccdf:result>
    </xccdf:rule-result>
  </xccdf:TestResult>
</arf>
""",
            encoding="utf-8",
        )
        uncovered_na.write_text(covered_na.read_text(encoding="utf-8"), encoding="utf-8")
        failing.write_text(
            """<arf xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <xccdf:TestResult>
    <xccdf:rule-result idref="rule_fail" severity="low">
      <xccdf:result>fail</xccdf:result>
    </xccdf:rule-result>
  </xccdf:TestResult>
</arf>
""",
            encoding="utf-8",
        )
        erroring.write_text(
            """<arf xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <xccdf:TestResult>
    <xccdf:rule-result idref="rule_error" severity="low">
      <xccdf:result>error</xccdf:result>
    </xccdf:rule-result>
  </xccdf:TestResult>
</arf>
""",
            encoding="utf-8",
        )
        equivalent.write_text(
            json.dumps(
                {
                    "coveredRules": ["accounts_no_uid_except_zero"],
                    "assertions": {
                        "no_uid0_accounts_except_root": {
                            "result": "pass",
                            "coveredRules": ["accounts_no_uid_except_zero"],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        parse_arf(passing, "low")
        parse_arf(covered_na, "low", [equivalent])
        try:
            parse_arf(uncovered_na, "low")
        except ArfError:
            pass
        else:
            raise AssertionError("self-test failed to reject uncovered must-verify notapplicable rule")
        for path in [failing, erroring]:
            try:
                parse_arf(path, "low")
            except ArfError:
                pass
            else:
                raise AssertionError(f"self-test failed to reject {path.name}")

    print("STIG ARF assertion self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arf", type=Path)
    parser.add_argument("--fail-on", default="low", choices=sorted(SEVERITY_ORDER))
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--equivalent-assertions", type=Path, action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_test:
            self_test()
            return 0
        require(args.arf is not None, "--arf is required unless --self-test is used")
        summary = parse_arf(args.arf, args.fail_on, args.equivalent_assertions)
        if args.summary:
            args.summary.parent.mkdir(parents=True, exist_ok=True)
            args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (ArfError, ET.ParseError, json.JSONDecodeError) as exc:
        print(f"STIG ARF assertion failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
