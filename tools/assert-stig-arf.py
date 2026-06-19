#!/usr/bin/env python3
"""Fail closed on tailored OpenSCAP ARF results."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


class ArfError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArfError(message)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_arf(path: Path, fail_on: str) -> dict:
    threshold = SEVERITY_ORDER.get(fail_on.lower())
    require(threshold is not None, f"invalid fail threshold: {fail_on}")
    require(path.is_file() and path.stat().st_size > 0, f"ARF is missing or empty: {path}")

    tree = ET.parse(path)
    counts: dict[str, int] = {}
    blocking: list[dict[str, str]] = []
    rule_results: list[dict[str, str]] = []

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

    require(rule_results, "ARF contains no rule-result elements")
    summary = {
        "profile": find_profile(tree),
        "fail_on": fail_on.lower(),
        "total_rule_results": len(rule_results),
        "counts": counts,
        "blocking_results": blocking,
    }

    print(
        "OpenSCAP STIG ARF results: "
        f"total={summary['total_rule_results']} "
        + " ".join(f"{key}={counts.get(key, 0)}" for key in sorted(counts))
    )
    require(not blocking, "blocking STIG rule results: " + ", ".join(f"{item['idref']}={item['result']}:{item['severity']}" for item in blocking))
    return summary


def find_profile(tree: ET.ElementTree) -> str:
    for element in tree.iter():
        if local_name(element.tag) == "profile":
            return (element.text or "").strip()
    return "unknown"


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        passing = root / "passing.arf.xml"
        failing = root / "failing.arf.xml"
        erroring = root / "error.arf.xml"

        passing.write_text(
            """<arf xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <xccdf:TestResult>
    <xccdf:profile>tailored</xccdf:profile>
    <xccdf:rule-result idref="rule_ok" severity="low"><xccdf:result>pass</xccdf:result></xccdf:rule-result>
    <xccdf:rule-result idref="rule_na" severity="medium"><xccdf:result>notapplicable</xccdf:result></xccdf:rule-result>
  </xccdf:TestResult>
</arf>
""",
            encoding="utf-8",
        )
        failing.write_text(
            """<arf xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <xccdf:TestResult>
    <xccdf:rule-result idref="rule_fail" severity="low"><xccdf:result>fail</xccdf:result></xccdf:rule-result>
  </xccdf:TestResult>
</arf>
""",
            encoding="utf-8",
        )
        erroring.write_text(
            """<arf xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2">
  <xccdf:TestResult>
    <xccdf:rule-result idref="rule_error" severity="low"><xccdf:result>error</xccdf:result></xccdf:rule-result>
  </xccdf:TestResult>
</arf>
""",
            encoding="utf-8",
        )

        parse_arf(passing, "low")
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
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_test:
            self_test()
            return 0
        require(args.arf is not None, "--arf is required unless --self-test is used")
        summary = parse_arf(args.arf, args.fail_on)
        if args.summary:
            args.summary.parent.mkdir(parents=True, exist_ok=True)
            args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (ArfError, ET.ParseError) as exc:
        print(f"STIG ARF assertion failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
