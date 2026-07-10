#!/usr/bin/env python3
# Purpose: Fail unless fixable-CVE scanner ignores remain exact, current, and applied only to the approved findings
# Role: gate
# Micro-container candidate: yes - pure-stdlib, policy/report-in/exit-out, has --self-test

"""Validate the exact TD-6 scanner-ignore scope and optional Grype gate evidence."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, NoReturn, cast

TRIVY_IGNORE = Path("security/cve-ignore.trivyignore.yaml")
GRYPE_IGNORE = Path("security/cve-ignore.grype.yaml")
ALLOWED_CVE = "CVE-2026-31790"
ALLOWED_PACKAGES = frozenset({"openssl-fips-provider", "openssl-fips-provider-so"})
ALLOWED_VERSION = "3.0.7-8.el9"
REVIEW_DATE = date(2026, 10, 10)
ALLOWED_PAIRS = frozenset((ALLOWED_CVE, package) for package in ALLOWED_PACKAGES)
ALLOWED_TRIPLES = frozenset((cve, package, ALLOWED_VERSION) for cve, package in ALLOWED_PAIRS)
PURL_PATTERN = re.compile(r"^pkg:rpm/redhat/(?P<package>[a-z0-9][a-z0-9+._-]*)@(?P<version>[^?]+)$")
REVIEW_DATE_PATTERN = re.compile(r"\breview-by (?P<date>\d{4}-\d{2}-\d{2})\b")
YAML_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


class IgnoreScopeError(Exception):
    pass


@dataclass(frozen=True)
class YamlLine:
    number: int
    indent: int
    content: str


def fail(message: str) -> NoReturn:
    raise IgnoreScopeError(message)


def yaml_lines(text: str, label: str) -> list[YamlLine]:
    parsed: list[YamlLine] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        if "\t" in raw_line:
            fail(f"{label}:{number}: tabs are not allowed")
        stripped = raw_line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(stripped)
        if indent % 2:
            fail(f"{label}:{number}: indentation must use two-space levels")
        parsed.append(YamlLine(number=number, indent=indent, content=stripped.rstrip()))
    if not parsed:
        fail(f"{label}: document is empty")
    return parsed


def split_mapping(content: str, label: str, number: int) -> tuple[str, str] | None:
    if ":" not in content:
        return None
    key, remainder = content.split(":", 1)
    if remainder and not remainder.startswith(" "):
        return None
    if not YAML_KEY_PATTERN.fullmatch(key):
        fail(f"{label}:{number}: invalid mapping key {key!r}")
    return key, remainder.strip()


def parse_scalar(value: str, label: str, number: int) -> str:
    if not value:
        fail(f"{label}:{number}: scalar value is empty")
    if value[0] in {'"', "'"}:
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise IgnoreScopeError(f"{label}:{number}: malformed quoted string") from exc
        if not isinstance(parsed, str):
            fail(f"{label}:{number}: quoted scalar must be a string")
        return parsed
    if value[0] in "{[&*!>|%@`" or value in {"null", "Null", "NULL", "~"}:
        fail(f"{label}:{number}: unsupported YAML scalar {value!r}")
    return value


class StrictYamlParser:
    def __init__(self, text: str, label: str) -> None:
        self.label = label
        self.lines = yaml_lines(text, label)

    def parse(self) -> dict[str, Any]:
        if self.lines[0].indent != 0:
            fail(f"{self.label}:{self.lines[0].number}: document must start at indentation zero")
        value, index = self._parse_node(0, 0)
        if index != len(self.lines):
            line = self.lines[index]
            fail(f"{self.label}:{line.number}: unexpected content or indentation")
        if not isinstance(value, dict):
            fail(f"{self.label}: document root must be a mapping")
        return cast(dict[str, Any], value)

    def _parse_node(self, index: int, indent: int) -> tuple[Any, int]:
        if index >= len(self.lines):
            fail(f"{self.label}: expected a value at indentation {indent}")
        line = self.lines[index]
        if line.indent != indent:
            fail(f"{self.label}:{line.number}: expected indentation {indent}, got {line.indent}")
        if line.content == "-" or line.content.startswith("- "):
            return self._parse_sequence(index, indent)
        return self._parse_mapping(index, indent)

    def _parse_mapping_entry(
        self,
        index: int,
        key_indent: int,
        content: str,
        target: dict[str, Any],
    ) -> int:
        line = self.lines[index]
        pair = split_mapping(content, self.label, line.number)
        if pair is None:
            fail(f"{self.label}:{line.number}: expected a key/value mapping")
        key, raw_value = pair
        if key in target:
            fail(f"{self.label}:{line.number}: duplicate key {key!r}")
        index += 1
        if raw_value:
            target[key] = parse_scalar(raw_value, self.label, line.number)
            return index
        child_indent = key_indent + 2
        if index >= len(self.lines) or self.lines[index].indent != child_indent:
            fail(f"{self.label}:{line.number}: key {key!r} requires an indented value")
        target[key], index = self._parse_node(index, child_indent)
        return index

    def _parse_mapping(self, index: int, indent: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            if line.indent > indent:
                fail(f"{self.label}:{line.number}: unexpected indentation {line.indent}")
            if line.content == "-" or line.content.startswith("- "):
                break
            index = self._parse_mapping_entry(index, indent, line.content, result)
        if not result:
            line = self.lines[index] if index < len(self.lines) else self.lines[-1]
            fail(f"{self.label}:{line.number}: mapping must not be empty")
        return result, index

    def _parse_sequence(self, index: int, indent: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent < indent:
                break
            if line.indent > indent:
                fail(f"{self.label}:{line.number}: unexpected indentation {line.indent}")
            if line.content != "-" and not line.content.startswith("- "):
                break
            item_content = line.content[1:].strip()
            if not item_content:
                index += 1
                child_indent = indent + 2
                if index >= len(self.lines) or self.lines[index].indent != child_indent:
                    fail(f"{self.label}:{line.number}: list item requires an indented value")
                item, index = self._parse_node(index, child_indent)
                result.append(item)
                continue

            first_pair = split_mapping(item_content, self.label, line.number)
            if first_pair is None:
                result.append(parse_scalar(item_content, self.label, line.number))
                index += 1
                continue

            item_mapping: dict[str, Any] = {}
            key_indent = indent + 2
            index = self._parse_mapping_entry(index, key_indent, item_content, item_mapping)
            while index < len(self.lines):
                next_line = self.lines[index]
                if next_line.indent != key_indent or next_line.content == "-" or next_line.content.startswith("- "):
                    break
                index = self._parse_mapping_entry(index, key_indent, next_line.content, item_mapping)
            result.append(item_mapping)
        if not result:
            line = self.lines[index] if index < len(self.lines) else self.lines[-1]
            fail(f"{self.label}:{line.number}: sequence must not be empty")
        return result, index


def load_yaml_mapping(path: Path, label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise IgnoreScopeError(f"{label} ignore file is missing: {path}") from exc
    except (OSError, UnicodeError) as exc:
        raise IgnoreScopeError(f"{label} ignore file is unreadable: {path}: {exc}") from exc
    return StrictYamlParser(text, str(path)).parse()


def load_json_mapping(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise IgnoreScopeError(f"{label} report is missing: {path}") from exc
    except (OSError, UnicodeError) as exc:
        raise IgnoreScopeError(f"{label} report is unreadable: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IgnoreScopeError(f"{label} report is malformed JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        fail(f"{label} report root must be an object: {path}")
    return cast(dict[str, Any], value)


def mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be a mapping")
    return cast(dict[str, Any], value)


def sequence(value: object, label: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        fail(f"{label} must be a non-empty list")
    return value


def text_value(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
    return value.strip()


def require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        fail(f"{label} keys must be exact ({', '.join(details)})")


def parse_date(value: object, label: str) -> date:
    raw = text_value(value, label)
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise IgnoreScopeError(f"{label} must be a YYYY-MM-DD date, got {raw!r}") from exc


def assert_review_date(value: object, label: str, today: date) -> None:
    parsed = parse_date(value, label)
    if today > parsed:
        fail("TD-6 review date reached — re-check the CMVP #4857 hold; this is NOT a new CVE.")
    if parsed != REVIEW_DATE:
        fail(f"{label} must equal the TD-6 review date {REVIEW_DATE.isoformat()}, got {parsed.isoformat()}")


def validate_trivy(document: dict[str, Any], today: date) -> frozenset[tuple[str, str]]:
    require_keys(document, {"vulnerabilities"}, "trivy document")
    entries = sequence(document["vulnerabilities"], "trivy vulnerabilities")
    pairs: list[tuple[str, str]] = []
    for index, raw_entry in enumerate(entries):
        label = f"trivy vulnerabilities[{index}]"
        entry = mapping(raw_entry, label)
        require_keys(entry, {"id", "purls", "statement", "expired_at"}, label)
        cve = text_value(entry["id"], f"{label}.id")
        text_value(entry["statement"], f"{label}.statement")
        assert_review_date(entry["expired_at"], f"{label}.expired_at", today)
        raw_purls = sequence(entry["purls"], f"{label}.purls")
        for purl_index, raw_purl in enumerate(raw_purls):
            purl = text_value(raw_purl, f"{label}.purls[{purl_index}]")
            match = PURL_PATTERN.fullmatch(purl)
            if match is None:
                fail(f"{label}.purls[{purl_index}] must be an exact qualifier-free Red Hat rpm purl with name+version")
            package = match.group("package")
            version = match.group("version")
            if version != ALLOWED_VERSION:
                fail(f"{label}.purls[{purl_index}] version must be {ALLOWED_VERSION}, got {version}")
            pairs.append((cve, package))
    if len(pairs) != len(set(pairs)):
        fail("trivy ignore contains duplicate CVE/package pairs")
    pair_set = frozenset(pairs)
    if pair_set != ALLOWED_PAIRS:
        fail(f"trivy ignored CVE/package pairs must be exactly {sorted(ALLOWED_PAIRS)}, got {sorted(pair_set)}")
    return pair_set


def grype_reason_date(reason: object, label: str, today: date) -> None:
    raw = text_value(reason, label)
    matches = REVIEW_DATE_PATTERN.findall(raw)
    if len(matches) != 1:
        fail(f"{label} must contain exactly one review-by YYYY-MM-DD marker")
    assert_review_date(matches[0], label, today)


def validate_grype(document: dict[str, Any], today: date) -> frozenset[tuple[str, str]]:
    require_keys(document, {"ignore"}, "grype document")
    entries = sequence(document["ignore"], "grype ignore")
    pairs: list[tuple[str, str]] = []
    for index, raw_entry in enumerate(entries):
        label = f"grype ignore[{index}]"
        entry = mapping(raw_entry, label)
        require_keys(entry, {"vulnerability", "reason", "package"}, label)
        cve = text_value(entry["vulnerability"], f"{label}.vulnerability")
        grype_reason_date(entry["reason"], f"{label}.reason", today)
        package = mapping(entry["package"], f"{label}.package")
        require_keys(package, {"name", "version"}, f"{label}.package")
        package_name = text_value(package["name"], f"{label}.package.name")
        version = text_value(package["version"], f"{label}.package.version")
        if version != ALLOWED_VERSION:
            fail(f"{label}.package.version must be {ALLOWED_VERSION}, got {version}")
        pairs.append((cve, package_name))
    if len(pairs) != len(set(pairs)):
        fail("grype ignore contains duplicate CVE/package pairs")
    pair_set = frozenset(pairs)
    if pair_set != ALLOWED_PAIRS:
        fail(f"grype ignored CVE/package pairs must be exactly {sorted(ALLOWED_PAIRS)}, got {sorted(pair_set)}")
    return pair_set


def validate_ignore_files(trivy_path: Path, grype_path: Path, today: date) -> None:
    trivy_pairs = validate_trivy(load_yaml_mapping(trivy_path, "trivy"), today)
    grype_pairs = validate_grype(load_yaml_mapping(grype_path, "grype"), today)
    if trivy_pairs != grype_pairs:
        fail(f"trivy and grype ignored pairs differ: trivy={sorted(trivy_pairs)}, grype={sorted(grype_pairs)}")


def validate_grype_report(path: Path) -> list[tuple[str, str, str]]:
    document = load_json_mapping(path, "grype gate")
    ignored_matches = document.get("ignoredMatches")
    if not isinstance(ignored_matches, list):
        fail("grype gate report ignoredMatches must be a list")
    applied: list[tuple[str, str, str]] = []
    for index, raw_match in enumerate(ignored_matches):
        item = mapping(raw_match, f"grype ignoredMatches[{index}]")
        raw_rules = item.get("appliedIgnoreRules")
        if raw_rules is None:
            fail(f"grype ignoredMatches[{index}] is missing appliedIgnoreRules")
        if not isinstance(raw_rules, list):
            fail(f"grype ignoredMatches[{index}].appliedIgnoreRules must be a list")
        policy_rules: list[dict[str, Any]] = []
        for rule_index, raw_rule in enumerate(raw_rules):
            rule = mapping(raw_rule, f"grype ignoredMatches[{index}].appliedIgnoreRules[{rule_index}]")
            if "vulnerability" in rule or "package" in rule or "reason" in rule:
                policy_rules.append(rule)
                continue
            if set(rule) != {"namespace", "fix-state"} or not isinstance(rule["fix-state"], str):
                fail(f"grype ignoredMatches[{index}].appliedIgnoreRules[{rule_index}] has an unknown rule shape")
        if not policy_rules:
            continue
        if len(policy_rules) != 1:
            fail(f"grype ignoredMatches[{index}] must have exactly one applied policy ignore rule")
        vulnerability = mapping(item.get("vulnerability"), f"grype ignoredMatches[{index}].vulnerability")
        artifact = mapping(item.get("artifact"), f"grype ignoredMatches[{index}].artifact")
        cve = text_value(vulnerability.get("id"), f"grype ignoredMatches[{index}].vulnerability.id")
        package = text_value(artifact.get("name"), f"grype ignoredMatches[{index}].artifact.name")
        version = text_value(artifact.get("version"), f"grype ignoredMatches[{index}].artifact.version")

        rule = policy_rules[0]
        require_keys(
            rule,
            {"vulnerability", "reason", "namespace", "package"},
            f"grype ignoredMatches[{index}].appliedIgnoreRules[0]",
        )
        grype_reason_date(rule["reason"], f"grype ignoredMatches[{index}].appliedIgnoreRules[0].reason", REVIEW_DATE)
        rule_package = mapping(rule.get("package"), f"grype ignoredMatches[{index}].appliedIgnoreRules[0].package")
        require_keys(
            rule_package,
            {"name", "version", "language"},
            f"grype ignoredMatches[{index}].appliedIgnoreRules[0].package",
        )
        rule_values = (
            text_value(rule.get("vulnerability"), f"grype ignoredMatches[{index}].appliedIgnoreRules[0].vulnerability"),
            text_value(rule_package.get("name"), f"grype ignoredMatches[{index}].appliedIgnoreRules[0].package.name"),
            text_value(
                rule_package.get("version"), f"grype ignoredMatches[{index}].appliedIgnoreRules[0].package.version"
            ),
        )
        finding = (cve, package, version)
        if rule_values != finding:
            fail(f"grype applied ignore rule {rule_values} does not exactly match finding {finding}")
        applied.append(finding)
    if len(applied) != len(set(applied)):
        fail("grype gate report contains duplicate applied ignore findings")
    if frozenset(applied) != ALLOWED_TRIPLES:
        fail(f"grype gate applied ignores must be exactly {sorted(ALLOWED_TRIPLES)}, got {sorted(applied)}")
    return sorted(applied)


TRIVY_FIXTURE = """\
vulnerabilities:
  - id: CVE-2026-31790
    purls:
      - pkg:rpm/redhat/openssl-fips-provider@3.0.7-8.el9
      - pkg:rpm/redhat/openssl-fips-provider-so@3.0.7-8.el9
    statement: "TD-6 held CMVP #4857 module"
    expired_at: 2026-10-10
"""

GRYPE_FIXTURE = """\
ignore:
  - vulnerability: CVE-2026-31790
    reason: "TD-6 held CMVP #4857 module; review-by 2026-10-10"
    package:
      name: openssl-fips-provider
      version: 3.0.7-8.el9
  - vulnerability: CVE-2026-31790
    reason: "TD-6 held CMVP #4857 module; review-by 2026-10-10"
    package:
      name: openssl-fips-provider-so
      version: 3.0.7-8.el9
"""


def grype_report_fixture(extra: bool = False) -> dict[str, Any]:
    ignored_matches: list[dict[str, Any]] = [
        {
            "vulnerability": {"id": ALLOWED_CVE},
            "artifact": {"name": package, "version": ALLOWED_VERSION},
            "appliedIgnoreRules": [
                {
                    "vulnerability": ALLOWED_CVE,
                    "reason": "TD-6 held CMVP #4857 module; review-by 2026-10-10",
                    "namespace": "",
                    "package": {"name": package, "version": ALLOWED_VERSION, "language": ""},
                }
            ],
        }
        for package in sorted(ALLOWED_PACKAGES)
    ]
    ignored_matches.append(
        {
            "vulnerability": {"id": "CVE-2026-2673"},
            "artifact": {"name": "openssl-libs", "version": "1:3.5.5-4.el9_8"},
            "appliedIgnoreRules": [{"namespace": "", "fix-state": "not-fixed"}],
        }
    )
    if extra:
        ignored_matches.append(
            {
                "vulnerability": {"id": "CVE-2099-0001"},
                "artifact": {"name": "openssl-libs", "version": "1.0"},
                "appliedIgnoreRules": [
                    {
                        "vulnerability": "CVE-2099-0001",
                        "reason": "extra rule; review-by 2026-10-10",
                        "namespace": "",
                        "package": {"name": "openssl-libs", "version": "1.0", "language": ""},
                    }
                ],
            }
        )
    return {"matches": [], "ignoredMatches": ignored_matches}


def expect_failure(name: str, callback: Callable[[], object]) -> None:
    try:
        callback()
    except IgnoreScopeError:
        return
    fail(f"{name}: negative self-test unexpectedly passed")


def run_self_test() -> None:
    today = date(2026, 7, 10)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        trivy = root / "trivy.yaml"
        grype = root / "grype.yaml"
        report = root / "grype.json"
        trivy.write_text(TRIVY_FIXTURE, encoding="utf-8")
        grype.write_text(GRYPE_FIXTURE, encoding="utf-8")
        report.write_text(json.dumps(grype_report_fixture()), encoding="utf-8")
        validate_ignore_files(trivy, grype, today)
        validate_grype_report(report)

        mutations = {
            "bare trivy id": TRIVY_FIXTURE.replace(
                "    purls:\n      - pkg:rpm/redhat/openssl-fips-provider@3.0.7-8.el9\n"
                "      - pkg:rpm/redhat/openssl-fips-provider-so@3.0.7-8.el9\n",
                "",
            ),
            "singular trivy purl": TRIVY_FIXTURE.replace(
                "    purls:\n      - pkg:rpm/redhat/openssl-fips-provider@3.0.7-8.el9\n"
                "      - pkg:rpm/redhat/openssl-fips-provider-so@3.0.7-8.el9\n",
                "    purl: pkg:rpm/redhat/not-the-provider@3.0.7-8.el9\n",
            ),
            "unknown trivy top-level key": TRIVY_FIXTURE + "zzzfoo: junk\n",
            "unknown trivy key": TRIVY_FIXTURE.replace(
                "    expired_at: 2026-10-10", "    expired_at: 2026-10-10\n    zzzfoo: junk"
            ),
            "extra trivy CVE": TRIVY_FIXTURE.replace(
                "vulnerabilities:\n",
                "vulnerabilities:\n"
                "  - id: CVE-2099-0001\n"
                "    purls:\n"
                "      - pkg:rpm/redhat/openssl-fips-provider@3.0.7-8.el9\n"
                '    statement: "mutation"\n'
                "    expired_at: 2026-10-10\n",
                1,
            ),
            "extra trivy package": TRIVY_FIXTURE.replace("openssl-fips-provider-so", "openssl-libs"),
            "wildcard trivy package": TRIVY_FIXTURE.replace("openssl-fips-provider-so", "openssl-*"),
            "wrong trivy version": TRIVY_FIXTURE.replace(ALLOWED_VERSION, "3.0.7-9.el9", 1),
            "expired trivy date": TRIVY_FIXTURE.replace("2026-10-10", "2020-01-01"),
            "unparseable trivy date": TRIVY_FIXTURE.replace("2026-10-10", "not-a-date"),
            "malformed trivy YAML": "vulnerabilities:\n   - id: CVE-2026-31790\n",
        }
        for name, content in mutations.items():
            trivy.write_text(content, encoding="utf-8")
            expect_failure(name, lambda: validate_ignore_files(trivy, grype, today))
        trivy.write_text(TRIVY_FIXTURE, encoding="utf-8")

        grype_mutations = {
            "grype date drift": GRYPE_FIXTURE.replace("2026-10-10", "2026-10-11", 1),
            "unknown grype key": GRYPE_FIXTURE.replace("    package:\n", "    zzzfoo: junk\n    package:\n", 1),
            "wrong grype version": GRYPE_FIXTURE.replace(ALLOWED_VERSION, "3.0.7-9.el9", 1),
            "missing grype package": GRYPE_FIXTURE.replace("    package:\n", "    omitted:\n", 1),
        }
        for name, content in grype_mutations.items():
            grype.write_text(content, encoding="utf-8")
            expect_failure(name, lambda: validate_ignore_files(trivy, grype, today))
        grype.write_text(GRYPE_FIXTURE, encoding="utf-8")

        expect_failure("missing trivy file", lambda: validate_ignore_files(root / "missing.yaml", grype, today))
        expect_failure("unreadable trivy path", lambda: validate_ignore_files(root, grype, today))
        expect_failure("review date elapsed", lambda: validate_ignore_files(trivy, grype, date(2026, 10, 11)))
        report.write_text(json.dumps(grype_report_fixture(extra=True)), encoding="utf-8")
        expect_failure("extra runtime suppression", lambda: validate_grype_report(report))
        report.write_text("{", encoding="utf-8")
        expect_failure("malformed grype report", lambda: validate_grype_report(report))

    print("CVE ignore scope self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail unless TD-6 scanner ignores remain exact and current.")
    parser.add_argument("--trivy-ignore", type=Path, default=TRIVY_IGNORE)
    parser.add_argument("--grype-ignore", type=Path, default=GRYPE_IGNORE)
    parser.add_argument("--grype-report", type=Path, help="also assert exact applied ignores in Grype gate JSON")
    parser.add_argument("--self-test", action="store_true", help="run built-in positive and negative checks")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0
        today = datetime.now(UTC).date()
        validate_ignore_files(cast(Path, args.trivy_ignore), cast(Path, args.grype_ignore), today)
        print(
            f"CVE ignore scope: {ALLOWED_CVE}; packages={','.join(sorted(ALLOWED_PACKAGES))}; "
            f"version={ALLOWED_VERSION}; review-by={REVIEW_DATE.isoformat()}"
        )
        grype_report = cast(Path | None, args.grype_report)
        if grype_report is not None:
            applied = validate_grype_report(grype_report)
            for cve, package, version in applied:
                print(f"grype applied ignore: {cve} package={package} version={version}")
            print(f"grype applied ignore count: {len(applied)}")
    except IgnoreScopeError as exc:
        print(f"CVE ignore scope check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
