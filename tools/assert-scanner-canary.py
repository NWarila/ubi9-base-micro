#!/usr/bin/env python3
# Purpose: Fail unless Grype and Trivy detect the committed Log4Shell canary
# Role: gate
# Micro-container candidate: yes - pure-stdlib, scanner-reports-in/exit-out, has --self-test

"""Assert that Grype and Trivy detect the scanner content canary."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, cast

DEFAULT_EXPECTED_CVE = "CVE-2021-44228"
GRYPE_PRIMARY_ID = "GHSA-jfh8-c2jp-5v3q"


class ScannerCanaryError(Exception):
    """Base class for scanner canary failures."""


class ScannerReportLoadError(ScannerCanaryError):
    """Raised when a scanner report cannot be loaded as a JSON object."""


class ScannerReportSchemaError(ScannerCanaryError):
    """Raised when a scanner report does not have the required record shape."""


class ScannerDetectionError(ScannerCanaryError):
    """Raised when a valid report does not contain the expected detection."""


@dataclass(frozen=True)
class Detection:
    scanner: str
    vulnerability_id: str
    location: str

    def log_line(self) -> str:
        return f"scanner content canary: {self.scanner} detected {self.vulnerability_id} ({self.location})"


def fail_schema(message: str) -> NoReturn:
    raise ScannerReportSchemaError(message)


def load_json_object(path: Path, scanner: str) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            loaded = json.load(handle)
    except FileNotFoundError as exc:
        raise ScannerReportLoadError(f"{scanner} report is missing: {path}") from exc
    except OSError as exc:
        raise ScannerReportLoadError(f"{scanner} report is unreadable: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ScannerReportLoadError(f"{scanner} report is malformed JSON: {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        fail_schema(f"{scanner} report must be a JSON object: {path}")
    return cast(dict[str, Any], loaded)


def require_non_empty_list(report: dict[str, Any], field: str, scanner: str) -> list[Any]:
    value = report.get(field)
    if not isinstance(value, list):
        fail_schema(f"{scanner} report field {field} must be an array")
    if not value:
        fail_schema(f"{scanner} report field {field} must not be empty")
    return value


def require_object(value: object, field: str, scanner: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail_schema(f"{scanner} report field {field} must be an object")
    return cast(dict[str, Any], value)


def require_id(value: object, field: str, scanner: str) -> str:
    if not isinstance(value, str) or not value:
        fail_schema(f"{scanner} report field {field} must be a non-empty string")
    return value


def assert_grype(report: dict[str, Any], expected_cve: str) -> Detection:
    matches = require_non_empty_list(report, "matches", "grype")
    detection: Detection | None = None
    for index, raw_match in enumerate(matches):
        match = require_object(raw_match, f"matches[{index}]", "grype")
        vulnerability = require_object(match.get("vulnerability"), f"matches[{index}].vulnerability", "grype")
        primary_id = require_id(vulnerability.get("id"), f"matches[{index}].vulnerability.id", "grype")
        if detection is None and primary_id == GRYPE_PRIMARY_ID:
            detection = Detection("grype", primary_id, "primary id")

        related = match.get("relatedVulnerabilities", [])
        if not isinstance(related, list):
            fail_schema(f"grype report field matches[{index}].relatedVulnerabilities must be an array")
        for related_index, raw_related in enumerate(related):
            related_record = require_object(
                raw_related,
                f"matches[{index}].relatedVulnerabilities[{related_index}]",
                "grype",
            )
            related_id = require_id(
                related_record.get("id"),
                f"matches[{index}].relatedVulnerabilities[{related_index}].id",
                "grype",
            )
            if detection is None and related_id == expected_cve:
                detection = Detection("grype", related_id, "related id")
    if detection is not None:
        return detection
    raise ScannerDetectionError(
        f"grype did not report primary {GRYPE_PRIMARY_ID} or related {expected_cve} in any match record"
    )


def assert_trivy(report: dict[str, Any], expected_cve: str) -> Detection:
    results = require_non_empty_list(report, "Results", "trivy")
    vulnerability_records = 0
    detection: Detection | None = None
    for result_index, raw_result in enumerate(results):
        result = require_object(raw_result, f"Results[{result_index}]", "trivy")
        vulnerabilities = result.get("Vulnerabilities")
        if not isinstance(vulnerabilities, list):
            fail_schema(f"trivy report field Results[{result_index}].Vulnerabilities must be an array")
        for vulnerability_index, raw_vulnerability in enumerate(vulnerabilities):
            vulnerability_records += 1
            vulnerability = require_object(
                raw_vulnerability,
                f"Results[{result_index}].Vulnerabilities[{vulnerability_index}]",
                "trivy",
            )
            vulnerability_id = require_id(
                vulnerability.get("VulnerabilityID"),
                f"Results[{result_index}].Vulnerabilities[{vulnerability_index}].VulnerabilityID",
                "trivy",
            )
            if detection is None and vulnerability_id == expected_cve:
                detection = Detection("trivy", vulnerability_id, "vulnerability record")
    if vulnerability_records == 0:
        fail_schema("trivy report Vulnerabilities arrays must not all be empty")
    if detection is not None:
        return detection
    raise ScannerDetectionError(f"trivy did not report {expected_cve} in any vulnerability record")


def assert_reports(
    grype_report: dict[str, Any],
    trivy_report: dict[str, Any],
    expected_cve: str,
) -> list[Detection]:
    if not expected_cve:
        fail_schema("expected CVE must be a non-empty string")
    return [assert_grype(grype_report, expected_cve), assert_trivy(trivy_report, expected_cve)]


def expect_failure(name: str, callback: Callable[[], object]) -> None:
    try:
        callback()
    except ScannerCanaryError:
        return
    raise ScannerCanaryError(f"{name}: negative self-test unexpectedly passed")


def run_self_test() -> None:
    positive_grype = {
        "matches": [
            {
                "vulnerability": {"id": GRYPE_PRIMARY_ID},
                "relatedVulnerabilities": [{"id": DEFAULT_EXPECTED_CVE}],
            }
        ]
    }
    positive_trivy = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": DEFAULT_EXPECTED_CVE}]}]}
    assert_reports(positive_grype, positive_trivy, DEFAULT_EXPECTED_CVE)

    missing_grype = {"matches": [{"vulnerability": {"id": "GHSA-bogus"}, "relatedVulnerabilities": []}]}
    expect_failure(
        "missing grype canary",
        lambda: assert_reports(missing_grype, positive_trivy, DEFAULT_EXPECTED_CVE),
    )
    missing_trivy = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-0000-0000"}]}]}
    expect_failure(
        "missing trivy canary",
        lambda: assert_reports(positive_grype, missing_trivy, DEFAULT_EXPECTED_CVE),
    )
    expect_failure("empty grype matches", lambda: assert_grype({"matches": []}, DEFAULT_EXPECTED_CVE))
    expect_failure("empty trivy results", lambda: assert_trivy({"Results": []}, DEFAULT_EXPECTED_CVE))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        malformed = root / "malformed.json"
        malformed.write_text("{", encoding="utf-8")
        non_object = root / "non-object.json"
        non_object.write_text("[]", encoding="utf-8")
        expect_failure("malformed report", lambda: load_json_object(malformed, "test"))
        expect_failure("non-object report", lambda: load_json_object(non_object, "test"))
        expect_failure("missing report", lambda: load_json_object(root / "missing.json", "test"))

    print("scanner content canary self-test: ok")


def non_empty(value: str) -> str:
    if not value:
        raise argparse.ArgumentTypeError("expected a non-empty value")
    return value


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail unless Grype and Trivy detect the scanner content canary.")
    parser.add_argument("--grype-json", type=Path, help="Grype JSON report", required=False)
    parser.add_argument("--trivy-json", type=Path, help="Trivy JSON report", required=False)
    parser.add_argument(
        "--expect-cve",
        type=non_empty,
        default=DEFAULT_EXPECTED_CVE,
        help="CVE identifier Trivy must report and Grype may report as a related identifier",
    )
    parser.add_argument("--self-test", action="store_true", help="run built-in positive and negative parser checks")
    args = parser.parse_args(argv)
    if not args.self_test and (args.grype_json is None or args.trivy_json is None):
        parser.error("--grype-json and --trivy-json are required unless --self-test is used")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0
        grype_report = load_json_object(cast(Path, args.grype_json), "grype")
        trivy_report = load_json_object(cast(Path, args.trivy_json), "trivy")
        for detection in assert_reports(grype_report, trivy_report, cast(str, args.expect_cve)):
            print(detection.log_line())
    except ScannerCanaryError as exc:
        print(f"scanner content canary failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
