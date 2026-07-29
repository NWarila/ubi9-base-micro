#!/usr/bin/env python3
# Purpose: Prove raw Trivy and Grype reports contain neither sqlite-libs nor the five SQLite findings.
# Role: gate
# Micro-container candidate: yes - pure-stdlib JSON-in/exit-out gate with a --self-test entrypoint

"""Reject SQLite package or CVE evidence in raw scanner reports before VEX."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, Final, cast

SQLITE_PACKAGE: Final = "sqlite-libs"
SQLITE_CVES: Final = frozenset(
    {
        "CVE-2026-51296",
        "CVE-2026-51297",
        "CVE-2026-51302",
        "CVE-2026-51303",
        "CVE-2026-51304",
    }
)


class RawScannerError(RuntimeError):
    """Raised when raw scanner evidence contains SQLite or has an unknown shape."""


def _load(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RawScannerError(f"could not load scanner report {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise RawScannerError(f"{path}: scanner report must be a JSON object")
    return cast(dict[str, Any], loaded)


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from _strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _strings(nested)


def _is_sqlite_package_reference(value: str) -> bool:
    lowered = value.lower()
    return lowered == SQLITE_PACKAGE or (lowered.startswith("pkg:rpm/") and f"/{SQLITE_PACKAGE}@" in lowered)


def assert_raw_report(document: dict[str, Any], scanner: str) -> None:
    """Assert a recognized raw report has no SQLite package reference or target CVE."""
    if scanner == "trivy":
        if not isinstance(document.get("Results"), list):
            raise RawScannerError("Trivy report must contain a Results list")
    elif scanner == "grype":
        if not isinstance(document.get("matches"), list):
            raise RawScannerError("Grype report must contain a matches list")
        descriptor = document.get("descriptor")
        if not isinstance(descriptor, dict) or descriptor.get("name") != "grype":
            raise RawScannerError("Grype report must contain a grype descriptor")
        if not isinstance(document.get("source"), dict):
            raise RawScannerError("Grype report must contain a source object")
        if not isinstance(document.get("distro"), dict):
            raise RawScannerError("Grype report must contain a distro object")
    else:
        raise RawScannerError(f"unsupported scanner: {scanner}")

    values = list(_strings(document))
    package_references = sorted({value for value in values if _is_sqlite_package_reference(value)})
    findings = sorted(SQLITE_CVES & set(values))
    problems: list[str] = []
    if package_references:
        problems.append("SQLite package reference(s): " + ", ".join(package_references))
    if findings:
        problems.append("SQLite finding(s): " + ", ".join(findings))
    if problems:
        raise RawScannerError(f"{scanner} raw report contains " + "; ".join(problems))


def self_test() -> None:
    clean_trivy = {
        "Results": [
            {
                "Packages": [{"Name": "python3.12-libs"}],
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2025-0001", "PkgName": "python3.12-libs"}],
            }
        ]
    }
    clean_grype = {
        "descriptor": {"name": "grype"},
        "distro": {"name": "redhat", "version": "9.8"},
        "matches": [{"vulnerability": {"id": "CVE-2025-0001"}, "artifact": {"name": "python3.12-libs"}}],
        "source": {"type": "directory"},
    }
    assert_raw_report(clean_trivy, "trivy")
    assert_raw_report(clean_grype, "grype")

    mutations: list[tuple[str, dict[str, Any], str]] = [
        ("Trivy package", {"Results": [{"Packages": [{"Name": SQLITE_PACKAGE}]}]}, "trivy"),
        (
            "Trivy CVE",
            {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2026-51296", "PkgName": "other"}]}]},
            "trivy",
        ),
        (
            "Grype package",
            {
                **clean_grype,
                "matches": [{"vulnerability": {"id": "CVE-2025-0001"}, "artifact": {"name": SQLITE_PACKAGE}}],
            },
            "grype",
        ),
        (
            "Grype CVE",
            {
                **clean_grype,
                "matches": [{"vulnerability": {"id": "CVE-2026-51304"}, "artifact": {"name": "other"}}],
            },
            "grype",
        ),
        ("Grype missing matches", {key: value for key, value in clean_grype.items() if key != "matches"}, "grype"),
        ("Grype wrong descriptor", {**clean_grype, "descriptor": {"name": "other"}}, "grype"),
        ("Grype missing source", {key: value for key, value in clean_grype.items() if key != "source"}, "grype"),
        ("Grype missing distro", {key: value for key, value in clean_grype.items() if key != "distro"}, "grype"),
    ]
    rejected = 0
    for label, document, scanner in mutations:
        try:
            assert_raw_report(document, scanner)
        except RawScannerError:
            rejected += 1
        else:
            raise RawScannerError(f"self-test mutation unexpectedly passed: {label}")
    print(f"raw scanner SQLite absence self-test: clean reports accepted; {rejected}/8 mutations rejected")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail if raw Trivy or Grype JSON contains sqlite-libs or a targeted SQLite CVE."
    )
    parser.add_argument("--trivy-json", type=Path, help="raw Trivy JSON report")
    parser.add_argument("--grype-json", type=Path, help="raw Grype JSON report")
    parser.add_argument("--self-test", action="store_true", help="run the offline self-test")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            self_test()
            return 0
        if args.trivy_json is None or args.grype_json is None:
            raise RawScannerError("--trivy-json and --grype-json are required")
        assert_raw_report(_load(args.trivy_json), "trivy")
        assert_raw_report(_load(args.grype_json), "grype")
        print(
            "raw scanner SQLite absence: Trivy and Grype contain neither sqlite-libs nor "
            + ",".join(sorted(SQLITE_CVES))
        )
    except RawScannerError as exc:
        print(f"raw scanner SQLite absence failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
