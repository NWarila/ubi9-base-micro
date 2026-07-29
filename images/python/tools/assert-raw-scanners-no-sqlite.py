#!/usr/bin/env python3
# Purpose: Prove raw Trivy and Grype reports contain neither sqlite-libs nor the five SQLite findings.
# Role: gate
# Micro-container candidate: yes - pure-stdlib JSON-in/exit-out gate with a --self-test entrypoint

"""Reject SQLite package or CVE evidence in raw scanner reports before VEX."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, Final, cast

SQLITE_PACKAGE: Final = "sqlite-libs"
RUNTIME_PACKAGE_MARKER: Final = "python3.12-libs"
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


def _grype_source_identity(source: dict[str, Any]) -> str:
    source_type = source.get("type")
    if not isinstance(source_type, str) or not source_type.strip():
        raise RawScannerError("Grype source.type must be a non-empty string")

    target = source.get("target")
    if isinstance(target, str):
        identity = target.strip()
        if not identity:
            raise RawScannerError("Grype directory source.target must be a non-empty path string")
        return identity
    if isinstance(target, dict):
        if source_type != "image":
            raise RawScannerError("Grype object source.target requires source.type image")
        identities = [
            value.strip()
            for field in ("userInput", "imageID")
            if isinstance((value := target.get(field)), str) and value.strip()
        ]
        if not identities:
            raise RawScannerError("Grype image source.target must contain a non-empty userInput or imageID identity")
        return identities[0]
    raise RawScannerError("Grype source.target must be a directory path string or image identity object")


def assert_raw_report(document: dict[str, Any], scanner: str) -> None:
    """Assert a recognized raw report has no SQLite package reference or target CVE."""
    if scanner == "trivy":
        trivy = document.get("Trivy")
        if not isinstance(trivy, dict) or not isinstance(trivy.get("Version"), str) or not trivy["Version"].strip():
            raise RawScannerError("Trivy report must contain a Trivy version identity")
        if document.get("SchemaVersion") != 2:
            raise RawScannerError("Trivy report must use SchemaVersion 2")
        artifact_name = document.get("ArtifactName")
        if not isinstance(artifact_name, str) or not artifact_name.strip():
            raise RawScannerError("Trivy ArtifactName must be a non-empty string")
        artifact_type = document.get("ArtifactType")
        if artifact_type not in {"container_image", "filesystem"}:
            raise RawScannerError("Trivy ArtifactType must be container_image or filesystem")
        if not isinstance(document.get("Metadata"), dict):
            raise RawScannerError("Trivy Metadata must be an object")
        results = document.get("Results")
        if not isinstance(results, list) or not results:
            raise RawScannerError("Trivy report must contain a non-empty Results list")
        runtime_marker_seen = False
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                raise RawScannerError(f"Trivy Results[{result_index}] must be an object")
            for field in ("Target", "Class", "Type"):
                value = result.get(field)
                if not isinstance(value, str) or not value.strip():
                    raise RawScannerError(f"Trivy Results[{result_index}].{field} must be a non-empty string")
            packages = result.get("Packages")
            if packages is not None:
                if not isinstance(packages, list):
                    raise RawScannerError(f"Trivy Results[{result_index}].Packages must be a list")
                for package_index, package in enumerate(packages):
                    if not isinstance(package, dict):
                        raise RawScannerError(
                            f"Trivy Results[{result_index}].Packages[{package_index}] must be an object"
                        )
                    name = package.get("Name")
                    if not isinstance(name, str) or not name.strip():
                        raise RawScannerError(
                            f"Trivy Results[{result_index}].Packages[{package_index}].Name must be a non-empty string"
                        )
                    runtime_marker_seen |= name == RUNTIME_PACKAGE_MARKER
            vulnerabilities = result.get("Vulnerabilities")
            if vulnerabilities is not None:
                if not isinstance(vulnerabilities, list):
                    raise RawScannerError(f"Trivy Results[{result_index}].Vulnerabilities must be a list or null")
                for finding_index, finding in enumerate(vulnerabilities):
                    if not isinstance(finding, dict):
                        raise RawScannerError(
                            f"Trivy Results[{result_index}].Vulnerabilities[{finding_index}] must be an object"
                        )
                    for field in ("VulnerabilityID", "PkgName"):
                        value = finding.get(field)
                        if not isinstance(value, str) or not value.strip():
                            raise RawScannerError(
                                f"Trivy Results[{result_index}].Vulnerabilities[{finding_index}].{field} "
                                "must be a non-empty string"
                            )
        if not runtime_marker_seen:
            raise RawScannerError(f"Trivy report did not enumerate runtime package {RUNTIME_PACKAGE_MARKER}")
    elif scanner == "grype":
        descriptor = document.get("descriptor")
        if (
            not isinstance(descriptor, dict)
            or descriptor.get("name") != "grype"
            or not isinstance(descriptor.get("version"), str)
            or not descriptor["version"].strip()
        ):
            raise RawScannerError("Grype report must contain a versioned grype descriptor")
        source = document.get("source")
        if not isinstance(source, dict):
            raise RawScannerError("Grype report must contain a source object")
        _grype_source_identity(source)
        distro = document.get("distro")
        if not isinstance(distro, dict):
            raise RawScannerError("Grype report must contain a distro object")
        for field in ("name", "version"):
            value = distro.get(field)
            if not isinstance(value, str) or not value.strip():
                raise RawScannerError(f"Grype distro.{field} must be a non-empty string")
        matches = document.get("matches")
        if not isinstance(matches, list) or not matches:
            raise RawScannerError("Grype report must contain a non-empty matches list")
        runtime_marker_seen = False
        for match_index, match in enumerate(matches):
            if not isinstance(match, dict):
                raise RawScannerError(f"Grype matches[{match_index}] must be an object")
            artifact = match.get("artifact")
            if not isinstance(artifact, dict):
                raise RawScannerError(f"Grype matches[{match_index}].artifact must be an object")
            for field in ("name", "type"):
                value = artifact.get(field)
                if not isinstance(value, str) or not value.strip():
                    raise RawScannerError(f"Grype matches[{match_index}].artifact.{field} must be a non-empty string")
            runtime_marker_seen |= artifact["name"] == RUNTIME_PACKAGE_MARKER
            vulnerability = match.get("vulnerability")
            if not isinstance(vulnerability, dict):
                raise RawScannerError(f"Grype matches[{match_index}].vulnerability must be an object")
            vulnerability_id = vulnerability.get("id")
            if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
                raise RawScannerError(f"Grype matches[{match_index}].vulnerability.id must be a non-empty string")
        if not runtime_marker_seen:
            raise RawScannerError(f"Grype report did not enumerate runtime package {RUNTIME_PACKAGE_MARKER}")
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
    clean_trivy: dict[str, Any] = {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.71.0"},
        "ArtifactName": "/rootfs",
        "ArtifactType": "filesystem",
        "Metadata": {"OS": {"Family": "redhat", "Name": "9.8"}},
        "Results": [
            {
                "Target": "rootfs (redhat 9.8)",
                "Class": "os-pkgs",
                "Type": "redhat",
                "Packages": [{"Name": "python3.12-libs"}],
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2025-0001", "PkgName": "python3.12-libs"}],
            }
        ],
    }
    clean_trivy_image = copy.deepcopy(clean_trivy)
    clean_trivy_image["ArtifactName"] = "local/ubi9-base-python:self-test"
    clean_trivy_image["ArtifactType"] = "container_image"
    clean_trivy_image["Metadata"] = {"ImageID": "sha256:self-test"}
    clean_trivy_image["Results"][0]["Target"] = "local/ubi9-base-python:self-test (redhat 9.8)"

    clean_grype_directory: dict[str, Any] = {
        "descriptor": {"name": "grype", "version": "0.115.0"},
        "distro": {"name": "redhat", "version": "9.8"},
        "matches": [
            {
                "vulnerability": {"id": "CVE-2025-0001"},
                "artifact": {"name": "python3.12-libs", "type": "rpm"},
            }
        ],
        "source": {"type": "directory", "target": "/rootfs"},
    }
    clean_grype_image = copy.deepcopy(clean_grype_directory)
    clean_grype_image["source"] = {
        "type": "image",
        "target": {
            "userInput": "local/ubi9-base-python:self-test",
            "imageID": "sha256:self-test",
        },
    }
    clean_grype_image_id_only = copy.deepcopy(clean_grype_image)
    clean_grype_image_id_only["source"]["target"]["userInput"] = ""

    assert_raw_report(clean_trivy, "trivy")
    assert_raw_report(clean_trivy_image, "trivy")
    assert_raw_report(clean_grype_directory, "grype")
    assert_raw_report(clean_grype_image, "grype")
    assert_raw_report(clean_grype_image_id_only, "grype")

    trivy_package = copy.deepcopy(clean_trivy)
    trivy_package["Results"][0]["Packages"][0]["Name"] = SQLITE_PACKAGE
    trivy_cve = copy.deepcopy(clean_trivy)
    trivy_cve["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = "CVE-2026-51296"
    trivy_no_marker = copy.deepcopy(clean_trivy)
    trivy_no_marker["Results"][0]["Packages"][0]["Name"] = "other-libs"
    trivy_empty = copy.deepcopy(clean_trivy)
    trivy_empty["Results"] = []
    trivy_hollow = copy.deepcopy(clean_trivy)
    trivy_hollow["Results"] = [{}]
    trivy_malformed_packages = copy.deepcopy(clean_trivy)
    trivy_malformed_packages["Results"][0]["Packages"] = {}
    trivy_malformed_package = copy.deepcopy(clean_trivy)
    trivy_malformed_package["Results"][0]["Packages"] = [{"Name": {"nested": RUNTIME_PACKAGE_MARKER}}]
    trivy_malformed_finding = copy.deepcopy(clean_trivy)
    trivy_malformed_finding["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": ["CVE-2025-0001"]}]
    trivy_missing_artifact_identity = copy.deepcopy(clean_trivy)
    trivy_missing_artifact_identity["ArtifactName"] = ""
    trivy_unknown_artifact_type = copy.deepcopy(clean_trivy)
    trivy_unknown_artifact_type["ArtifactType"] = "unknown"
    trivy_malformed_metadata = copy.deepcopy(clean_trivy)
    trivy_malformed_metadata["Metadata"] = []

    grype_package = copy.deepcopy(clean_grype_directory)
    grype_package["matches"][0]["artifact"]["name"] = SQLITE_PACKAGE
    grype_cve = copy.deepcopy(clean_grype_directory)
    grype_cve["matches"][0]["vulnerability"]["id"] = "CVE-2026-51304"
    grype_no_marker = copy.deepcopy(clean_grype_directory)
    grype_no_marker["matches"][0]["artifact"]["name"] = "other-libs"
    grype_malformed_match = copy.deepcopy(clean_grype_directory)
    grype_malformed_match["matches"] = [{"artifact": [], "vulnerability": {"id": "CVE-2025-0001"}}]
    grype_empty_image_identity = copy.deepcopy(clean_grype_image)
    grype_empty_image_identity["source"]["target"] = {"userInput": " ", "imageID": ""}
    grype_malformed_target = copy.deepcopy(clean_grype_image)
    grype_malformed_target["source"]["target"] = []
    grype_object_directory_target = copy.deepcopy(clean_grype_directory)
    grype_object_directory_target["source"]["target"] = {"userInput": "/rootfs"}

    mutations: list[tuple[str, dict[str, Any], str]] = [
        ("Trivy package", trivy_package, "trivy"),
        ("Trivy CVE", trivy_cve, "trivy"),
        ("Trivy empty Results", {"Results": []}, "trivy"),
        ("Trivy hollow result", {"Results": [{}]}, "trivy"),
        ("Trivy identified empty Results", trivy_empty, "trivy"),
        ("Trivy identified hollow result", trivy_hollow, "trivy"),
        ("Trivy missing runtime marker", trivy_no_marker, "trivy"),
        ("Trivy malformed Packages object", trivy_malformed_packages, "trivy"),
        ("Trivy malformed package name", trivy_malformed_package, "trivy"),
        ("Trivy malformed finding", trivy_malformed_finding, "trivy"),
        ("Trivy missing artifact identity", trivy_missing_artifact_identity, "trivy"),
        ("Trivy unknown artifact type", trivy_unknown_artifact_type, "trivy"),
        ("Trivy malformed metadata", trivy_malformed_metadata, "trivy"),
        ("Grype package", grype_package, "grype"),
        ("Grype CVE", grype_cve, "grype"),
        (
            "Grype hollow report",
            {
                "descriptor": {"name": "grype"},
                "distro": {},
                "matches": [],
                "source": {},
            },
            "grype",
        ),
        ("Grype empty matches", {**clean_grype_directory, "matches": []}, "grype"),
        ("Grype missing runtime marker", grype_no_marker, "grype"),
        ("Grype malformed nested artifact", grype_malformed_match, "grype"),
        (
            "Grype missing matches",
            {key: value for key, value in clean_grype_directory.items() if key != "matches"},
            "grype",
        ),
        ("Grype wrong descriptor", {**clean_grype_directory, "descriptor": {"name": "other"}}, "grype"),
        (
            "Grype missing source",
            {key: value for key, value in clean_grype_directory.items() if key != "source"},
            "grype",
        ),
        (
            "Grype missing distro",
            {key: value for key, value in clean_grype_directory.items() if key != "distro"},
            "grype",
        ),
        ("Grype empty image identity", grype_empty_image_identity, "grype"),
        ("Grype malformed target", grype_malformed_target, "grype"),
        ("Grype object directory target", grype_object_directory_target, "grype"),
    ]
    rejected = 0
    for label, document, scanner in mutations:
        try:
            assert_raw_report(document, scanner)
        except RawScannerError:
            rejected += 1
        else:
            raise RawScannerError(f"self-test mutation unexpectedly passed: {label}")
    print(
        f"raw scanner SQLite absence self-test: clean reports accepted; {rejected}/{len(mutations)} mutations rejected"
    )


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
