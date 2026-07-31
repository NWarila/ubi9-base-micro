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
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any, Final, cast

SQLITE_PACKAGE: Final = "sqlite-libs"
RUNTIME_PACKAGE_MARKER: Final = "python3.12-libs"
RPM_ARCHITECTURES: Final = {"amd64": "x86_64", "arm64": "aarch64"}
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


@dataclass(frozen=True)
class RuntimeMarker:
    """Contract-derived identity for the policy-selected runtime package."""

    workflow_arch: str
    name: str
    epoch: str
    version: str
    release: str
    rpm_arch: str


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RawScannerError(f"could not load {label} {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise RawScannerError(f"{path}: {label} must be a JSON object")
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


def _is_canonical_package_name(value: str) -> bool:
    return value == value.strip() and not any(character.isspace() for character in value)


def _parse_runtime_marker_nevra(value: str, arch: str) -> RuntimeMarker:
    try:
        name, epoch_version, release_arch = value.rsplit("-", 2)
        release, rpm_arch = release_arch.rsplit(".", 1)
    except ValueError as exc:
        raise RawScannerError(f"contract runtime marker NEVRA is malformed: {value!r}") from exc

    if epoch_version.count(":") > 1 or ":" in release:
        raise RawScannerError(f"contract runtime marker NEVRA is malformed: {value!r}")
    if ":" in epoch_version:
        epoch, version = epoch_version.split(":", 1)
        if not epoch.isdigit():
            raise RawScannerError(f"contract runtime marker NEVRA has an invalid epoch: {value!r}")
    else:
        epoch = "0"
        version = epoch_version
    fields = (name, version, release, rpm_arch)
    if any(not field or any(character.isspace() for character in field) for field in fields):
        raise RawScannerError(f"contract runtime marker NEVRA is malformed: {value!r}")
    return RuntimeMarker(
        workflow_arch=arch,
        name=name,
        epoch=epoch,
        version=version,
        release=release,
        rpm_arch=rpm_arch,
    )


def runtime_marker_from_contract(document: Any, arch: str) -> RuntimeMarker:
    """Return the exactly-one policy marker identity from runtime.shipped[arch]."""
    if arch not in RPM_ARCHITECTURES:
        raise RawScannerError("--arch must be one of: amd64, arm64")
    if not isinstance(document, dict):
        raise RawScannerError("contract must be a JSON object")
    runtime = document.get("runtime")
    if not isinstance(runtime, dict):
        raise RawScannerError("contract runtime must be an object")
    shipped = runtime.get("shipped")
    if not isinstance(shipped, dict):
        raise RawScannerError("contract runtime.shipped must be an object")
    if arch not in shipped:
        raise RawScannerError(f"contract runtime.shipped[{arch}] is required")
    entries = shipped[arch]
    if not isinstance(entries, list):
        raise RawScannerError(f"contract runtime.shipped[{arch}] must be a list")
    if not entries:
        raise RawScannerError(f"contract runtime.shipped[{arch}] must be non-empty")

    selected: list[RuntimeMarker] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, str) or not entry.strip():
            raise RawScannerError(f"contract runtime.shipped[{arch}][{index}] must be a non-empty NEVRA string")
        try:
            identity = _parse_runtime_marker_nevra(entry, arch)
        except RawScannerError:
            if entry.startswith(f"{RUNTIME_PACKAGE_MARKER}-"):
                raise
            continue
        if identity.name == RUNTIME_PACKAGE_MARKER:
            selected.append(identity)

    if len(selected) != 1:
        raise RawScannerError(
            f"contract runtime.shipped[{arch}] must contain exactly one {RUNTIME_PACKAGE_MARKER} NEVRA; "
            f"found {len(selected)}"
        )
    marker = selected[0]
    expected_rpm_arch = RPM_ARCHITECTURES[arch]
    if marker.rpm_arch != expected_rpm_arch:
        raise RawScannerError(
            f"contract runtime marker architecture for --arch {arch} must be {expected_rpm_arch}, got {marker.rpm_arch}"
        )
    return marker


def _grype_source_identity(source: dict[str, Any]) -> str:
    source_type = source.get("type")
    target = source.get("target")
    if source_type == "directory":
        if not isinstance(target, str):
            raise RawScannerError("Grype directory source.target must be a non-empty path string")
        identity = target.strip()
        if not identity:
            raise RawScannerError("Grype directory source.target must be a non-empty path string")
        return identity
    if source_type == "image":
        if not isinstance(target, dict):
            raise RawScannerError("Grype image source.target must be an object")
        identities = [
            value.strip()
            for field in ("userInput", "imageID")
            if isinstance((value := target.get(field)), str) and value.strip()
        ]
        if not identities:
            raise RawScannerError("Grype image source.target must contain a non-empty userInput or imageID identity")
        return identities[0]
    raise RawScannerError("Grype source.type must be image or directory")


def _trivy_epoch(value: Any, location: str) -> str:
    if value is None:
        return "0"
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return str(value)
    raise RawScannerError(f"{location} must be null, absent, or a non-negative integer")


def _assert_runtime_marker_package(
    package: dict[str, Any],
    location: str,
    expected: RuntimeMarker,
) -> None:
    comparisons = (
        ("Epoch", _trivy_epoch(package.get("Epoch"), f"{location}.Epoch"), expected.epoch),
        ("Version", package.get("Version"), expected.version),
        ("Release", package.get("Release"), expected.release),
        ("Arch", package.get("Arch"), expected.rpm_arch),
    )
    for field, actual, wanted in comparisons:
        if field in {"Version", "Release"} and isinstance(actual, str) and ":" in actual:
            raise RawScannerError(f"Trivy runtime package {expected.name} {field} must not contain ':'")
        if actual != wanted:
            qualifier = f"--arch {expected.workflow_arch} contract" if field == "Arch" else "contract"
            raise RawScannerError(
                f"Trivy runtime package {expected.name} {field} does not match {qualifier}: "
                f"expected {wanted}, got {actual!r}"
            )


def assert_raw_report(
    document: dict[str, Any],
    scanner: str,
    expected_runtime: RuntimeMarker | None = None,
) -> None:
    """Assert a recognized raw report has no SQLite package reference or target CVE."""
    if scanner == "trivy":
        if expected_runtime is None:
            raise RawScannerError("Trivy validation requires a contract-derived runtime marker")
        if not _is_canonical_package_name(expected_runtime.name):
            raise RawScannerError("contract runtime marker package name must be canonical without whitespace")
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
            target = result.get("Target")
            if not isinstance(target, str) or not target.strip():
                raise RawScannerError(f"Trivy Results[{result_index}].Target must be a non-empty string")
            if result.get("Class") != "os-pkgs":
                raise RawScannerError(f"Trivy Results[{result_index}].Class must be os-pkgs")
            if result.get("Type") != "redhat":
                raise RawScannerError(f"Trivy Results[{result_index}].Type must be redhat")
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
                    if not _is_canonical_package_name(name):
                        raise RawScannerError(
                            f"Trivy Results[{result_index}].Packages[{package_index}].Name "
                            "must be canonical without whitespace"
                        )
                    version = package.get("Version")
                    if not isinstance(version, str) or not version.strip():
                        raise RawScannerError(
                            f"Trivy Results[{result_index}].Packages[{package_index}].Version "
                            "must be a non-empty string"
                        )
                    if name == expected_runtime.name:
                        _assert_runtime_marker_package(
                            package,
                            f"Trivy Results[{result_index}].Packages[{package_index}]",
                            expected_runtime,
                        )
                        runtime_marker_seen = True
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
            raise RawScannerError(f"Trivy report did not enumerate runtime package {expected_runtime.name}")
    elif scanner == "grype":
        descriptor = document.get("descriptor")
        if not isinstance(descriptor, dict):
            raise RawScannerError("Grype descriptor must be an object")
        if descriptor.get("name") != "grype":
            raise RawScannerError("Grype descriptor.name must be grype")
        descriptor_version = descriptor.get("version")
        if not isinstance(descriptor_version, str) or not descriptor_version.strip():
            raise RawScannerError("Grype descriptor.version must be a non-empty string")
        source = document.get("source")
        if not isinstance(source, dict):
            raise RawScannerError("Grype report must contain a source object")
        _grype_source_identity(source)
        distro = document.get("distro")
        if not isinstance(distro, dict):
            raise RawScannerError("Grype report must contain a distro object")
        if distro.get("name") != "redhat":
            raise RawScannerError("Grype distro.name must be redhat")
        distro_version = distro.get("version")
        if not isinstance(distro_version, str) or not distro_version.strip():
            raise RawScannerError("Grype distro.version must be a non-empty string")
        matches = document.get("matches")
        if not isinstance(matches, list):
            raise RawScannerError("Grype matches must be a list")
        for match_index, match in enumerate(matches):
            if not isinstance(match, dict):
                raise RawScannerError(f"Grype matches[{match_index}] must be an object")
            artifact = match.get("artifact")
            if not isinstance(artifact, dict):
                raise RawScannerError(f"Grype matches[{match_index}].artifact must be an object")
            artifact_name = artifact.get("name")
            if not isinstance(artifact_name, str) or not artifact_name.strip():
                raise RawScannerError(f"Grype matches[{match_index}].artifact.name must be a non-empty string")
            if not _is_canonical_package_name(artifact_name):
                raise RawScannerError(
                    f"Grype matches[{match_index}].artifact.name must be canonical without whitespace"
                )
            if artifact.get("type") != "rpm":
                raise RawScannerError(f"Grype matches[{match_index}].artifact.type must be rpm")
            vulnerability = match.get("vulnerability")
            if not isinstance(vulnerability, dict):
                raise RawScannerError(f"Grype matches[{match_index}].vulnerability must be an object")
            vulnerability_id = vulnerability.get("id")
            if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
                raise RawScannerError(f"Grype matches[{match_index}].vulnerability.id must be a non-empty string")
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


def _expect_rejection(label: str, action: Callable[[], object], expected_reason: str) -> None:
    try:
        action()
    except RawScannerError as exc:
        if expected_reason not in str(exc):
            raise RawScannerError(
                f"self-test probe rejected for the wrong reason: {label}: expected {expected_reason!r}, got {exc}"
            ) from exc
    else:
        raise RawScannerError(f"self-test probe unexpectedly passed: {label}")


def self_test() -> None:
    clean_contract: dict[str, Any] = {
        "runtime": {
            "shipped": {
                "amd64": ["python3.12-libs-3.12.13-3.el9_8.1.x86_64"],
                "arm64": ["python3.12-libs-3.12.13-3.el9_8.1.aarch64"],
            }
        }
    }
    amd64_marker = runtime_marker_from_contract(clean_contract, "amd64")
    arm64_marker = runtime_marker_from_contract(clean_contract, "arm64")

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
                "Packages": [
                    {
                        "Name": RUNTIME_PACKAGE_MARKER,
                        "Version": "3.12.13",
                        "Release": "3.el9_8.1",
                        "Arch": "x86_64",
                    }
                ],
                "Vulnerabilities": [{"VulnerabilityID": "CVE-2025-0001", "PkgName": RUNTIME_PACKAGE_MARKER}],
            }
        ],
    }
    clean_trivy_image = copy.deepcopy(clean_trivy)
    clean_trivy_image["ArtifactName"] = "local/ubi9-base-python:self-test"
    clean_trivy_image["ArtifactType"] = "container_image"
    clean_trivy_image["Metadata"] = {"ImageID": "sha256:self-test"}
    clean_trivy_image["Results"][0]["Target"] = "local/ubi9-base-python:self-test (redhat 9.8)"
    zero_finding_trivy = copy.deepcopy(clean_trivy_image)
    zero_finding_trivy["Results"][0].pop("Vulnerabilities")

    clean_grype_directory: dict[str, Any] = {
        "descriptor": {"name": "grype", "version": "0.115.0"},
        "distro": {"name": "redhat", "version": "9.8"},
        "matches": [
            {
                "vulnerability": {"id": "CVE-2025-0001"},
                "artifact": {"name": RUNTIME_PACKAGE_MARKER, "type": "rpm"},
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
    zero_finding_grype_directory = copy.deepcopy(clean_grype_directory)
    zero_finding_grype_directory["matches"] = []
    zero_finding_grype_image = copy.deepcopy(clean_grype_image)
    zero_finding_grype_image["matches"] = []
    grype_without_runtime_marker = copy.deepcopy(clean_grype_directory)
    grype_without_runtime_marker["matches"][0]["artifact"]["name"] = "other-libs"

    assert_raw_report(clean_trivy, "trivy", amd64_marker)
    assert_raw_report(clean_trivy_image, "trivy", amd64_marker)
    assert_raw_report(zero_finding_trivy, "trivy", amd64_marker)
    assert_raw_report(clean_grype_directory, "grype")
    assert_raw_report(clean_grype_image, "grype")
    assert_raw_report(clean_grype_image_id_only, "grype")
    assert_raw_report(zero_finding_grype_directory, "grype")
    assert_raw_report(zero_finding_grype_image, "grype")
    assert_raw_report(grype_without_runtime_marker, "grype")

    report_probes: list[tuple[str, dict[str, Any], str, RuntimeMarker | None, str]] = []

    trivy_wrong_identity = copy.deepcopy(clean_trivy)
    trivy_wrong_identity["Trivy"]["Version"] = ""
    report_probes.append(("Trivy identity", trivy_wrong_identity, "trivy", amd64_marker, "Trivy version identity"))
    trivy_wrong_schema = copy.deepcopy(clean_trivy)
    trivy_wrong_schema["SchemaVersion"] = 1
    report_probes.append(("Trivy schema", trivy_wrong_schema, "trivy", amd64_marker, "SchemaVersion 2"))
    trivy_missing_artifact_identity = copy.deepcopy(clean_trivy)
    trivy_missing_artifact_identity["ArtifactName"] = ""
    report_probes.append(
        (
            "Trivy artifact identity",
            trivy_missing_artifact_identity,
            "trivy",
            amd64_marker,
            "ArtifactName must be a non-empty string",
        )
    )
    trivy_unknown_artifact_type = copy.deepcopy(clean_trivy)
    trivy_unknown_artifact_type["ArtifactType"] = "unknown"
    report_probes.append(
        (
            "Trivy artifact type",
            trivy_unknown_artifact_type,
            "trivy",
            amd64_marker,
            "ArtifactType must be container_image or filesystem",
        )
    )
    trivy_malformed_metadata = copy.deepcopy(clean_trivy)
    trivy_malformed_metadata["Metadata"] = []
    report_probes.append(
        ("Trivy metadata", trivy_malformed_metadata, "trivy", amd64_marker, "Metadata must be an object")
    )
    trivy_results_type = copy.deepcopy(clean_trivy)
    trivy_results_type["Results"] = {}
    report_probes.append(
        (
            "Trivy Results type",
            trivy_results_type,
            "trivy",
            amd64_marker,
            "non-empty Results list",
        )
    )
    trivy_empty_results = copy.deepcopy(clean_trivy)
    trivy_empty_results["Results"] = []
    report_probes.append(
        (
            "Trivy empty Results",
            trivy_empty_results,
            "trivy",
            amd64_marker,
            "non-empty Results list",
        )
    )
    trivy_result_type = copy.deepcopy(clean_trivy)
    trivy_result_type["Results"] = [[]]
    report_probes.append(
        ("Trivy result object", trivy_result_type, "trivy", amd64_marker, "Results[0] must be an object")
    )
    trivy_target = copy.deepcopy(clean_trivy)
    trivy_target["Results"][0]["Target"] = ""
    report_probes.append(("Trivy target", trivy_target, "trivy", amd64_marker, "Target must be a non-empty string"))
    trivy_class = copy.deepcopy(clean_trivy)
    trivy_class["Results"][0]["Class"] = "unknown"
    report_probes.append(("Trivy result class", trivy_class, "trivy", amd64_marker, "Class must be os-pkgs"))
    trivy_type = copy.deepcopy(clean_trivy)
    trivy_type["Results"][0]["Type"] = "unknown"
    report_probes.append(("Trivy result type", trivy_type, "trivy", amd64_marker, "Type must be redhat"))
    trivy_packages_type = copy.deepcopy(clean_trivy)
    trivy_packages_type["Results"][0]["Packages"] = {}
    report_probes.append(("Trivy Packages type", trivy_packages_type, "trivy", amd64_marker, "Packages must be a list"))
    trivy_package_type = copy.deepcopy(clean_trivy)
    trivy_package_type["Results"][0]["Packages"] = [[]]
    report_probes.append(
        (
            "Trivy package object",
            trivy_package_type,
            "trivy",
            amd64_marker,
            "Packages[0] must be an object",
        )
    )
    trivy_package_name = copy.deepcopy(clean_trivy)
    trivy_package_name["Results"][0]["Packages"][0]["Name"] = {}
    report_probes.append(
        (
            "Trivy package name",
            trivy_package_name,
            "trivy",
            amd64_marker,
            "Packages[0].Name must be a non-empty string",
        )
    )
    trivy_package_version = copy.deepcopy(clean_trivy)
    trivy_package_version["Results"][0]["Packages"][0]["Version"] = ""
    report_probes.append(
        (
            "Trivy package version shape",
            trivy_package_version,
            "trivy",
            amd64_marker,
            "Packages[0].Version must be a non-empty string",
        )
    )
    trivy_padded_package_name = copy.deepcopy(clean_trivy)
    trivy_padded_package_name["Results"][0]["Packages"].append({"Name": " sqlite-libs ", "Version": "3.34.1"})
    report_probes.append(
        (
            "Trivy padded package name",
            trivy_padded_package_name,
            "trivy",
            amd64_marker,
            "Packages[1].Name must be canonical without whitespace",
        )
    )
    trivy_embedded_package_whitespace = copy.deepcopy(clean_trivy)
    trivy_embedded_package_whitespace["Results"][0]["Packages"].append({"Name": "sqlite libs", "Version": "3.34.1"})
    report_probes.append(
        (
            "Trivy embedded package name whitespace",
            trivy_embedded_package_whitespace,
            "trivy",
            amd64_marker,
            "Packages[1].Name must be canonical without whitespace",
        )
    )
    trivy_vulnerabilities_type = copy.deepcopy(clean_trivy)
    trivy_vulnerabilities_type["Results"][0]["Vulnerabilities"] = {}
    report_probes.append(
        (
            "Trivy Vulnerabilities type",
            trivy_vulnerabilities_type,
            "trivy",
            amd64_marker,
            "Vulnerabilities must be a list or null",
        )
    )
    trivy_finding_type = copy.deepcopy(clean_trivy)
    trivy_finding_type["Results"][0]["Vulnerabilities"] = [[]]
    report_probes.append(
        (
            "Trivy finding object",
            trivy_finding_type,
            "trivy",
            amd64_marker,
            "Vulnerabilities[0] must be an object",
        )
    )
    trivy_finding_id = copy.deepcopy(clean_trivy)
    trivy_finding_id["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = []
    report_probes.append(
        (
            "Trivy finding id",
            trivy_finding_id,
            "trivy",
            amd64_marker,
            "Vulnerabilities[0].VulnerabilityID must be a non-empty string",
        )
    )
    trivy_finding_package = copy.deepcopy(clean_trivy)
    trivy_finding_package["Results"][0]["Vulnerabilities"][0]["PkgName"] = ""
    report_probes.append(
        (
            "Trivy finding package",
            trivy_finding_package,
            "trivy",
            amd64_marker,
            "Vulnerabilities[0].PkgName must be a non-empty string",
        )
    )
    trivy_marker_name = copy.deepcopy(clean_trivy)
    trivy_marker_name["Results"][0]["Packages"][0]["Name"] = "other-libs"
    report_probes.append(
        (
            "Trivy runtime marker name",
            trivy_marker_name,
            "trivy",
            amd64_marker,
            f"did not enumerate runtime package {RUNTIME_PACKAGE_MARKER}",
        )
    )
    trivy_padded_marker_name = copy.deepcopy(clean_trivy)
    trivy_padded_marker_name["Results"][0]["Packages"][0]["Name"] = f"{RUNTIME_PACKAGE_MARKER} "
    report_probes.append(
        (
            "Trivy runtime marker package name whitespace",
            trivy_padded_marker_name,
            "trivy",
            amd64_marker,
            "Packages[0].Name must be canonical without whitespace",
        )
    )
    noncanonical_expected_marker = RuntimeMarker(
        workflow_arch=amd64_marker.workflow_arch,
        name=f" {amd64_marker.name}",
        epoch=amd64_marker.epoch,
        version=amd64_marker.version,
        release=amd64_marker.release,
        rpm_arch=amd64_marker.rpm_arch,
    )
    report_probes.append(
        (
            "contract runtime marker package name",
            clean_trivy,
            "trivy",
            noncanonical_expected_marker,
            "contract runtime marker package name must be canonical without whitespace",
        )
    )
    trivy_marker_epoch = copy.deepcopy(clean_trivy)
    trivy_marker_epoch["Results"][0]["Packages"][0]["Epoch"] = 1
    report_probes.append(
        (
            "Trivy runtime marker epoch",
            trivy_marker_epoch,
            "trivy",
            amd64_marker,
            f"{RUNTIME_PACKAGE_MARKER} Epoch does not match contract",
        )
    )
    trivy_marker_epoch_type = copy.deepcopy(clean_trivy)
    trivy_marker_epoch_type["Results"][0]["Packages"][0]["Epoch"] = "0"
    report_probes.append(
        (
            "Trivy runtime marker epoch type",
            trivy_marker_epoch_type,
            "trivy",
            amd64_marker,
            "Epoch must be null, absent, or a non-negative integer",
        )
    )
    trivy_marker_version = copy.deepcopy(clean_trivy)
    trivy_marker_version["Results"][0]["Packages"][0]["Version"] = "3.12.12"
    report_probes.append(
        (
            "Trivy runtime marker version",
            trivy_marker_version,
            "trivy",
            amd64_marker,
            f"{RUNTIME_PACKAGE_MARKER} Version does not match contract",
        )
    )
    trivy_marker_version_colon = copy.deepcopy(clean_trivy)
    trivy_marker_version_colon["Results"][0]["Packages"][0]["Version"] = "1:3.12.13"
    report_probes.append(
        (
            "Trivy runtime marker version colon",
            trivy_marker_version_colon,
            "trivy",
            amd64_marker,
            f"{RUNTIME_PACKAGE_MARKER} Version must not contain ':'",
        )
    )
    trivy_marker_release = copy.deepcopy(clean_trivy)
    trivy_marker_release["Results"][0]["Packages"][0]["Release"] = "2.el9"
    report_probes.append(
        (
            "Trivy runtime marker release",
            trivy_marker_release,
            "trivy",
            amd64_marker,
            f"{RUNTIME_PACKAGE_MARKER} Release does not match contract",
        )
    )
    trivy_marker_release_colon = copy.deepcopy(clean_trivy)
    trivy_marker_release_colon["Results"][0]["Packages"][0]["Release"] = "3:el9_8.1"
    report_probes.append(
        (
            "Trivy runtime marker release colon",
            trivy_marker_release_colon,
            "trivy",
            amd64_marker,
            f"{RUNTIME_PACKAGE_MARKER} Release must not contain ':'",
        )
    )
    trivy_marker_arch = copy.deepcopy(clean_trivy)
    trivy_marker_arch["Results"][0]["Packages"][0]["Arch"] = "aarch64"
    report_probes.append(
        (
            "Trivy runtime marker architecture",
            trivy_marker_arch,
            "trivy",
            amd64_marker,
            f"{RUNTIME_PACKAGE_MARKER} Arch does not match --arch amd64 contract",
        )
    )
    report_probes.append(
        (
            "workflow architecture versus report architecture",
            clean_trivy,
            "trivy",
            arm64_marker,
            f"{RUNTIME_PACKAGE_MARKER} Arch does not match --arch arm64 contract",
        )
    )

    grype_descriptor_type = copy.deepcopy(clean_grype_directory)
    grype_descriptor_type["descriptor"] = []
    report_probes.append(
        (
            "Grype descriptor object",
            grype_descriptor_type,
            "grype",
            None,
            "descriptor must be an object",
        )
    )
    grype_descriptor_name = copy.deepcopy(clean_grype_directory)
    grype_descriptor_name["descriptor"]["name"] = "other"
    report_probes.append(
        ("Grype descriptor name", grype_descriptor_name, "grype", None, "descriptor.name must be grype")
    )
    grype_descriptor_version = copy.deepcopy(clean_grype_directory)
    grype_descriptor_version["descriptor"]["version"] = ""
    report_probes.append(
        (
            "Grype descriptor version",
            grype_descriptor_version,
            "grype",
            None,
            "descriptor.version must be a non-empty string",
        )
    )
    grype_source_type = copy.deepcopy(clean_grype_directory)
    grype_source_type["source"] = []
    report_probes.append(("Grype source object", grype_source_type, "grype", None, "must contain a source object"))
    grype_unknown_source = copy.deepcopy(clean_grype_directory)
    grype_unknown_source["source"]["type"] = "unknown"
    report_probes.append(
        (
            "Grype source discriminator",
            grype_unknown_source,
            "grype",
            None,
            "source.type must be image or directory",
        )
    )
    grype_image_string_target = copy.deepcopy(clean_grype_image)
    grype_image_string_target["source"]["target"] = "/rootfs"
    report_probes.append(
        (
            "Grype image plus string target",
            grype_image_string_target,
            "grype",
            None,
            "image source.target must be an object",
        )
    )
    grype_directory_object_target = copy.deepcopy(clean_grype_directory)
    grype_directory_object_target["source"]["target"] = {"userInput": "/rootfs"}
    report_probes.append(
        (
            "Grype directory plus object target",
            grype_directory_object_target,
            "grype",
            None,
            "directory source.target must be a non-empty path string",
        )
    )
    grype_empty_directory_target = copy.deepcopy(clean_grype_directory)
    grype_empty_directory_target["source"]["target"] = " "
    report_probes.append(
        (
            "Grype empty directory target",
            grype_empty_directory_target,
            "grype",
            None,
            "directory source.target must be a non-empty path string",
        )
    )
    grype_empty_image_identity = copy.deepcopy(clean_grype_image)
    grype_empty_image_identity["source"]["target"] = {"userInput": " ", "imageID": ""}
    report_probes.append(
        (
            "Grype empty image identity",
            grype_empty_image_identity,
            "grype",
            None,
            "image source.target must contain a non-empty userInput or imageID identity",
        )
    )
    grype_distro_type = copy.deepcopy(clean_grype_directory)
    grype_distro_type["distro"] = []
    report_probes.append(("Grype distro object", grype_distro_type, "grype", None, "must contain a distro object"))
    grype_distro_name = copy.deepcopy(clean_grype_directory)
    grype_distro_name["distro"]["name"] = "other"
    report_probes.append(("Grype distro name", grype_distro_name, "grype", None, "distro.name must be redhat"))
    grype_distro_version = copy.deepcopy(clean_grype_directory)
    grype_distro_version["distro"]["version"] = ""
    report_probes.append(
        (
            "Grype distro version",
            grype_distro_version,
            "grype",
            None,
            "distro.version must be a non-empty string",
        )
    )
    grype_missing_matches = copy.deepcopy(clean_grype_directory)
    grype_missing_matches.pop("matches")
    report_probes.append(("Grype missing matches", grype_missing_matches, "grype", None, "matches must be a list"))
    grype_matches_type = copy.deepcopy(clean_grype_directory)
    grype_matches_type["matches"] = {}
    report_probes.append(("Grype matches type", grype_matches_type, "grype", None, "matches must be a list"))
    grype_match_type = copy.deepcopy(clean_grype_directory)
    grype_match_type["matches"] = [[]]
    report_probes.append(("Grype match object", grype_match_type, "grype", None, "matches[0] must be an object"))
    grype_artifact_type = copy.deepcopy(clean_grype_directory)
    grype_artifact_type["matches"][0]["artifact"] = []
    report_probes.append(
        (
            "Grype artifact object",
            grype_artifact_type,
            "grype",
            None,
            "matches[0].artifact must be an object",
        )
    )
    grype_artifact_name = copy.deepcopy(clean_grype_directory)
    grype_artifact_name["matches"][0]["artifact"]["name"] = ""
    report_probes.append(
        (
            "Grype artifact name",
            grype_artifact_name,
            "grype",
            None,
            "matches[0].artifact.name must be a non-empty string",
        )
    )
    grype_padded_artifact_name = copy.deepcopy(clean_grype_directory)
    grype_padded_artifact_name["matches"][0]["artifact"]["name"] = " sqlite-libs "
    report_probes.append(
        (
            "Grype padded artifact name",
            grype_padded_artifact_name,
            "grype",
            None,
            "matches[0].artifact.name must be canonical without whitespace",
        )
    )
    grype_embedded_artifact_whitespace = copy.deepcopy(clean_grype_directory)
    grype_embedded_artifact_whitespace["matches"][0]["artifact"]["name"] = "sqlite libs"
    report_probes.append(
        (
            "Grype embedded artifact name whitespace",
            grype_embedded_artifact_whitespace,
            "grype",
            None,
            "matches[0].artifact.name must be canonical without whitespace",
        )
    )
    grype_artifact_kind = copy.deepcopy(clean_grype_directory)
    grype_artifact_kind["matches"][0]["artifact"]["type"] = "deb"
    report_probes.append(
        (
            "Grype artifact type",
            grype_artifact_kind,
            "grype",
            None,
            "matches[0].artifact.type must be rpm",
        )
    )
    grype_vulnerability_type = copy.deepcopy(clean_grype_directory)
    grype_vulnerability_type["matches"][0]["vulnerability"] = []
    report_probes.append(
        (
            "Grype vulnerability object",
            grype_vulnerability_type,
            "grype",
            None,
            "matches[0].vulnerability must be an object",
        )
    )
    grype_vulnerability_id = copy.deepcopy(clean_grype_directory)
    grype_vulnerability_id["matches"][0]["vulnerability"]["id"] = ""
    report_probes.append(
        (
            "Grype vulnerability id",
            grype_vulnerability_id,
            "grype",
            None,
            "matches[0].vulnerability.id must be a non-empty string",
        )
    )

    trivy_sqlite_package = copy.deepcopy(clean_trivy)
    trivy_sqlite_package["Results"][0]["Packages"].append({"Name": SQLITE_PACKAGE, "Version": "3.34.1"})
    report_probes.append(
        (
            "Trivy SQLite package detector",
            trivy_sqlite_package,
            "trivy",
            amd64_marker,
            f"SQLite package reference(s): {SQLITE_PACKAGE}",
        )
    )
    grype_sqlite_package = copy.deepcopy(clean_grype_directory)
    grype_sqlite_package["matches"].append(
        {
            "vulnerability": {"id": "CVE-2025-0002"},
            "artifact": {"name": SQLITE_PACKAGE, "type": "rpm"},
        }
    )
    report_probes.append(
        (
            "Grype SQLite package detector",
            grype_sqlite_package,
            "grype",
            None,
            f"SQLite package reference(s): {SQLITE_PACKAGE}",
        )
    )
    for cve in sorted(SQLITE_CVES):
        trivy_cve = copy.deepcopy(clean_trivy)
        trivy_cve["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = cve
        report_probes.append(
            (
                f"Trivy {cve} detector",
                trivy_cve,
                "trivy",
                amd64_marker,
                f"SQLite finding(s): {cve}",
            )
        )
        grype_cve = copy.deepcopy(clean_grype_directory)
        grype_cve["matches"][0]["vulnerability"]["id"] = cve
        report_probes.append(
            (
                f"Grype {cve} detector",
                grype_cve,
                "grype",
                None,
                f"SQLite finding(s): {cve}",
            )
        )

    for label, document, scanner, expected_runtime, expected_reason in report_probes:
        _expect_rejection(
            label,
            partial(assert_raw_report, document, scanner, expected_runtime),
            expected_reason,
        )

    contract_probes: list[tuple[str, Any, str]] = [
        ("contract object", [], "contract must be a JSON object"),
        ("contract runtime", {}, "contract runtime must be an object"),
        (
            "contract runtime type",
            {"runtime": []},
            "contract runtime must be an object",
        ),
        (
            "contract runtime.shipped",
            {"runtime": {}},
            "contract runtime.shipped must be an object",
        ),
        (
            "contract runtime.shipped type",
            {"runtime": {"shipped": []}},
            "contract runtime.shipped must be an object",
        ),
        (
            "contract missing runtime.shipped[amd64]",
            {"runtime": {"shipped": {"arm64": clean_contract["runtime"]["shipped"]["arm64"]}}},
            "contract runtime.shipped[amd64] is required",
        ),
        (
            "contract runtime.shipped[amd64] type",
            {"runtime": {"shipped": {"amd64": {}}}},
            "contract runtime.shipped[amd64] must be a list",
        ),
        (
            "contract empty runtime.shipped[amd64]",
            {"runtime": {"shipped": {"amd64": []}}},
            "contract runtime.shipped[amd64] must be non-empty",
        ),
        (
            "contract non-string shipped entry",
            {"runtime": {"shipped": {"amd64": [1, "python3.12-libs-3.12.13-3.el9_8.1.x86_64"]}}},
            "runtime.shipped[amd64][0] must be a non-empty NEVRA string",
        ),
        (
            "contract malformed marker NEVRA",
            {"runtime": {"shipped": {"amd64": ["python3.12-libs-not-a-nevra"]}}},
            "contract runtime marker NEVRA is malformed",
        ),
        (
            "contract marker NEVRA with second epoch separator",
            {"runtime": {"shipped": {"amd64": ["python3.12-libs-0:1:3.12.13-3.el9_8.1.x86_64"]}}},
            "contract runtime marker NEVRA is malformed",
        ),
        (
            "contract marker NEVRA with release colon",
            {"runtime": {"shipped": {"amd64": ["python3.12-libs-0:3.12.13-3:el9_8.1.x86_64"]}}},
            "contract runtime marker NEVRA is malformed",
        ),
        (
            "contract zero marker matches",
            {"runtime": {"shipped": {"amd64": ["python3.12-3.12.13-3.el9_8.1.x86_64"]}}},
            f"must contain exactly one {RUNTIME_PACKAGE_MARKER} NEVRA; found 0",
        ),
        (
            "contract duplicate marker matches",
            {
                "runtime": {
                    "shipped": {
                        "amd64": [
                            "python3.12-libs-3.12.13-3.el9_8.1.x86_64",
                            "python3.12-libs-3.12.13-3.el9_8.1.x86_64",
                        ]
                    }
                }
            },
            f"must contain exactly one {RUNTIME_PACKAGE_MARKER} NEVRA; found 2",
        ),
        (
            "contract marker architecture",
            {"runtime": {"shipped": {"amd64": ["python3.12-libs-3.12.13-3.el9_8.1.aarch64"]}}},
            "runtime marker architecture for --arch amd64 must be x86_64",
        ),
    ]
    for label, document, expected_reason in contract_probes:
        _expect_rejection(
            label,
            partial(runtime_marker_from_contract, document, "amd64"),
            expected_reason,
        )
    _expect_rejection(
        "runtime marker invalid --arch",
        partial(runtime_marker_from_contract, clean_contract, "s390x"),
        "--arch must be one of: amd64, arm64",
    )

    shifted_contract = copy.deepcopy(clean_contract)
    shifted_contract["runtime"]["shipped"]["amd64"][0] = "python3.12-libs-3.12.12-3.el9_8.1.x86_64"
    shifted_marker = runtime_marker_from_contract(shifted_contract, "amd64")
    _expect_rejection(
        "contract version versus Trivy marker",
        lambda: assert_raw_report(clean_trivy, "trivy", shifted_marker),
        f"{RUNTIME_PACKAGE_MARKER} Version does not match contract",
    )

    valid_args = argparse.Namespace(
        trivy_json=Path("trivy.json"),
        grype_json=Path("grype.json"),
        contract=Path("contract.json"),
        arch="amd64",
        self_test=False,
    )
    for attribute, flag in (
        ("trivy_json", "--trivy-json"),
        ("grype_json", "--grype-json"),
        ("contract", "--contract"),
        ("arch", "--arch"),
    ):
        missing = copy.copy(valid_args)
        setattr(missing, attribute, None)
        _expect_rejection(
            f"missing {flag}",
            partial(_normal_inputs, missing),
            f"{flag} is required",
        )
    invalid_arch = copy.copy(valid_args)
    invalid_arch.arch = "s390x"
    _expect_rejection(
        "invalid --arch",
        lambda: _normal_inputs(invalid_arch),
        "--arch must be one of: amd64, arm64",
    )
    _expect_rejection(
        "invalid --contract",
        lambda: _load(Path("/__raw_scanner_self_test_missing_contract__"), "contract"),
        "could not load contract",
    )
    standalone = parse_args(["--self-test"])
    if not standalone.self_test:
        raise RawScannerError("--self-test did not parse as a standalone mode")

    total_probes = len(report_probes) + len(contract_probes) + 8
    print(
        "raw scanner SQLite absence self-test: zero-finding and non-marker Grype reports accepted; "
        f"{total_probes} singleton probes rejected for their expected reasons"
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail if raw Trivy or Grype JSON contains sqlite-libs or a targeted SQLite CVE."
    )
    parser.add_argument("--trivy-json", type=Path, help="raw Trivy JSON report")
    parser.add_argument("--grype-json", type=Path, help="raw Grype JSON report")
    parser.add_argument("--contract", type=Path, help="image manifest contract")
    parser.add_argument("--arch", metavar="{amd64,arm64}", help="workflow architecture")
    parser.add_argument("--self-test", action="store_true", help="run the offline self-test")
    return parser.parse_args(argv)


def _normal_inputs(args: argparse.Namespace) -> tuple[Path, Path, Path, str]:
    required = (
        ("trivy_json", "--trivy-json"),
        ("grype_json", "--grype-json"),
        ("contract", "--contract"),
        ("arch", "--arch"),
    )
    for attribute, flag in required:
        if getattr(args, attribute) is None:
            raise RawScannerError(f"{flag} is required unless --self-test is used")
    if args.arch not in RPM_ARCHITECTURES:
        raise RawScannerError("--arch must be one of: amd64, arm64")
    return args.trivy_json, args.grype_json, args.contract, args.arch


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            self_test()
            return 0
        trivy_path, grype_path, contract_path, arch = _normal_inputs(args)
        marker = runtime_marker_from_contract(_load(contract_path, "contract"), arch)
        assert_raw_report(_load(trivy_path, "Trivy scanner report"), "trivy", marker)
        assert_raw_report(_load(grype_path, "Grype scanner report"), "grype")
        print(
            f"raw scanner SQLite absence ({arch}): Trivy and Grype contain neither sqlite-libs nor "
            + ",".join(sorted(SQLITE_CVES))
        )
    except RawScannerError as exc:
        print(f"raw scanner SQLite absence failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
