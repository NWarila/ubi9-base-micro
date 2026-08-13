#!/usr/bin/env python3
# Purpose: Default-deny OpenVEX gate over unfixed HIGH/CRITICAL Trivy+Grype findings
# Role: gate
# Micro-container candidate: yes - pure-stdlib, scanner-JSON-in/exit-out, has --self-test

"""Default-deny OpenVEX gate for unfixed HIGH/CRITICAL findings."""

from __future__ import annotations

import argparse
import copy
import io
import json
import re
import sys
import tempfile
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

HIGH_CRITICAL = {"HIGH", "CRITICAL"}
SEVERITY_ORDER = {"UNKNOWN": 0, "NEGLIGIBLE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ACCEPTED_STATUSES = {"fixed", "not_affected"}
OPENVEX_STATUSES = {"affected", "fixed", "not_affected", "under_investigation"}
OPENVEX_NOT_AFFECTED_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
CONTENT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SCANNER_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
IMAGE_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
REGISTRY_COMPONENT = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
REGISTRY = rf"{REGISTRY_COMPONENT}(?:\.{REGISTRY_COMPONENT})*(?::[0-9]+)?"
IMAGE_NAME = rf"(?:(?:{REGISTRY})/)?{IMAGE_NAME_COMPONENT}(?:/{IMAGE_NAME_COMPONENT})*"
IMAGE_REFERENCE = re.compile(rf"{IMAGE_NAME}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{{0,127}}|@sha256:[0-9a-f]{{64}})?\Z")
DIGEST_IMAGE_REFERENCE = re.compile(rf"{IMAGE_NAME}@sha256:[0-9a-f]{{64}}\Z")
RHEL_9_RELEASE = re.compile(r"9(?:\.[0-9]+)*\Z")
SUPPORTED_ARCHITECTURES = {"amd64", "arm64"}
TRIVY_FIX_STATUSES = {
    "affected",
    "end_of_life",
    "fixed",
    "fix_deferred",
    "not_affected",
    "under_investigation",
    "unknown",
    "will_not_fix",
}
GRYPE_FIX_STATES = {"fixed", "not-fixed", "unknown", "wont-fix"}
Mutation = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], Any]

ACCEPT_AND_TRACK_ACTION_STATEMENT = (
    "This image ships the vulnerable CPython standard-library tarfile module in python3.12-libs "
    "3.12.13-3.el9_8. As of 2026-08-13 Red Hat lists RHEL 9 python3.12 as Affected with no fixed RPM "
    "(RHEL 9 python3.9 is fixed via RHSA-2026:54268; the upstream CPython 3.12 branch is fixed). "
    "Consumers must not rely on tarfile.extractall() 'data' or 'tar' filters to contain untrusted archives "
    "until a fixed RPM is absorbed; risk is realized only by a consumer that extracts attacker-supplied "
    "archives relying on those filters. Accepted and tracked as TD-9 in docs/TECH-DEBT.md; review-by "
    "2026-10-01."
)


class VexError(Exception):
    pass


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise VexError(f"duplicate JSON object member {key!r}")
        document[key] = value
    return document


@dataclass
class Finding:
    vulnerability: str
    severity: str
    scanners: set[str] = field(default_factory=set)
    packages: set[str] = field(default_factory=set)
    records: list[FindingRecord] = field(default_factory=list)

    def merge(self, other: Finding) -> None:
        if other.scanners and (not self.scanners or SEVERITY_ORDER[other.severity] > SEVERITY_ORDER[self.severity]):
            self.severity = other.severity
        self.scanners.update(other.scanners)
        self.packages.update(other.packages)
        self.records.extend(other.records)


@dataclass(frozen=True)
class FindingRecord:
    scanner: str
    package: str
    version: str
    has_fix: bool


@dataclass(frozen=True)
class Statement:
    path: Path
    index: int
    vulnerabilities: frozenset[str]
    products: frozenset[str]
    status: str
    justification: str | None
    document: dict[str, Any]
    statement: dict[str, Any]


@dataclass(frozen=True)
class AcceptAndTrackDisposition:
    vulnerability: str
    products: tuple[str, ...]
    packages: tuple[tuple[str, str], ...]
    debt_id: str
    review_by: str
    statement_path: str


ACCEPT_AND_TRACK_DISPOSITIONS = (
    AcceptAndTrackDisposition(
        vulnerability="CVE-2026-11940",
        products=(
            "local/ubi9-base-python:ci-amd64",
            "local/ubi9-base-python:ci-arm64",
        ),
        packages=(
            ("python3.12", "3.12.13-3.el9_8.1"),
            ("python3.12-libs", "3.12.13-3.el9_8.1"),
        ),
        debt_id="TD-9",
        review_by="2026-10-01",
        statement_path="images/python/vex/cve-2026-11940.openvex.json",
    ),
)


@dataclass(frozen=True)
class TrivyEvidence:
    artifact_name: str
    image_id: str
    architecture: str
    os_version: str
    repo_digests: tuple[str, ...]
    package_names: frozenset[str]


@dataclass(frozen=True)
class GrypeEvidence:
    source_type: str
    user_input: str | None
    image_id: str | None
    architecture: str | None
    distro_version: str
    repo_digests: tuple[str, ...]


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_members,
        )
    except FileNotFoundError as exc:
        raise VexError(f"missing JSON input: {path}") from exc
    except json.JSONDecodeError as exc:
        raise VexError(f"invalid JSON in {path}: {exc}") from exc


def scanner_document(path: Path, scanner: str) -> dict[str, Any]:
    document = load_json(path)
    if not isinstance(document, dict):
        raise VexError(f"{scanner} report must be a JSON object")
    return document


def non_empty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VexError(f"{label} must be a non-empty string")
    return value.strip()


def content_digest(value: Any, label: str) -> str:
    digest = non_empty_string(value, label)
    if digest != value or CONTENT_DIGEST.fullmatch(digest) is None:
        raise VexError(f"{label} must be a sha256 content digest")
    return digest


def scanner_version(value: Any, label: str) -> str:
    version = non_empty_string(value, label)
    if version != value or SCANNER_VERSION.fullmatch(version) is None:
        raise VexError(f"{label} must be a three-component numeric version")
    return version


def supported_architecture(value: Any, label: str) -> str:
    architecture = non_empty_string(value, label)
    if architecture != value or architecture not in SUPPORTED_ARCHITECTURES:
        raise VexError(f"{label} must be amd64 or arm64")
    return architecture


def finding_severity(value: Any, label: str) -> str:
    normalized = non_empty_string(value, label).upper()
    if normalized not in SEVERITY_ORDER:
        raise VexError(f"{label} has unsupported value {value!r}")
    return normalized


def repository_digest(value: Any, label: str) -> str:
    reference = non_empty_string(value, label)
    if reference != value or DIGEST_IMAGE_REFERENCE.fullmatch(reference) is None:
        raise VexError(f"{label} must be a digest-qualified image reference")
    return reference


def optional_repo_digests(value: dict[str, Any], key: str, label: str) -> tuple[str, ...]:
    if key not in value:
        return ()
    raw_references = value[key]
    if not isinstance(raw_references, list):
        raise VexError(f"{label} must be a list when present")
    return tuple(repository_digest(reference, f"{label}[{index}]") for index, reference in enumerate(raw_references))


def validate_trivy_report(document: dict[str, Any]) -> TrivyEvidence:
    schema_version = document.get("SchemaVersion")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version != 2:
        raise VexError("Trivy SchemaVersion must be 2")

    trivy = document.get("Trivy")
    if not isinstance(trivy, dict):
        raise VexError("Trivy identity must be an object")
    scanner_version(trivy.get("Version"), "Trivy.Version")

    artifact_name = non_empty_string(document.get("ArtifactName"), "Trivy ArtifactName")
    if document.get("ArtifactType") != "container_image":
        raise VexError("Trivy ArtifactType must be container_image")

    metadata = document.get("Metadata")
    if not isinstance(metadata, dict):
        raise VexError("Trivy Metadata must be an object")
    operating_system = metadata.get("OS")
    if not isinstance(operating_system, dict):
        raise VexError("Trivy Metadata.OS must be an object")
    if operating_system.get("Family") != "redhat":
        raise VexError("Trivy Metadata.OS.Family must be redhat")
    os_version = non_empty_string(operating_system.get("Name"), "Trivy Metadata.OS.Name")
    image_id = content_digest(metadata.get("ImageID"), "Trivy Metadata.ImageID")
    image_config = metadata.get("ImageConfig")
    if not isinstance(image_config, dict):
        raise VexError("Trivy Metadata.ImageConfig must be an object")
    architecture = supported_architecture(
        image_config.get("architecture"),
        "Trivy Metadata.ImageConfig.architecture",
    )
    repo_digests = optional_repo_digests(metadata, "RepoDigests", "Trivy Metadata.RepoDigests")

    results = document.get("Results")
    if not isinstance(results, list):
        raise VexError("Trivy Results must be a list")
    package_names: set[str] = set()
    os_result_seen = False
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise VexError(f"Trivy Results[{result_index}] must be an object")
        non_empty_string(result.get("Target"), f"Trivy Results[{result_index}].Target")
        if result.get("Class") != "os-pkgs" or result.get("Type") != "redhat":
            continue
        os_result_seen = True
        packages = result.get("Packages")
        if not isinstance(packages, list):
            raise VexError(f"Trivy Results[{result_index}].Packages must be a list")
        for package_index, package in enumerate(packages):
            if not isinstance(package, dict):
                raise VexError(f"Trivy Results[{result_index}].Packages[{package_index}] must be an object")
            package_names.add(
                non_empty_string(
                    package.get("Name"),
                    f"Trivy Results[{result_index}].Packages[{package_index}].Name",
                )
            )
            non_empty_string(
                package.get("Version"),
                f"Trivy Results[{result_index}].Packages[{package_index}].Version",
            )
    if not os_result_seen:
        raise VexError("Trivy report requires at least one Class=os-pkgs Type=redhat result")
    if not package_names:
        raise VexError("Trivy os-pkgs/redhat inventory must be non-empty")

    return TrivyEvidence(
        artifact_name=artifact_name,
        image_id=image_id,
        architecture=architecture,
        os_version=os_version,
        repo_digests=repo_digests,
        package_names=frozenset(package_names),
    )


def validate_grype_report(document: dict[str, Any]) -> GrypeEvidence:
    descriptor = document.get("descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("name") != "grype":
        raise VexError("Grype report must contain a grype descriptor")
    scanner_version(descriptor.get("version"), "Grype descriptor.version")

    distro = document.get("distro")
    if not isinstance(distro, dict):
        raise VexError("Grype distro must be an object")
    if distro.get("name") != "redhat":
        raise VexError("Grype distro.name must be redhat")
    distro_version = non_empty_string(distro.get("version"), "Grype distro.version")

    source = document.get("source")
    if not isinstance(source, dict):
        raise VexError("Grype source must be an object")
    source_type = source.get("type")
    target = source.get("target")
    if source_type == "image":
        if not isinstance(target, dict):
            raise VexError("Grype image source.target must be an object")
        user_input = non_empty_string(target.get("userInput"), "Grype source.target.userInput")
        image_id = content_digest(target.get("imageID"), "Grype source.target.imageID")
        architecture = supported_architecture(target.get("architecture"), "Grype source.target.architecture")
        repo_digests = optional_repo_digests(target, "repoDigests", "Grype source.target.repoDigests")
    elif source_type == "directory":
        non_empty_string(target, "Grype directory source.target")
        user_input = None
        image_id = None
        architecture = None
        repo_digests = ()
    else:
        raise VexError("Grype source.type must be image or directory")

    matches = document.get("matches")
    if not isinstance(matches, list):
        raise VexError("Grype matches must be a list")

    return GrypeEvidence(
        source_type=source_type,
        user_input=user_input,
        image_id=image_id,
        architecture=architecture,
        distro_version=distro_version,
        repo_digests=repo_digests,
    )


def validate_report_binding(
    product: str,
    trivy: TrivyEvidence,
    grype: GrypeEvidence,
) -> None:
    expected_product = non_empty_string(product, "--product")
    if expected_product != product:
        raise VexError("--product must not contain surrounding whitespace")
    if IMAGE_REFERENCE.fullmatch(expected_product) is None:
        raise VexError("--product must be a well-formed image reference")
    if grype.source_type != "image":
        raise VexError("report binding requires a Grype image source")
    if trivy.artifact_name != expected_product:
        raise VexError("Trivy ArtifactName does not match --product")
    if grype.user_input != expected_product:
        raise VexError("Grype source.target.userInput does not match --product")
    if trivy.image_id != grype.image_id:
        raise VexError("Trivy and Grype imageID values do not match")
    if trivy.architecture != grype.architecture:
        raise VexError("Trivy and Grype architecture values do not match")
    if trivy.os_version != grype.distro_version:
        raise VexError("Trivy OS and Grype distro versions do not match")
    if RHEL_9_RELEASE.fullmatch(trivy.os_version) is None:
        raise VexError("Trivy OS and Grype distro versions must identify RHEL 9")
    digest_addressed = DIGEST_IMAGE_REFERENCE.fullmatch(expected_product) is not None
    if digest_addressed and not trivy.repo_digests:
        raise VexError("Trivy Metadata.RepoDigests is required for a digest-addressed --product")
    if digest_addressed and not grype.repo_digests:
        raise VexError("Grype source.target.repoDigests is required for a digest-addressed --product")
    if digest_addressed and expected_product not in trivy.repo_digests:
        raise VexError("Trivy Metadata.RepoDigests does not contain --product")
    if digest_addressed and expected_product not in grype.repo_digests:
        raise VexError("Grype source.target.repoDigests does not contain --product")
    if frozenset(trivy.repo_digests) != frozenset(grype.repo_digests):
        raise VexError("Trivy and Grype repository digest evidence does not match")


def package_floor_names(path: Path, architecture: str) -> frozenset[str]:
    document = load_json(path)
    if not isinstance(document, dict):
        raise VexError(f"package floor contract must be a JSON object: {path}")

    runtime = document.get("runtime")
    raw_floor: Any
    nevra_floor = False
    if isinstance(runtime, dict) and "package_floor" in runtime:
        raw_floor = runtime["package_floor"]
    else:
        parent = document.get("parent")
        floor = parent.get("floor") if isinstance(parent, dict) else None
        if not isinstance(floor, dict) or architecture not in floor:
            raise VexError(f"{path}: missing package floor for architecture {architecture}")
        raw_floor = floor[architecture]
        nevra_floor = True

    if not isinstance(raw_floor, list) or not raw_floor:
        raise VexError(f"{path}: package floor must be a non-empty list")

    names: set[str] = set()
    for index, raw_package in enumerate(raw_floor):
        package = non_empty_string(raw_package, f"{path}: package floor[{index}]")
        if nevra_floor:
            parts = package.rsplit("-", 2)
            if len(parts) != 3 or not parts[0]:
                raise VexError(f"{path}: package floor[{index}] must be an RPM NEVRA")
            package = parts[0]
        names.add(package)
    return frozenset(names)


def validate_contract_floor(path: Path, architecture: str, inventory: frozenset[str]) -> None:
    expected = package_floor_names(path, architecture)
    missing = sorted(expected - inventory)
    if missing:
        raise VexError("Trivy inventory missing contract package floor: " + ", ".join(missing))


def trivy_has_fix(vulnerability: dict[str, Any]) -> bool:
    fixed_version = ""
    if "FixedVersion" in vulnerability:
        raw_fixed_version = vulnerability["FixedVersion"]
        if not isinstance(raw_fixed_version, str):
            return False
        fixed_version = raw_fixed_version.strip()
    status: str | None = None
    if "Status" in vulnerability:
        raw_status = vulnerability["Status"]
        if not isinstance(raw_status, str) or raw_status not in TRIVY_FIX_STATUSES:
            return False
        status = raw_status
    return bool(fixed_version) or status == "fixed"


def parse_trivy(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    results = data.get("Results")
    if not isinstance(results, list):
        raise VexError("Trivy Results must be a list")
    for result_index, result in enumerate(results):
        raw_vulnerabilities = result.get("Vulnerabilities")
        if raw_vulnerabilities is None:
            continue
        if not isinstance(raw_vulnerabilities, list):
            raise VexError(f"Trivy Results[{result_index}].Vulnerabilities must be a list or null")
        for finding_index, vulnerability in enumerate(raw_vulnerabilities):
            label = f"Trivy Results[{result_index}].Vulnerabilities[{finding_index}]"
            if not isinstance(vulnerability, dict):
                raise VexError(f"{label} must be an object")
            vuln_id = non_empty_string(vulnerability.get("VulnerabilityID"), f"{label}.VulnerabilityID")
            sev = finding_severity(vulnerability.get("Severity"), f"{label}.Severity")
            package = non_empty_string(vulnerability.get("PkgName"), f"{label}.PkgName")
            if sev not in HIGH_CRITICAL:
                continue
            raw_version = vulnerability.get("InstalledVersion")
            version = raw_version.strip() if isinstance(raw_version, str) else ""
            has_fix = trivy_has_fix(vulnerability)
            findings.append(
                Finding(
                    vulnerability=vuln_id,
                    severity=sev,
                    scanners=set() if has_fix else {"trivy"},
                    packages=set() if has_fix else {package},
                    records=[FindingRecord("trivy", package, version, has_fix)],
                )
            )
    return findings


def grype_has_fix(vulnerability: dict[str, Any]) -> bool:
    raw_fix = vulnerability.get("fix")
    if raw_fix is None:
        return False
    if not isinstance(raw_fix, dict):
        return False
    # `available` is deliberately unread and descriptive here. Any future fixability
    # decision that consults it must validate it in the same change.
    raw_versions = raw_fix.get("versions")
    versions_valid = isinstance(raw_versions, list) and all(
        isinstance(version, str) and bool(version.strip()) for version in raw_versions
    )
    if not versions_valid:
        return False
    versions = raw_versions
    raw_state = raw_fix.get("state")
    state_valid = isinstance(raw_state, str) and raw_state in GRYPE_FIX_STATES
    if not state_valid:
        return False
    state = raw_state
    return bool(versions) or state == "fixed"


def parse_grype(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    matches = data.get("matches")
    if not isinstance(matches, list):
        raise VexError("Grype matches must be a list")
    for match_index, match in enumerate(matches):
        label = f"Grype matches[{match_index}]"
        if not isinstance(match, dict):
            raise VexError(f"{label} must be an object")
        vulnerability = match.get("vulnerability")
        if not isinstance(vulnerability, dict):
            raise VexError(f"{label}.vulnerability must be an object")
        artifact = match.get("artifact")
        if not isinstance(artifact, dict):
            raise VexError(f"{label}.artifact must be an object")
        vuln_id = non_empty_string(vulnerability.get("id"), f"{label}.vulnerability.id")
        sev = finding_severity(vulnerability.get("severity"), f"{label}.vulnerability.severity")
        package = non_empty_string(artifact.get("name"), f"{label}.artifact.name")
        if sev not in HIGH_CRITICAL:
            continue
        raw_version = artifact.get("version")
        version = raw_version.strip() if isinstance(raw_version, str) else ""
        has_fix = grype_has_fix(vulnerability)
        findings.append(
            Finding(
                vulnerability=vuln_id,
                severity=sev,
                scanners=set() if has_fix else {"grype"},
                packages=set() if has_fix else {package},
                records=[FindingRecord("grype", package, version, has_fix)],
            )
        )
    return findings


def union_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.vulnerability)
        if existing is None:
            merged[finding.vulnerability] = finding
        else:
            existing.merge(finding)
    return [merged[key] for key in sorted(merged) if merged[key].scanners]


def extract_vulnerability_ids(value: Any) -> frozenset[str]:
    ids: set[str] = set()
    if isinstance(value, str):
        ids.add(value.strip())
    elif isinstance(value, dict):
        for key in ("name", "id", "@id"):
            candidate = value.get(key)
            if candidate:
                ids.add(str(candidate).strip())
        aliases = value.get("aliases")
        if isinstance(aliases, list):
            ids.update(str(alias).strip() for alias in aliases if str(alias).strip())
    return frozenset(vuln for vuln in ids if vuln)


def extract_product_ids(product: Any) -> set[str]:
    ids: set[str] = set()
    if isinstance(product, str):
        if product.strip():
            ids.add(product.strip())
        return ids

    if not isinstance(product, dict):
        return ids

    for key in ("@id", "id", "name"):
        candidate = product.get(key)
        if candidate:
            ids.add(str(candidate).strip())

    identifiers = product.get("identifiers")
    if isinstance(identifiers, dict):
        ids.update(str(value).strip() for value in identifiers.values() if str(value).strip())
    elif isinstance(identifiers, list):
        for item in identifiers:
            if isinstance(item, str) and item.strip():
                ids.add(item.strip())
            elif isinstance(item, dict):
                ids.update(str(value).strip() for value in item.values() if str(value).strip())

    return ids


def load_vex_statements(vex_dir: Path) -> list[Statement]:
    if not vex_dir.is_dir():
        raise VexError(f"missing VEX directory: {vex_dir}")

    statements: list[Statement] = []
    for path in sorted(vex_dir.glob("*.json")):
        document = load_json(path)
        if "@context" not in document:
            raise VexError(f"{path}: missing @context")
        raw_statements = document.get("statements")
        if not isinstance(raw_statements, list):
            raise VexError(f"{path}: statements must be a list")

        for index, raw in enumerate(raw_statements):
            if not isinstance(raw, dict):
                raise VexError(f"{path}: statement {index} must be an object")
            vulnerabilities = extract_vulnerability_ids(raw.get("vulnerability"))
            if not vulnerabilities:
                raise VexError(f"{path}: statement {index} missing vulnerability id")

            status = str(raw.get("status") or "").strip()
            if status not in OPENVEX_STATUSES:
                raise VexError(f"{path}: statement {index} has invalid status {status!r}")

            justification = raw.get("justification")
            justification_text = str(justification).strip() if justification is not None else None
            if status == "not_affected":
                if not justification_text:
                    raise VexError(f"{path}: statement {index} not_affected requires justification")
                if justification_text not in OPENVEX_NOT_AFFECTED_JUSTIFICATIONS:
                    raise VexError(f"{path}: statement {index} has unsupported justification {justification_text!r}")

            raw_products = raw.get("products")
            if not isinstance(raw_products, list) or not raw_products:
                raise VexError(f"{path}: statement {index} requires non-empty products")
            products: set[str] = set()
            for product in raw_products:
                products.update(extract_product_ids(product))
            if not products:
                raise VexError(f"{path}: statement {index} has no product identifiers")

            statements.append(
                Statement(
                    path=path,
                    index=index,
                    vulnerabilities=vulnerabilities,
                    products=frozenset(products),
                    status=status,
                    justification=justification_text,
                    document=document,
                    statement=raw,
                )
            )
    return statements


def product_candidates(product: str) -> set[str]:
    return {product, f"pkg:oci/{product}"}


def accepted_statement(finding: Finding, product: str, statements: list[Statement]) -> Statement | None:
    candidates = product_candidates(product)
    for statement in statements:
        if finding.vulnerability not in statement.vulnerabilities:
            continue
        if statement.status not in ACCEPTED_STATUSES:
            continue
        if statement.status == "not_affected" and not statement.justification:
            continue
        if statement.products.isdisjoint(candidates):
            continue
        return statement
    return None


def expected_accept_and_track_document() -> dict[str, Any]:
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://github.com/NWarila/ubi9-base-micro/images/python/vex/cve-2026-11940",
        "author": "NWarila",
        "timestamp": "2026-08-13T00:00:00Z",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": "CVE-2026-11940"},
                "products": [
                    {
                        "@id": "local/ubi9-base-python:ci-amd64",
                        "subcomponents": [
                            {"@id": "pkg:rpm/redhat/python3.12@3.12.13-3.el9_8.1"},
                            {"@id": "pkg:rpm/redhat/python3.12-libs@3.12.13-3.el9_8.1"},
                        ],
                    },
                    {
                        "@id": "local/ubi9-base-python:ci-arm64",
                        "subcomponents": [
                            {"@id": "pkg:rpm/redhat/python3.12@3.12.13-3.el9_8.1"},
                            {"@id": "pkg:rpm/redhat/python3.12-libs@3.12.13-3.el9_8.1"},
                        ],
                    },
                ],
                "status": "affected",
                "action_statement": ACCEPT_AND_TRACK_ACTION_STATEMENT,
                "action_statement_timestamp": "2026-08-13T00:00:00Z",
            }
        ],
    }


def finding_package_versions(finding: Finding) -> frozenset[tuple[str, str]]:
    return frozenset((record.package, record.version) for record in finding.records if not record.has_fix)


def disposition_identity_matches(
    disposition: AcceptAndTrackDisposition,
    finding: Finding,
    product: str,
) -> bool:
    return (
        disposition.vulnerability == finding.vulnerability
        and product in disposition.products
        and finding_package_versions(finding) == frozenset(disposition.packages)
    )


def statement_path_matches(path: Path, expected: str) -> bool:
    expected_parts = Path(expected).parts
    return len(path.parts) >= len(expected_parts) and path.parts[-len(expected_parts) :] == expected_parts


def accept_and_track_statement_rejection(
    statement: Statement,
    disposition: AcceptAndTrackDisposition,
) -> str | None:
    if not statement_path_matches(statement.path, disposition.statement_path):
        return f"statement source must be {disposition.statement_path}"

    document = statement.document
    expected = expected_accept_and_track_document()
    top_keys = {"@context", "@id", "author", "timestamp", "version", "statements"}
    if set(document) != top_keys:
        return "statement document has unexpected or missing top-level fields"
    for key in ("@context", "@id", "author", "timestamp", "version"):
        if document.get(key) != expected[key]:
            return f"statement document field {key} does not match the canonical value"

    raw_statements = document.get("statements")
    if not isinstance(raw_statements, list) or len(raw_statements) != 1:
        return "statement document must contain exactly one statement"
    raw = statement.statement
    statement_keys = {
        "vulnerability",
        "products",
        "status",
        "action_statement",
        "action_statement_timestamp",
    }
    if set(raw) != statement_keys:
        return "accept-and-track statement has unexpected or missing fields"
    vulnerability = raw.get("vulnerability")
    if not isinstance(vulnerability, dict) or set(vulnerability) != {"name"}:
        return "accept-and-track vulnerability must contain only its name"
    if vulnerability.get("name") != disposition.vulnerability:
        return f"accept-and-track vulnerability must be {disposition.vulnerability}"

    expected_statement = expected["statements"][0]
    if raw.get("products") != expected_statement["products"]:
        return "accept-and-track products and subcomponents must match the canonical ordered set"
    if raw.get("status") != "affected":
        return "accept-and-track status must be affected"

    action_statement = raw.get("action_statement")
    if not isinstance(action_statement, str):
        return "accept-and-track action_statement must be a string"
    review_markers = re.findall(r"review-by [0-9]{4}-[0-9]{2}-[0-9]{2}", action_statement)
    if len(review_markers) != 1:
        return "accept-and-track action_statement must contain exactly one review-by marker"
    expected_review_marker = f"review-by {disposition.review_by}"
    if review_markers[0] != expected_review_marker:
        return f"accept-and-track action_statement must contain {expected_review_marker}"
    if disposition.debt_id not in action_statement:
        return f"accept-and-track action_statement must name {disposition.debt_id}"
    if action_statement != ACCEPT_AND_TRACK_ACTION_STATEMENT:
        return "accept-and-track action_statement does not match the canonical text"
    if raw.get("action_statement_timestamp") != expected_statement["action_statement_timestamp"]:
        return "accept-and-track action_statement_timestamp does not match the canonical value"
    if document != expected:
        return "accept-and-track statement does not match the canonical document"
    return None


def accepted_accept_and_track_statement(
    finding: Finding,
    product: str,
    statements: list[Statement],
    dispositions: tuple[AcceptAndTrackDisposition, ...],
    today: date,
) -> tuple[Statement | None, AcceptAndTrackDisposition | None, str | None]:
    candidates = [
        disposition for disposition in dispositions if disposition_identity_matches(disposition, finding, product)
    ]
    if len(candidates) != 1:
        return None, None, "no exact in-tool accept-and-track allowlist entry"
    disposition = candidates[0]
    if disposition != ACCEPT_AND_TRACK_DISPOSITIONS[0]:
        return None, None, "in-tool accept-and-track allowlist entry does not match the canonical authorization"

    review_by = date.fromisoformat(disposition.review_by)
    if today > review_by:
        packages = ",".join(f"{name}@{version}" for name, version in disposition.packages)
        raise VexError(
            "expired accept-and-track entry: "
            f"{disposition.vulnerability} product={product} packages={packages} "
            f"debt={disposition.debt_id} review-by={disposition.review_by}"
        )

    fixed_records = sorted(
        {
            (record.scanner, record.package, record.version)
            for record in finding.records
            if record.has_fix and (record.package, record.version) in disposition.packages
        }
    )
    if fixed_records:
        evidence = ",".join(f"{scanner}:{package}@{version}" for scanner, package, version in fixed_records)
        return None, None, f"valid fix evidence refuses accept-and-track disposition: {evidence}"

    target_statements = [
        statement for statement in statements if disposition.vulnerability in statement.vulnerabilities
    ]
    if len(target_statements) > 1:
        locations = ",".join(f"{statement.path}#{statement.index}" for statement in target_statements)
        raise VexError(f"duplicate accept-and-track statements for {disposition.vulnerability}: {locations}")
    if not target_statements:
        return None, None, f"no reviewed OpenVEX statement for {disposition.vulnerability}"
    statement = target_statements[0]
    rejection = accept_and_track_statement_rejection(statement, disposition)
    if rejection is not None:
        return None, None, rejection
    return statement, disposition, None


def assert_vex(
    product: str,
    trivy_json: Path,
    grype_json: Path,
    package_floor: Path,
    vex_dir: Path,
    emit: bool = True,
    *,
    accept_and_track: tuple[AcceptAndTrackDisposition, ...] = ACCEPT_AND_TRACK_DISPOSITIONS,
    today: date | None = None,
) -> int:
    trivy_document = scanner_document(trivy_json, "Trivy")
    grype_document = scanner_document(grype_json, "Grype")
    trivy_evidence = validate_trivy_report(trivy_document)
    grype_evidence = validate_grype_report(grype_document)
    validate_report_binding(product, trivy_evidence, grype_evidence)
    validate_contract_floor(package_floor, trivy_evidence.architecture, trivy_evidence.package_names)

    findings = union_findings(parse_trivy(trivy_document) + parse_grype(grype_document))
    statements = load_vex_statements(vex_dir)

    if emit:
        print(f"unfixed HIGH/CRITICAL findings requiring VEX: {len(findings)}")

    evaluation_date = date.today() if today is None else today
    missing: list[Finding] = []
    rejection_reasons: list[tuple[Finding, str]] = []
    matched: list[tuple[Finding, Statement]] = []
    tracked: list[tuple[Finding, Statement, AcceptAndTrackDisposition]] = []
    for finding in findings:
        if (
            finding.vulnerability == ACCEPT_AND_TRACK_DISPOSITIONS[0].vulnerability
            and product in ACCEPT_AND_TRACK_DISPOSITIONS[0].products
        ):
            statement, disposition, rejection = accepted_accept_and_track_statement(
                finding,
                product,
                statements,
                accept_and_track,
                evaluation_date,
            )
            if statement is not None and disposition is not None:
                tracked.append((finding, statement, disposition))
            else:
                missing.append(finding)
                if rejection is not None:
                    rejection_reasons.append((finding, rejection))
            continue
        statement = accepted_statement(finding, product, statements)
        if statement is None:
            missing.append(finding)
        else:
            matched.append((finding, statement))

    for finding, statement in matched:
        if emit:
            print(
                "accepted VEX: "
                f"{finding.vulnerability} status={statement.status} "
                f"product={product} source={statement.path}"
            )

    for _finding, statement, disposition in tracked:
        if emit:
            packages = ",".join(f"{name}@{version}" for name, version in disposition.packages)
            print(
                "accept-and-track disposition: "
                f"{disposition.vulnerability} packages={packages} debt={disposition.debt_id} "
                f"review-by={disposition.review_by} product={product} source={statement.path}"
            )

    if tracked and emit:
        print(f"undispositioned unfixed HIGH/CRITICAL findings: {len(missing)}")

    if missing:
        if emit:
            for finding, reason in rejection_reasons:
                print(f"accept-and-track rejected for {finding.vulnerability}: {reason}", file=sys.stderr)
            print("un-vexed unfixed HIGH/CRITICAL findings:", file=sys.stderr)
            for finding in missing:
                scanners = ",".join(sorted(finding.scanners))
                packages = ",".join(sorted(finding.packages))
                print(
                    f"- {finding.vulnerability} severity={finding.severity} scanners={scanners} packages={packages}",
                    file=sys.stderr,
                )
        return 1

    return 0


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="assert-vex-") as raw_tmp:
        tmp = Path(raw_tmp)
        product = "example.invalid/base-micro@sha256:" + ("a" * 64)
        image_id = "sha256:" + ("b" * 64)
        trivy_json = tmp / "trivy.json"
        grype_json = tmp / "grype.json"
        package_floor = tmp / "package-floor.json"
        vex_dir = tmp / "vex"
        vex_dir.mkdir()

        clean_trivy: dict[str, Any] = {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.71.0"},
            "ArtifactName": product,
            "ArtifactType": "container_image",
            "Metadata": {
                "OS": {"Family": "redhat", "Name": "9.8"},
                "ImageID": image_id,
                "ImageConfig": {"architecture": "amd64"},
                "RepoDigests": [product],
            },
            "Results": [
                {
                    "Target": f"{product} (redhat 9.8)",
                    "Class": "os-pkgs",
                    "Type": "redhat",
                    "Packages": [{"Name": "glibc", "Version": "2.34"}],
                    "Vulnerabilities": [],
                },
                {
                    "Target": "Python",
                    "Class": "lang-pkgs",
                    "Type": "python-pkg",
                },
            ],
        }
        clean_grype: dict[str, Any] = {
            "descriptor": {"name": "grype", "version": "0.115.0"},
            "distro": {"name": "redhat", "version": "9.8"},
            "source": {
                "type": "image",
                "target": {
                    "userInput": product,
                    "imageID": image_id,
                    "architecture": "amd64",
                    "repoDigests": [product],
                },
            },
            "matches": [],
            "ignoredMatches": [],
            "alertsByPackage": {},
        }
        clean_floor: dict[str, Any] = {"runtime": {"package_floor": ["glibc"]}}

        def run_fixture(
            trivy: Any,
            grype: Any,
            floor: Any,
            *,
            emit: bool = False,
            expected_product: str = product,
        ) -> int:
            write_json(trivy_json, trivy)
            write_json(grype_json, grype)
            write_json(package_floor, floor)
            return assert_vex(
                expected_product,
                trivy_json,
                grype_json,
                package_floor,
                vex_dir,
                emit=emit,
            )

        def run_fixture_with_output(
            trivy: Any,
            grype: Any,
            floor: Any,
        ) -> tuple[int, str]:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = run_fixture(trivy, grype, floor, emit=True)
            return result, stdout.getvalue() + stderr.getvalue()

        def expect_vex_rejection(label: str, action: Callable[[], Any], expected_reason: str) -> None:
            try:
                action()
            except VexError as exc:
                if expected_reason not in str(exc):
                    print(f"self-test failed: {label} rejected for wrong reason: {exc}", file=sys.stderr)
                    raise SystemExit(1) from exc
            except Exception as exc:
                print(
                    f"self-test failed: {label} rejected for wrong reason: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                raise SystemExit(1) from exc
            else:
                print(f"self-test failed: {label} unexpectedly passed", file=sys.stderr)
                raise SystemExit(1)
            print(f"assert-vex self-test: {label} rejected at its expected discriminator")

        if run_fixture(clean_trivy, clean_grype, clean_floor) != 0:
            print("self-test failed: correctly bound zero-finding reports did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: correctly bound zero-finding reports passed")

        local_trivy = copy.deepcopy(clean_trivy)
        local_grype = copy.deepcopy(clean_grype)
        local_product = "example.invalid/base-micro:self-test"
        local_trivy["ArtifactName"] = local_product
        local_grype["source"]["target"]["userInput"] = local_product
        local_trivy["Metadata"].pop("RepoDigests")
        local_grype["source"]["target"]["repoDigests"] = []
        if run_fixture(local_trivy, local_grype, clean_floor, expected_product=local_product) != 0:
            print("self-test failed: local-mode empty/absent repo digests did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: local-mode empty/absent repo digests passed")

        tag_trivy = copy.deepcopy(clean_trivy)
        tag_grype = copy.deepcopy(clean_grype)
        tag_product = "example.invalid/base-micro:self-test"
        tag_trivy["ArtifactName"] = tag_product
        tag_grype["source"]["target"]["userInput"] = tag_product
        if run_fixture(tag_trivy, tag_grype, clean_floor, expected_product=tag_product) != 0:
            print("self-test failed: tag-mode digest repository evidence did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: tag-mode digest repository evidence passed")

        inherited_floor = {
            "parent": {
                "floor": {
                    "amd64": ["glibc-2.34-1.el9.x86_64"],
                }
            }
        }
        if run_fixture(clean_trivy, clean_grype, inherited_floor) != 0:
            print("self-test failed: inherited architecture floor did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: inherited architecture floor passed")

        directory_grype = copy.deepcopy(clean_grype)
        directory_grype["source"] = {"type": "directory", "target": "/rootfs"}
        directory_evidence = validate_grype_report(directory_grype)
        if directory_evidence.source_type != "directory":
            print("self-test failed: directory/string source pair was not accepted", file=sys.stderr)
            return 1
        print("assert-vex self-test: exact directory/string source pair accepted")

        missing_json = tmp / "missing-input.json"
        invalid_json = tmp / "invalid-input.json"
        invalid_json.write_text("{", encoding="utf-8")

        loader_document: dict[str, Any] = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2099-0003"},
                    "products": [{"@id": product}],
                    "status": "fixed",
                }
            ],
        }

        def loader_fixture(label: str, document: dict[str, Any]) -> Callable[[], list[Statement]]:
            directory = tmp / f"loader-{label}"
            directory.mkdir()
            write_json(directory / "fixture.json", document)
            return lambda: load_vex_statements(directory)

        singleton_probes: list[tuple[str, Callable[[], Any], str]] = [
            (
                "missing JSON input",
                lambda: load_json(missing_json),
                f"missing JSON input: {missing_json}",
            ),
            (
                "invalid JSON input",
                lambda: load_json(invalid_json),
                f"invalid JSON in {invalid_json}:",
            ),
            (
                "missing VEX directory",
                lambda: load_vex_statements(tmp / "missing-vex"),
                f"missing VEX directory: {tmp / 'missing-vex'}",
            ),
            (
                "OpenVEX context",
                loader_fixture(
                    "context",
                    {key: value for key, value in loader_document.items() if key != "@context"},
                ),
                ": missing @context",
            ),
            (
                "OpenVEX statements container",
                loader_fixture("statements-container", {**loader_document, "statements": {}}),
                ": statements must be a list",
            ),
            (
                "OpenVEX statement object",
                loader_fixture("statement-object", {**loader_document, "statements": [[]]}),
                ": statement 0 must be an object",
            ),
            (
                "OpenVEX vulnerability identifier",
                loader_fixture(
                    "vulnerability-id",
                    {
                        **loader_document,
                        "statements": [
                            {
                                **loader_document["statements"][0],
                                "vulnerability": {},
                            }
                        ],
                    },
                ),
                ": statement 0 missing vulnerability id",
            ),
            (
                "OpenVEX status",
                loader_fixture(
                    "status",
                    {
                        **loader_document,
                        "statements": [{**loader_document["statements"][0], "status": "invalid"}],
                    },
                ),
                ": statement 0 has invalid status 'invalid'",
            ),
            (
                "OpenVEX not-affected justification",
                loader_fixture(
                    "missing-justification",
                    {
                        **loader_document,
                        "statements": [{**loader_document["statements"][0], "status": "not_affected"}],
                    },
                ),
                ": statement 0 not_affected requires justification",
            ),
            (
                "OpenVEX justification vocabulary",
                loader_fixture(
                    "unsupported-justification",
                    {
                        **loader_document,
                        "statements": [
                            {
                                **loader_document["statements"][0],
                                "status": "not_affected",
                                "justification": "unsupported",
                            }
                        ],
                    },
                ),
                ": statement 0 has unsupported justification 'unsupported'",
            ),
            (
                "OpenVEX products container",
                loader_fixture(
                    "products-container",
                    {
                        **loader_document,
                        "statements": [
                            {key: value for key, value in loader_document["statements"][0].items() if key != "products"}
                        ],
                    },
                ),
                ": statement 0 requires non-empty products",
            ),
            (
                "OpenVEX product identifiers",
                loader_fixture(
                    "product-identifiers",
                    {
                        **loader_document,
                        "statements": [{**loader_document["statements"][0], "products": [{}]}],
                    },
                ),
                ": statement 0 has no product identifiers",
            ),
        ]
        for label, action, expected_reason in singleton_probes:
            expect_vex_rejection(label, action, expected_reason)

        probes: list[tuple[str, str, Any, Any, Any, str]] = []

        def add_probe(
            label: str,
            expected_reason: str,
            mutate: Mutation,
            *,
            expected_product: str = product,
        ) -> None:
            trivy = copy.deepcopy(clean_trivy)
            grype = copy.deepcopy(clean_grype)
            floor = copy.deepcopy(clean_floor)
            mutate(trivy, grype, floor)
            probes.append((label, expected_reason, trivy, grype, floor, expected_product))

        def replace_with_malformed_inherited_floor(
            _trivy: dict[str, Any],
            _grype: dict[str, Any],
            floor: dict[str, Any],
        ) -> None:
            floor.clear()
            floor.update({"parent": {"floor": {"amd64": ["glibc"]}}})

        def replace_with_invalid_product(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            _floor: dict[str, Any],
        ) -> None:
            trivy["ArtifactName"] = "not an image"
            grype["source"]["target"]["userInput"] = "not an image"

        def replace_with_invalid_trivy_tag_digest(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            _floor: dict[str, Any],
        ) -> None:
            trivy["ArtifactName"] = tag_product
            grype["source"]["target"]["userInput"] = tag_product
            trivy["Metadata"]["RepoDigests"] = [malformed_digest_reference]

        def replace_with_invalid_grype_tag_digest(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            _floor: dict[str, Any],
        ) -> None:
            trivy["ArtifactName"] = tag_product
            grype["source"]["target"]["userInput"] = tag_product
            grype["source"]["target"]["repoDigests"] = [malformed_digest_reference]

        probes.append(
            (
                "Trivy non-object document",
                "Trivy report must be a JSON object",
                [],
                copy.deepcopy(clean_grype),
                copy.deepcopy(clean_floor),
                product,
            )
        )
        probes.append(
            (
                "Trivy hollow document",
                "Trivy SchemaVersion must be 2",
                {},
                copy.deepcopy(clean_grype),
                copy.deepcopy(clean_floor),
                product,
            )
        )
        add_probe(
            "Trivy schema version",
            "Trivy SchemaVersion must be 2",
            lambda trivy, _grype, _floor: trivy.__setitem__("SchemaVersion", 1),
        )
        add_probe(
            "Trivy identity object",
            "Trivy identity must be an object",
            lambda trivy, _grype, _floor: trivy.__setitem__("Trivy", "0.71.0"),
        )
        add_probe(
            "Trivy identity version",
            "Trivy.Version must be a non-empty string",
            lambda trivy, _grype, _floor: trivy.__setitem__("Trivy", {}),
        )
        add_probe(
            "Trivy identity version shape",
            "Trivy.Version must be a three-component numeric version",
            lambda trivy, _grype, _floor: trivy["Trivy"].__setitem__("Version", "opaque"),
        )
        add_probe(
            "Trivy artifact identity",
            "Trivy ArtifactName must be a non-empty string",
            lambda trivy, _grype, _floor: trivy.__setitem__("ArtifactName", ""),
        )
        add_probe(
            "Trivy artifact type",
            "Trivy ArtifactType must be container_image",
            lambda trivy, _grype, _floor: trivy.__setitem__("ArtifactType", "filesystem"),
        )
        add_probe(
            "Trivy metadata object",
            "Trivy Metadata must be an object",
            lambda trivy, _grype, _floor: trivy.__setitem__("Metadata", []),
        )
        add_probe(
            "Trivy OS object",
            "Trivy Metadata.OS must be an object",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("OS", []),
        )
        add_probe(
            "Trivy Red Hat family",
            "Trivy Metadata.OS.Family must be redhat",
            lambda trivy, _grype, _floor: trivy["Metadata"]["OS"].__setitem__("Family", "alpine"),
        )
        add_probe(
            "Trivy OS release",
            "Trivy Metadata.OS.Name must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Metadata"]["OS"].__setitem__("Name", ""),
        )
        add_probe(
            "Trivy image ID",
            "Trivy Metadata.ImageID must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("ImageID", ""),
        )
        add_probe(
            "Trivy image ID content digest",
            "Trivy Metadata.ImageID must be a sha256 content digest",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("ImageID", "opaque"),
        )
        add_probe(
            "Padded image IDs",
            "Trivy Metadata.ImageID must be a sha256 content digest",
            lambda trivy, grype, _floor: (
                trivy["Metadata"].__setitem__("ImageID", f" {image_id}"),
                grype["source"]["target"].__setitem__("imageID", f" {image_id}"),
            ),
        )
        add_probe(
            "Trivy image config object",
            "Trivy Metadata.ImageConfig must be an object",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("ImageConfig", []),
        )
        add_probe(
            "Trivy architecture",
            "Trivy Metadata.ImageConfig.architecture must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Metadata"]["ImageConfig"].__setitem__("architecture", ""),
        )
        add_probe(
            "Trivy architecture domain",
            "Trivy Metadata.ImageConfig.architecture must be amd64 or arm64",
            lambda trivy, _grype, _floor: trivy["Metadata"]["ImageConfig"].__setitem__(
                "architecture",
                "opaque",
            ),
        )
        add_probe(
            "Trivy repo digest container",
            "Trivy Metadata.RepoDigests must be a list when present",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("RepoDigests", product),
        )
        add_probe(
            "Trivy repo digest entry",
            "Trivy Metadata.RepoDigests[0] must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("RepoDigests", [""]),
        )
        add_probe(
            "Trivy repo digest shape",
            "Trivy Metadata.RepoDigests[0] must be a digest-qualified image reference",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("RepoDigests", ["opaque"]),
        )
        add_probe(
            "Trivy results container",
            "Trivy Results must be a list",
            lambda trivy, _grype, _floor: trivy.__setitem__("Results", {}),
        )
        add_probe(
            "Trivy result object",
            "Trivy Results[1] must be an object",
            lambda trivy, _grype, _floor: trivy.__setitem__("Results", [trivy["Results"][0], []]),
        )
        add_probe(
            "Trivy result target",
            "Trivy Results[0].Target must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0].pop("Target"),
        )
        add_probe(
            "Trivy OS result class",
            "Trivy report requires at least one Class=os-pkgs Type=redhat result",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Class", "lang-pkgs"),
        )
        add_probe(
            "Trivy OS result type",
            "Trivy report requires at least one Class=os-pkgs Type=redhat result",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Type", "debian"),
        )
        add_probe(
            "Trivy packages container",
            "Trivy Results[0].Packages must be a list",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Packages", {}),
        )
        add_probe(
            "Trivy package object",
            "Trivy Results[0].Packages[0] must be an object",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Packages", ["glibc"]),
        )
        add_probe(
            "Trivy package name",
            "Trivy Results[0].Packages[0].Name must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0]["Packages"][0].__setitem__("Name", ""),
        )
        add_probe(
            "Trivy package version",
            "Trivy Results[0].Packages[0].Version must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0]["Packages"][0].__setitem__("Version", ""),
        )
        add_probe(
            "Trivy empty inventory",
            "Trivy os-pkgs/redhat inventory must be non-empty",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Packages", []),
        )
        add_probe(
            "Trivy vulnerabilities container",
            "Trivy Results[0].Vulnerabilities must be a list or null",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Vulnerabilities", {}),
        )
        add_probe(
            "Trivy finding object",
            "Trivy Results[0].Vulnerabilities[0] must be an object",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Vulnerabilities", [[]]),
        )
        valid_trivy_finding = {
            "VulnerabilityID": "CVE-2099-0001",
            "PkgName": "glibc",
            "Severity": "HIGH",
        }
        add_probe(
            "Trivy finding ID",
            "Trivy Results[0].Vulnerabilities[0].VulnerabilityID must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__(
                "Vulnerabilities",
                [{key: value for key, value in valid_trivy_finding.items() if key != "VulnerabilityID"}],
            ),
        )
        add_probe(
            "Trivy finding severity",
            "Trivy Results[0].Vulnerabilities[0].Severity must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__(
                "Vulnerabilities",
                [{key: value for key, value in valid_trivy_finding.items() if key != "Severity"}],
            ),
        )
        add_probe(
            "Trivy unsupported finding severity",
            "Trivy Results[0].Vulnerabilities[0].Severity has unsupported value",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__(
                "Vulnerabilities",
                [{**valid_trivy_finding, "Severity": "UNSUPPORTED"}],
            ),
        )
        add_probe(
            "Trivy finding package",
            "Trivy Results[0].Vulnerabilities[0].PkgName must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__(
                "Vulnerabilities",
                [{key: value for key, value in valid_trivy_finding.items() if key != "PkgName"}],
            ),
        )
        probes.append(
            (
                "Grype non-object document",
                "Grype report must be a JSON object",
                copy.deepcopy(clean_trivy),
                [],
                copy.deepcopy(clean_floor),
                product,
            )
        )
        probes.append(
            (
                "Grype hollow document",
                "Grype report must contain a grype descriptor",
                copy.deepcopy(clean_trivy),
                {},
                copy.deepcopy(clean_floor),
                product,
            )
        )
        add_probe(
            "Grype descriptor object",
            "Grype report must contain a grype descriptor",
            lambda _trivy, grype, _floor: grype.__setitem__("descriptor", []),
        )
        add_probe(
            "Grype descriptor name",
            "Grype report must contain a grype descriptor",
            lambda _trivy, grype, _floor: grype["descriptor"].__setitem__("name", "other"),
        )
        add_probe(
            "Grype descriptor version",
            "Grype descriptor.version must be a non-empty string",
            lambda _trivy, grype, _floor: grype["descriptor"].__setitem__("version", ""),
        )
        add_probe(
            "Grype descriptor version shape",
            "Grype descriptor.version must be a three-component numeric version",
            lambda _trivy, grype, _floor: grype["descriptor"].__setitem__("version", "opaque"),
        )
        add_probe(
            "Grype distro object",
            "Grype distro must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__("distro", []),
        )
        add_probe(
            "Grype Red Hat distro",
            "Grype distro.name must be redhat",
            lambda _trivy, grype, _floor: grype["distro"].__setitem__("name", "ubuntu"),
        )
        add_probe(
            "Grype distro version",
            "Grype distro.version must be a non-empty string",
            lambda _trivy, grype, _floor: grype["distro"].__setitem__("version", ""),
        )
        add_probe(
            "Grype source object",
            "Grype source must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__("source", []),
        )
        add_probe(
            "Grype image target pair",
            "Grype image source.target must be an object",
            lambda _trivy, grype, _floor: grype["source"].__setitem__("target", product),
        )
        add_probe(
            "Grype image user input",
            "Grype source.target.userInput must be a non-empty string",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("userInput", ""),
        )
        add_probe(
            "Grype image ID",
            "Grype source.target.imageID must be a non-empty string",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("imageID", ""),
        )
        add_probe(
            "Grype image ID content digest",
            "Grype source.target.imageID must be a sha256 content digest",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("imageID", "opaque"),
        )
        add_probe(
            "Grype architecture",
            "Grype source.target.architecture must be a non-empty string",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("architecture", ""),
        )
        add_probe(
            "Grype architecture domain",
            "Grype source.target.architecture must be amd64 or arm64",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("architecture", "opaque"),
        )
        add_probe(
            "Shared opaque architecture",
            "Trivy Metadata.ImageConfig.architecture must be amd64 or arm64",
            lambda trivy, grype, _floor: (
                trivy["Metadata"]["ImageConfig"].__setitem__("architecture", "opaque"),
                grype["source"]["target"].__setitem__("architecture", "opaque"),
            ),
        )
        add_probe(
            "Grype repo digest container",
            "Grype source.target.repoDigests must be a list when present",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("repoDigests", product),
        )
        add_probe(
            "Grype repo digest entry",
            "Grype source.target.repoDigests[0] must be a non-empty string",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("repoDigests", [""]),
        )
        add_probe(
            "Grype repo digest shape",
            "Grype source.target.repoDigests[0] must be a digest-qualified image reference",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("repoDigests", ["opaque"]),
        )
        add_probe(
            "Grype directory target pair",
            "Grype directory source.target must be a non-empty string",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "directory", "target": {"path": "/rootfs"}},
            ),
        )
        add_probe(
            "Grype SBOM source mode",
            "Grype source.type must be image or directory",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "sbom", "target": "/tmp/image.cdx.json"},
            ),
        )
        add_probe(
            "Grype file source mode",
            "Grype source.type must be image or directory",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "file", "target": "/tmp/rootfs.tar"},
            ),
        )
        add_probe(
            "Grype unknown source mode",
            "Grype source.type must be image or directory",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "unknown", "target": "/tmp/unknown"},
            ),
        )
        add_probe(
            "Grype matches container",
            "Grype matches must be a list",
            lambda _trivy, grype, _floor: grype.__setitem__("matches", {}),
        )
        valid_grype_match = {
            "vulnerability": {"id": "CVE-2099-0002", "severity": "HIGH"},
            "artifact": {"name": "glibc"},
        }
        add_probe(
            "Grype match object",
            "Grype matches[0] must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__("matches", [[]]),
        )
        add_probe(
            "Grype vulnerability object",
            "Grype matches[0].vulnerability must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "vulnerability": []}],
            ),
        )
        add_probe(
            "Grype finding ID",
            "Grype matches[0].vulnerability.id must be a non-empty string",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "vulnerability": {"severity": "HIGH"}}],
            ),
        )
        add_probe(
            "Grype finding severity",
            "Grype matches[0].vulnerability.severity must be a non-empty string",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "vulnerability": {"id": "CVE-2099-0002"}}],
            ),
        )
        add_probe(
            "Grype artifact object",
            "Grype matches[0].artifact must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "artifact": []}],
            ),
        )
        add_probe(
            "Grype finding package",
            "Grype matches[0].artifact.name must be a non-empty string",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "artifact": {}}],
            ),
        )
        add_probe(
            "Directory evidence cannot bypass image binding",
            "report binding requires a Grype image source",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "directory", "target": "/rootfs"},
            ),
        )
        add_probe(
            "Product image reference shape",
            "--product must be a well-formed image reference",
            replace_with_invalid_product,
            expected_product="not an image",
        )
        add_probe(
            "Trivy stale product",
            "Trivy ArtifactName does not match --product",
            lambda trivy, _grype, _floor: trivy.__setitem__("ArtifactName", "example.invalid/stale:old"),
        )
        add_probe(
            "Grype wrong product",
            "Grype source.target.userInput does not match --product",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__(
                "userInput",
                "example.invalid/wrong:target",
            ),
        )
        add_probe(
            "Cross-scanner image ID",
            "Trivy and Grype imageID values do not match",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__(
                "imageID",
                "sha256:" + ("c" * 64),
            ),
        )
        add_probe(
            "Cross-scanner architecture",
            "Trivy and Grype architecture values do not match",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("architecture", "arm64"),
        )
        add_probe(
            "Cross-scanner OS release",
            "Trivy OS and Grype distro versions do not match",
            lambda trivy, grype, _floor: (
                trivy["Metadata"]["OS"].__setitem__("Name", "8.10"),
                grype["distro"].__setitem__("version", "7.9"),
            ),
        )
        add_probe(
            "Consumer RHEL major release",
            "Trivy OS and Grype distro versions must identify RHEL 9",
            lambda trivy, grype, _floor: (
                trivy["Metadata"]["OS"].__setitem__("Name", "8.10"),
                grype["distro"].__setitem__("version", "8.10"),
            ),
        )
        add_probe(
            "Trivy required digest repository evidence",
            "Trivy Metadata.RepoDigests is required for a digest-addressed --product",
            lambda trivy, _grype, _floor: trivy["Metadata"].pop("RepoDigests"),
        )
        add_probe(
            "Grype required digest repository evidence",
            "Grype source.target.repoDigests is required for a digest-addressed --product",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("repoDigests", []),
        )
        add_probe(
            "Trivy populated repo digest binding",
            "Trivy Metadata.RepoDigests does not contain --product",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__(
                "RepoDigests",
                ["example.invalid/wrong@sha256:" + ("d" * 64)],
            ),
        )
        add_probe(
            "Grype populated repo digest binding",
            "Grype source.target.repoDigests does not contain --product",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__(
                "repoDigests",
                ["example.invalid/wrong@sha256:" + ("d" * 64)],
            ),
        )
        additional_digest = "example.invalid/base-micro@sha256:" + ("d" * 64)
        add_probe(
            "Cross-scanner repo digest evidence",
            "Trivy and Grype repository digest evidence does not match",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__(
                "repoDigests",
                [product, additional_digest],
            ),
        )
        malformed_digest_reference = "!@sha256:" + ("d" * 64)
        add_probe(
            "Trivy tag-mode repository digest shape",
            "Trivy Metadata.RepoDigests[0] must be a digest-qualified image reference",
            replace_with_invalid_trivy_tag_digest,
            expected_product=tag_product,
        )
        add_probe(
            "Grype tag-mode repository digest shape",
            "Grype source.target.repoDigests[0] must be a digest-qualified image reference",
            replace_with_invalid_grype_tag_digest,
            expected_product=tag_product,
        )
        probes.append(
            (
                "Package floor non-object",
                "package floor contract must be a JSON object",
                copy.deepcopy(clean_trivy),
                copy.deepcopy(clean_grype),
                [],
                product,
            )
        )
        add_probe(
            "Package floor schema",
            "missing package floor for architecture amd64",
            lambda _trivy, _grype, floor: floor.clear(),
        )
        add_probe(
            "Package floor non-empty",
            "package floor must be a non-empty list",
            lambda _trivy, _grype, floor: floor["runtime"].__setitem__("package_floor", []),
        )
        add_probe(
            "Package floor entry",
            "package floor[0] must be a non-empty string",
            lambda _trivy, _grype, floor: floor["runtime"].__setitem__("package_floor", [""]),
        )
        add_probe(
            "Package floor inventory binding",
            "Trivy inventory missing contract package floor: zlib",
            lambda _trivy, _grype, floor: floor["runtime"].__setitem__("package_floor", ["glibc", "zlib"]),
        )
        add_probe(
            "Inherited floor NEVRA",
            "package floor[0] must be an RPM NEVRA",
            replace_with_malformed_inherited_floor,
        )

        rejected = 0
        for label, expected_reason, trivy, grype, floor, expected_product in probes:
            try:
                run_fixture(trivy, grype, floor, expected_product=expected_product)
            except VexError as exc:
                if expected_reason not in str(exc):
                    print(
                        f"self-test failed: {label} rejected for wrong reason: {exc}",
                        file=sys.stderr,
                    )
                    return 1
                rejected += 1
            else:
                print(f"self-test failed: {label} unexpectedly passed", file=sys.stderr)
                return 1
        print(f"assert-vex self-test: {rejected}/{len(probes)} mutations rejected at their expected discriminator")

        try:
            run_fixture(clean_trivy, clean_grype, clean_floor, expected_product=f" {product}")
        except VexError as exc:
            expected_reason = "--product must not contain surrounding whitespace"
            if expected_reason not in str(exc):
                print(
                    f"self-test failed: product whitespace rejected for wrong reason: {exc}",
                    file=sys.stderr,
                )
                return 1
        else:
            print("self-test failed: product whitespace unexpectedly passed", file=sys.stderr)
            return 1
        print("assert-vex self-test: product whitespace rejected at its expected discriminator")

        parser_probes: list[tuple[str, Callable[[dict[str, Any]], list[Finding]], dict[str, Any], str]] = [
            ("Trivy parser missing Results", parse_trivy, {}, "Trivy Results must be a list"),
            ("Grype parser missing matches", parse_grype, {}, "Grype matches must be a list"),
        ]
        for label, parser, document, expected_reason in parser_probes:
            try:
                parser(document)
            except VexError as exc:
                if expected_reason not in str(exc):
                    print(f"self-test failed: {label} rejected for wrong reason: {exc}", file=sys.stderr)
                    return 1
            else:
                print(f"self-test failed: {label} unexpectedly passed", file=sys.stderr)
                return 1
            print(f"assert-vex self-test: {label} rejected at its expected discriminator")

        duplicate_documents = [
            (
                "duplicate fix keys malicious-last order",
                '{"fix":{"versions":[{}],"versions":["1.2.3"],"state":[],"state":"fixed"}}',
            ),
            (
                "duplicate fix keys malformed-last order",
                '{"fix":{"versions":["1.2.3"],"versions":[{}],"state":"fixed","state":[]}}',
            ),
        ]
        for label, raw_document in duplicate_documents:
            duplicate_json = tmp / f"{label.replace(' ', '-')}.json"
            duplicate_json.write_text(raw_document, encoding="utf-8")
            try:
                load_json(duplicate_json)
            except VexError as exc:
                if "duplicate JSON object member" not in str(exc):
                    print(f"self-test failed: {label} rejected for wrong reason: {exc}", file=sys.stderr)
                    return 1
            else:
                print(f"self-test failed: {label} unexpectedly passed", file=sys.stderr)
                return 1
            print(f"assert-vex self-test: {label} rejected at its expected discriminator")

        def trivy_fix_fixture(fix: Any) -> dict[str, Any]:
            trivy = copy.deepcopy(clean_trivy)
            trivy["Results"][0]["Vulnerabilities"] = [{**valid_trivy_finding, **fix}]
            return trivy

        def grype_fix_fixture(fix: Any) -> dict[str, Any]:
            grype = copy.deepcopy(clean_grype)
            grype["matches"] = [
                {
                    **valid_grype_match,
                    "vulnerability": {
                        **valid_grype_match["vulnerability"],
                        "fix": fix,
                    },
                }
            ]
            return grype

        no_fix_probes = [
            (
                "Trivy null FixedVersion with fixed Status",
                trivy_fix_fixture({"FixedVersion": None, "Status": "fixed"}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy malformed FixedVersion type",
                trivy_fix_fixture({"FixedVersion": [], "Status": "fixed"}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy non-canonical Status case",
                trivy_fix_fixture({"Status": "FiXeD"}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy padded Status",
                trivy_fix_fixture({"Status": " fixed "}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy fixed version with malformed Status type",
                trivy_fix_fixture({"FixedVersion": "1.2.3", "Status": []}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy fixed version with unrecognised Status",
                trivy_fix_fixture({"FixedVersion": "1.2.3", "Status": "surprising"}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Grype malformed fix object",
                clean_trivy,
                grype_fix_fixture([]),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype malformed versions container",
                clean_trivy,
                grype_fix_fixture({"versions": {}, "state": "fixed"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype malformed versions entry",
                clean_trivy,
                grype_fix_fixture({"versions": [{}], "state": "not-fixed"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype empty versions entry",
                clean_trivy,
                grype_fix_fixture({"versions": [""], "state": "not-fixed"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype version with malformed state type",
                clean_trivy,
                grype_fix_fixture({"versions": ["1.2.3"], "state": []}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype version with missing state",
                clean_trivy,
                grype_fix_fixture({"versions": ["1.2.3"]}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype version with unrecognised state",
                clean_trivy,
                grype_fix_fixture({"versions": ["1.2.3"], "state": "surprising"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype non-canonical state case",
                clean_trivy,
                grype_fix_fixture({"versions": [], "state": "FiXeD"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype padded state",
                clean_trivy,
                grype_fix_fixture({"versions": [], "state": " fixed "}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
        ]
        no_fix_rejected = 0
        for label, trivy, grype, expected_reason in no_fix_probes:
            result, output = run_fixture_with_output(trivy, grype, clean_floor)
            if result != 1 or expected_reason not in output:
                print(
                    f"self-test failed: {label} was not treated as an unfixed finding: {output}",
                    file=sys.stderr,
                )
                return 1
            print(f"assert-vex self-test: {label} treated as no fix")
            no_fix_rejected += 1
        print(
            "assert-vex self-test: "
            f"{no_fix_rejected}/{len(no_fix_probes)} malformed fix records retained their findings"
        )

        valid_fixed_trivy = trivy_fix_fixture({"FixedVersion": "1.2.3", "Status": "fixed"})
        if run_fixture(valid_fixed_trivy, clean_grype, clean_floor) != 0:
            print("self-test failed: complete Trivy fix evidence was not honoured", file=sys.stderr)
            return 1
        valid_fixed_trivy_without_status = trivy_fix_fixture({"FixedVersion": "1.2.3"})
        if run_fixture(valid_fixed_trivy_without_status, clean_grype, clean_floor) != 0:
            print("self-test failed: Trivy FixedVersion without Status was not honoured", file=sys.stderr)
            return 1
        valid_fixed_trivy_status_only = trivy_fix_fixture({"Status": "fixed"})
        if run_fixture(valid_fixed_trivy_status_only, clean_grype, clean_floor) != 0:
            print("self-test failed: Trivy fixed Status without FixedVersion was not honoured", file=sys.stderr)
            return 1
        valid_deferred_trivy = trivy_fix_fixture({"FixedVersion": "1.2.3", "Status": "fix_deferred"})
        if run_fixture(valid_deferred_trivy, clean_grype, clean_floor) != 0:
            print("self-test failed: Trivy fix_deferred status was not honoured", file=sys.stderr)
            return 1
        valid_fixed_grype = grype_fix_fixture({"versions": ["1.2.3"], "state": "fixed"})
        if run_fixture(clean_trivy, valid_fixed_grype, clean_floor) != 0:
            print("self-test failed: complete Grype fix evidence was not honoured", file=sys.stderr)
            return 1
        print("assert-vex self-test: complete Trivy and Grype fix evidence honoured")
        print("assert-vex self-test: Trivy FixedVersion without Status honoured")
        print("assert-vex self-test: Trivy fixed Status without FixedVersion honoured")
        print("assert-vex self-test: Trivy fix_deferred status honoured")

        accept_product = "local/ubi9-base-python:ci-amd64"
        accept_vex_dir = tmp / "images" / "python" / "vex"
        accept_vex_dir.mkdir(parents=True)
        canonical_vex_name = "cve-2026-11940.openvex.json"
        canonical_vex = expected_accept_and_track_document()

        accept_trivy = copy.deepcopy(clean_trivy)
        accept_trivy["ArtifactName"] = accept_product
        accept_trivy["Metadata"]["ImageConfig"]["architecture"] = "amd64"
        accept_trivy["Metadata"].pop("RepoDigests")
        accept_trivy["Results"][0]["Packages"] = [
            {"Name": "glibc", "Version": "2.34"},
            {"Name": "python3.12", "Version": "3.12.13-3.el9_8.1"},
            {"Name": "python3.12-libs", "Version": "3.12.13-3.el9_8.1"},
        ]
        accept_trivy["Results"][0]["Vulnerabilities"] = []

        accept_grype = copy.deepcopy(clean_grype)
        accept_grype["source"]["target"]["userInput"] = accept_product
        accept_grype["source"]["target"]["architecture"] = "amd64"
        accept_grype["source"]["target"]["repoDigests"] = []

        def target_trivy_records(*, fixed: bool) -> list[dict[str, Any]]:
            records: list[dict[str, Any]] = []
            for package in ("python3.12", "python3.12-libs"):
                record: dict[str, Any] = {
                    "VulnerabilityID": "CVE-2026-11940",
                    "PkgName": package,
                    "InstalledVersion": "3.12.13-3.el9_8.1",
                    "Severity": "HIGH",
                }
                if fixed:
                    record.update({"FixedVersion": "3.12.13-4.el9_8", "Status": "fixed"})
                records.append(record)
            return records

        def target_grype_records(*, fixed: bool) -> list[dict[str, Any]]:
            records: list[dict[str, Any]] = []
            for package in ("python3.12", "python3.12-libs"):
                vulnerability: dict[str, Any] = {
                    "id": "CVE-2026-11940",
                    "severity": "High",
                }
                if fixed:
                    vulnerability["fix"] = {"versions": ["3.12.13-4.el9_8"], "state": "fixed"}
                records.append(
                    {
                        "vulnerability": vulnerability,
                        "artifact": {"name": package, "version": "3.12.13-3.el9_8.1"},
                    }
                )
            return records

        accept_grype["matches"] = target_grype_records(fixed=False)

        def bind_accept_reports(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            fixture_product: str,
            architecture: str = "amd64",
        ) -> None:
            trivy["ArtifactName"] = fixture_product
            trivy["Metadata"]["ImageConfig"]["architecture"] = architecture
            trivy["Metadata"].pop("RepoDigests", None)
            grype["source"]["target"]["userInput"] = fixture_product
            grype["source"]["target"]["architecture"] = architecture
            grype["source"]["target"]["repoDigests"] = []

        def run_accept_fixture(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            *,
            fixture_product: str = accept_product,
            document: dict[str, Any] | None = canonical_vex,
            filename: str = canonical_vex_name,
            extra_documents: tuple[tuple[str, dict[str, Any]], ...] = (),
            dispositions: tuple[AcceptAndTrackDisposition, ...] = ACCEPT_AND_TRACK_DISPOSITIONS,
            evaluation_date: date = date(2026, 8, 13),
        ) -> tuple[int | None, str, VexError | None]:
            for old_document in accept_vex_dir.glob("*.json"):
                old_document.unlink()
            if document is not None:
                write_json(accept_vex_dir / filename, document)
            for extra_name, extra_document in extra_documents:
                write_json(accept_vex_dir / extra_name, extra_document)
            write_json(trivy_json, trivy)
            write_json(grype_json, grype)
            write_json(package_floor, clean_floor)
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = assert_vex(
                        fixture_product,
                        trivy_json,
                        grype_json,
                        package_floor,
                        accept_vex_dir,
                        emit=True,
                        accept_and_track=dispositions,
                        today=evaluation_date,
                    )
            except VexError as exc:
                return None, stdout.getvalue() + stderr.getvalue(), exc
            return result, stdout.getvalue() + stderr.getvalue(), None

        def expect_accept_rejection(
            label: str,
            *,
            expected_reason: str,
            trivy: dict[str, Any] = accept_trivy,
            grype: dict[str, Any] = accept_grype,
            fixture_product: str = accept_product,
            document: dict[str, Any] | None = canonical_vex,
            filename: str = canonical_vex_name,
            dispositions: tuple[AcceptAndTrackDisposition, ...] = ACCEPT_AND_TRACK_DISPOSITIONS,
        ) -> None:
            result, output, error = run_accept_fixture(
                copy.deepcopy(trivy),
                copy.deepcopy(grype),
                fixture_product=fixture_product,
                document=copy.deepcopy(document),
                filename=filename,
                dispositions=dispositions,
            )
            if error is not None or result != 1 or expected_reason not in output:
                print(
                    f"self-test failed: {label} rejected for wrong reason: "
                    f"result={result} error={error} output={output}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if any(line.startswith("accept-and-track disposition:") for line in output.splitlines()):
                print(f"self-test failed: {label} emitted a disposition: {output}", file=sys.stderr)
                raise SystemExit(1)
            print(f"assert-vex self-test: {label} rejected at its expected discriminator")

        baseline_result, baseline_output, baseline_error = run_accept_fixture(accept_trivy, accept_grype)
        baseline_markers = [
            "accept-and-track disposition: CVE-2026-11940",
            "python3.12@3.12.13-3.el9_8.1",
            "python3.12-libs@3.12.13-3.el9_8.1",
            "debt=TD-9",
            "review-by=2026-10-01",
            "undispositioned unfixed HIGH/CRITICAL findings: 0",
        ]
        if (
            baseline_error is not None
            or baseline_result != 0
            or any(marker not in baseline_output for marker in baseline_markers)
        ):
            print(
                "self-test failed: canonical accept-and-track fixture did not pass with complete output: "
                f"result={baseline_result} error={baseline_error} output={baseline_output}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: canonical accept-and-track disposition passed with zero undispositioned findings")

        def mutate_vex(apply: Callable[[dict[str, Any]], Any]) -> dict[str, Any]:
            mutated = copy.deepcopy(canonical_vex)
            apply(mutated)
            return mutated

        statement_mutations: list[tuple[str, dict[str, Any], str]] = [
            (
                "accept-and-track statement wrong CVE",
                mutate_vex(lambda value: value["statements"][0]["vulnerability"].update(name="CVE-2099-0000")),
                "no reviewed OpenVEX statement for CVE-2026-11940",
            ),
            (
                "accept-and-track statement first package altered",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"][0].update(
                        {"@id": "pkg:rpm/redhat/python3.12-extra@3.12.13-3.el9_8.1"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement first package missing",
                mutate_vex(lambda value: value["statements"][0]["products"][0]["subcomponents"].pop(0)),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement second package altered",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"][1].update(
                        {"@id": "pkg:rpm/redhat/python3.12-libs-extra@3.12.13-3.el9_8.1"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement second package missing",
                mutate_vex(lambda value: value["statements"][0]["products"][0]["subcomponents"].pop(1)),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement extra package",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"].append(
                        {"@id": "pkg:rpm/redhat/extra@1"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement first version altered",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"][0].update(
                        {"@id": "pkg:rpm/redhat/python3.12@3.12.13-3.el9_8.2"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement second version altered",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"][1].update(
                        {"@id": "pkg:rpm/redhat/python3.12-libs@3.12.13-3.el9_8.2"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement wrong product",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0].update(
                        {"@id": "local/ubi9-base-python:ci-other"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement status other than affected",
                mutate_vex(lambda value: value["statements"][0].update(status="fixed")),
                "accept-and-track status must be affected",
            ),
            (
                "accept-and-track statement zero review markers",
                mutate_vex(
                    lambda value: value["statements"][0].update(
                        action_statement=ACCEPT_AND_TRACK_ACTION_STATEMENT.replace("review-by", "review by")
                    )
                ),
                "accept-and-track action_statement must contain exactly one review-by marker",
            ),
            (
                "accept-and-track statement two review markers",
                mutate_vex(
                    lambda value: value["statements"][0].update(
                        action_statement=ACCEPT_AND_TRACK_ACTION_STATEMENT + " review-by 2026-10-01"
                    )
                ),
                "accept-and-track action_statement must contain exactly one review-by marker",
            ),
            (
                "accept-and-track statement wrong review date",
                mutate_vex(
                    lambda value: value["statements"][0].update(
                        action_statement=ACCEPT_AND_TRACK_ACTION_STATEMENT.replace("2026-10-01", "2026-10-02")
                    )
                ),
                "accept-and-track action_statement must contain review-by 2026-10-01",
            ),
            (
                "accept-and-track statement wrong debt id",
                mutate_vex(
                    lambda value: value["statements"][0].update(
                        action_statement=ACCEPT_AND_TRACK_ACTION_STATEMENT.replace("TD-9", "TD-10")
                    )
                ),
                "accept-and-track action_statement must name TD-9",
            ),
            (
                "accept-and-track statement added alias",
                mutate_vex(lambda value: value["statements"][0]["vulnerability"].update(aliases=[])),
                "accept-and-track vulnerability must contain only its name",
            ),
            (
                "accept-and-track statement added product",
                mutate_vex(
                    lambda value: value["statements"][0]["products"].append(
                        {"@id": "local/ubi9-base-python:ci-extra", "subcomponents": []}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
        ]
        for label, mutated_document, expected_reason in statement_mutations:
            expect_accept_rejection(label, expected_reason=expected_reason, document=mutated_document)

        expect_accept_rejection(
            "accept-and-track allowlist present but statement absent",
            expected_reason="no reviewed OpenVEX statement for CVE-2026-11940",
            document=None,
        )
        expect_accept_rejection(
            "accept-and-track statement present but allowlist absent",
            expected_reason="no exact in-tool accept-and-track allowlist entry",
            dispositions=(),
        )
        expect_accept_rejection(
            "accept-and-track canonical statement under wrong file name",
            expected_reason="statement source must be images/python/vex/cve-2026-11940.openvex.json",
            filename="wrong.openvex.json",
        )

        canonical_disposition = ACCEPT_AND_TRACK_DISPOSITIONS[0]
        allowlist_mutations: list[tuple[str, AcceptAndTrackDisposition, str]] = [
            (
                "accept-and-track allowlist wrong CVE",
                replace(canonical_disposition, vulnerability="CVE-2099-0000"),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist wrong product",
                replace(canonical_disposition, products=("local/ubi9-base-python:ci-other",)),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist missing first package",
                replace(canonical_disposition, packages=canonical_disposition.packages[1:]),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist missing second package",
                replace(canonical_disposition, packages=canonical_disposition.packages[:1]),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist extra package",
                replace(canonical_disposition, packages=(*canonical_disposition.packages, ("extra", "1"))),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist first version altered",
                replace(
                    canonical_disposition,
                    packages=(("python3.12", "3.12.13-3.el9_8.2"), canonical_disposition.packages[1]),
                ),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist second version altered",
                replace(
                    canonical_disposition,
                    packages=(canonical_disposition.packages[0], ("python3.12-libs", "3.12.13-3.el9_8.2")),
                ),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist wrong debt id",
                replace(canonical_disposition, debt_id="TD-10"),
                "in-tool accept-and-track allowlist entry does not match the canonical authorization",
            ),
            (
                "accept-and-track allowlist wrong review date",
                replace(canonical_disposition, review_by="2026-10-02"),
                "in-tool accept-and-track allowlist entry does not match the canonical authorization",
            ),
            (
                "accept-and-track allowlist wrong statement path",
                replace(canonical_disposition, statement_path="images/python/vex/other.openvex.json"),
                "in-tool accept-and-track allowlist entry does not match the canonical authorization",
            ),
        ]
        for label, mutated_disposition, expected_reason in allowlist_mutations:
            expect_accept_rejection(
                label,
                expected_reason=expected_reason,
                dispositions=(mutated_disposition,),
            )

        unintended_trivy = copy.deepcopy(accept_trivy)
        unintended_grype = copy.deepcopy(accept_grype)
        unintended_product = "local/ubi9-base-python:ci-amd64-extra"
        bind_accept_reports(unintended_trivy, unintended_grype, unintended_product)
        expect_accept_rejection(
            "accept-and-track unintended base-python tag",
            expected_reason="un-vexed unfixed HIGH/CRITICAL findings",
            trivy=unintended_trivy,
            grype=unintended_grype,
            fixture_product=unintended_product,
        )

        duplicate_file_result, _, duplicate_file_error = run_accept_fixture(
            accept_trivy,
            accept_grype,
            extra_documents=(("duplicate.openvex.json", canonical_vex),),
        )
        if (
            duplicate_file_result is not None
            or duplicate_file_error is None
            or "duplicate accept-and-track statements for CVE-2026-11940" not in str(duplicate_file_error)
        ):
            print(
                f"self-test failed: duplicate accept-and-track file rejected for wrong reason: {duplicate_file_error}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: duplicate accept-and-track file rejected at its expected discriminator")

        duplicate_statement = copy.deepcopy(canonical_vex)
        duplicate_statement["statements"].append(copy.deepcopy(duplicate_statement["statements"][0]))
        duplicate_statement_result, _, duplicate_statement_error = run_accept_fixture(
            accept_trivy,
            accept_grype,
            document=duplicate_statement,
        )
        if (
            duplicate_statement_result is not None
            or duplicate_statement_error is None
            or "duplicate accept-and-track statements for CVE-2026-11940" not in str(duplicate_statement_error)
        ):
            print(
                "self-test failed: duplicate accept-and-track statement rejected for wrong reason: "
                f"{duplicate_statement_error}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: duplicate accept-and-track statement rejected at its expected discriminator")

        expired_result, _, expired_error = run_accept_fixture(
            accept_trivy,
            accept_grype,
            evaluation_date=date(2026, 10, 2),
        )
        expected_expiry = (
            "expired accept-and-track entry: CVE-2026-11940 product=local/ubi9-base-python:ci-amd64 "
            "packages=python3.12@3.12.13-3.el9_8.1,python3.12-libs@3.12.13-3.el9_8.1 "
            "debt=TD-9 review-by=2026-10-01"
        )
        if expired_result is not None or expired_error is None or str(expired_error) != expected_expiry:
            print(
                f"self-test failed: elapsed accept-and-track entry rejected for wrong reason: {expired_error}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: elapsed candidate-scoped entry failed with its complete identity")

        micro_product = "ghcr.io/nwarila/ubi9-base-micro:base-micro"
        micro_trivy = copy.deepcopy(accept_trivy)
        micro_grype = copy.deepcopy(accept_grype)
        bind_accept_reports(micro_trivy, micro_grype, micro_product)
        micro_before = run_accept_fixture(
            micro_trivy,
            micro_grype,
            fixture_product=micro_product,
            evaluation_date=date(2026, 10, 1),
        )
        micro_after = run_accept_fixture(
            micro_trivy,
            micro_grype,
            fixture_product=micro_product,
            evaluation_date=date(2026, 10, 2),
        )
        if (
            micro_before[:2] != micro_after[:2]
            or micro_before[0] != 1
            or "un-vexed unfixed HIGH/CRITICAL findings" not in micro_before[1]
            or any(line.startswith("accept-and-track disposition:") for line in micro_before[1].splitlines())
            or micro_before[2] is not None
            or micro_after[2] is not None
        ):
            print("self-test failed: micro product output changed after the review date", file=sys.stderr)
            return 1
        print("assert-vex self-test: micro product evaluation remained byte-identical after review date")

        dormant_trivy = copy.deepcopy(accept_trivy)
        dormant_grype = copy.deepcopy(clean_grype)
        bind_accept_reports(dormant_trivy, dormant_grype, accept_product)
        dormant_before = run_accept_fixture(
            dormant_trivy,
            dormant_grype,
            evaluation_date=date(2026, 10, 1),
        )
        dormant_after = run_accept_fixture(
            dormant_trivy,
            dormant_grype,
            evaluation_date=date(2026, 10, 2),
        )
        if (
            dormant_before[:2] != dormant_after[:2]
            or dormant_before[0] != 0
            or "unfixed HIGH/CRITICAL findings requiring VEX: 0" not in dormant_before[1]
            or dormant_before[2] is not None
            or dormant_after[2] is not None
        ):
            print("self-test failed: dormant base-python entry output changed after the review date", file=sys.stderr)
            return 1
        print("assert-vex self-test: dormant base-python entry evaluation remained byte-identical after review date")

        trivy_fixed = copy.deepcopy(accept_trivy)
        trivy_fixed["Results"][0]["Vulnerabilities"] = target_trivy_records(fixed=True)
        grype_unfixed = copy.deepcopy(accept_grype)
        expect_accept_rejection(
            "accept-and-track Trivy-fixed Grype-unfixed contradiction",
            expected_reason=(
                "valid fix evidence refuses accept-and-track disposition: "
                "trivy:python3.12@3.12.13-3.el9_8.1,trivy:python3.12-libs@3.12.13-3.el9_8.1"
            ),
            trivy=trivy_fixed,
            grype=grype_unfixed,
        )

        trivy_unfixed = copy.deepcopy(accept_trivy)
        trivy_unfixed["Results"][0]["Vulnerabilities"] = target_trivy_records(fixed=False)
        grype_fixed = copy.deepcopy(accept_grype)
        grype_fixed["matches"] = target_grype_records(fixed=True)
        expect_accept_rejection(
            "accept-and-track Grype-fixed Trivy-unfixed contradiction",
            expected_reason=(
                "valid fix evidence refuses accept-and-track disposition: "
                "grype:python3.12@3.12.13-3.el9_8.1,grype:python3.12-libs@3.12.13-3.el9_8.1"
            ),
            trivy=trivy_unfixed,
            grype=grype_fixed,
        )

        all_fixed_result, all_fixed_output, all_fixed_error = run_accept_fixture(trivy_fixed, grype_fixed)
        if (
            all_fixed_error is not None
            or all_fixed_result != 0
            or "unfixed HIGH/CRITICAL findings requiring VEX: 0" not in all_fixed_output
            or "accept-and-track disposition:" in all_fixed_output
        ):
            print(
                "self-test failed: all-fixed target pair did not take the trivial pass: "
                f"result={all_fixed_result} error={all_fixed_error} output={all_fixed_output}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: all-fixed target pair passed without an accept-and-track disposition")

        critical_trivy = copy.deepcopy(clean_trivy)
        critical_trivy["Results"][0]["Vulnerabilities"] = [
            {
                "VulnerabilityID": "CVE-2099-0001",
                "PkgName": "openssl-libs",
                "InstalledVersion": "0",
                "Severity": "CRITICAL",
            }
        ]
        if run_fixture(critical_trivy, clean_grype, clean_floor) == 0:
            print("self-test failed: synthetic-unvexed-critical unexpectedly passed", file=sys.stderr)
            return 1
        print("assert-vex self-test: synthetic-unvexed-critical failed as expected")

        write_json(
            vex_dir / "synthetic.openvex.json",
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": "https://github.com/NWarila/ubi9-base-micro/vex/synthetic",
                "author": "NWarila",
                "timestamp": "2026-01-01T00:00:00Z",
                "version": 1,
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2099-0001"},
                        "products": [{"@id": product}],
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present",
                    }
                ],
            },
        )

        if run_fixture(critical_trivy, clean_grype, clean_floor) != 0:
            print("self-test failed: synthetic-vexed-critical did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: synthetic-vexed-critical passed")

    print("assert-vex self-test: ok")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", help="exact image reference scanned")
    parser.add_argument("--trivy-json", type=Path, help="Trivy JSON report without --ignore-unfixed")
    parser.add_argument("--grype-json", type=Path, help="Grype JSON report without --only-fixed")
    parser.add_argument("--package-floor", type=Path, help="contract containing the applicable package floor")
    parser.add_argument("--vex-dir", type=Path, default=Path("vex"), help="directory containing OpenVEX JSON")
    parser.add_argument("--self-test", action="store_true", help="prove default-deny behavior with synthetic data")
    args = parser.parse_args(argv)

    if args.self_test:
        return args
    missing = [name for name in ("product", "trivy_json", "grype_json", "package_floor") if getattr(args, name) is None]
    if missing:
        parser.error("missing required argument(s): " + ", ".join("--" + item.replace("_", "-") for item in missing))
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            return self_test()
        return assert_vex(
            args.product,
            args.trivy_json,
            args.grype_json,
            args.package_floor,
            args.vex_dir,
        )
    except VexError as exc:
        print(f"assert-vex failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
