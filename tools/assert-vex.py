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
from dataclasses import dataclass, field
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
DIGEST_IMAGE_REFERENCE = re.compile(r".+@sha256:[0-9a-f]{64}\Z")
RHEL_9_RELEASE = re.compile(r"9(?:\.[0-9]+)*\Z")
TRIVY_FIX_STATUSES = {
    "affected",
    "end_of_life",
    "fixed",
    "not_affected",
    "under_investigation",
    "unknown",
    "will_not_fix",
}
GRYPE_FIX_STATES = {"fixed", "not-fixed", "unknown", "wont-fix"}
Mutation = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], Any]


class VexError(Exception):
    pass


@dataclass
class Finding:
    vulnerability: str
    severity: str
    scanners: set[str] = field(default_factory=set)
    packages: set[str] = field(default_factory=set)

    def merge(self, other: Finding) -> None:
        if SEVERITY_ORDER[other.severity] > SEVERITY_ORDER[self.severity]:
            self.severity = other.severity
        self.scanners.update(other.scanners)
        self.packages.update(other.packages)


@dataclass(frozen=True)
class Statement:
    path: Path
    vulnerabilities: frozenset[str]
    products: frozenset[str]
    status: str
    justification: str | None


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
        return json.loads(path.read_text(encoding="utf-8"))
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
    if CONTENT_DIGEST.fullmatch(digest) is None:
        raise VexError(f"{label} must be a sha256 content digest")
    return digest


def finding_severity(value: Any, label: str) -> str:
    normalized = non_empty_string(value, label).upper()
    if normalized not in SEVERITY_ORDER:
        raise VexError(f"{label} has unsupported value {value!r}")
    return normalized


def optional_references(value: dict[str, Any], key: str, label: str) -> tuple[str, ...]:
    if key not in value:
        return ()
    raw_references = value[key]
    if not isinstance(raw_references, list):
        raise VexError(f"{label} must be a list when present")
    return tuple(non_empty_string(reference, f"{label}[{index}]") for index, reference in enumerate(raw_references))


def validate_trivy_report(document: dict[str, Any]) -> TrivyEvidence:
    schema_version = document.get("SchemaVersion")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version != 2:
        raise VexError("Trivy SchemaVersion must be 2")

    trivy = document.get("Trivy")
    if not isinstance(trivy, dict):
        raise VexError("Trivy identity must be an object")
    non_empty_string(trivy.get("Version"), "Trivy.Version")

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
    architecture = non_empty_string(
        image_config.get("architecture"),
        "Trivy Metadata.ImageConfig.architecture",
    )
    repo_digests = optional_references(metadata, "RepoDigests", "Trivy Metadata.RepoDigests")

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
    non_empty_string(descriptor.get("version"), "Grype descriptor.version")

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
        architecture = non_empty_string(target.get("architecture"), "Grype source.target.architecture")
        repo_digests = optional_references(target, "repoDigests", "Grype source.target.repoDigests")
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
    if trivy.repo_digests and expected_product not in trivy.repo_digests:
        raise VexError("Trivy Metadata.RepoDigests does not contain --product")
    if grype.repo_digests and expected_product not in grype.repo_digests:
        raise VexError("Grype source.target.repoDigests does not contain --product")


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
    raw_fixed_version = vulnerability.get("FixedVersion")
    fixed_version_valid = raw_fixed_version is None or isinstance(raw_fixed_version, str)
    if not fixed_version_valid:
        return False
    fixed_version = (raw_fixed_version or "").strip()
    raw_status = vulnerability.get("Status")
    status_valid = isinstance(raw_status, str) and raw_status.strip().lower() in TRIVY_FIX_STATUSES
    if not status_valid:
        return False
    status = str(raw_status).strip().lower()
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
            if sev not in HIGH_CRITICAL or trivy_has_fix(vulnerability):
                continue
            findings.append(
                Finding(
                    vulnerability=vuln_id,
                    severity=sev,
                    scanners={"trivy"},
                    packages={package},
                )
            )
    return findings


def grype_has_fix(vulnerability: dict[str, Any]) -> bool:
    raw_fix = vulnerability.get("fix")
    if raw_fix is None:
        return False
    if not isinstance(raw_fix, dict):
        return False
    raw_versions = raw_fix.get("versions")
    versions_valid = isinstance(raw_versions, list) and all(
        isinstance(version, str) and bool(version.strip()) for version in raw_versions
    )
    if not versions_valid:
        return False
    versions = raw_versions
    raw_state = raw_fix.get("state")
    state_valid = isinstance(raw_state, str) and raw_state.strip().lower() in GRYPE_FIX_STATES
    if not state_valid:
        return False
    state = str(raw_state).strip().lower()
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
        if sev not in HIGH_CRITICAL or grype_has_fix(vulnerability):
            continue
        findings.append(
            Finding(
                vulnerability=vuln_id,
                severity=sev,
                scanners={"grype"},
                packages={package},
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
    return [merged[key] for key in sorted(merged)]


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
                    vulnerabilities=vulnerabilities,
                    products=frozenset(products),
                    status=status,
                    justification=justification_text,
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


def assert_vex(
    product: str,
    trivy_json: Path,
    grype_json: Path,
    package_floor: Path,
    vex_dir: Path,
    emit: bool = True,
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

    missing: list[Finding] = []
    matched: list[tuple[Finding, Statement]] = []
    for finding in findings:
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

    if missing:
        if emit:
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

        probes: list[tuple[str, str, Any, Any, Any]] = []

        def add_probe(label: str, expected_reason: str, mutate: Mutation) -> None:
            trivy = copy.deepcopy(clean_trivy)
            grype = copy.deepcopy(clean_grype)
            floor = copy.deepcopy(clean_floor)
            mutate(trivy, grype, floor)
            probes.append((label, expected_reason, trivy, grype, floor))

        def replace_with_malformed_inherited_floor(
            _trivy: dict[str, Any],
            _grype: dict[str, Any],
            floor: dict[str, Any],
        ) -> None:
            floor.clear()
            floor.update({"parent": {"floor": {"amd64": ["glibc"]}}})

        probes.append(
            (
                "Trivy non-object document",
                "Trivy report must be a JSON object",
                [],
                copy.deepcopy(clean_grype),
                copy.deepcopy(clean_floor),
            )
        )
        probes.append(
            (
                "Trivy hollow document",
                "Trivy SchemaVersion must be 2",
                {},
                copy.deepcopy(clean_grype),
                copy.deepcopy(clean_floor),
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
            )
        )
        probes.append(
            (
                "Grype hollow document",
                "Grype report must contain a grype descriptor",
                copy.deepcopy(clean_trivy),
                {},
                copy.deepcopy(clean_floor),
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
        probes.append(
            (
                "Package floor non-object",
                "package floor contract must be a JSON object",
                copy.deepcopy(clean_trivy),
                copy.deepcopy(clean_grype),
                [],
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
        for label, expected_reason, trivy, grype, floor in probes:
            try:
                run_fixture(trivy, grype, floor)
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
                "Trivy malformed FixedVersion type",
                trivy_fix_fixture({"FixedVersion": [], "Status": "fixed"}),
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
                "Trivy fixed version with missing Status",
                trivy_fix_fixture({"FixedVersion": "1.2.3"}),
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
        valid_fixed_grype = grype_fix_fixture({"versions": ["1.2.3"], "state": "fixed"})
        if run_fixture(clean_trivy, valid_fixed_grype, clean_floor) != 0:
            print("self-test failed: complete Grype fix evidence was not honoured", file=sys.stderr)
            return 1
        print("assert-vex self-test: complete Trivy and Grype fix evidence honoured")

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
