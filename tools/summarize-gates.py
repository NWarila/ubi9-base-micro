#!/usr/bin/env python3
# Purpose: Collect fail-closed per-architecture decision envelopes from existing gate reports.
# Role: reporting
# Micro-container candidate: yes - pure-stdlib, JSON-in/JSON-out reporting with no gate side effects.

"""Collect compact hardening or reproducibility decision envelopes."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ARCHES = {"amd64", "arm64"}
HIGH_CRITICAL = {"HIGH", "CRITICAL"}
OPENVEX_STATUSES = {"affected", "fixed", "not_affected", "under_investigation"}
OPENVEX_NOT_AFFECTED_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
SCHEMA_VERSION = "1.1.0"


class SummaryError(Exception):
    """An input cannot support a complete decision envelope."""


@dataclass(frozen=True)
class Finding:
    vulnerability: str
    package: str
    version: str
    severity: str
    fixable: bool
    fixed_version: str | None = None
    purl: str | None = None


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SummaryError(f"missing {label}: {path}") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SummaryError(f"malformed {label}: {path}: {exc}") from exc


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SummaryError(f"{label} must be a JSON object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SummaryError(f"{label} must be a JSON array")
    return value


def _integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SummaryError(f"{label} must be a non-negative integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise SummaryError(f"{label} must be a boolean")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SummaryError(f"{label} must be a non-empty string")
    return value.strip()


def _base_envelope(kind: str, arch: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "arch": arch,
        "complete": False,
        "attention_reasons": [],
    }


def _contract_values(contract_path: Path, arch: str) -> tuple[int, str, str]:
    contract = _object(_load_json(contract_path, "image contract"), "image contract")
    architectures = _list(contract.get("architectures"), "contract.architectures")
    if arch not in architectures:
        raise SummaryError(f"contract does not declare architecture {arch}")
    runtime = _object(contract.get("runtime"), "contract.runtime")
    limit = _integer(runtime.get("footprint_limit_bytes"), "contract.runtime.footprint_limit_bytes")
    reproducibility = _object(contract.get("reproducibility"), "contract.reproducibility")
    rootfs = _object(
        reproducibility.get("canonical_rootfs_digest"),
        "contract.reproducibility.canonical_rootfs_digest",
    )
    rpmdb = _object(reproducibility.get("rpmdb_sha256"), "contract.reproducibility.rpmdb_sha256")
    rootfs_digest = _string(rootfs.get(arch), f"contract rootfs digest for {arch}")
    rpmdb_sha256 = _string(rpmdb.get(arch), f"contract rpmdb digest for {arch}")
    if re.fullmatch(r"[0-9a-f]{64}", rootfs_digest) is None:
        raise SummaryError(f"contract rootfs digest for {arch} must be lowercase SHA-256")
    if re.fullmatch(r"[0-9a-f]{64}", rpmdb_sha256) is None:
        raise SummaryError(f"contract rpmdb digest for {arch} must be lowercase SHA-256")
    return limit, rootfs_digest, rpmdb_sha256


def _trivy_findings(path: Path) -> list[Finding]:
    report = _object(_load_json(path, "Trivy report"), "Trivy report")
    findings: list[Finding] = []
    for result_index, raw_result in enumerate(_list(report.get("Results", []), "Trivy Results")):
        result = _object(raw_result, f"Trivy Results[{result_index}]")
        for finding_index, raw_finding in enumerate(
            _list(result.get("Vulnerabilities", []), f"Trivy Results[{result_index}].Vulnerabilities")
        ):
            finding = _object(raw_finding, f"Trivy vulnerability {finding_index}")
            severity = str(finding.get("Severity") or "").upper()
            if severity not in HIGH_CRITICAL:
                continue
            vulnerability = _string(finding.get("VulnerabilityID"), "Trivy vulnerability id")
            package = _string(finding.get("PkgName"), f"Trivy package for {vulnerability}")
            version = _string(finding.get("InstalledVersion"), f"Trivy installed version for {vulnerability}")
            fixed_version = str(finding.get("FixedVersion") or "").strip()
            fixable = bool(fixed_version) or str(finding.get("Status") or "").lower() == "fixed"
            purl: str | None = None
            identifier = finding.get("PkgIdentifier")
            if isinstance(identifier, dict) and isinstance(identifier.get("PURL"), str):
                purl = identifier["PURL"].strip() or None
            findings.append(Finding(vulnerability, package, version, severity, fixable, fixed_version or None, purl))
    return findings


def _grype_match(raw_match: Any, label: str) -> Finding | None:
    wrapper = _object(raw_match, label)
    match = wrapper.get("match") if isinstance(wrapper.get("match"), dict) else wrapper
    match = _object(match, label)
    vulnerability = _object(match.get("vulnerability"), f"{label}.vulnerability")
    severity = str(vulnerability.get("severity") or "").upper()
    if severity not in HIGH_CRITICAL:
        return None
    vulnerability_id = _string(vulnerability.get("id"), f"{label} vulnerability id")
    artifact = _object(match.get("artifact"), f"{label}.artifact")
    package = _string(artifact.get("name"), f"{label} package")
    version = _string(artifact.get("version"), f"{label} version")
    purl_value = artifact.get("purl")
    purl = purl_value.strip() if isinstance(purl_value, str) and purl_value.strip() else None
    fix = vulnerability.get("fix")
    fix_object = fix if isinstance(fix, dict) else {}
    versions = fix_object.get("versions")
    fixed_versions = [str(value).strip() for value in versions] if isinstance(versions, list) else []
    fixed_version = ", ".join(value for value in fixed_versions if value) or None
    fixable = bool(fixed_version) or str(fix_object.get("state") or "").lower() == "fixed"
    return Finding(vulnerability_id, package, version, severity, fixable, fixed_version, purl)


def _grype_findings(path: Path, key: str = "matches") -> list[Finding]:
    report = _object(_load_json(path, "Grype report"), "Grype report")
    findings: list[Finding] = []
    for index, raw_match in enumerate(_list(report.get(key, []), f"Grype {key}")):
        finding = _grype_match(raw_match, f"Grype {key}[{index}]")
        if finding is not None:
            findings.append(finding)
    return findings


def _trivy_ignore_entries(path: Path) -> dict[str, set[str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise SummaryError(f"missing Trivy ignore policy: {path}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise SummaryError(f"malformed Trivy ignore policy: {path}: {exc}") from exc

    entries: dict[str, set[str]] = {}
    current: str | None = None
    for line in lines:
        id_match = re.match(r"^\s*- id:\s*(\S+)\s*$", line)
        if id_match:
            current = id_match.group(1)
            entries.setdefault(current, set())
            continue
        purl_match = re.match(r"^\s+- (pkg:[^\s#]+)\s*$", line)
        if purl_match and current is not None:
            entries[current].add(purl_match.group(1))
    if not entries or any(not purls for purls in entries.values()):
        raise SummaryError(f"malformed or unscoped Trivy ignore policy: {path}")
    return entries


def _trivy_ignored(finding: Finding, entries: dict[str, set[str]]) -> bool:
    candidates = {
        finding.purl or "",
        f"pkg:rpm/redhat/{finding.package}@{finding.version}",
    }
    return not entries.get(finding.vulnerability, set()).isdisjoint(candidates)


def _vex_statements(vex_dir: Path) -> list[tuple[set[str], set[str], str, bool]]:
    if not vex_dir.is_dir():
        raise SummaryError(f"missing VEX directory: {vex_dir}")
    statements: list[tuple[set[str], set[str], str, bool]] = []
    for path in sorted(vex_dir.glob("*.json")):
        document = _object(_load_json(path, "VEX document"), f"VEX document {path}")
        if "@context" not in document:
            raise SummaryError(f"VEX document missing @context: {path}")
        for index, raw_statement in enumerate(_list(document.get("statements"), f"VEX statements in {path}")):
            statement = _object(raw_statement, f"VEX statement {index} in {path}")
            raw_vulnerability = statement.get("vulnerability")
            vulnerability_ids: set[str] = set()
            if isinstance(raw_vulnerability, str) and raw_vulnerability.strip():
                vulnerability_ids.add(raw_vulnerability.strip())
            elif isinstance(raw_vulnerability, dict):
                for key in ("name", "id", "@id"):
                    value = raw_vulnerability.get(key)
                    if isinstance(value, str) and value.strip():
                        vulnerability_ids.add(value.strip())
                aliases = raw_vulnerability.get("aliases")
                if isinstance(aliases, list):
                    vulnerability_ids.update(str(alias).strip() for alias in aliases if str(alias).strip())
            if not vulnerability_ids:
                raise SummaryError(f"VEX statement {index} in {path} has no vulnerability id")
            products: set[str] = set()
            for product in _list(statement.get("products"), f"VEX products in {path}"):
                if isinstance(product, str) and product.strip():
                    products.add(product.strip())
                elif isinstance(product, dict):
                    for key in ("@id", "id", "name"):
                        value = product.get(key)
                        if isinstance(value, str) and value.strip():
                            products.add(value.strip())
                    identifiers = product.get("identifiers")
                    if isinstance(identifiers, dict):
                        products.update(str(value).strip() for value in identifiers.values() if str(value).strip())
                    elif isinstance(identifiers, list):
                        for identifier in identifiers:
                            if isinstance(identifier, str) and identifier.strip():
                                products.add(identifier.strip())
                            elif isinstance(identifier, dict):
                                products.update(
                                    str(value).strip() for value in identifier.values() if str(value).strip()
                                )
            if not products:
                raise SummaryError(f"VEX statement {index} in {path} has no product identifier")
            status = _string(statement.get("status"), f"VEX status in {path}")
            if status not in OPENVEX_STATUSES:
                raise SummaryError(f"VEX statement {index} in {path} has invalid status {status}")
            justification = str(statement.get("justification") or "").strip()
            if status == "not_affected" and justification not in OPENVEX_NOT_AFFECTED_JUSTIFICATIONS:
                raise SummaryError(f"VEX statement {index} in {path} has invalid not_affected justification")
            justified = bool(justification)
            statements.append((vulnerability_ids, products, status, justified))
    return statements


def _accepted_vex(vulnerability: str, product: str, statements: list[tuple[set[str], set[str], str, bool]]) -> bool:
    candidates = {product, f"pkg:oci/{product}"}
    for vulnerability_ids, products, status, justified in statements:
        if vulnerability not in vulnerability_ids or products.isdisjoint(candidates):
            continue
        if status == "fixed" or (status == "not_affected" and justified):
            return True
    return False


def _count_by_scanner(trivy: list[Finding], grype: list[Finding]) -> dict[str, int]:
    return {
        "trivy": len({finding.vulnerability for finding in trivy}),
        "grype": len({finding.vulnerability for finding in grype}),
        "unique": len({finding.vulnerability for finding in trivy + grype}),
    }


def _actionable_cve_list(findings: list[Finding]) -> list[dict[str, str | bool | None]]:
    selected: dict[str, Finding] = {}
    for finding in sorted(
        findings,
        key=lambda item: (
            item.vulnerability,
            item.severity != "CRITICAL",
            item.package,
            item.fixed_version or "",
        ),
    ):
        selected.setdefault(finding.vulnerability, finding)
    return [
        {
            "id": finding.vulnerability,
            "severity": finding.severity,
            "package": finding.package,
            "fixable": finding.fixable,
            "fixed_version": finding.fixed_version,
        }
        for finding in selected.values()
    ]


def _secret_scan_fields(path: Path) -> dict[str, int | bool]:
    report = _object(_load_json(path, "secret-scan report"), "secret-scan report")
    raw_result = report.get("result")
    if raw_result not in {"passed", "failed"}:
        raise SummaryError("secret-scan result must be passed or failed")
    finding_count = len(_list(report.get("findings"), "secret-scan findings"))
    passed = finding_count == 0
    if (raw_result == "passed") != passed:
        raise SummaryError("secret-scan result disagrees with finding count")
    return {"finding_count": finding_count, "passed": passed}


def _hardening_fields(
    arch: str,
    dist_dir: Path,
    contract_limit: int,
    trivy_ignore: Path,
    vex_dir: Path,
    product: str,
) -> dict[str, Any]:
    trivy_path = dist_dir / f"vuln/base-micro.{arch}.trivy.all.json"
    grype_path = dist_dir / f"vuln/base-micro.{arch}.grype.all.json"
    grype_gate_path = dist_dir / f"vuln/base-micro.{arch}.grype.gate.json"
    trivy = _trivy_findings(trivy_path)
    grype = _grype_findings(grype_path)
    grype_gate_active = _grype_findings(grype_gate_path)
    grype_gate_ignored = _grype_findings(grype_gate_path, "ignoredMatches")
    ignore_entries = _trivy_ignore_entries(trivy_ignore)

    trivy_ignored = [finding for finding in trivy if finding.fixable and _trivy_ignored(finding, ignore_entries)]
    trivy_actionable = [finding for finding in trivy if finding.fixable and not _trivy_ignored(finding, ignore_entries)]
    grype_actionable = [finding for finding in grype_gate_active if finding.fixable]
    grype_ignored = [finding for finding in grype_gate_ignored if finding.fixable]
    ignored_ids = {finding.vulnerability for finding in trivy_ignored + grype_ignored}
    actionable_findings = trivy_actionable + grype_actionable
    actionable_ids = {finding.vulnerability for finding in actionable_findings}

    unfixed = {finding.vulnerability for finding in trivy + grype if not finding.fixable}
    statements = _vex_statements(vex_dir)
    accepted_vex = {vulnerability for vulnerability in unfixed if _accepted_vex(vulnerability, product, statements)}
    missing_vex = unfixed.difference(accepted_vex)

    stig_path = dist_dir / f"stig/{arch}/base-micro.{arch}.stig.summary.json"
    stig = _object(_load_json(stig_path, "STIG summary"), "STIG summary")
    total_rule_results = _integer(stig.get("total_rule_results"), "STIG total_rule_results")
    counts = _object(stig.get("counts"), "STIG counts")
    pass_count = _integer(counts.get("pass", 0), "STIG pass count")
    fail_count = _integer(counts.get("fail", 0), "STIG fail count")
    not_selected = _integer(counts.get("notselected", 0), "STIG not-selected count")
    count_total = sum(_integer(value, f"STIG count {key}") for key, value in counts.items())
    if count_total != total_rule_results:
        raise SummaryError("STIG counts do not sum to total_rule_results")

    secret_path = dist_dir / f"rootfs-secret-scan/base-micro.{arch}.secret-scan.json"
    secrets = _secret_scan_fields(secret_path)

    footprint_path = dist_dir / f"footprint/base-micro.{arch}.json"
    footprint = _object(_load_json(footprint_path, "footprint report"), "footprint report")
    regular_file_bytes = _integer(footprint.get("regular_file_bytes"), "footprint regular_file_bytes")
    limit_bytes = _integer(footprint.get("limit_bytes"), "footprint limit_bytes")
    passed = _boolean(footprint.get("passed"), "footprint passed")
    if limit_bytes != contract_limit:
        raise SummaryError("footprint limit does not match the image contract")
    if passed != (regular_file_bytes <= limit_bytes):
        raise SummaryError("footprint passed flag disagrees with byte counts")

    return {
        "cves": {
            "raw": _count_by_scanner(trivy, grype),
            "ignored": {"unique": len(ignored_ids)},
            "actionable": {
                "unique": len(actionable_ids),
                "findings": _actionable_cve_list(actionable_findings),
            },
        },
        "stig": {
            "total_rule_results": total_rule_results,
            "pass": pass_count,
            "fail": fail_count,
            "not_selected": not_selected,
        },
        "secrets": secrets,
        "footprint": {
            "regular_file_bytes": regular_file_bytes,
            "limit_bytes": limit_bytes,
            "passed": passed,
        },
        "vex": {
            "accepted": len(accepted_vex),
            "missing": len(missing_vex),
        },
    }


def summarize_hardening(
    arch: str,
    dist_dir: Path,
    contract: Path,
    trivy_ignore: Path,
    vex_dir: Path,
    product: str,
) -> dict[str, Any]:
    envelope = _base_envelope("hardening", arch)
    try:
        if arch not in ARCHES:
            raise SummaryError(f"unsupported architecture: {arch}")
        contract_limit, _, _ = _contract_values(contract, arch)
        envelope.update(_hardening_fields(arch, dist_dir, contract_limit, trivy_ignore, vex_dir, product))
        reasons: list[str] = []
        cves = _object(envelope["cves"], "cves")
        actionable = _object(cves["actionable"], "cves.actionable")
        if _integer(actionable["unique"], "actionable CVEs"):
            reasons.append(f"{arch} has actionable HIGH/CRITICAL CVEs")
        stig = _object(envelope["stig"], "stig")
        if _integer(stig["fail"], "STIG failures"):
            reasons.append(f"{arch} has failing STIG results")
        secrets = _object(envelope["secrets"], "secrets")
        if _integer(secrets["finding_count"], "secret findings"):
            reasons.append(f"{arch} has secret-scan findings")
        footprint = _object(envelope["footprint"], "footprint")
        if not _boolean(footprint["passed"], "footprint passed"):
            reasons.append(f"{arch} exceeds the footprint cap")
        vex = _object(envelope["vex"], "vex")
        if _integer(vex["missing"], "missing VEX"):
            reasons.append(f"{arch} has findings missing VEX")
        envelope["complete"] = True
        envelope["attention_reasons"] = reasons
    except (SummaryError, KeyError, TypeError, ValueError):
        envelope["attention_reasons"] = ["hardening evidence is missing or malformed"]
    return envelope


def _repro_fields(report_path: Path, expected_rootfs: str, expected_rpmdb: str) -> dict[str, Any]:
    report = _object(_load_json(report_path, "reproducibility report"), "reproducibility report")
    byte_identical = _boolean(report.get("byte_identical"), "reproducibility byte_identical")
    builds = _list(report.get("builds"), "reproducibility builds")
    if len(builds) != 2:
        raise SummaryError("reproducibility report must contain exactly two builds")
    rootfs_values: list[str] = []
    rpmdb_values: list[str] = []
    for index, raw_build in enumerate(builds):
        build = _object(raw_build, f"reproducibility build {index}")
        rootfs_values.append(_string(build.get("rootfs_digest"), f"build {index} rootfs_digest"))
        rpmdb_values.append(_string(build.get("rpmdb_sha256"), f"build {index} rpmdb_sha256"))
    return {
        "reproducibility": {
            "byte_identical": byte_identical,
            "rootfs_matches_contract": all(value == expected_rootfs for value in rootfs_values),
            "rpmdb_matches_contract": all(value == expected_rpmdb for value in rpmdb_values),
        }
    }


def summarize_repro(arch: str, report: Path, contract: Path) -> dict[str, Any]:
    envelope = _base_envelope("repro", arch)
    try:
        if arch not in ARCHES:
            raise SummaryError(f"unsupported architecture: {arch}")
        _, expected_rootfs, expected_rpmdb = _contract_values(contract, arch)
        envelope.update(_repro_fields(report, expected_rootfs, expected_rpmdb))
        reproducibility = _object(envelope["reproducibility"], "reproducibility")
        reasons: list[str] = []
        if not _boolean(reproducibility["byte_identical"], "byte_identical"):
            reasons.append(f"{arch} builds are not byte-identical")
        if not _boolean(reproducibility["rootfs_matches_contract"], "rootfs_matches_contract"):
            reasons.append(f"{arch} rootfs digest needs rebaseline")
        if not _boolean(reproducibility["rpmdb_matches_contract"], "rpmdb_matches_contract"):
            reasons.append(f"{arch} rpmdb digest needs rebaseline")
        envelope["complete"] = True
        envelope["attention_reasons"] = reasons
    except (SummaryError, KeyError, TypeError, ValueError):
        envelope["attention_reasons"] = ["reproducibility evidence is missing or malformed"]
    return envelope


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", required=True, choices=("hardening", "repro"))
    parser.add_argument("--arch", required=True, choices=sorted(ARCHES))
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--repro-report", type=Path)
    parser.add_argument("--trivy-ignore", type=Path, default=Path("security/cve-ignore.trivyignore.yaml"))
    parser.add_argument("--vex-dir", type=Path, default=Path("vex"))
    parser.add_argument("--product", default="ghcr.io/nwarila/ubi9-base-micro:base-micro")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.kind == "hardening":
        envelope = summarize_hardening(
            args.arch,
            args.dist_dir,
            args.contract,
            args.trivy_ignore,
            args.vex_dir,
            args.product,
        )
    else:
        report = args.repro_report or (args.dist_dir / f"reproducibility/base-micro.{args.arch}.reproducibility.json")
        envelope = summarize_repro(args.arch, report, args.contract)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
