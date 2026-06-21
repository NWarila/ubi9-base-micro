#!/usr/bin/env python3
"""Default-deny OpenVEX gate for unfixed HIGH/CRITICAL findings."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HIGH_CRITICAL = {"HIGH", "CRITICAL"}
SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ACCEPTED_STATUSES = {"fixed", "not_affected"}
OPENVEX_STATUSES = {"affected", "fixed", "not_affected", "under_investigation"}
OPENVEX_NOT_AFFECTED_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


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


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise VexError(f"missing JSON input: {path}") from exc
    except json.JSONDecodeError as exc:
        raise VexError(f"invalid JSON in {path}: {exc}") from exc


def severity(value: Any) -> str:
    return str(value or "UNKNOWN").upper()


def package_name(value: dict[str, Any]) -> str:
    for key in ("PkgName", "name", "package"):
        candidate = value.get(key)
        if candidate:
            return str(candidate)
    return "unknown-package"


def trivy_has_fix(vulnerability: dict[str, Any]) -> bool:
    fixed_version = str(vulnerability.get("FixedVersion") or "").strip()
    if fixed_version:
        return True
    return str(vulnerability.get("Status") or "").strip().lower() == "fixed"


def parse_trivy(path: Path) -> list[Finding]:
    data = load_json(path)
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            sev = severity(vulnerability.get("Severity"))
            vuln_id = str(vulnerability.get("VulnerabilityID") or "").strip()
            if not vuln_id or sev not in HIGH_CRITICAL or trivy_has_fix(vulnerability):
                continue
            findings.append(
                Finding(
                    vulnerability=vuln_id,
                    severity=sev,
                    scanners={"trivy"},
                    packages={package_name(vulnerability)},
                )
            )
    return findings


def grype_has_fix(match: dict[str, Any]) -> bool:
    vulnerability = match.get("vulnerability") or {}
    fix = vulnerability.get("fix") or {}
    versions = fix.get("versions") or []
    if versions:
        return True
    return str(fix.get("state") or "").strip().lower() == "fixed"


def parse_grype(path: Path) -> list[Finding]:
    data = load_json(path)
    findings: list[Finding] = []
    for match in data.get("matches") or []:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        sev = severity(vulnerability.get("severity"))
        vuln_id = str(vulnerability.get("id") or "").strip()
        if not vuln_id or sev not in HIGH_CRITICAL or grype_has_fix(match):
            continue
        findings.append(
            Finding(
                vulnerability=vuln_id,
                severity=sev,
                scanners={"grype"},
                packages={str(artifact.get("name") or "unknown-package")},
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


def assert_vex(product: str, trivy_json: Path, grype_json: Path, vex_dir: Path, emit: bool = True) -> int:
    findings = union_findings(parse_trivy(trivy_json) + parse_grype(grype_json))
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
        trivy_json = tmp / "trivy.json"
        grype_json = tmp / "grype.json"
        vex_dir = tmp / "vex"
        vex_dir.mkdir()

        write_json(
            trivy_json,
            {
                "Results": [
                    {
                        "Target": product,
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2099-0001",
                                "PkgName": "openssl-libs",
                                "InstalledVersion": "0",
                                "Severity": "CRITICAL",
                            }
                        ],
                    }
                ]
            },
        )
        write_json(grype_json, {"matches": []})

        if assert_vex(product, trivy_json, grype_json, vex_dir, emit=False) == 0:
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

        if assert_vex(product, trivy_json, grype_json, vex_dir, emit=False) != 0:
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
    parser.add_argument("--vex-dir", type=Path, default=Path("vex"), help="directory containing OpenVEX JSON")
    parser.add_argument("--self-test", action="store_true", help="prove default-deny behavior with synthetic data")
    args = parser.parse_args(argv)

    if args.self_test:
        return args
    missing = [name for name in ("product", "trivy_json", "grype_json") if getattr(args, name) is None]
    if missing:
        parser.error("missing required argument(s): " + ", ".join("--" + item.replace("_", "-") for item in missing))
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            return self_test()
        return assert_vex(args.product, args.trivy_json, args.grype_json, args.vex_dir)
    except VexError as exc:
        print(f"assert-vex failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
