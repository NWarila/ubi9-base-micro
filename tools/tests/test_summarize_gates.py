# Purpose: Prove decision envelopes distinguish raw, accepted, actionable, incomplete, and repro states.
# Role: test
# Micro-container candidate: gate-adjacent - fixture coverage for pure decision reporting.

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/summarize-gates.py"
SHA_A = "a" * 64
SHA_B = "b" * 64


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("summarize_gates", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUMMARY = _load_tool()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _contract(tmp_path: Path) -> Path:
    path = tmp_path / "image-manifest.json"
    _write(
        path,
        {
            "architectures": ["amd64", "arm64"],
            "runtime": {"footprint_limit_bytes": 1000},
            "reproducibility": {
                "canonical_rootfs_digest": {"amd64": SHA_A, "arm64": SHA_B},
                "rpmdb_sha256": {"amd64": SHA_B, "arm64": SHA_A},
            },
        },
    )
    return path


def _trivy(vulnerability: str, package: str, version: str, *, fixable: bool) -> dict[str, Any]:
    return {
        "VulnerabilityID": vulnerability,
        "PkgName": package,
        "InstalledVersion": version,
        "FixedVersion": "2" if fixable else "",
        "Severity": "HIGH",
        "PkgIdentifier": {"PURL": f"pkg:rpm/redhat/{package}@{version}"},
    }


def _grype(vulnerability: str, package: str, version: str, *, fixable: bool) -> dict[str, Any]:
    return {
        "vulnerability": {
            "id": vulnerability,
            "severity": "High",
            "fix": {"state": "fixed" if fixable else "not-fixed", "versions": ["2"] if fixable else []},
        },
        "artifact": {
            "name": package,
            "version": version,
            "purl": f"pkg:rpm/redhat/{package}@{version}",
        },
    }


@pytest.fixture
def hardening_inputs(tmp_path: Path) -> dict[str, Path]:
    arch = "amd64"
    dist = tmp_path / "dist"
    td6 = _trivy("CVE-2026-31790", "openssl-fips-provider", "3.0.7-8.el9", fixable=True)
    vexed = _trivy("CVE-2099-0001", "example", "1", fixable=False)
    _write(dist / f"vuln/base-micro.{arch}.trivy.all.json", {"Results": [{"Vulnerabilities": [td6, vexed]}]})
    _write(
        dist / f"vuln/base-micro.{arch}.grype.all.json",
        {"matches": [_grype("CVE-2026-31790", "openssl-fips-provider", "3.0.7-8.el9", fixable=True)]},
    )
    _write(
        dist / f"vuln/base-micro.{arch}.grype.gate.json",
        {
            "matches": [],
            "ignoredMatches": [
                {
                    **_grype("CVE-2026-31790", "openssl-fips-provider", "3.0.7-8.el9", fixable=True),
                    "appliedIgnoreRules": [{"vulnerability": "CVE-2026-31790"}],
                }
            ],
        },
    )
    _write(
        dist / f"stig/{arch}/base-micro.{arch}.stig.summary.json",
        {"total_rule_results": 10, "counts": {"pass": 3, "fail": 0, "notselected": 7}},
    )
    _write(
        dist / f"rootfs-secret-scan/base-micro.{arch}.secret-scan.json",
        {"result": "passed", "findings": []},
    )
    _write(
        dist / f"footprint/base-micro.{arch}.json",
        {"regular_file_bytes": 900, "limit_bytes": 1000, "passed": True},
    )
    ignore = tmp_path / "cve-ignore.trivyignore.yaml"
    ignore.write_text(
        "vulnerabilities:\n"
        "  - id: CVE-2026-31790\n"
        "    purls:\n"
        "      - pkg:rpm/redhat/openssl-fips-provider@3.0.7-8.el9\n",
        encoding="utf-8",
    )
    vex = tmp_path / "vex"
    _write(
        vex / "accepted.json",
        {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2099-0001"},
                    "products": [{"@id": "example.invalid/base-micro"}],
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_present",
                }
            ],
        },
    )
    return {"dist": dist, "contract": _contract(tmp_path), "ignore": ignore, "vex": vex}


def _summarize(inputs: dict[str, Path]) -> dict[str, Any]:
    result: dict[str, Any] = SUMMARY.summarize_hardening(
        "amd64",
        inputs["dist"],
        inputs["contract"],
        inputs["ignore"],
        inputs["vex"],
        "example.invalid/base-micro",
    )
    return result


def test_clean_hardening_separates_raw_accepted_and_actionable(hardening_inputs: dict[str, Path]) -> None:
    envelope = _summarize(hardening_inputs)

    assert envelope["complete"] is True
    assert envelope["attention_reasons"] == []
    assert envelope["cves"] == {
        "raw": {"trivy": 2, "grype": 1, "unique": 2},
        "ignored": {"unique": 1, "ids": ["CVE-2026-31790"]},
        "actionable": {"unique": 0, "ids": []},
    }
    assert envelope["vex"] == {
        "accepted": 1,
        "accepted_ids": ["CVE-2099-0001"],
        "missing": 0,
        "missing_ids": [],
    }
    assert envelope["stig"] == {"total_rule_results": 10, "pass": 3, "fail": 0, "not_selected": 7}


def test_actionable_cve_is_not_hidden_by_raw_or_ignored_counts(hardening_inputs: dict[str, Path]) -> None:
    dist = hardening_inputs["dist"]
    path = dist / "vuln/base-micro.amd64.trivy.all.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    report["Results"][0]["Vulnerabilities"].append(_trivy("CVE-2099-9999", "bad", "1", fixable=True))
    _write(path, report)

    envelope = _summarize(hardening_inputs)

    assert envelope["complete"] is True
    assert envelope["cves"]["actionable"] == {"unique": 1, "ids": ["CVE-2099-9999"]}
    assert envelope["attention_reasons"] == ["amd64 has actionable HIGH/CRITICAL CVEs"]


@pytest.mark.parametrize("failure", ["missing", "malformed"])
def test_missing_or_malformed_input_emits_incomplete_envelope(
    hardening_inputs: dict[str, Path], failure: str
) -> None:
    path = hardening_inputs["dist"] / "rootfs-secret-scan/base-micro.amd64.secret-scan.json"
    if failure == "missing":
        path.unlink()
    else:
        path.write_text("{not-json", encoding="utf-8")

    envelope = _summarize(hardening_inputs)

    assert envelope["complete"] is False
    assert envelope["attention_reasons"]
    assert "secret-scan report" in envelope["attention_reasons"][0]


def test_cli_exits_zero_when_input_is_incomplete(hardening_inputs: dict[str, Path], tmp_path: Path) -> None:
    (hardening_inputs["dist"] / "vuln/base-micro.amd64.grype.all.json").unlink()
    output = tmp_path / "decision.json"
    result = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--kind",
            "hardening",
            "--arch",
            "amd64",
            "--dist-dir",
            str(hardening_inputs["dist"]),
            "--contract",
            str(hardening_inputs["contract"]),
            "--trivy-ignore",
            str(hardening_inputs["ignore"]),
            "--vex-dir",
            str(hardening_inputs["vex"]),
            "--product",
            "example.invalid/base-micro",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert json.loads(output.read_text(encoding="utf-8"))["complete"] is False


def test_invalid_vex_statement_is_malformed_input(hardening_inputs: dict[str, Path]) -> None:
    path = hardening_inputs["vex"] / "accepted.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["statements"][0]["justification"] = "unsupported"
    _write(path, document)

    envelope = _summarize(hardening_inputs)

    assert envelope["complete"] is False
    assert "invalid not_affected justification" in envelope["attention_reasons"][0]


def test_repro_matches_each_build_against_contract(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    report = tmp_path / "repro.json"
    _write(
        report,
        {
            "byte_identical": True,
            "builds": [
                {"rootfs_digest": SHA_A, "rpmdb_sha256": SHA_B},
                {"rootfs_digest": SHA_A, "rpmdb_sha256": SHA_B},
            ],
        },
    )

    envelope = SUMMARY.summarize_repro("amd64", report, contract)

    assert envelope["complete"] is True
    assert envelope["attention_reasons"] == []
    assert envelope["reproducibility"] == {
        "byte_identical": True,
        "rootfs_matches_contract": True,
        "rpmdb_matches_contract": True,
    }


def test_repro_mismatch_requires_rebaseline(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    report = tmp_path / "repro.json"
    _write(
        report,
        {
            "byte_identical": True,
            "builds": [
                {"rootfs_digest": SHA_A, "rpmdb_sha256": SHA_B},
                {"rootfs_digest": "c" * 64, "rpmdb_sha256": SHA_B},
            ],
        },
    )

    envelope = SUMMARY.summarize_repro("amd64", report, contract)

    assert envelope["complete"] is True
    assert envelope["reproducibility"]["rootfs_matches_contract"] is False
    assert envelope["attention_reasons"] == ["amd64 rootfs digest needs rebaseline"]
