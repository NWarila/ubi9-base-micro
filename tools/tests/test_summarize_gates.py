# Purpose: Prove hardening/repro decision envelopes remain fail-closed and secret-safe.
# Role: test
# Micro-container candidate: gate-adjacent - fixture coverage for pure decision reporting.

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

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


def _hardening_inputs(tmp_path: Path) -> tuple[Path, Path]:
    dist = tmp_path / "dist"
    _write(
        dist / "stig/amd64/base-micro.amd64.stig.summary.json",
        {
            "total_rule_results": 10,
            "counts": {"pass": 3, "fail": 0, "notselected": 7},
        },
    )
    _write(
        dist / "rootfs-secret-scan/base-micro.amd64.secret-scan.json",
        {"result": "passed", "findings": []},
    )
    _write(
        dist / "footprint/base-micro.amd64.json",
        {"regular_file_bytes": 900, "limit_bytes": 1000, "passed": True},
    )
    return dist, _contract(tmp_path)


def test_clean_hardening_uses_independent_gate_evidence(tmp_path: Path) -> None:
    dist, contract = _hardening_inputs(tmp_path)

    envelope = SUMMARY.summarize_hardening("amd64", dist, contract)

    assert envelope == {
        "schema_version": "1.1.0",
        "kind": "hardening",
        "arch": "amd64",
        "complete": True,
        "attention_reasons": [],
        "stig": {"total_rule_results": 10, "pass": 3, "fail": 0, "not_selected": 7},
        "secrets": {"finding_count": 0, "passed": True},
        "footprint": {"regular_file_bytes": 900, "limit_bytes": 1000, "passed": True},
    }


def test_secret_scan_exports_only_count_and_derived_status(tmp_path: Path) -> None:
    dist, contract = _hardening_inputs(tmp_path)
    raw_secret = "RAW-MATCHED-SECRET-MUST-NOT-ESCAPE"
    _write(
        dist / "rootfs-secret-scan/base-micro.amd64.secret-scan.json",
        {"result": "failed", "findings": [{"path": "/root/private-key.pem", "match": raw_secret}]},
    )

    envelope = SUMMARY.summarize_hardening("amd64", dist, contract)
    serialized = json.dumps(envelope, sort_keys=True)

    assert envelope["complete"] is True
    assert envelope["secrets"] == {"finding_count": 1, "passed": False}
    assert envelope["attention_reasons"] == ["amd64 has secret-scan findings"]
    assert raw_secret not in serialized


@pytest.mark.parametrize("failure", ["missing", "malformed"])
def test_missing_or_malformed_hardening_evidence_is_incomplete(tmp_path: Path, failure: str) -> None:
    dist, contract = _hardening_inputs(tmp_path)
    path = dist / "rootfs-secret-scan/base-micro.amd64.secret-scan.json"
    if failure == "missing":
        path.unlink()
    else:
        path.write_text("{not-json", encoding="utf-8")

    envelope = SUMMARY.summarize_hardening("amd64", dist, contract)

    assert envelope["complete"] is False
    assert envelope["attention_reasons"] == ["hardening evidence is missing or malformed"]


def test_repro_matches_each_build_against_contract(tmp_path: Path) -> None:
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

    envelope = SUMMARY.summarize_repro("amd64", report, _contract(tmp_path))

    assert envelope["complete"] is True
    assert envelope["attention_reasons"] == []
    assert all(envelope["reproducibility"].values())


def test_repro_mismatch_requires_rebaseline(tmp_path: Path) -> None:
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

    envelope = SUMMARY.summarize_repro("amd64", report, _contract(tmp_path))

    assert envelope["complete"] is True
    assert envelope["reproducibility"]["rootfs_matches_contract"] is False
    assert envelope["attention_reasons"] == ["amd64 rootfs digest needs rebaseline"]


def test_failure_log_exports_only_a_reconstructed_known_diagnostic(tmp_path: Path) -> None:
    expected = (
        "runtime rootfs openssl-libs NEVRA does not match verified stage: "
        "openssl-libs-1:3.5.5-5.el9_8.x86_64 != openssl-libs-1:3.5.5-4.el9_8.x86_64"
    )
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(f"ordinary output\n\x1b[31m{expected}\x1b[0m\n", encoding="utf-8")

    assert SUMMARY._failure_detail(failure_log) == expected


def test_failure_log_does_not_export_arbitrary_secret_lines(tmp_path: Path) -> None:
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text("ERROR token=ghp_SECRET_TOKEN_123\n", encoding="utf-8")

    assert SUMMARY._failure_detail(failure_log) is None


def test_cli_writes_incomplete_envelope_without_failing(tmp_path: Path) -> None:
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
            str(tmp_path / "dist"),
            "--contract",
            str(_contract(tmp_path)),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert cast(dict[str, Any], json.loads(output.read_text(encoding="utf-8")))["complete"] is False
