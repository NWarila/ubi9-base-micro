# Purpose: Validate byte-exact, mode-stable, and fail-closed FIPS status generation.
# Role: test
# Micro-container candidate: gate-adjacent - pytest coverage for builder-stage FIPS status generation.
# Build-process: no - test-only contract and golden-fixture coverage.

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
WRITER = ROOT / "tools/write-fips-status.py"
CONTRACT = ROOT / "contracts/image-manifest.json"
PROVIDER_NEVRA = "openssl-fips-provider-so-3.0.7-8.el9"
MODULE_VERSION = "3.0.7-395c1a240fbfffd8"


def _command(contract: Path, target_arch: str, output: Path) -> list[str]:
    return [
        sys.executable,
        str(WRITER),
        "--contract",
        str(contract),
        "--target-arch",
        target_arch,
        "--provider-nevra",
        PROVIDER_NEVRA,
        "--module-version",
        MODULE_VERSION,
        "--output",
        str(output),
    ]


def _run(contract: Path, target_arch: str, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(_command(contract, target_arch, output), check=False, capture_output=True, text=True)


def _write_contract(tmp_path: Path, payload: Any) -> Path:
    contract = tmp_path / "image-manifest.json"
    contract.write_text(json.dumps(payload), encoding="utf-8")
    return contract


def _contract_payload() -> dict[str, Any]:
    payload: Any = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


@pytest.mark.parametrize("target_arch", ["amd64", "arm64"])
def test_status_bytes_match_committed_example(tmp_path: Path, target_arch: str) -> None:
    output = tmp_path / target_arch / "etc/nwarila/fips-status.json"
    result = subprocess.run(_command(CONTRACT, target_arch, output), check=True, capture_output=True, text=True)

    assert result.stdout == ""
    assert output.read_bytes() == (ROOT / f"contracts/examples/fips-status.{target_arch}.json").read_bytes()


def test_status_output_modes_follow_explicit_umask(tmp_path: Path) -> None:
    output = tmp_path / "rootfs/etc/nwarila/fips-status.json"
    previous_umask = os.umask(0o022)
    try:
        subprocess.run(_command(CONTRACT, "amd64", output), check=True, capture_output=True, text=True)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(output.stat().st_mode) == 0o644


def test_unknown_target_arch_fails(tmp_path: Path) -> None:
    result = _run(CONTRACT, "s390x", tmp_path / "fips-status.json")

    assert result.returncode != 0
    assert "invalid choice" in result.stderr


def test_provider_nevra_skew_fails(tmp_path: Path) -> None:
    command = _command(CONTRACT, "amd64", tmp_path / "fips-status.json")
    command[command.index(PROVIDER_NEVRA)] = "openssl-fips-provider-so-0.0.0-0.el9"
    result = subprocess.run(command, check=False, capture_output=True, text=True)

    assert result.returncode != 0
    assert "provider NEVRA build pin does not match" in result.stderr


def test_module_version_skew_fails(tmp_path: Path) -> None:
    command = _command(CONTRACT, "amd64", tmp_path / "fips-status.json")
    command[command.index(MODULE_VERSION)] = "0.0.0-invalid"
    result = subprocess.run(command, check=False, capture_output=True, text=True)

    assert result.returncode != 0
    assert "module version build pin does not match" in result.stderr


def test_malformed_fips_object_fails(tmp_path: Path) -> None:
    payload = _contract_payload()
    payload["fips"] = []
    result = _run(_write_contract(tmp_path, payload), "amd64", tmp_path / "fips-status.json")

    assert result.returncode != 0
    assert "contract.fips must be a JSON object" in result.stderr


def test_missing_fips_key_fails(tmp_path: Path) -> None:
    payload = _contract_payload()
    del payload["fips"]["module_version"]
    result = _run(_write_contract(tmp_path, payload), "amd64", tmp_path / "fips-status.json")

    assert result.returncode != 0
    assert "contract.fips keys must be exactly" in result.stderr


def test_missing_architecture_key_fails(tmp_path: Path) -> None:
    payload = _contract_payload()
    del payload["fips"]["architectures"]["amd64"]["disclaimer"]
    result = _run(_write_contract(tmp_path, payload), "amd64", tmp_path / "fips-status.json")

    assert result.returncode != 0
    assert "contract.fips.architectures.amd64 keys must be exactly" in result.stderr


def test_non_utf8_contract_fails_with_clean_diagnostic(tmp_path: Path) -> None:
    contract = tmp_path / "image-manifest.json"
    contract.write_bytes(b"{\xff}\n")

    result = _run(contract, "amd64", tmp_path / "fips-status.json")

    assert result.returncode != 0
    assert "FIPS status write failed:" in result.stderr
    assert "Traceback" not in result.stderr
