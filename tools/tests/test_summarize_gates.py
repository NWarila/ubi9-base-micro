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
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/summarize-gates.py"
SHA_A = "a" * 64
SHA_B = "b" * 64
OPENSSL_LIBS_NEVRA_MISMATCH = (
    "runtime rootfs openssl-libs NEVRA does not match verified stage: "
    "openssl-libs-1:3.5.5-5.el9_8.x86_64 != openssl-libs-1:3.5.5-4.el9_8.x86_64"
)
PROVIDER_NEVRA_MISMATCH = (
    "runtime rootfs provider NEVRA does not match verified stage: "
    "openssl-fips-provider-so-3.0.7-8.el9.x86_64 != openssl-fips-provider-so-3.0.7-7.el9.x86_64"
)
DIGEST_MISMATCH_LOG = (
    f"rootfs_digest mismatch for left: expected {SHA_A} from /workspace/contracts/image-manifest.json, actual {SHA_B}"
)
DIGEST_MISMATCH_DETAIL = f"rootfs_digest mismatch for left: expected {SHA_A}, actual {SHA_B}"


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


def _run_repro_cli(
    tmp_path: Path,
    *,
    failure_log: Path | None = None,
    complete_report: bool = False,
) -> dict[str, Any]:
    dist = tmp_path / "dist"
    if complete_report:
        _write(
            dist / "reproducibility/base-micro.amd64.reproducibility.json",
            {
                "byte_identical": True,
                "builds": [
                    {"rootfs_digest": SHA_A, "rpmdb_sha256": SHA_B},
                    {"rootfs_digest": SHA_A, "rpmdb_sha256": SHA_B},
                ],
            },
        )
    output = tmp_path / "decision.json"
    command = [
        sys.executable,
        str(TOOL),
        "--kind",
        "repro",
        "--arch",
        "amd64",
        "--dist-dir",
        str(dist),
        "--contract",
        str(_contract(tmp_path)),
        "--output",
        str(output),
    ]
    if failure_log is not None:
        command.extend(["--failure-log", str(failure_log)])
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout == ""
    return cast(dict[str, Any], json.loads(output.read_text(encoding="utf-8")))


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
        "ignored": {"unique": 1},
        "actionable": {"unique": 0, "findings": []},
    }
    assert envelope["vex"] == {"accepted": 1, "missing": 0}
    assert envelope["secrets"] == {"finding_count": 0, "passed": True}
    assert envelope["stig"] == {"total_rule_results": 10, "pass": 3, "fail": 0, "not_selected": 7}


def test_actionable_cve_is_not_hidden_by_raw_or_ignored_counts(hardening_inputs: dict[str, Path]) -> None:
    dist = hardening_inputs["dist"]
    path = dist / "vuln/base-micro.amd64.trivy.all.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    report["Results"][0]["Vulnerabilities"].append(_trivy("CVE-2099-9999", "bad", "1", fixable=True))
    _write(path, report)

    envelope = _summarize(hardening_inputs)

    assert envelope["complete"] is True
    assert envelope["schema_version"] == "1.1.0"
    assert envelope["cves"]["actionable"] == {
        "unique": 1,
        "findings": [
            {
                "id": "CVE-2099-9999",
                "severity": "HIGH",
                "package": "bad",
                "fixable": True,
                "fixed_version": "2",
            }
        ],
    }
    assert envelope["attention_reasons"] == ["amd64 has actionable HIGH/CRITICAL CVEs"]


def test_secret_scan_exports_only_count_and_derived_status(hardening_inputs: dict[str, Path]) -> None:
    raw_secret = "RAW-MATCHED-SECRET-MUST-NOT-ESCAPE"
    raw_path = "/root/private-key.pem"
    path = hardening_inputs["dist"] / "rootfs-secret-scan/base-micro.amd64.secret-scan.json"
    _write(
        path,
        {
            "result": "failed",
            "findings": [{"path": raw_path, "match": raw_secret, "rule": "private-key"}],
        },
    )

    envelope = _summarize(hardening_inputs)
    serialized = json.dumps(envelope, sort_keys=True)

    assert envelope["complete"] is True
    assert envelope["secrets"] == {"finding_count": 1, "passed": False}
    assert envelope["attention_reasons"] == ["amd64 has secret-scan findings"]
    assert raw_secret not in serialized
    assert raw_path not in serialized
    assert "findings" not in envelope["secrets"]


@pytest.mark.parametrize("failure", ["missing", "malformed"])
def test_missing_or_malformed_input_emits_incomplete_envelope(hardening_inputs: dict[str, Path], failure: str) -> None:
    path = hardening_inputs["dist"] / "rootfs-secret-scan/base-micro.amd64.secret-scan.json"
    if failure == "missing":
        path.unlink()
    else:
        path.write_text("{not-json", encoding="utf-8")

    envelope = _summarize(hardening_inputs)

    assert envelope["complete"] is False
    assert envelope["attention_reasons"] == ["hardening evidence is missing or malformed"]


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
    assert result.stdout == ""
    assert json.loads(output.read_text(encoding="utf-8"))["complete"] is False


@pytest.mark.parametrize(
    ("logged", "expected"),
    [
        (
            f"\x1b[31mruntime rootfs build failed: {OPENSSL_LIBS_NEVRA_MISMATCH}\x1b[0m",
            OPENSSL_LIBS_NEVRA_MISMATCH,
        ),
        (f"#17 0.321 runtime rootfs build failed: {PROVIDER_NEVRA_MISMATCH}", PROVIDER_NEVRA_MISMATCH),
        (f"reproducibility assertion failed: {DIGEST_MISMATCH_LOG}", DIGEST_MISMATCH_DETAIL),
    ],
)
def test_failure_log_reconstructs_first_known_safe_diagnostic(tmp_path: Path, logged: str, expected: str) -> None:
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(
        f"ordinary setup output\n{logged}\nreproducibility assertion failed: {DIGEST_MISMATCH_LOG}\n",
        encoding="utf-8",
    )

    envelope = _run_repro_cli(tmp_path, failure_log=failure_log)

    assert envelope["complete"] is False
    assert envelope["failure_detail"] == expected


@pytest.mark.parametrize(
    "candidate",
    [
        "openssl-libs-CorrectHorseBattery123.x86_64",
        "openssl-libs-1:CorrectHorseBattery123-5.el9_8.x86_64",
        "openssl-libs-1:3.5.5-CorrectHorseBattery123.x86_64",
        "openssl-libs-1:3.5.5-5.el9_8.ppc64le",
        f"openssl-libs-{'1' * 11}:3.5.5-5.el9_8.x86_64",
        f"openssl-libs-1:{'1' * 33}-5.el9_8.x86_64",
        f"openssl-libs-1:3.5.5-{'1' * 49}.x86_64",
    ],
)
def test_nevra_reconstruction_rejects_out_of_domain_components(candidate: str) -> None:
    assert SUMMARY._canonical_nevra(candidate, "openssl-libs") is None


def test_failure_log_detail_is_length_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def oversized_detail(_line: str) -> str:
        return "x" * 600

    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text("known diagnostic\n", encoding="utf-8")
    monkeypatch.setattr(SUMMARY, "_reconstruct_failure_detail", oversized_detail)

    detail = cast(str, SUMMARY._failure_detail(failure_log))

    assert detail == "x" * SUMMARY.FAILURE_DETAIL_LIMIT
    assert len(detail) == 500


@pytest.mark.parametrize(
    ("unsafe_line", "secret"),
    [
        ("ERROR: request failed password=CorrectHorseBattery123", "CorrectHorseBattery123"),
        ("ERROR: request failed token=ghp_SECRET_TOKEN_123", "ghp_SECRET_TOKEN_123"),
        ("ERROR: request failed Authorization: Bearer SECRET_AUTH_456", "SECRET_AUTH_456"),
    ],
)
def test_failure_log_never_exports_arbitrary_secret_lines(tmp_path: Path, unsafe_line: str, secret: str) -> None:
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(f"{unsafe_line}\n", encoding="utf-8")

    envelope = _run_repro_cli(tmp_path, failure_log=failure_log)
    serialized = json.dumps(envelope, sort_keys=True)

    assert "failure_detail" not in envelope
    assert secret not in serialized


def test_failure_log_drops_digest_source_before_reconstruction(tmp_path: Path) -> None:
    secret = "CorrectHorseBattery123"
    diagnostic = (
        f"rootfs_digest mismatch for left: expected {SHA_A} from Authorization: Bearer {secret}, actual {SHA_B}"
    )
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(f"reproducibility assertion failed: {diagnostic}\n", encoding="utf-8")

    envelope = _run_repro_cli(tmp_path, failure_log=failure_log)
    serialized = json.dumps(envelope, sort_keys=True)

    assert envelope["failure_detail"] == (f"rootfs_digest mismatch for left: expected {SHA_A}, actual {SHA_B}")
    assert secret not in serialized


@pytest.mark.parametrize("suffix", ["", ".x86_64"])
def test_failure_log_rejects_letter_led_nevra_components(tmp_path: Path, suffix: str) -> None:
    secret = "CorrectHorseBattery123"
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(
        "runtime rootfs openssl-libs NEVRA does not match verified stage: "
        f"openssl-libs-{secret}{suffix} != openssl-libs-1:3.5.5-5.el9_8.x86_64\n",
        encoding="utf-8",
    )

    envelope = _run_repro_cli(tmp_path, failure_log=failure_log)
    serialized = json.dumps(envelope, sort_keys=True)

    assert "failure_detail" not in envelope
    assert secret not in serialized


def test_failure_log_strips_osc_sequences_before_reconstruction(tmp_path: Path) -> None:
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(f"\x1b]0;private build title\x07{OPENSSL_LIBS_NEVRA_MISMATCH}\n", encoding="utf-8")

    envelope = _run_repro_cli(tmp_path, failure_log=failure_log)
    serialized = json.dumps(envelope, sort_keys=True)

    assert envelope["failure_detail"] == OPENSSL_LIBS_NEVRA_MISMATCH
    assert "\x1b" not in envelope["failure_detail"]
    assert "\x1b" not in serialized
    assert "private build title" not in serialized


@pytest.mark.parametrize("case", ["missing", "nonmatching", "unsafe_group"])
def test_unusable_failure_log_does_not_export_detail(tmp_path: Path, case: str) -> None:
    failure_log = tmp_path / "failed-gate.log"
    if case == "nonmatching":
        failure_log.write_text("ordinary gate output only\n", encoding="utf-8")
    elif case == "unsafe_group":
        failure_log.write_text(
            "runtime rootfs openssl-libs NEVRA does not match verified stage: "
            "openssl-libs-password=SECRET.x86_64 != openssl-libs-1:3.5.5-5.el9_8.x86_64\n",
            encoding="utf-8",
        )

    envelope = _run_repro_cli(tmp_path, failure_log=failure_log)

    assert envelope["complete"] is False
    assert "failure_detail" not in envelope


def test_clean_run_without_failure_log_does_not_export_detail(tmp_path: Path) -> None:
    envelope = _run_repro_cli(tmp_path, complete_report=True)

    assert envelope["complete"] is True
    assert envelope["attention_reasons"] == []
    assert "failure_detail" not in envelope


def test_invalid_vex_statement_is_malformed_input(hardening_inputs: dict[str, Path]) -> None:
    path = hardening_inputs["vex"] / "accepted.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["statements"][0]["justification"] = "unsupported"
    _write(path, document)

    envelope = _summarize(hardening_inputs)

    assert envelope["complete"] is False
    assert envelope["attention_reasons"] == ["hardening evidence is missing or malformed"]


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
