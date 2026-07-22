# Purpose: Prove nightly drift rendering is clean only for complete, both-arch, all-success evidence.
# Role: test
# Micro-container candidate: gate-adjacent - fixture coverage for pure Markdown rendering.

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/render-drift-issue.py"
SUMMARY_TOOL = ROOT / "tools/summarize-gates.py"
SHA_A = "a" * 64
SHA_B = "b" * 64
DIGEST_MISMATCH_LOG = (
    f"rootfs_digest mismatch for left: expected {SHA_A} from /workspace/contracts/image-manifest.json, actual {SHA_B}"
)
DIGEST_MISMATCH_DETAIL = f"rootfs_digest mismatch for left: expected {SHA_A}, actual {SHA_B}"


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("render_drift_issue", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RENDERER = _load_tool()


def _hardening(arch: str) -> dict[str, Any]:
    return {
        "schema_version": "1.1.0",
        "kind": "hardening",
        "arch": arch,
        "complete": True,
        "attention_reasons": [],
        "cves": {
            "raw": {"trivy": 1, "grype": 1, "unique": 1},
            "ignored": {"unique": 1},
            "actionable": {"unique": 0, "findings": []},
        },
        "stig": {"total_rule_results": 1532, "pass": 39, "fail": 0, "not_selected": 1493},
        "secrets": {"finding_count": 0, "passed": True},
        "footprint": {"regular_file_bytes": 23841246, "limit_bytes": 26214400, "passed": True},
        "vex": {"accepted": 0, "missing": 0},
    }


def _repro(arch: str) -> dict[str, Any]:
    return {
        "schema_version": "1.1.0",
        "kind": "repro",
        "arch": arch,
        "complete": True,
        "attention_reasons": [],
        "reproducibility": {
            "byte_identical": True,
            "rootfs_matches_contract": True,
            "rpmdb_matches_contract": True,
        },
    }


@pytest.fixture
def clean_inputs() -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    envelopes = [_hardening("amd64"), _hardening("arm64"), _repro("amd64"), _repro("arm64")]
    results = {"hardening": "success", "build": "success", "reproducibility-gate": "success"}
    context = {
        "run_url": "https://github.com/NWarila/ubi9-base-micro/actions/runs/123",
        "date": "2026-07-13",
    }
    return envelopes, results, context


def _render(inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]) -> tuple[str, bool]:
    body, attention = RENDERER.render_issue(*inputs)
    return str(body), bool(attention)


def _summarize_failed_repro(tmp_path: Path, failure_log: Path | None) -> dict[str, Any]:
    contract = tmp_path / "image-manifest.json"
    contract.write_text(
        json.dumps(
            {
                "architectures": ["amd64", "arm64"],
                "runtime": {"footprint_limit_bytes": 1000},
                "reproducibility": {
                    "canonical_rootfs_digest": {"amd64": SHA_A, "arm64": SHA_B},
                    "rpmdb_sha256": {"amd64": SHA_B, "arm64": SHA_A},
                },
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "repro-amd64.json"
    command = [
        sys.executable,
        str(SUMMARY_TOOL),
        "--kind",
        "repro",
        "--arch",
        "amd64",
        "--dist-dir",
        str(tmp_path / "dist"),
        "--contract",
        str(contract),
        "--output",
        str(output),
    ]
    if failure_log is not None:
        command.extend(["--failure-log", str(failure_log)])
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert result.returncode == 0
    return cast(dict[str, Any], json.loads(output.read_text(encoding="utf-8")))


def test_clean_is_explicitly_no_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]],
) -> None:
    body, attention = _render(clean_inputs)

    assert attention is False
    assert body.startswith("## ✅ Nightly base-micro sentinel clean\n")
    assert "Actionable fixable HIGH/CRITICAL CVEs: 0" in body
    assert "byte-identical=yes; rootfs-contract=match; RPMDB-contract=match" in body
    assert body.count(RENDERER.MARKER) == 1


def test_actionable_cve_is_named_and_markdown_safe(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]],
) -> None:
    clean_inputs[0][0]["cves"]["actionable"] = {
        "unique": 1,
        "findings": [
            {
                "id": "CVE-2099-9999<script>",
                "severity": "CRITICAL",
                "package": "openssl|[unsafe](url)",
                "fixable": True,
                "fixed_version": "3.0.9`code`",
            }
        ],
    }
    clean_inputs[0][0]["attention_reasons"] = ["amd64 has actionable HIGH/CRITICAL CVEs"]

    body, attention = _render(clean_inputs)

    assert attention is True
    assert r"CVE\-2099\-9999&lt;script&gt;" in body
    assert "openssl\\|\\[unsafe\\]\\(url\\)" in body
    assert "3\\.0\\.9\\`code\\`" in body
    assert "<script>" not in body


def test_arm64_only_finding_is_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]],
) -> None:
    clean_inputs[0][1]["stig"]["fail"] = 1
    clean_inputs[0][1]["attention_reasons"] = ["arm64 has failing STIG results"]

    body, attention = _render(clean_inputs)

    assert attention is True
    assert "arm64 has 1 failing STIG result(s)" in body
    assert "### arm64" in body
    assert "STIG failures: 1" in body


@pytest.mark.parametrize("case", ["missing", "malformed", "duplicate", "incomplete"])
def test_missing_malformed_duplicate_or_incomplete_envelope_is_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]], case: str
) -> None:
    if case == "missing":
        clean_inputs[0].pop()
    elif case == "malformed":
        clean_inputs[0][3] = {"input_error": "invalid JSON"}
    elif case == "duplicate":
        clean_inputs[0].append(copy.deepcopy(clean_inputs[0][3]))
    else:
        clean_inputs[0][3]["complete"] = False
        clean_inputs[0][3]["attention_reasons"] = ["producer detail must not be trusted"]

    body, attention = _render(clean_inputs)

    assert attention is True
    assert "## ⚠️ Action needed" in body


@pytest.mark.parametrize("job", ["hardening", "build", "reproducibility-gate"])
@pytest.mark.parametrize("result", ["failure", "skipped", "cancelled", "timed_out", "unknown"])
def test_every_non_success_gate_result_is_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]], job: str, result: str
) -> None:
    clean_inputs[1][job] = result

    body, attention = _render(clean_inputs)

    assert attention is True
    assert f"result is {result.replace('_', r'\_')}, not success" in body


def test_raw_secret_material_is_never_rendered(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]],
) -> None:
    raw_secret = "RAW-MATCHED-SECRET-MUST-NOT-ESCAPE"
    clean_inputs[0][0]["secrets"] = {
        "finding_count": 1,
        "passed": False,
        "findings": [{"path": "/root/key", "match": raw_secret}],
    }
    clean_inputs[0][0]["attention_reasons"] = [raw_secret]

    body, attention = _render(clean_inputs)

    assert attention is True
    assert "Secret findings: 1 (count only; matched material is never rendered)" in body
    assert raw_secret not in body
    assert "/root/key" not in body


def test_failed_gate_diagnostic_propagates_through_summary_and_render(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]], tmp_path: Path
) -> None:
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(
        f"setup completed\n\x1b[31mreproducibility assertion failed: {DIGEST_MISMATCH_LOG}\x1b[0m\n",
        encoding="utf-8",
    )
    clean_inputs[0][2] = _summarize_failed_repro(tmp_path, failure_log)
    clean_inputs[1]["reproducibility-gate"] = "failure"

    body, attention = _render(clean_inputs)

    assert attention is True
    assert "- Reproducibility evidence: unavailable or malformed" in body
    assert (
        rf"- Reproducibility failure detail: rootfs\_digest mismatch for left: expected {SHA_A}"
        rf", actual {SHA_B}" in body
    )
    assert "\x1b" not in body


@pytest.mark.parametrize(
    ("unsafe_line", "secret"),
    [
        ("ERROR: request failed password=CorrectHorseBattery123", "CorrectHorseBattery123"),
        ("ERROR: request failed token=ghp_SECRET_TOKEN_123", "ghp_SECRET_TOKEN_123"),
        ("ERROR: request failed Authorization: Bearer SECRET_AUTH_456", "SECRET_AUTH_456"),
    ],
)
def test_failed_gate_secret_is_absent_from_envelope_and_rendered_issue(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]],
    tmp_path: Path,
    unsafe_line: str,
    secret: str,
) -> None:
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(f"{unsafe_line}\n", encoding="utf-8")
    clean_inputs[0][2] = _summarize_failed_repro(tmp_path, failure_log)
    clean_inputs[1]["reproducibility-gate"] = "failure"

    serialized = json.dumps(clean_inputs[0][2], sort_keys=True)
    body, attention = _render(clean_inputs)

    assert attention is True
    assert "failure_detail" not in clean_inputs[0][2]
    assert secret not in serialized
    assert secret not in body


def test_digest_source_secret_is_absent_from_envelope_and_rendered_issue(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]], tmp_path: Path
) -> None:
    secret = "CorrectHorseBattery123"
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(
        "reproducibility assertion failed: "
        f"rootfs_digest mismatch for left: expected {SHA_A} "
        f"from Authorization: Bearer {secret}, actual {SHA_B}\n",
        encoding="utf-8",
    )
    clean_inputs[0][2] = _summarize_failed_repro(tmp_path, failure_log)
    clean_inputs[1]["reproducibility-gate"] = "failure"

    serialized = json.dumps(clean_inputs[0][2], sort_keys=True)
    body, attention = _render(clean_inputs)

    assert attention is True
    assert clean_inputs[0][2]["failure_detail"] == DIGEST_MISMATCH_DETAIL
    assert secret not in serialized
    assert secret not in body


@pytest.mark.parametrize("suffix", ["", ".x86_64"])
def test_letter_led_nevra_secret_is_absent_from_envelope_and_rendered_issue(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]],
    tmp_path: Path,
    suffix: str,
) -> None:
    secret = "CorrectHorseBattery123"
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(
        "runtime rootfs openssl-libs NEVRA does not match verified stage: "
        f"openssl-libs-{secret}{suffix} != openssl-libs-1:3.5.5-5.el9_8.x86_64\n",
        encoding="utf-8",
    )
    clean_inputs[0][2] = _summarize_failed_repro(tmp_path, failure_log)
    clean_inputs[1]["reproducibility-gate"] = "failure"

    serialized = json.dumps(clean_inputs[0][2], sort_keys=True)
    body, attention = _render(clean_inputs)

    assert attention is True
    assert "failure_detail" not in clean_inputs[0][2]
    assert secret not in serialized
    assert secret not in body


def test_osc_escape_is_absent_from_envelope_and_rendered_issue(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]], tmp_path: Path
) -> None:
    failure_log = tmp_path / "failed-gate.log"
    failure_log.write_text(
        f"\x1b]0;private build title\x1b\\reproducibility assertion failed: {DIGEST_MISMATCH_LOG}\n",
        encoding="utf-8",
    )
    clean_inputs[0][2] = _summarize_failed_repro(tmp_path, failure_log)
    clean_inputs[1]["reproducibility-gate"] = "failure"

    serialized = json.dumps(clean_inputs[0][2], sort_keys=True)
    body, attention = _render(clean_inputs)

    assert attention is True
    assert clean_inputs[0][2]["failure_detail"] == DIGEST_MISMATCH_DETAIL
    assert "\x1b" not in clean_inputs[0][2]["failure_detail"]
    assert "\x1b" not in serialized
    assert "\x1b" not in body
    assert "private build title" not in serialized
    assert "private build title" not in body


@pytest.mark.parametrize("case", ["absent_argument", "missing_file", "nonmatching"])
def test_absent_or_unusable_failure_log_keeps_honest_fallback(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]], tmp_path: Path, case: str
) -> None:
    failure_log: Path | None = None
    if case != "absent_argument":
        failure_log = tmp_path / "failed-gate.log"
        if case == "nonmatching":
            failure_log.write_text("ordinary gate output only\n", encoding="utf-8")
    clean_inputs[0][2] = _summarize_failed_repro(tmp_path, failure_log)
    clean_inputs[1]["reproducibility-gate"] = "failure"

    body, attention = _render(clean_inputs)

    assert attention is True
    assert "- Reproducibility evidence: unavailable or malformed" in body
    assert "Reproducibility failure detail:" not in body


def test_malformed_failure_detail_is_not_rendered(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]],
) -> None:
    clean_inputs[0][2] = {
        "schema_version": "1.1.0",
        "kind": "repro",
        "arch": "amd64",
        "complete": False,
        "attention_reasons": ["reproducibility evidence is missing or malformed"],
        "failure_detail": ["ERROR: unvalidated detail"],
    }

    body, attention = _render(clean_inputs)

    assert attention is True
    assert "- Reproducibility evidence: unavailable or malformed" in body
    assert "Reproducibility failure detail:" not in body
    assert "unvalidated detail" not in body


def test_cli_writes_body_and_machine_decision(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, str], dict[str, str]], tmp_path: Path
) -> None:
    paths: list[Path] = []
    for index, value in enumerate(clean_inputs[0]):
        path = tmp_path / f"envelope-{index}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        paths.append(path)
    results = tmp_path / "results.json"
    results.write_text(json.dumps(clean_inputs[1]), encoding="utf-8")
    context = tmp_path / "context.json"
    context.write_text(json.dumps(clean_inputs[2]), encoding="utf-8")
    body = tmp_path / "issue.md"
    decision = tmp_path / "decision.json"

    result = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--hardening-amd64",
            str(paths[0]),
            "--hardening-arm64",
            str(paths[1]),
            "--repro-amd64",
            str(paths[2]),
            "--repro-arm64",
            str(paths[3]),
            "--job-results",
            str(results),
            "--run-context",
            str(context),
            "--body-output",
            str(body),
            "--decision-output",
            str(decision),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == "attention=false\n"
    assert json.loads(decision.read_text(encoding="utf-8")) == {"attention": False}
    assert body.read_text(encoding="utf-8").count(RENDERER.MARKER) == 1
