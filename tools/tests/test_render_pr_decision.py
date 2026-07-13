# Purpose: Prove the PR decision headline is SAFE only for complete, clear, all-success inputs.
# Role: test
# Micro-container candidate: gate-adjacent - fixture coverage for pure Markdown rendering.

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/render-pr-decision.py"
HEAD_SHA = "a" * 40


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("render_pr_decision", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RENDERER = _load_tool()


def _hardening(arch: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "kind": "hardening",
        "arch": arch,
        "complete": True,
        "attention_reasons": [],
        "cves": {
            "raw": {"trivy": 1, "grype": 1, "unique": 1},
            "ignored": {"unique": 1},
            "actionable": {"unique": 0},
        },
        "stig": {"total_rule_results": 1532, "pass": 39, "fail": 0, "not_selected": 1491},
        "secrets": {"finding_count": 0, "passed": True},
        "footprint": {"regular_file_bytes": 23841246, "limit_bytes": 26214400, "passed": True},
        "vex": {"accepted": 0, "missing": 0},
    }


def _repro(arch: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
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
def clean_inputs() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    envelopes = [_hardening("amd64"), _hardening("arm64"), _repro("amd64"), _repro("arm64")]
    context = {
        "title": "Post a one-minute decision surface",
        "number": 83,
        "changed_files": "5 files: build.yaml and decision tooling/tests",
        "head_sha": HEAD_SHA,
        "run_url": "https://github.com/NWarila/ubi9-base-micro/actions/runs/123",
    }
    snapshot = {
        "api_error": None,
        "head_sha": HEAD_SHA,
        "required_contexts": ["repo contract", "build and hardening"],
        "contexts": [
            {"context": "repo contract", "conclusion": "success", "source": "check"},
            {"context": "build and hardening", "conclusion": "success", "source": "check"},
        ],
    }
    return envelopes, context, snapshot


def _render(inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]) -> str:
    envelopes, context, snapshot = inputs
    result: str = RENDERER.render_decision(envelopes, context, snapshot)
    return result


def _assert_attention(markdown: str) -> None:
    assert "## ⚠️ NEEDS ATTENTION:" in markdown
    assert "SAFE TO APPROVE" not in markdown


def test_clean_pr_is_safe_and_explicit(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]],
) -> None:
    markdown = _render(clean_inputs)

    assert markdown.startswith("## ✅ SAFE TO APPROVE\n")
    assert "digest-neutral ✓" in markdown
    assert "pass 39 · fail 0 · not-selected 1491 (1532 rule results)" in markdown
    assert "Raw HIGH/CRITICAL CVEs" in markdown
    assert "Current posture" in markdown
    assert markdown.count(RENDERER.MARKER) == 1


def test_actionable_cve_is_attention(clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]) -> None:
    clean_inputs[0][0]["cves"]["actionable"] = {"unique": 1}

    _assert_attention(_render(clean_inputs))


def test_unexplained_envelope_attention_reason_cannot_be_safe(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]],
) -> None:
    clean_inputs[0][0]["attention_reasons"] = ["producer reported an inconsistency"]

    _assert_attention(_render(clean_inputs))


def test_arm64_only_finding_is_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]],
) -> None:
    clean_inputs[0][1]["secrets"] = {"finding_count": 1, "passed": False}

    markdown = _render(clean_inputs)
    _assert_attention(markdown)
    assert "arm64 has 1 secret finding(s)" in markdown


def test_needs_rebaseline_is_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]],
) -> None:
    clean_inputs[0][2]["reproducibility"]["rootfs_matches_contract"] = False

    markdown = _render(clean_inputs)
    _assert_attention(markdown)
    assert "needs rebaseline" in markdown


@pytest.mark.parametrize("case", ["missing", "malformed", "incomplete", "invalid-complete"])
def test_missing_malformed_or_incomplete_envelope_is_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]], case: str
) -> None:
    if case == "missing":
        clean_inputs[0].pop()
    elif case == "malformed":
        clean_inputs[0][3] = {"input_error": "invalid JSON"}
    else:
        if case == "incomplete":
            clean_inputs[0][3]["complete"] = False
            clean_inputs[0][3]["attention_reasons"] = ["missing reproducibility report"]
        else:
            del clean_inputs[0][0]["cves"]["raw"]["trivy"]

    _assert_attention(_render(clean_inputs))


@pytest.mark.parametrize(
    "conclusion",
    [
        "failure",
        "pending",
        "queued",
        "in_progress",
        "skipped",
        "neutral",
        "cancelled",
        "timed_out",
        "action_required",
        "stale",
    ],
)
def test_every_non_success_required_check_is_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]], conclusion: str
) -> None:
    clean_inputs[2]["contexts"][0]["conclusion"] = conclusion

    _assert_attention(_render(clean_inputs))


@pytest.mark.parametrize("case", ["missing", "empty-required", "stale"])
def test_incomplete_check_snapshot_is_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]], case: str
) -> None:
    if case == "missing":
        clean_inputs[2]["contexts"].pop()
    elif case == "empty-required":
        clean_inputs[2]["required_contexts"] = []
    else:
        clean_inputs[2]["head_sha"] = "b" * 40

    _assert_attention(_render(clean_inputs))


def test_duplicate_required_context_runs_all_success_are_safe(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]],
) -> None:
    clean_inputs[2]["contexts"].append(copy.deepcopy(clean_inputs[2]["contexts"][0]))

    markdown = _render(clean_inputs)

    assert markdown.startswith("## ✅ SAFE TO APPROVE\n")
    assert "duplicated" not in markdown


def test_duplicate_required_context_with_failure_is_attention(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]],
) -> None:
    duplicate = copy.deepcopy(clean_inputs[2]["contexts"][0])
    duplicate["conclusion"] = "failure"
    clean_inputs[2]["contexts"].append(duplicate)

    markdown = _render(clean_inputs)

    _assert_attention(markdown)
    assert "repo contract has non-success run(s): failure" in markdown


def test_envelope_attention_text_is_not_rendered(
    clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]],
) -> None:
    raw_secret = "RAW-MATCHED-SECRET-MUST-NOT-ESCAPE"
    clean_inputs[0][0]["complete"] = False
    clean_inputs[0][0]["attention_reasons"] = [raw_secret]

    markdown = _render(clean_inputs)

    _assert_attention(markdown)
    assert raw_secret not in markdown


def test_api_error_is_attention(clean_inputs: tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]) -> None:
    clean_inputs[2].update(
        {
            "api_error": "ruleset query failed",
            "head_sha": HEAD_SHA,
            "required_contexts": [],
            "contexts": [],
        }
    )

    _assert_attention(_render(clean_inputs))
