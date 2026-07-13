#!/usr/bin/env python3
# Purpose: Render a fail-closed, one-minute PR decision surface from tested JSON inputs.
# Role: reporting
# Micro-container candidate: yes - pure-stdlib, JSON-in/Markdown-out with no API access.

"""Render the sticky pull-request decision comment from envelopes and a check snapshot."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path
from typing import Any

ARCHES = ("amd64", "arm64")
MARKER = "<!-- ubi9-base-micro-pr-decision:v1 -->"
SCHEMA_VERSION = "1.0.0"


class RenderError(Exception):
    """An input is malformed or cannot establish a safe decision."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RenderError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RenderError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RenderError(f"{label} must be a non-empty string")
    return value.strip()


def _integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RenderError(f"{label} must be a non-negative integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise RenderError(f"{label} must be a boolean")
    return value


def _one_line(value: str) -> str:
    return " ".join(value.split())


def _safe_text(value: str) -> str:
    return html.escape(_one_line(value), quote=False).replace("|", "&#124;")


def _check_snapshot(snapshot_value: Any, context: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    try:
        snapshot = _object(snapshot_value, "check snapshot")
        api_error = snapshot.get("api_error")
        if api_error is not None:
            reasons.append(f"check API failure: {_safe_text(_string(api_error, 'check snapshot api_error'))}")
            return reasons
        head_sha = _string(snapshot.get("head_sha"), "check snapshot head_sha")
        context_sha = _string(context.get("head_sha"), "PR context head_sha")
        if re.fullmatch(r"[0-9a-f]{40}", head_sha) is None or re.fullmatch(r"[0-9a-f]{40}", context_sha) is None:
            reasons.append("check snapshot or PR context has a malformed head SHA")
        elif head_sha != context_sha:
            reasons.append("check snapshot is stale for the PR head")
        required_raw = _array(snapshot.get("required_contexts"), "required contexts")
        required = [_string(value, "required context") for value in required_raw]
        if not required:
            reasons.append("required-check set is empty")
            return reasons
        if len(required) != len(set(required)):
            reasons.append("required-check set contains duplicates")
        contexts_by_name: dict[str, list[str]] = {}
        for index, raw_context in enumerate(_array(snapshot.get("contexts"), "check contexts")):
            check = _object(raw_context, f"check context {index}")
            name = _string(check.get("context"), f"check context {index} name")
            conclusion = _string(check.get("conclusion"), f"check context {name} conclusion").lower()
            source = _string(check.get("source"), f"check context {name} source")
            if source not in {"check", "status"}:
                raise RenderError(f"check context {name} has unsupported source {source}")
            contexts_by_name.setdefault(name, []).append(conclusion)
        for required_context in required:
            matches = contexts_by_name.get(required_context, [])
            if not matches:
                reasons.append(f"required check missing: {required_context}")
                continue
            non_success = list(dict.fromkeys(result for result in matches if result != "success"))
            if non_success:
                reasons.append(f"required check {required_context} has non-success run(s): {', '.join(non_success)}")
    except (RenderError, KeyError, TypeError, ValueError) as exc:
        reasons.append(f"malformed check snapshot: {exc}")
    return reasons


def _hardening_view(envelope: dict[str, Any], arch: str) -> tuple[dict[str, int], list[str]]:
    reasons: list[str] = []
    cves = _object(envelope.get("cves"), f"{arch} cves")
    raw = _object(cves.get("raw"), f"{arch} raw CVEs")
    ignored = _object(cves.get("ignored"), f"{arch} ignored CVEs")
    actionable = _object(cves.get("actionable"), f"{arch} actionable CVEs")
    stig = _object(envelope.get("stig"), f"{arch} STIG")
    secrets = _object(envelope.get("secrets"), f"{arch} secrets")
    footprint = _object(envelope.get("footprint"), f"{arch} footprint")
    vex = _object(envelope.get("vex"), f"{arch} VEX")
    raw_trivy = _integer(raw.get("trivy"), f"{arch} raw Trivy CVEs")
    raw_grype = _integer(raw.get("grype"), f"{arch} raw Grype CVEs")
    view = {
        "raw": _integer(raw.get("unique"), f"{arch} raw CVEs"),
        "ignored": _integer(ignored.get("unique"), f"{arch} ignored CVEs"),
        "actionable": _integer(actionable.get("unique"), f"{arch} actionable CVEs"),
        "stig_total": _integer(stig.get("total_rule_results"), f"{arch} STIG total"),
        "stig_pass": _integer(stig.get("pass"), f"{arch} STIG pass"),
        "stig_fail": _integer(stig.get("fail"), f"{arch} STIG fail"),
        "stig_not_selected": _integer(stig.get("not_selected"), f"{arch} STIG not-selected"),
        "secrets": _integer(secrets.get("finding_count"), f"{arch} secret findings"),
        "footprint_bytes": _integer(footprint.get("regular_file_bytes"), f"{arch} footprint bytes"),
        "footprint_limit": _integer(footprint.get("limit_bytes"), f"{arch} footprint limit"),
        "missing_vex": _integer(vex.get("missing"), f"{arch} missing VEX"),
        "accepted_vex": _integer(vex.get("accepted"), f"{arch} accepted VEX"),
    }
    footprint_passed = _boolean(footprint.get("passed"), f"{arch} footprint passed")
    secret_passed = _boolean(secrets.get("passed"), f"{arch} secret scan passed")
    if raw_trivy > view["raw"] or raw_grype > view["raw"]:
        raise RenderError(f"{arch} raw scanner CVE count exceeds the unique count")
    if view["ignored"] > view["raw"] or view["actionable"] > view["raw"]:
        raise RenderError(f"{arch} classified CVE count exceeds the raw unique count")
    if view["accepted_vex"] > view["raw"] or view["missing_vex"] > view["raw"]:
        raise RenderError(f"{arch} VEX count exceeds the raw unique CVE count")
    if view["stig_pass"] + view["stig_fail"] + view["stig_not_selected"] > view["stig_total"]:
        raise RenderError(f"{arch} STIG counts exceed total rule results")
    if secret_passed != (view["secrets"] == 0):
        raise RenderError(f"{arch} secret status disagrees with finding count")
    if footprint_passed != (view["footprint_bytes"] <= view["footprint_limit"]):
        raise RenderError(f"{arch} footprint passed flag disagrees with byte counts")
    if view["actionable"]:
        reasons.append(f"{arch} has {view['actionable']} actionable HIGH/CRITICAL CVE(s)")
    if view["stig_fail"]:
        reasons.append(f"{arch} has {view['stig_fail']} failing STIG result(s)")
    if view["secrets"]:
        reasons.append(f"{arch} has {view['secrets']} secret finding(s)")
    if view["missing_vex"]:
        reasons.append(f"{arch} has {view['missing_vex']} finding(s) missing VEX")
    if not footprint_passed:
        reasons.append(f"{arch} exceeds the footprint cap")
    view["footprint_passed"] = int(footprint_passed)
    return view, reasons


def _repro_view(envelope: dict[str, Any], arch: str) -> tuple[dict[str, bool], list[str]]:
    repro = _object(envelope.get("reproducibility"), f"{arch} reproducibility")
    view = {
        "byte_identical": _boolean(repro.get("byte_identical"), f"{arch} byte_identical"),
        "rootfs_matches_contract": _boolean(repro.get("rootfs_matches_contract"), f"{arch} rootfs_matches_contract"),
        "rpmdb_matches_contract": _boolean(repro.get("rpmdb_matches_contract"), f"{arch} rpmdb_matches_contract"),
    }
    reasons: list[str] = []
    if not view["byte_identical"]:
        reasons.append(f"{arch} builds are not byte-identical")
    if not view["rootfs_matches_contract"]:
        reasons.append(f"{arch} rootfs digest needs rebaseline")
    if not view["rpmdb_matches_contract"]:
        reasons.append(f"{arch} rpmdb digest needs rebaseline")
    return view, reasons


def _envelopes(envelope_values: list[Any]) -> tuple[dict[str, dict[str, int]], dict[str, dict[str, bool]], list[str]]:
    reasons: list[str] = []
    indexed: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for index, value in enumerate(envelope_values):
        try:
            envelope = _object(value, f"envelope {index}")
            if envelope.get("schema_version") != SCHEMA_VERSION:
                raise RenderError(f"envelope {index} has unsupported schema version")
            kind = _string(envelope.get("kind"), f"envelope {index} kind")
            arch = _string(envelope.get("arch"), f"envelope {index} arch")
            indexed.setdefault((kind, arch), []).append(envelope)
        except (RenderError, KeyError, TypeError, ValueError) as exc:
            reasons.append(f"malformed envelope: {exc}")

    hardening_views: dict[str, dict[str, int]] = {}
    repro_views: dict[str, dict[str, bool]] = {}
    for arch in ARCHES:
        for kind in ("hardening", "repro"):
            matches = indexed.get((kind, arch), [])
            if not matches:
                reasons.append(f"missing {kind} envelope for {arch}")
                continue
            if len(matches) > 1:
                reasons.append(f"duplicate {kind} envelope for {arch}")
                continue
            envelope = matches[0]
            try:
                complete = _boolean(envelope.get("complete"), f"{arch} {kind} complete")
                attention = _array(envelope.get("attention_reasons"), f"{arch} {kind} attention_reasons")
                for item in attention:
                    _string(item, f"{arch} {kind} attention reason")
                if not complete:
                    reasons.append(f"incomplete {kind} envelope for {arch}")
                    continue
                if kind == "hardening":
                    hardening_views[arch], actionable_reasons = _hardening_view(envelope, arch)
                else:
                    repro_views[arch], actionable_reasons = _repro_view(envelope, arch)
                reasons.extend(actionable_reasons)
                if attention and not actionable_reasons:
                    reasons.append(f"{arch} {kind} producer reported an inconsistency")
            except (RenderError, KeyError, TypeError, ValueError) as exc:
                reasons.append(f"malformed {kind} envelope for {arch}: {exc}")
    return hardening_views, repro_views, reasons


def _headline(reasons: list[str]) -> str:
    if not reasons:
        return "## ✅ SAFE TO APPROVE"
    unique = list(dict.fromkeys(reasons))
    shown = "; ".join(unique[:3])
    if len(unique) > 3:
        shown += f"; +{len(unique) - 3} more"
    return f"## ⚠️ NEEDS ATTENTION: {shown}"


def _posture_row(arch: str, view: dict[str, int] | None) -> str:
    if view is None:
        return f"| {arch} | unavailable | unavailable | unavailable | unavailable | unavailable |"
    accepted = f"{view['ignored']} CVE · {view['accepted_vex']} VEX"
    stig = (
        f"pass {view['stig_pass']} · fail {view['stig_fail']} · "
        f"not-selected {view['stig_not_selected']} ({view['stig_total']} rule results)"
    )
    return (
        f"| {arch} | {view['raw']} | {accepted} | {view['actionable']} | {stig} | "
        f"{view['secrets']} / {view['missing_vex']} |"
    )


def _footprint_line(views: dict[str, dict[str, int]]) -> str:
    parts: list[str] = []
    for arch in ARCHES:
        view = views.get(arch)
        if view is None:
            parts.append(f"{arch} unavailable ⚠️")
            continue
        mark = "✓" if view["footprint_passed"] else "⚠️"
        parts.append(f"{arch} {view['footprint_bytes']:,} / {view['footprint_limit']:,} bytes {mark}")
    return " · ".join(parts)


def render_decision(envelope_values: list[Any], context_value: Any, snapshot_value: Any) -> str:
    reasons: list[str] = []
    try:
        context = _object(context_value, "PR context")
        title = _safe_text(_string(context.get("title"), "PR title"))
        number = _integer(context.get("number"), "PR number")
        synopsis = _safe_text(_string(context.get("changed_files"), "changed-file synopsis"))
        run_url = _string(context.get("run_url"), "run URL")
        _string(context.get("head_sha"), "PR head SHA")
    except (RenderError, KeyError, TypeError, ValueError) as exc:
        context = context_value if isinstance(context_value, dict) else {}
        title = "unavailable"
        number = 0
        synopsis = "changed files unavailable"
        run_url = "#"
        reasons.append(f"malformed PR context: {exc}")

    reasons.extend(_check_snapshot(snapshot_value, context))
    hardening, repro, envelope_reasons = _envelopes(envelope_values)
    reasons.extend(envelope_reasons)
    repro_green = len(repro) == len(ARCHES) and all(all(view.values()) for view in repro.values())
    repro_line = "digest-neutral ✓" if repro_green else "⚠️ needs rebaseline / complete evidence"

    lines = [
        _headline(reasons),
        "",
        f"**What changed:** #{number} — {title}; {synopsis}",
        "",
        f"**Reproducibility:** {repro_line}",
        "",
        "**Current posture**",
        "",
        "| Arch | Raw HIGH/CRITICAL CVEs | Policy-ignored CVEs / accepted VEX | "
        "Actionable CVEs | STIG | Secrets / missing VEX |",
        "|---|---:|---:|---:|---|---:|",
        _posture_row("amd64", hardening.get("amd64")),
        _posture_row("arm64", hardening.get("arm64")),
        "",
        f"**Footprint:** {_footprint_line(hardening)}",
        "",
        f"[Open full run]({html.escape(run_url, quote=True)})",
        "",
        MARKER,
    ]
    return "\n".join(lines) + "\n"


def _load(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"input_error": f"{label}: {exc}"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hardening-amd64", required=True, type=Path)
    parser.add_argument("--hardening-arm64", required=True, type=Path)
    parser.add_argument("--repro-amd64", required=True, type=Path)
    parser.add_argument("--repro-arm64", required=True, type=Path)
    parser.add_argument("--pr-context", required=True, type=Path)
    parser.add_argument("--check-snapshot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    envelopes = [
        _load(args.hardening_amd64, "amd64 hardening envelope"),
        _load(args.hardening_arm64, "arm64 hardening envelope"),
        _load(args.repro_amd64, "amd64 repro envelope"),
        _load(args.repro_arm64, "arm64 repro envelope"),
    ]
    body = render_decision(
        envelopes,
        _load(args.pr_context, "PR context"),
        _load(args.check_snapshot, "check snapshot"),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(body, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
