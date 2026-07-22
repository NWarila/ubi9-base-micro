#!/usr/bin/env python3
# Purpose: Render a fail-closed nightly drift issue from gate envelopes and explicit job results.
# Role: reporting
# Micro-container candidate: yes - pure-stdlib, JSON-in/Markdown-out with no API access.

"""Render the sticky nightly drift issue and a machine-readable attention decision."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from pathlib import Path
from typing import Any

ARCHES = ("amd64", "arm64")
EXPECTED_KEYS = tuple((kind, arch) for kind in ("hardening", "repro") for arch in ARCHES)
MARKER = "<!-- ubi9-base-micro-nightly-drift:v1 -->"
SCHEMA_VERSION = "1.1.0"
SIGNATURE_VERSION = "v1"
FAILURE_DETAIL_LIMIT = 500
JOB_RESULTS = {
    "hardening": "hardening matrix",
    "build": "build and hardening aggregate",
    "reproducibility-gate": "reproducibility gate",
}


class RenderError(Exception):
    """An input cannot establish a clean nightly result."""


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


def _safe_text(value: str) -> str:
    one_line = " ".join(value.split())
    escaped = html.escape(one_line, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", escaped)


def _job_result_view(value: Any) -> tuple[dict[str, str], list[str]]:
    try:
        results = _object(value, "job results")
    except RenderError:
        return (dict.fromkeys(JOB_RESULTS, "missing_or_malformed"), ["nightly job-results input is malformed"])

    view: dict[str, str] = {}
    reasons: list[str] = []
    for key, label in JOB_RESULTS.items():
        result = results.get(key)
        if not isinstance(result, str) or not result.strip():
            view[key] = "missing_or_malformed"
            reasons.append(f"{label} result is missing or malformed")
            continue
        normalized = result.strip().lower()
        view[key] = normalized
        if normalized != "success":
            reasons.append(f"{label} result is {_safe_text(normalized)}, not success")
    return view, reasons


def _context(value: Any) -> tuple[str, str, bool, list[str]]:
    reasons: list[str] = []
    run_url = ""
    date = "unknown date"
    try:
        context = _object(value, "run context")
        run_url = _string(context.get("run_url"), "run URL")
        if re.fullmatch(r"https://[^\s]+", run_url) is None:
            raise RenderError("run URL must use https")
        date = _string(context.get("date"), "run date")
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) is None:
            raise RenderError("run date must be YYYY-MM-DD")
    except RenderError:
        reasons.append("nightly run context is missing or malformed")
    return run_url, date, not reasons, reasons


def _actionable_cves(value: Any, arch: str) -> tuple[list[dict[str, str | bool | None]], list[str]]:
    actionable = _object(value, f"{arch} actionable CVEs")
    count = _integer(actionable.get("unique"), f"{arch} actionable CVE count")
    findings: list[dict[str, str | bool | None]] = []
    seen_ids: set[str] = set()
    for index, raw_finding in enumerate(_array(actionable.get("findings"), f"{arch} actionable CVE findings")):
        finding = _object(raw_finding, f"{arch} actionable CVE {index}")
        vulnerability = _string(finding.get("id"), f"{arch} actionable CVE id")
        severity = _string(finding.get("severity"), f"{arch} actionable CVE severity").upper()
        if severity not in {"HIGH", "CRITICAL"}:
            raise RenderError(f"{arch} actionable CVE severity is unsupported")
        package = _string(finding.get("package"), f"{arch} actionable CVE package")
        fixable = _boolean(finding.get("fixable"), f"{arch} actionable CVE fixable")
        if not fixable:
            raise RenderError(f"{arch} actionable CVE is not fixable")
        raw_fixed_version = finding.get("fixed_version")
        fixed_version = None if raw_fixed_version is None else _string(raw_fixed_version, "fixed version")
        if vulnerability in seen_ids:
            raise RenderError(f"{arch} actionable CVE list contains duplicate ids")
        seen_ids.add(vulnerability)
        findings.append(
            {
                "id": vulnerability,
                "severity": severity,
                "package": package,
                "fixable": fixable,
                "fixed_version": fixed_version,
            }
        )
    if count != len(findings):
        raise RenderError(f"{arch} actionable CVE count disagrees with its sanitized list")
    findings.sort(
        key=lambda finding: (
            str(finding["id"]),
            str(finding["severity"]),
            str(finding["package"]),
            str(finding["fixed_version"]),
        )
    )
    reasons = [f"{arch} has {count} actionable HIGH/CRITICAL CVE(s)"] if count else []
    return findings, reasons


def _hardening_view(envelope: dict[str, Any], arch: str) -> tuple[dict[str, Any], list[str]]:
    cves = _object(envelope.get("cves"), f"{arch} CVEs")
    findings, reasons = _actionable_cves(cves.get("actionable"), arch)
    stig = _object(envelope.get("stig"), f"{arch} STIG")
    stig_fail = _integer(stig.get("fail"), f"{arch} STIG failures")
    secrets = _object(envelope.get("secrets"), f"{arch} secrets")
    secret_count = _integer(secrets.get("finding_count"), f"{arch} secret findings")
    secret_passed = _boolean(secrets.get("passed"), f"{arch} secret status")
    if secret_passed != (secret_count == 0):
        raise RenderError(f"{arch} secret status disagrees with its count")
    footprint = _object(envelope.get("footprint"), f"{arch} footprint")
    footprint_passed = _boolean(footprint.get("passed"), f"{arch} footprint status")
    vex = _object(envelope.get("vex"), f"{arch} VEX")
    missing_vex = _integer(vex.get("missing"), f"{arch} missing VEX")

    if stig_fail:
        reasons.append(f"{arch} has {stig_fail} failing STIG result(s)")
    if secret_count:
        reasons.append(f"{arch} has {secret_count} secret finding(s)")
    if missing_vex:
        reasons.append(f"{arch} has {missing_vex} finding(s) missing VEX")
    if not footprint_passed:
        reasons.append(f"{arch} exceeds the footprint cap")
    return {
        "cves": findings,
        "stig_fail": stig_fail,
        "secret_count": secret_count,
        "footprint_passed": footprint_passed,
        "missing_vex": missing_vex,
    }, reasons


def _repro_view(envelope: dict[str, Any], arch: str) -> tuple[dict[str, bool], list[str]]:
    repro = _object(envelope.get("reproducibility"), f"{arch} reproducibility")
    view = {
        "byte_identical": _boolean(repro.get("byte_identical"), f"{arch} byte identity"),
        "rootfs_matches_contract": _boolean(repro.get("rootfs_matches_contract"), f"{arch} rootfs contract"),
        "rpmdb_matches_contract": _boolean(repro.get("rpmdb_matches_contract"), f"{arch} RPMDB contract"),
    }
    reasons: list[str] = []
    if not view["byte_identical"]:
        reasons.append(f"{arch} builds are not byte-identical")
    if not view["rootfs_matches_contract"]:
        reasons.append(f"{arch} rootfs digest drifted from the contract")
    if not view["rpmdb_matches_contract"]:
        reasons.append(f"{arch} RPMDB digest drifted from the contract")
    return view, reasons


def _envelopes(
    values: list[Any],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, bool]],
    dict[tuple[str, str], str],
    dict[str, Any],
    list[str],
]:
    indexed: dict[tuple[str, str], list[dict[str, Any]]] = {}
    malformed_keys: set[tuple[str, str]] = set()
    unassigned_malformed = 0
    reasons: list[str] = []
    for index, value in enumerate(values):
        claimed_key: tuple[str, str] | None = None
        if isinstance(value, dict):
            raw_kind = value.get("kind")
            raw_arch = value.get("arch")
            if isinstance(raw_kind, str) and isinstance(raw_arch, str):
                candidate = (raw_kind.strip(), raw_arch.strip())
                if candidate in EXPECTED_KEYS:
                    claimed_key = candidate
        try:
            envelope = _object(value, f"envelope {index}")
            if envelope.get("schema_version") != SCHEMA_VERSION:
                raise RenderError("unsupported envelope schema")
            kind = _string(envelope.get("kind"), f"envelope {index} kind")
            arch = _string(envelope.get("arch"), f"envelope {index} arch")
            if (kind, arch) not in EXPECTED_KEYS:
                raise RenderError("unexpected envelope kind or architecture")
            indexed.setdefault((kind, arch), []).append(envelope)
        except RenderError:
            reasons.append(f"envelope {index} is malformed")
            if claimed_key is None:
                unassigned_malformed += 1
            else:
                malformed_keys.add(claimed_key)

    hardening: dict[str, dict[str, Any]] = {}
    repro: dict[str, dict[str, bool]] = {}
    failure_details: dict[tuple[str, str], str] = {}
    projection: dict[str, Any] = {
        "arches": {
            arch: {
                kind: {
                    "failure_detail": None,
                    "producer_reported_attention": False,
                    "state": "missing",
                    "view": None,
                }
                for kind in ("hardening", "repro")
            }
            for arch in ARCHES
        },
        "unassigned_malformed_envelopes": unassigned_malformed,
    }
    for kind, arch in EXPECTED_KEYS:
        incident = projection["arches"][arch][kind]
        matches = indexed.get((kind, arch), [])
        if len(matches) != 1:
            state = "missing" if not matches else "duplicated"
            if (kind, arch) in malformed_keys:
                state = "malformed" if not matches else "duplicated_or_malformed"
            incident["state"] = state
            reasons.append(f"{arch} {kind} envelope is {state}")
            continue
        envelope = matches[0]
        try:
            raw_failure_detail = envelope.get("failure_detail")
            if raw_failure_detail is not None:
                failure_detail = _string(raw_failure_detail, f"{arch} {kind} failure detail")
                if len(failure_detail) > FAILURE_DETAIL_LIMIT:
                    raise RenderError(f"{arch} {kind} failure detail exceeds the length limit")
                failure_details[(kind, arch)] = failure_detail
                incident["failure_detail"] = failure_detail
            if not _boolean(envelope.get("complete"), f"{arch} {kind} complete"):
                incident["state"] = "incomplete"
                reasons.append(f"{arch} {kind} envelope is incomplete")
                continue
            producer_reasons = _array(envelope.get("attention_reasons"), f"{arch} {kind} attention reasons")
            if any(not isinstance(reason, str) for reason in producer_reasons):
                raise RenderError("producer attention reasons are malformed")
            incident["producer_reported_attention"] = bool(producer_reasons)
            if producer_reasons:
                reasons.append(f"{arch} {kind} producer reported attention")
            if kind == "hardening":
                view, view_reasons = _hardening_view(envelope, arch)
                hardening[arch] = view
            else:
                repro_view, view_reasons = _repro_view(envelope, arch)
                repro[arch] = repro_view
                view = repro_view
            incident["state"] = "complete" if (kind, arch) not in malformed_keys else "malformed_or_duplicated"
            incident["view"] = view
            reasons.extend(view_reasons)
        except RenderError:
            incident["state"] = "malformed"
            reasons.append(f"{arch} {kind} envelope content is malformed")
    return hardening, repro, failure_details, projection, list(dict.fromkeys(reasons))


def _signature(projection: dict[str, Any]) -> str:
    canonical = json.dumps(projection, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _arch_section(
    arch: str,
    hardening: dict[str, dict[str, Any]],
    repro: dict[str, dict[str, bool]],
    failure_details: dict[tuple[str, str], str],
) -> list[str]:
    hardening_view = hardening.get(arch)
    repro_view = repro.get(arch)
    lines = [f"### {arch}", ""]
    if hardening_view is None:
        lines.append("- Hardening evidence: unavailable or malformed")
    else:
        cves = hardening_view["cves"]
        if cves:
            lines.append("- Actionable fixable HIGH/CRITICAL CVEs:")
            for finding in cves:
                fixed_version = finding["fixed_version"]
                fix = "fix available" if fixed_version is None else f"fixed version {_safe_text(str(fixed_version))}"
                lines.append(
                    f"  - {_safe_text(str(finding['id']))} — {_safe_text(str(finding['severity']))}; "
                    f"package {_safe_text(str(finding['package']))}; {fix}"
                )
        else:
            lines.append("- Actionable fixable HIGH/CRITICAL CVEs: 0")
        lines.extend(
            [
                f"- STIG failures: {hardening_view['stig_fail']}",
                f"- Secret findings: {hardening_view['secret_count']} (count only; matched material is never rendered)",
                f"- Findings missing VEX: {hardening_view['missing_vex']}",
                f"- Footprint: {'passed' if hardening_view['footprint_passed'] else 'failed'}",
            ]
        )
    hardening_failure_detail = failure_details.get(("hardening", arch))
    if hardening_failure_detail is not None:
        lines.append(f"- Hardening failure detail: {_safe_text(hardening_failure_detail)}")
    if repro_view is None:
        lines.append("- Reproducibility evidence: unavailable or malformed")
    else:
        lines.append(
            "- Reproducibility: "
            f"byte-identical={'yes' if repro_view['byte_identical'] else 'no'}; "
            f"rootfs-contract={'match' if repro_view['rootfs_matches_contract'] else 'drift'}; "
            f"RPMDB-contract={'match' if repro_view['rpmdb_matches_contract'] else 'drift'}"
        )
    repro_failure_detail = failure_details.get(("repro", arch))
    if repro_failure_detail is not None:
        lines.append(f"- Reproducibility failure detail: {_safe_text(repro_failure_detail)}")
    return lines


def render_issue(envelope_values: list[Any], results_value: Any, context_value: Any) -> tuple[str, bool, str]:
    job_results, reasons = _job_result_view(results_value)
    run_url, date, run_context_valid, context_reasons = _context(context_value)
    reasons.extend(context_reasons)
    hardening, repro, failure_details, envelope_projection, envelope_reasons = _envelopes(envelope_values)
    reasons.extend(envelope_reasons)
    reasons = list(dict.fromkeys(reasons))
    attention = bool(reasons)
    signature = _signature(
        {
            "envelopes": envelope_projection,
            "job_results": job_results,
            "run_context_valid": run_context_valid,
            "version": SIGNATURE_VERSION,
        }
    )

    lines = [
        "## ⚠️ Action needed: nightly base-micro drift" if attention else "## ✅ Nightly base-micro sentinel clean",
        "",
        f"Sentinel date: {_safe_text(date)}",
        "",
    ]
    if attention:
        lines.extend(["The run cannot establish a clean result:", ""])
        lines.extend(f"- {reason}" for reason in reasons)
        lines.append("")
    else:
        lines.extend(["Both architectures are complete, reproducible, and free of actionable drift.", ""])
    for arch in ARCHES:
        lines.extend(_arch_section(arch, hardening, repro, failure_details))
        lines.append("")
    if run_url:
        lines.extend([f'<a href="{html.escape(run_url, quote=True)}">Open the complete nightly run</a>', ""])
    lines.append(MARKER)
    return "\n".join(lines) + "\n", attention, signature


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {"input_error": "missing or malformed JSON input"}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hardening-amd64", required=True, type=Path)
    parser.add_argument("--hardening-arm64", required=True, type=Path)
    parser.add_argument("--repro-amd64", required=True, type=Path)
    parser.add_argument("--repro-arm64", required=True, type=Path)
    parser.add_argument("--job-results", required=True, type=Path)
    parser.add_argument("--run-context", required=True, type=Path)
    parser.add_argument("--body-output", required=True, type=Path)
    parser.add_argument("--decision-output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    envelopes = [
        _load(args.hardening_amd64),
        _load(args.hardening_arm64),
        _load(args.repro_amd64),
        _load(args.repro_arm64),
    ]
    body, attention, signature = render_issue(envelopes, _load(args.job_results), _load(args.run_context))
    args.body_output.parent.mkdir(parents=True, exist_ok=True)
    args.body_output.write_text(body, encoding="utf-8")
    args.decision_output.parent.mkdir(parents=True, exist_ok=True)
    args.decision_output.write_text(
        json.dumps({"attention": attention, "signature": signature}, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"attention={'true' if attention else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
