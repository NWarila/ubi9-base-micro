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
from pathlib import Path
from typing import Any

ARCHES = {"amd64", "arm64"}
SCHEMA_VERSION = "1.1.0"
FAILURE_DETAIL_LIMIT = 500
NEVRA_CANDIDATE_LIMIT = 160
NEVRA_EPOCH_LIMIT = 10
NEVRA_VERSION_LIMIT = 32
NEVRA_RELEASE_LIMIT = 48
CONTROL_OR_ESCAPE_SEQUENCE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)"
    r"|\x1b[P^_X][^\x1b]*(?:\x1b\\|$)"
    r"|\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b[ -/]*[@-~]"
    r"|[\x00-\x1f\x7f-\x9f]"
)
ROOTFS_FAILURE_PREFIX = r"(?:#[0-9]+ [0-9.]+ )?(?:runtime rootfs build failed: )?"
OPENSSL_LIBS_NEVRA_MISMATCH = re.compile(
    rf"^{ROOTFS_FAILURE_PREFIX}"
    r"runtime rootfs openssl-libs NEVRA does not match verified stage: "
    rf"(?P<actual>\S{{1,{NEVRA_CANDIDATE_LIMIT}}}) != "
    rf"(?P<verified>\S{{1,{NEVRA_CANDIDATE_LIMIT}}})$"
)
PROVIDER_NEVRA_MISMATCH = re.compile(
    rf"^{ROOTFS_FAILURE_PREFIX}"
    r"runtime rootfs provider NEVRA does not match verified stage: "
    rf"(?P<actual>\S{{1,{NEVRA_CANDIDATE_LIMIT}}}) != "
    rf"(?P<verified>\S{{1,{NEVRA_CANDIDATE_LIMIT}}})$"
)
NEVRA = re.compile(
    r"^(?P<name>openssl-libs|openssl-fips-provider-so)-"
    r"(?:(?P<epoch>[0-9]+):)?"
    r"(?P<version>[0-9][0-9.]*)-"
    r"(?P<release>[0-9][0-9A-Za-z._+~]*)\."
    r"(?P<arch>x86_64|aarch64|noarch)$"
)
DIGEST_MISMATCH = re.compile(
    r"^(?:reproducibility assertion failed: )?"
    r"(?P<fact>rootfs_digest|rpmdb_sha256) mismatch for "
    r"(?P<side>left|right|single rootfs linux/(?:amd64|arm64)): expected "
    r"(?P<expected>[0-9a-f]{64}) from "
    r".+, actual "
    r"(?P<actual>[0-9a-f]{64})$"
)


class SummaryError(Exception):
    """An input cannot support a complete decision envelope."""


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


def _canonical_nevra(candidate: str, expected_name: str) -> str | None:
    match = NEVRA.fullmatch(candidate)
    if match is None or match.group("name") != expected_name:
        return None
    epoch = match.group("epoch")
    version = match.group("version")
    release = match.group("release")
    arch = match.group("arch")
    if (
        (epoch is not None and len(epoch) > NEVRA_EPOCH_LIMIT)
        or len(version) > NEVRA_VERSION_LIMIT
        or len(release) > NEVRA_RELEASE_LIMIT
    ):
        return None
    canonical_epoch = "" if epoch is None else f"{epoch}:"
    return f"{expected_name}-{canonical_epoch}{version}-{release}.{arch}"


def _reconstruct_failure_detail(line: str) -> str | None:
    match = OPENSSL_LIBS_NEVRA_MISMATCH.fullmatch(line)
    if match is not None:
        actual = _canonical_nevra(match.group("actual"), "openssl-libs")
        verified = _canonical_nevra(match.group("verified"), "openssl-libs")
        if actual is None or verified is None:
            return None
        return f"runtime rootfs openssl-libs NEVRA does not match verified stage: {actual} != {verified}"

    match = PROVIDER_NEVRA_MISMATCH.fullmatch(line)
    if match is not None:
        actual = _canonical_nevra(match.group("actual"), "openssl-fips-provider-so")
        verified = _canonical_nevra(match.group("verified"), "openssl-fips-provider-so")
        if actual is None or verified is None:
            return None
        return f"runtime rootfs provider NEVRA does not match verified stage: {actual} != {verified}"

    match = DIGEST_MISMATCH.fullmatch(line)
    if match is not None:
        return (
            f"{match.group('fact')} mismatch for {match.group('side')}: "
            f"expected {match.group('expected')}, actual {match.group('actual')}"
        )
    return None


def _failure_detail(path: Path) -> str | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return None
    for line in lines:
        sanitized = CONTROL_OR_ESCAPE_SEQUENCE.sub("", line).strip()
        detail = _reconstruct_failure_detail(sanitized)
        if detail is not None:
            return detail[:FAILURE_DETAIL_LIMIT]
    return None


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
) -> dict[str, Any]:
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
    }


def summarize_hardening(
    arch: str,
    dist_dir: Path,
    contract: Path,
) -> dict[str, Any]:
    envelope = _base_envelope("hardening", arch)
    try:
        if arch not in ARCHES:
            raise SummaryError(f"unsupported architecture: {arch}")
        contract_limit, _, _ = _contract_values(contract, arch)
        envelope.update(_hardening_fields(arch, dist_dir, contract_limit))
        reasons: list[str] = []
        stig = _object(envelope["stig"], "stig")
        if _integer(stig["fail"], "STIG failures"):
            reasons.append(f"{arch} has failing STIG results")
        secrets = _object(envelope["secrets"], "secrets")
        if _integer(secrets["finding_count"], "secret findings"):
            reasons.append(f"{arch} has secret-scan findings")
        footprint = _object(envelope["footprint"], "footprint")
        if not _boolean(footprint["passed"], "footprint passed"):
            reasons.append(f"{arch} exceeds the footprint cap")
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
    parser.add_argument("--failure-log", type=Path)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--repro-report", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.kind == "hardening":
        envelope = summarize_hardening(args.arch, args.dist_dir, args.contract)
    else:
        report = args.repro_report or (args.dist_dir / f"reproducibility/base-micro.{args.arch}.reproducibility.json")
        envelope = summarize_repro(args.arch, report, args.contract)
    if args.failure_log is not None:
        failure_detail = _failure_detail(args.failure_log)
        if failure_detail is not None:
            envelope["failure_detail"] = failure_detail
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
