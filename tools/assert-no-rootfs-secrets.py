#!/usr/bin/env python3
# Purpose: Fail if a container rootfs contains high-confidence clear-text secrets
# Role: gate
# Micro-container candidate: yes - pure-stdlib, rootfs-in/exit-out, has --self-test

"""Fail if a container rootfs contains high-confidence clear-text secrets."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_TEXT_BYTES = 8 * 1024 * 1024
SAMPLE_SCAN_BYTES = 64 * 1024
WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class SecretPattern:
    name: str
    expression: re.Pattern[str]


SECRET_PATTERNS = [
    SecretPattern(
        "private-key",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    SecretPattern(
        "openssh-private-key",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ),
    SecretPattern(
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    SecretPattern(
        "github-token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
    ),
    SecretPattern(
        "github-fine-grained-token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82,255}\b"),
    ),
    SecretPattern(
        "slack-token",
        re.compile(r"\bxox(?:b|p|a|r)-[A-Za-z0-9-]{20,}\b"),
    ),
    SecretPattern(
        "npm-token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"),
    ),
    SecretPattern(
        "pypi-token",
        re.compile(r"\bpypi-[A-Za-z0-9_-]{40,}\b"),
    ),
    SecretPattern(
        "generic-secret-assignment",
        re.compile(
            r"(?i)\b(?P<key>aws_secret_access_key|secret_access_key|client_secret|"
            r"api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|"
            r"private[_-]?key)\b\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9+/_=.!@#$%^&*~:\\-]{12,})"
        ),
    ),
]

HIGH_CONFIDENCE_SAMPLE_PATTERN_NAMES = {
    "private-key",
    "openssh-private-key",
    "aws-access-key-id",
    "github-token",
    "github-fine-grained-token",
    "slack-token",
}
HIGH_CONFIDENCE_SAMPLE_PATTERNS = [
    pattern for pattern in SECRET_PATTERNS if pattern.name in HIGH_CONFIDENCE_SAMPLE_PATTERN_NAMES
]


def is_probably_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def is_private_key_path_reference(value: str) -> bool:
    if value.startswith(("/", "./", "../", "~", "$", "%")):
        return True
    return WINDOWS_DRIVE_PATH.match(value) is not None


def is_benign_generic_assignment(match: re.Match[str]) -> bool:
    key = (match.groupdict().get("key") or "").lower().replace("-", "_")
    value = (match.groupdict().get("value") or "").strip().strip("\"'")
    lowered = value.lower()
    placeholders = {"changeme", "change_me", "example", "example_secret", "placeholder"}
    if lowered in placeholders:
        return True
    return key == "private_key" and is_private_key_path_reference(value)


def append_findings(
    findings: list[dict[str, Any]],
    rel: str,
    text: str,
    patterns: list[SecretPattern],
) -> None:
    for pattern in patterns:
        for match in pattern.expression.finditer(text):
            if pattern.name == "generic-secret-assignment" and is_benign_generic_assignment(match):
                continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                {
                    "path": rel,
                    "line": line,
                    "pattern": pattern.name,
                }
            )


def scan(rootfs: Path) -> dict[str, Any]:
    if not rootfs.is_dir():
        raise SystemExit(f"rootfs directory does not exist: {rootfs}")

    findings: list[dict[str, Any]] = []
    files_scanned = 0
    skipped_binary = 0
    skipped_large = 0
    skipped_symlinks = 0

    for path in sorted(rootfs.rglob("*")):
        if path.is_symlink():
            skipped_symlinks += 1
            continue
        if not path.is_file():
            continue
        rel = path.relative_to(rootfs).as_posix()
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                sample = handle.read(SAMPLE_SCAN_BYTES)
                sample_text = sample.decode("utf-8", errors="ignore")
                if is_probably_binary(sample):
                    append_findings(findings, rel, sample_text, HIGH_CONFIDENCE_SAMPLE_PATTERNS)
                    skipped_binary += 1
                    continue
                if size > MAX_TEXT_BYTES:
                    append_findings(findings, rel, sample_text, HIGH_CONFIDENCE_SAMPLE_PATTERNS)
                    skipped_large += 1
                    continue
                remainder = handle.read()
        except OSError as exc:
            raise SystemExit(f"failed to read {rel}: {exc}") from exc

        text = (sample + remainder).decode("utf-8", errors="ignore")
        files_scanned += 1
        append_findings(findings, rel, text, SECRET_PATTERNS)

    return {
        "result": "failed" if findings else "passed",
        "rootfs": str(rootfs),
        "filesScanned": files_scanned,
        "skippedBinaryFiles": skipped_binary,
        "skippedLargeTextFiles": skipped_large,
        "skippedSymlinks": skipped_symlinks,
        "sampleScanBytes": SAMPLE_SCAN_BYTES,
        "sampledPatterns": [pattern.name for pattern in HIGH_CONFIDENCE_SAMPLE_PATTERNS],
        "patterns": [pattern.name for pattern in SECRET_PATTERNS],
        "findings": findings,
    }


def write_report(report: dict[str, Any], path: Path | None) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        clean = Path(tmp) / "clean"
        dirty = Path(tmp) / "dirty"
        base64_private_key = Path(tmp) / "base64-private-key"
        binary_secret = Path(tmp) / "binary-secret"
        large_secret = Path(tmp) / "large-secret"
        clean.mkdir()
        dirty.mkdir()
        base64_private_key.mkdir()
        binary_secret.mkdir()
        large_secret.mkdir()
        (clean / "os-release").write_text('NAME="UBI"\n', encoding="utf-8")
        (clean / "openssl.cnf").write_text(
            "\n".join(
                [
                    "private_key = $dir/private/cakey.pem",
                    "private_key = /etc/pki/tls/private/x.key",
                    "private_key = C:\\pki\\private\\x.key",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (dirty / "env").write_text(
            "\n".join(
                [
                    "AWS_SECRET_ACCESS_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "password=correcthorsebatterystaple",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (base64_private_key / "env").write_text(
            "private_key = MIIEvQ/BADBADBADBADBADBAD\n",
            encoding="utf-8",
        )
        (binary_secret / "key.bin").write_bytes(b"\x00-----BEGIN PRIVATE KEY-----\n")
        (large_secret / "token.txt").write_text(
            "github_pat_" + ("A" * 82) + "\n" + ("x" * (MAX_TEXT_BYTES + 1)),
            encoding="utf-8",
        )

        clean_report = scan(clean)
        if clean_report["result"] != "passed":
            raise SystemExit("self-test clean rootfs unexpectedly failed")

        dirty_report = scan(dirty)
        if dirty_report["result"] != "failed" or not dirty_report["findings"]:
            raise SystemExit("self-test dirty rootfs did not produce a finding")

        base64_report = scan(base64_private_key)
        if base64_report["result"] != "failed" or not base64_report["findings"]:
            raise SystemExit("self-test base64 private_key assignment did not produce a finding")

        binary_report = scan(binary_secret)
        if binary_report["result"] != "failed" or binary_report["skippedBinaryFiles"] != 1:
            raise SystemExit("self-test binary high-confidence sample did not produce a finding")

        large_report = scan(large_secret)
        if large_report["result"] != "failed" or large_report["skippedLargeTextFiles"] != 1:
            raise SystemExit("self-test large text high-confidence sample did not produce a finding")

    print("rootfs secret scanner self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, help="exported rootfs directory to scan")
    parser.add_argument("--report", type=Path, help="JSON report path")
    parser.add_argument("--self-test", action="store_true", help="run positive and negative self-tests")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if args.rootfs is None:
        raise SystemExit("--rootfs is required unless --self-test is used")

    report = scan(args.rootfs)
    write_report(report, args.report)
    if report["result"] != "passed":
        print("clear-text secret findings in rootfs:", file=sys.stderr)
        for finding in report["findings"]:
            print(
                f"  {finding['path']}:{finding['line']} matched {finding['pattern']}",
                file=sys.stderr,
            )
        return 1

    print(
        "rootfs secret scan passed: "
        f"{report['filesScanned']} text files scanned, "
        f"{report['skippedBinaryFiles']} binary files sampled/skipped, "
        f"{report['skippedLargeTextFiles']} large text files sampled/skipped, "
        f"{report['skippedSymlinks']} symlinks skipped"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
