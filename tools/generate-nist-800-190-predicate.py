#!/usr/bin/env python3
# Purpose: Generate/validate the NIST SP 800-190 s4.1 image-control attestation predicate
# Role: tooling
# Micro-container candidate: yes - pure-stdlib, deterministic JSON out, has --self-test/--validate

"""Generate and validate the NIST SP 800-190 section 4.1 image predicate."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any, cast

PREDICATE_TYPE = "https://nwarila.dev/attestations/nist-sp-800-190-image/v1"
CONTROL_IDS = ("4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.5")
VALID_STATUSES = {"addressed", "not-applicable-with-reason"}


def evidence(kind: str, pointer: str, description: str) -> dict[str, str]:
    return {"kind": kind, "pointer": pointer, "description": description}


def load_secret_report(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise SystemExit(f"secret-scan report must be a JSON object: {path}")
    report = cast(dict[str, Any], loaded)
    if report.get("result") != "passed":
        raise SystemExit(f"secret-scan report did not pass: {path}")
    return report


def generate_predicate(args: argparse.Namespace) -> dict[str, Any]:
    secret_report = load_secret_report(args.secret_scan_report)
    base_image = args.base_image
    if "@sha256:" not in base_image:
        raise SystemExit(f"base image must be digest-pinned: {base_image}")

    return {
        "predicateType": PREDICATE_TYPE,
        "schemaVersion": "1.0",
        "standard": {
            "name": "NIST SP 800-190",
            "section": "4.1 Image Countermeasures",
            "scope": "image-control evidence for this container image only",
            "notCisDocker": True,
            "notCisDockerReason": (
                "CIS Docker Benchmark controls the host and daemon layer; this predicate "
                "covers the image-layer countermeasures in NIST SP 800-190 section 4.1."
            ),
        },
        "subject": {
            "imageRef": args.image_ref,
            "platform": args.platform,
            "architecture": args.arch,
        },
        "build": {
            "sourceUri": args.source_uri,
            "revision": args.revision,
            "baseImage": base_image,
        },
        "secretScan": {
            "status": "passed",
            "report": args.secret_scan_report.as_posix(),
            "filesScanned": secret_report.get("filesScanned"),
            "skippedBinaryFiles": secret_report.get("skippedBinaryFiles"),
            "skippedLargeTextFiles": secret_report.get("skippedLargeTextFiles"),
            "skippedSymlinks": secret_report.get("skippedSymlinks"),
            "sampleScanBytes": secret_report.get("sampleScanBytes"),
            "sampledPatterns": secret_report.get("sampledPatterns"),
            "scanner": "tools/assert-no-rootfs-secrets.py",
        },
        "controls": [
            {
                "id": "4.1.1",
                "countermeasure": "Image vulnerabilities",
                "status": "addressed",
                "posture": (
                    "Fixable HIGH and CRITICAL OS/library findings fail closed through both "
                    "Trivy and Grype, with OpenVEX default-deny for unfixed HIGH/CRITICAL "
                    "findings and rpmdb-derived package evidence."
                ),
                "evidence": [
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#Run Trivy fixable vulnerability gates",
                        "Trivy fixable HIGH/CRITICAL gate",
                    ),
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#Run Grype fixable vulnerability gates",
                        "Grype fixable HIGH/CRITICAL gate",
                    ),
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#Run OpenVEX default-deny gates",
                        "OpenVEX default-deny policy",
                    ),
                    evidence("script", "tools/assert-vex.py", "default-deny OpenVEX assertion"),
                    evidence("script", "tools/assert-sbom-rpms.py", "rpmdb-backed SBOM package assertion"),
                ],
            },
            {
                "id": "4.1.2",
                "countermeasure": "Image configuration defects",
                "status": "addressed",
                "posture": (
                    "The runtime is built from digest-pinned UBI micro, removes shell and "
                    "package-manager executables, runs as USER 65532:65532, preserves the "
                    "rpmdb, ships the RHEL CA bundle, and configures the OpenSSL FIPS provider "
                    "in approved mode with architecture-scoped CMVP wording."
                ),
                "evidence": [
                    evidence(
                        "dockerfile",
                        "containers/Dockerfile#runtime",
                        "distroless runtime, non-root user, rpmdb, FIPS config, digest-pinned base",
                    ),
                    evidence("test", "tests/hardening.sh", "no shell/package-manager and USER/rpmdb/CA assertions"),
                    evidence("test", "tests/fips.sh", "FIPS provider artifact and approved-mode assertions"),
                    evidence("doc", "docs/fips.md", "architecture-scoped FIPS claim and arm64 disclaimer"),
                ],
            },
            {
                "id": "4.1.3",
                "countermeasure": "Embedded malware",
                "status": "addressed",
                "posture": (
                    "Package-content risk is constrained by a minimal rpmdb-enumerated rootfs "
                    "and dual scanner gates over the published image package set. This is not "
                    "a claim of arbitrary antivirus detection for opaque payloads."
                ),
                "evidence": [
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#Generate and verify rpmdb SBOMs",
                        "published image package inventory from rpmdb",
                    ),
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#Run Trivy fixable vulnerability gates",
                        "Trivy scan over published image contents",
                    ),
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#Run Grype fixable vulnerability gates",
                        "Grype scan over published image contents",
                    ),
                    evidence(
                        "dockerfile",
                        "containers/Dockerfile#rpm-rootfs",
                        "minimal installroot with shell/package-manager removal",
                    ),
                ],
            },
            {
                "id": "4.1.4",
                "countermeasure": "Embedded clear-text secrets",
                "status": "addressed",
                "posture": (
                    "The exported rootfs is scanned during PR and publish paths for high-confidence "
                    "clear-text credential material. A finding stops the workflow before attestation."
                ),
                "evidence": [
                    evidence(
                        "script",
                        "tools/assert-no-rootfs-secrets.py",
                        "rootfs clear-text secret scanner with negative self-test",
                    ),
                    evidence(
                        "workflow",
                        ".github/workflows/build.yaml#Run runtime rootfs secret gate",
                        "PR-time rootfs secret gate",
                    ),
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#Run runtime rootfs secret gates",
                        "publish-time per-architecture rootfs secret gates",
                    ),
                    evidence(
                        "report", args.secret_scan_report.as_posix(), "secret-scan JSON report for this predicate"
                    ),
                ],
            },
            {
                "id": "4.1.5",
                "countermeasure": "Use of untrusted images",
                "status": "addressed",
                "posture": (
                    "The runtime base is UBI micro pinned by sha256 digest and covered by Renovate "
                    "metadata; published images are signed with the repository workflow identity "
                    "and receive SLSA L3 provenance from the trusted generator builder."
                ),
                "evidence": [
                    evidence(
                        "dockerfile",
                        "containers/Dockerfile#ARG UBI_MICRO_IMAGE",
                        "UBI micro base image is digest-pinned and Renovate-tracked",
                    ),
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#Verify Cosign signature",
                        "cosign signature verification with exact repository workflow identity",
                    ),
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#slsa-provenance",
                        "SLSA L3 generator reusable workflow",
                    ),
                    evidence(
                        "workflow",
                        ".github/workflows/publish-image.yaml#Verify Rekor roll-up",
                        "post-publish roll-up verifies signature and attestations with Rekor tlog entries",
                    ),
                ],
            },
        ],
        "limitations": [
            (
                "This predicate is NIST SP 800-190 section 4.1 image evidence, not CIS Docker Benchmark "
                "host or daemon evidence."
            ),
            (
                "The embedded-malware entry is bounded to package-content scanning and minimal-image controls; "
                "it does not assert arbitrary malware detection."
            ),
            "FIPS evidence is architecture-scoped exactly as documented in docs/fips.md.",
        ],
    }


def validate_predicate(predicate: dict[str, Any]) -> None:
    if predicate.get("predicateType") != PREDICATE_TYPE:
        raise SystemExit("predicateType mismatch")
    if predicate.get("schemaVersion") != "1.0":
        raise SystemExit("schemaVersion must be 1.0")
    standard = predicate.get("standard")
    if not isinstance(standard, dict) or standard.get("notCisDocker") is not True:
        raise SystemExit("predicate must explicitly state that it is not CIS Docker evidence")
    subject = predicate.get("subject")
    if not isinstance(subject, dict) or not subject.get("imageRef") or not subject.get("platform"):
        raise SystemExit("predicate subject must include imageRef and platform")
    build = predicate.get("build")
    if not isinstance(build, dict) or "@sha256:" not in str(build.get("baseImage", "")):
        raise SystemExit("predicate build.baseImage must be digest-pinned")
    secret_scan = predicate.get("secretScan")
    if not isinstance(secret_scan, dict) or secret_scan.get("status") != "passed":
        raise SystemExit("secretScan.status must be passed")
    controls = predicate.get("controls")
    if not isinstance(controls, list):
        raise SystemExit("controls must be a list")
    by_id = {control.get("id"): control for control in controls if isinstance(control, dict)}
    if tuple(by_id) != CONTROL_IDS:
        raise SystemExit("controls must cover exactly: " + ", ".join(CONTROL_IDS))
    for control_id in CONTROL_IDS:
        control = by_id[control_id]
        status = control.get("status")
        if status not in VALID_STATUSES:
            raise SystemExit(f"{control_id} has invalid status: {status}")
        if status == "not-applicable-with-reason" and not control.get("reason"):
            raise SystemExit(f"{control_id} is not applicable but has no reason")
        evidence_items = control.get("evidence")
        if not isinstance(evidence_items, list) or not evidence_items:
            raise SystemExit(f"{control_id} must include evidence")
        for item in evidence_items:
            if not isinstance(item, dict) or not item.get("pointer") or not item.get("description"):
                raise SystemExit(f"{control_id} contains malformed evidence")


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        report = root / "secret-report.json"
        report.write_text(
            json.dumps(
                {
                    "result": "passed",
                    "filesScanned": 3,
                    "skippedBinaryFiles": 2,
                    "skippedLargeTextFiles": 1,
                    "skippedSymlinks": 0,
                    "sampleScanBytes": 65536,
                    "sampledPatterns": ["private-key", "aws-access-key-id"],
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )
        args = argparse.Namespace(
            image_ref="ghcr.io/nwarila/ubi9-base-micro:base-micro",
            platform="linux/amd64",
            arch="amd64",
            base_image="registry.access.redhat.com/ubi9/ubi-micro@sha256:" + "a" * 64,
            source_uri="github.com/NWarila/ubi9-base-micro",
            revision="self-test",
            secret_scan_report=report,
        )
        predicate = generate_predicate(args)
        validate_predicate(predicate)

        predicate["controls"][0]["evidence"] = []
        try:
            validate_predicate(predicate)
        except SystemExit:
            pass
        else:
            raise SystemExit("self-test malformed predicate unexpectedly passed")

    print("NIST 800-190 predicate generator self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-ref")
    parser.add_argument("--platform")
    parser.add_argument("--arch")
    parser.add_argument("--base-image")
    parser.add_argument("--source-uri", default="github.com/NWarila/ubi9-base-micro")
    parser.add_argument("--revision", default="unknown")
    parser.add_argument("--secret-scan-report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if args.validate is not None:
        validate_predicate(json.loads(args.validate.read_text(encoding="utf-8")))
        print(f"NIST 800-190 predicate validated: {args.validate}")
        return 0

    missing = [
        name
        for name in ("image_ref", "platform", "arch", "base_image", "secret_scan_report", "output")
        if getattr(args, name) in (None, "")
    ]
    if missing:
        raise SystemExit(
            "missing required argument(s): " + ", ".join("--" + name.replace("_", "-") for name in missing)
        )

    predicate = generate_predicate(args)
    validate_predicate(predicate)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(predicate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"NIST 800-190 predicate written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
