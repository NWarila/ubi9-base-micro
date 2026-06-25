#!/usr/bin/env python3
# Purpose: Generate the STIG ARF attestation predicate summary (ARF hash + tailoring metadata)
# Role: tooling
# Micro-container candidate: yes - pure-stdlib, deterministic JSON out, has --self-test

"""Generate a STIG ARF attestation predicate summary."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

PREDICATE_TYPE = "https://nwarila.dev/attestations/stig-arf/v1"


class PredicateError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise PredicateError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate(args: argparse.Namespace) -> dict[str, Any]:
    require(args.arf.is_file() and args.arf.stat().st_size > 0, f"ARF is missing or empty: {args.arf}")
    require(args.summary.is_file(), f"ARF summary is missing: {args.summary}")
    require(args.tailoring.is_file(), f"tailoring file is missing: {args.tailoring}")
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    require(
        "blocking_results" in summary and not summary["blocking_results"], "predicate requires a passing ARF summary"
    )

    return {
        "predicateType": PREDICATE_TYPE,
        "image": {
            "ref": args.image_ref,
            "platform": args.platform,
            "arch": args.arch,
        },
        "scan": {
            "tool": "OpenSCAP",
            "profile": args.profile,
            "failOn": args.fail_on,
            "summary": summary,
        },
        "scapContent": {
            "source": "ComplianceAsCode/content",
            "version": args.ssg_version,
            "tarballSha512": args.ssg_tarball_sha512,
        },
        "tailoring": {
            "path": str(args.tailoring).replace("\\", "/"),
            "sha256": sha256_file(args.tailoring),
            "justificationsPath": str(args.justifications).replace("\\", "/"),
            "justificationsSha256": sha256_file(args.justifications),
        },
        "arf": {
            "mediaType": "application/xml",
            "path": str(args.arf).replace("\\", "/"),
            "sha256": sha256_file(args.arf),
            "bytes": args.arf.stat().st_size,
        },
    }


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        arf = root / "arf.xml"
        summary = root / "summary.json"
        tailoring = root / "tailoring.xml"
        justifications = root / "justifications.json"
        output = root / "predicate.json"
        arf.write_text("<arf/>\n", encoding="utf-8")
        summary.write_text(json.dumps({"blocking_results": [], "counts": {"pass": 1}}), encoding="utf-8")
        tailoring.write_text("<tailoring/>\n", encoding="utf-8")
        justifications.write_text("{}\n", encoding="utf-8")
        args = argparse.Namespace(
            arf=arf,
            summary=summary,
            tailoring=tailoring,
            justifications=justifications,
            image_ref="example@sha256:" + "0" * 64,
            platform="linux/amd64",
            arch="amd64",
            profile="tailored",
            fail_on="low",
            ssg_version="0.1.81",
            ssg_tarball_sha512="a" * 128,
            output=output,
        )
        predicate = generate(args)
        output.write_text(json.dumps(predicate, sort_keys=True), encoding="utf-8")
        loaded = json.loads(output.read_text(encoding="utf-8"))
        require(loaded["predicateType"] == PREDICATE_TYPE, "self-test predicate type mismatch")
        require(loaded["arf"]["sha256"] == sha256_file(arf), "self-test ARF hash mismatch")

    print("STIG ARF predicate generator self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arf", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--tailoring", type=Path, default=Path("stig/rhel9-base-micro-tailoring.xml"))
    parser.add_argument("--justifications", type=Path, default=Path("stig/tailoring-justifications.json"))
    parser.add_argument("--image-ref", default="")
    parser.add_argument("--platform", default="")
    parser.add_argument("--arch", default="")
    parser.add_argument("--profile", default="xccdf_org.nwarila.content_profile_ubi9_base_micro_stig")
    parser.add_argument("--fail-on", default="low")
    parser.add_argument("--ssg-version", default="0.1.81")
    parser.add_argument("--ssg-tarball-sha512", required=False, default="")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_test:
            self_test()
            return 0
        for field in ["arf", "summary", "output"]:
            require(
                getattr(args, field) is not None, f"--{field.replace('_', '-')} is required unless --self-test is used"
            )
        require(args.image_ref, "--image-ref is required")
        require(args.platform, "--platform is required")
        require(args.arch, "--arch is required")
        require(args.ssg_tarball_sha512, "--ssg-tarball-sha512 is required")
        predicate = generate(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(predicate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote STIG ARF predicate: {args.output}")
        return 0
    except (PredicateError, json.JSONDecodeError) as exc:
        print(f"STIG ARF predicate generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
