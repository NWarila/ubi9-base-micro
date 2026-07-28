#!/usr/bin/env python3
# Purpose: Decide whether a push must run micro publication, and extract the published revision label
# Role: policy
# Micro-container candidate: yes - pure-stdlib, stdin-in/stdout-out, has --self-test

"""Decide whether a push must run micro publication.

Decision mode reads a NUL-delimited changed-path list on stdin and prints
exactly ``true`` (publish) or ``false`` (skip). The only skip path is a
main-branch push whose entire delta against the currently published revision
lies strictly under ``images/``; every ambiguity publishes.

Base-extraction mode (``--print-base``) reads an OCI image-config JSON document
on stdin and prints the ``org.opencontainers.image.revision`` label iff it is a
40-hex commit, exiting nonzero otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

REVISION_LABEL = "org.opencontainers.image.revision"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAIN_REF = "refs/heads/main"
TAG_REF_PREFIX = "refs/tags/"
IMAGES_TREE_PREFIX = "images/"
DIFF_STATUSES = frozenset({"available", "unavailable"})


def parse_nul_paths(raw: bytes) -> list[str]:
    return [chunk.decode("utf-8", errors="surrogateescape") for chunk in raw.split(b"\0") if chunk]


def decide(ref: str, diff_status: str, paths: list[str]) -> tuple[str, str]:
    if diff_status not in DIFF_STATUSES:
        raise SystemExit(f"unknown --diff-status value: {diff_status}")
    if ref.startswith(TAG_REF_PREFIX):
        return "true", f"tag ref {ref} always publishes"
    if ref != MAIN_REF:
        return "true", f"ref {ref} is not {MAIN_REF}; publishing"
    if diff_status == "unavailable":
        return "true", "published-revision diff base unavailable; publishing"
    if not paths:
        return "true", "empty diff against the published revision; publishing"
    outside = [path for path in paths if not path.startswith(IMAGES_TREE_PREFIX)]
    if outside:
        return "true", f"{len(outside)} changed path(s) outside {IMAGES_TREE_PREFIX}; publishing"
    return (
        "false",
        f"all {len(paths)} changed path(s) under {IMAGES_TREE_PREFIX}; skipping micro publication",
    )


def extract_base(raw: str) -> str:
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"image config is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise SystemExit("image config is not a JSON object")
    config = loaded.get("config")
    if not isinstance(config, dict):
        raise SystemExit("image config has no config object")
    labels = config.get("Labels")
    if not isinstance(labels, dict):
        raise SystemExit("image config has no Labels object")
    revision = labels.get(REVISION_LABEL)
    if not isinstance(revision, str) or COMMIT_PATTERN.fullmatch(revision) is None:
        raise SystemExit(f"image config label {REVISION_LABEL} is absent or not a 40-hex commit")
    return revision


def self_test() -> None:
    decision_cases: list[tuple[str, str, list[str], str]] = [
        ("refs/tags/v1.0.0", "unavailable", [], "true"),
        ("refs/tags/python/v1.0.0", "available", ["images/python/Dockerfile"], "true"),
        ("refs/heads/feature", "available", ["images/README.md"], "true"),
        ("refs/heads/main", "unavailable", [], "true"),
        ("refs/heads/main", "unavailable", ["images/README.md"], "true"),
        ("refs/heads/main", "available", [], "true"),
        ("refs/heads/main", "available", ["README.md"], "true"),
        ("refs/heads/main", "available", ["README.md", "images/README.md"], "true"),
        ("refs/heads/main", "available", ["images"], "true"),
        ("refs/heads/main", "available", ["imagesque/file.md"], "true"),
        ("refs/heads/main", "available", ["images/README.md"], "false"),
        ("refs/heads/main", "available", ["images/python/rpm-lock/a.txt", "images/README.md"], "false"),
        # rename pairs as surfaced by git diff --no-renames (deletion + addition):
        ("refs/heads/main", "available", ["tools/verify.py", "images/verify.py"], "true"),
        ("refs/heads/main", "available", ["images/old.md", "docs/new.md"], "true"),
        ("refs/heads/main", "available", ["images/a.md", "images/b.md"], "false"),
        ("refs/heads/main", "available", ["images/with\nnewline.txt"], "false"),
    ]
    for ref, diff_status, paths, expected in decision_cases:
        decision, _ = decide(ref, diff_status, paths)
        if decision != expected:
            raise SystemExit(
                f"self-test: decide({ref!r}, {diff_status!r}, {paths!r}) returned {decision}, expected {expected}"
            )

    parsed = parse_nul_paths(b"images/a.md\0images/with\nnewline.txt\0")
    if parsed != ["images/a.md", "images/with\nnewline.txt"]:
        raise SystemExit(f"self-test: NUL parsing returned {parsed!r}")
    if parse_nul_paths(b""):
        raise SystemExit("self-test: empty input must parse to no paths")

    try:
        decide("refs/heads/main", "bogus", [])
    except SystemExit:
        pass
    else:
        raise SystemExit("self-test: unknown --diff-status value unexpectedly accepted")

    good_revision = "a" * 40
    good_config = json.dumps({"config": {"Labels": {REVISION_LABEL: good_revision}}})
    if extract_base(good_config) != good_revision:
        raise SystemExit("self-test: valid revision label not extracted")
    bad_configs = [
        json.dumps({"config": {"Labels": {}}}),
        json.dumps({"config": {}}),
        json.dumps({"config": {"Labels": {REVISION_LABEL: "not-a-commit"}}}),
        json.dumps({"config": {"Labels": {REVISION_LABEL: "A" * 40}}}),
        json.dumps([]),
        "{not json",
    ]
    rejected = 0
    for bad_config in bad_configs:
        try:
            extract_base(bad_config)
        except SystemExit:
            rejected += 1
            continue
        raise SystemExit(f"self-test: malformed image config unexpectedly accepted: {bad_config!r}")

    print(
        f"decide-publish-scope self-test: {len(decision_cases)} decision cases ok; "
        f"{rejected}/{len(bad_configs)} malformed base configs rejected"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Decide whether a push must run micro publication.")
    parser.add_argument("--ref", help="fully-qualified git ref of the push event")
    parser.add_argument("--diff-status", choices=sorted(DIFF_STATUSES), help="published-revision diff availability")
    parser.add_argument("--print-base", action="store_true", help="extract the published revision label from stdin")
    parser.add_argument("--self-test", action="store_true", help="run the built-in decision-table self-test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    if args.print_base:
        print(extract_base(sys.stdin.read()))
        return 0
    if not args.ref or not args.diff_status:
        parser.error("--ref and --diff-status are required in decision mode")
    paths = parse_nul_paths(sys.stdin.buffer.read())
    decision, reason = decide(args.ref, args.diff_status, paths)
    print(reason, file=sys.stderr)
    print(decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
