#!/usr/bin/env python3
# Purpose: Decide whether a push can safely skip base-python publication
# Role: policy
# Micro-container candidate: yes - pure-stdlib, stdin-in/stdout-out, has --self-test

"""Fail-closed publication scope policy for ``ubi9-base-python``.

Decision mode consumes a NUL-delimited changed-path list.  Only paths in the
closed unrelated allowlist can skip a main-branch publication.  Changes to the
Python tree or to any shared input consumed by the publisher always publish;
unknown paths and unavailable comparison bases publish as well.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

REVISION_LABEL = "org.opencontainers.image.revision"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAIN_REF = "refs/heads/main"
PYTHON_TAG_PREFIX = "refs/tags/python/v"
DIFF_STATUSES = frozenset({"available", "unavailable"})

PUBLISH_PREFIXES = ("images/python/",)
PUBLISH_EXACT = frozenset(
    {
        ".github/workflows/publish-python.yaml",
        "security/cve-ignore.grype.yaml",
        "security/cve-ignore.trivyignore.yaml",
        "tests/fixtures/scanner-canary/log4shell.cdx.json",
        "tools/assert-cosign-rekor.py",
        "tools/assert-no-phantom-packages.py",
        "tools/assert-rootfs-identity.py",
        "tools/assert-scanner-canary.py",
        "tools/assert-scanner-db-freshness.py",
        "tools/assert-stig-arf.py",
        "tools/assert-stig-tailoring.py",
        "tools/build-stig-datastream.sh",
        "tools/generate-stig-arf-predicate.py",
        "tools/install-crane.sh",
        "tools/install-grype.sh",
        "tools/install-openscap.sh",
        "tools/install-syft.sh",
        "tools/install-trivy.sh",
        "tools/assert-python-alias-policy.py",
        "tools/assert-python-attestation.py",
        "tools/assert-python-provenance.py",
        "tools/assert-python-slsa-certificate.py",
        "tools/decide-python-publish-scope.py",
        "tools/python-trust-contract.py",
        "tools/resolve-python-index.py",
    }
)

SKIP_PREFIXES = ("docs/", ".github/ISSUE_TEMPLATE/")
SKIP_EXACT = frozenset(
    {
        ".editorconfig",
        ".github/pull_request_template.md",
        ".github/renovate.json",
        ".github/zizmor.yml",
        ".markdownlint-cli2.jsonc",
        ".pre-commit-config.yaml",
        ".shellcheckrc",
        ".yamllint",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "SUPPORT.md",
        "images/README.md",
    }
)


def parse_nul_paths(raw: bytes) -> list[str]:
    return [chunk.decode("utf-8", errors="surrogateescape") for chunk in raw.split(b"\0") if chunk]


def path_class(path: str) -> str:
    if path in PUBLISH_EXACT or path.startswith(PUBLISH_PREFIXES):
        return "publish-input"
    if path in SKIP_EXACT or path.startswith(SKIP_PREFIXES):
        return "unrelated"
    return "ambiguous"


def decide(ref: str, diff_status: str, paths: list[str]) -> tuple[str, str]:
    if diff_status not in DIFF_STATUSES:
        raise SystemExit(f"unknown --diff-status value: {diff_status}")
    if ref.startswith(PYTHON_TAG_PREFIX):
        return "true", f"base-python release tag {ref} publishes"
    if ref != MAIN_REF:
        return "true", f"ref {ref} is outside the main-branch scope decision; publishing"
    if diff_status == "unavailable":
        return "true", "published base-python revision unavailable; publishing"
    if not paths:
        return "true", "empty revision delta is ambiguous; publishing"

    classified = [(path, path_class(path)) for path in paths]
    required = [path for path, category in classified if category == "publish-input"]
    if required:
        return "true", f"{len(required)} base-python publisher input(s) changed; publishing"
    ambiguous = [path for path, category in classified if category == "ambiguous"]
    if ambiguous:
        return "true", f"{len(ambiguous)} unclassified path(s) changed; publishing"
    return "false", f"all {len(paths)} changed path(s) are in the closed unrelated allowlist; skipping"


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
    decision_cases = [
        ("python tag", "refs/tags/python/v0.1.0", "available", ["README.md"], "true"),
        ("Dockerfile", MAIN_REF, "available", ["images/python/Dockerfile"], "true"),
        ("rootfs builder", MAIN_REF, "available", ["images/python/tools/build-python-rootfs.py"], "true"),
        ("unavailable base", MAIN_REF, "unavailable", [], "true"),
        ("empty delta", MAIN_REF, "available", [], "true"),
        ("unknown path", MAIN_REF, "available", ["new-root-input"], "true"),
        ("mixed unknown", MAIN_REF, "available", ["docs/a.md", "unknown/file"], "true"),
        ("docs only", MAIN_REF, "available", ["docs/reference/gates.md"], "false"),
        ("community only", MAIN_REF, "available", ["README.md", "SUPPORT.md"], "false"),
    ]
    for label, ref, status, paths, expected in decision_cases:
        actual, reason = decide(ref, status, paths)
        if actual != expected:
            raise SystemExit(f"self-test {label}: expected {expected}, observed {actual}")
        print(f"python publish-scope fixture [{label}] decision={actual} reason={reason}")

    for path in sorted(PUBLISH_EXACT):
        actual, reason = decide(MAIN_REF, "available", [path])
        if actual != "true":
            raise SystemExit(f"self-test shared input unexpectedly skipped: {path}")
        print(f"python publish-scope shared-input fixture [{path}] decision={actual} reason={reason}")

    parsed = parse_nul_paths(b"docs/a.md\0images/python/Dockerfile\0")
    if parsed != ["docs/a.md", "images/python/Dockerfile"]:
        raise SystemExit(f"self-test NUL parser mismatch: {parsed!r}")

    good = "a" * 40
    if extract_base(json.dumps({"config": {"Labels": {REVISION_LABEL: good}}})) != good:
        raise SystemExit("self-test valid published revision was not extracted")
    bad_configs = [
        "{not-json",
        json.dumps([]),
        json.dumps({}),
        json.dumps({"config": {}}),
        json.dumps({"config": {"Labels": {REVISION_LABEL: "A" * 40}}}),
    ]
    for index, bad in enumerate(bad_configs, start=1):
        try:
            extract_base(bad)
        except SystemExit as exc:
            print(f"python publish-scope bad-config fixture [{index}] rejected reason={exc}")
            continue
        raise SystemExit(f"self-test malformed published config unexpectedly passed: {bad}")

    print(
        "python publish-scope self-test passed: "
        f"{len(decision_cases)} decisions, {len(PUBLISH_EXACT)} shared inputs, {len(bad_configs)} bad configs"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref")
    parser.add_argument("--diff-status", choices=sorted(DIFF_STATUSES))
    parser.add_argument("--print-base", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.print_base:
        print(extract_base(sys.stdin.read()))
        return 0
    if not args.ref or not args.diff_status:
        parser.error("--ref and --diff-status are required in decision mode")
    decision, reason = decide(args.ref, args.diff_status, parse_nul_paths(sys.stdin.buffer.read()))
    print(reason, file=sys.stderr)
    print(decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
