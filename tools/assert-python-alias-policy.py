#!/usr/bin/env python3
# Purpose: Derive and enforce create-once base-python publication aliases
# Role: gate
# Micro-container candidate: yes - pure-stdlib policy with an optional Crane subprocess boundary

"""Fail closed on base-python alias spelling, collision, and post-apply state."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

IMAGE = "ghcr.io/nwarila/ubi9-base-python"
MAIN_REF = "refs/heads/main"
TAG_PREFIX = "refs/tags/python/v"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$"
)
ABSENT_MARKERS = ("MANIFEST_UNKNOWN", "NAME_UNKNOWN", "404 Not Found")


class AliasError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise AliasError(message)


def aliases(ref: str, sha: str, version: str) -> tuple[str, ...]:
    require(SHA.fullmatch(sha) is not None, "GITHUB_SHA must be exactly 40 lowercase hex characters")
    require(VERSION.fullmatch(version) is not None, "images/python/VERSION must be an exact semantic version")
    commit_alias = f"base-python-{sha[:12]}"
    if ref == MAIN_REF:
        return commit_alias, "base-python"
    expected_tag = f"{TAG_PREFIX}{version}"
    require(ref == expected_tag, f"release ref must equal {expected_tag}")
    return commit_alias, version


def check_observations(
    *,
    phase: str,
    ref: str,
    sha: str,
    version: str,
    digest: str,
    observations: dict[str, str | None],
) -> None:
    require(DIGEST.fullmatch(digest) is not None, "candidate digest must be sha256 plus 64 lowercase hex characters")
    expected_aliases = aliases(ref, sha, version)
    require(
        set(observations) == set(expected_aliases) and len(observations) == len(expected_aliases),
        "alias observation key set must exactly match the applicable aliases",
    )
    require(phase in {"pre-evidence", "pre-apply", "post-apply"}, "unknown alias policy phase")
    for alias in expected_aliases:
        observed = observations[alias]
        require(
            observed is None or DIGEST.fullmatch(observed) is not None, f"alias {alias} resolved to an invalid digest"
        )
        if phase == "post-apply":
            require(observed == digest, f"post-apply alias {alias} does not resolve to the candidate digest")
            continue
        if alias == "base-python" and ref == MAIN_REF:
            continue
        require(
            observed is None or observed == digest,
            f"create-once alias {alias} conflicts with an existing digest",
        )


def resolve(crane: str, image: str, expected_aliases: tuple[str, ...]) -> dict[str, str | None]:
    observations: dict[str, str | None] = {}
    for alias in expected_aliases:
        reference = f"{image}:{alias}"
        result = subprocess.run(
            [crane, "digest", reference],
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            observed = result.stdout.strip()
            require(DIGEST.fullmatch(observed) is not None, f"alias {alias} returned a non-digest value")
            observations[alias] = observed
            continue
        diagnostic = result.stderr + result.stdout
        require(
            any(marker in diagnostic for marker in ABSENT_MARKERS),
            f"alias {alias} could not be resolved unambiguously: {diagnostic.strip()}",
        )
        observations[alias] = None
    return observations


def self_test() -> None:
    sha = "a" * 40
    digest = "sha256:" + "b" * 64
    other = "sha256:" + "c" * 64
    version = "0.1.0"
    main_aliases = aliases(MAIN_REF, sha, version)
    tag_ref = TAG_PREFIX + version
    tag_aliases = aliases(tag_ref, sha, version)
    require(main_aliases == ("base-python-aaaaaaaaaaaa", "base-python"), "main alias spelling mismatch")
    require(tag_aliases == ("base-python-aaaaaaaaaaaa", "0.1.0"), "release alias spelling mismatch")

    positive: list[tuple[str, str, str, dict[str, str | None]]] = [
        ("absent", "pre-evidence", MAIN_REF, {main_aliases[0]: None, main_aliases[1]: None}),
        ("same digest", "pre-apply", tag_ref, {tag_aliases[0]: digest, tag_aliases[1]: digest}),
        ("moving main", "pre-apply", MAIN_REF, {main_aliases[0]: digest, main_aliases[1]: other}),
        ("post apply", "post-apply", tag_ref, {tag_aliases[0]: digest, tag_aliases[1]: digest}),
    ]
    for _label, phase, ref, observed in positive:
        check_observations(
            phase=phase,
            ref=ref,
            sha=sha,
            version=version,
            digest=digest,
            observations=observed,
        )

    negative: list[tuple[str, str, str, str, dict[str, str | None]]] = [
        (
            "conflicting commit",
            "create-once alias base-python-aaaaaaaaaaaa conflicts with an existing digest",
            "pre-evidence",
            MAIN_REF,
            {main_aliases[0]: other, main_aliases[1]: None},
        ),
        (
            "conflicting version",
            "create-once alias 0.1.0 conflicts with an existing digest",
            "pre-apply",
            tag_ref,
            {tag_aliases[0]: digest, tag_aliases[1]: other},
        ),
        (
            "moving tag after apply",
            "post-apply alias 0.1.0 does not resolve to the candidate digest",
            "post-apply",
            tag_ref,
            {tag_aliases[0]: digest, tag_aliases[1]: other},
        ),
        (
            "missing observation",
            "alias observation key set must exactly match the applicable aliases",
            "pre-apply",
            MAIN_REF,
            {main_aliases[0]: digest},
        ),
    ]
    for label, expected, phase, ref, observed in negative:
        try:
            check_observations(
                phase=phase,
                ref=ref,
                sha=sha,
                version=version,
                digest=digest,
                observations=observed,
            )
        except AliasError as exc:
            require(str(exc) == expected, f"self-test {label} rejected for the wrong reason: {exc}")
            print(f"python alias-policy negative rejected [{label}] reason={exc}")
        else:
            raise AliasError(f"self-test negative fixture unexpectedly passed: {label}")

    for bad_ref, expected in [
        ("refs/tags/v0.1.0", f"release ref must equal {tag_ref}"),
        ("refs/tags/python/v0.1.1", f"release ref must equal {tag_ref}"),
    ]:
        try:
            aliases(bad_ref, sha, version)
        except AliasError as exc:
            require(str(exc) == expected, f"tag fixture rejected for the wrong reason: {exc}")
            print(f"python alias-policy negative rejected [{bad_ref}] reason={exc}")
        else:
            raise AliasError(f"nonconforming tag unexpectedly accepted: {bad_ref}")
    print(f"python alias-policy self-test passed: {len(positive)} positive and {len(negative) + 2} negative fixtures")


def load_observations(path: Path) -> dict[str, str | None]:
    loaded: Any = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(loaded, dict), "alias observations must be a JSON object")
    require(
        all(isinstance(key, str) and (value is None or isinstance(value, str)) for key, value in loaded.items()),
        "alias observations must map strings to digests or null",
    )
    return {str(key): value if isinstance(value, str) else None for key, value in loaded.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref")
    parser.add_argument("--sha")
    parser.add_argument("--version")
    parser.add_argument("--digest")
    parser.add_argument("--phase")
    parser.add_argument("--observations", type=Path)
    parser.add_argument("--crane")
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--print-aliases", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        for name in ("ref", "sha", "version"):
            require(getattr(args, name), f"--{name} is required")
        expected_aliases = aliases(args.ref, args.sha, args.version)
        if args.print_aliases:
            print("\n".join(expected_aliases))
            return 0
        require(args.digest and args.phase, "--digest and --phase are required for policy checks")
        require(bool(args.observations) != bool(args.crane), "provide exactly one of --observations or --crane")
        observations = (
            load_observations(args.observations)
            if args.observations
            else resolve(args.crane, args.image, expected_aliases)
        )
        check_observations(
            phase=args.phase,
            ref=args.ref,
            sha=args.sha,
            version=args.version,
            digest=args.digest,
            observations=observations,
        )
        print(f"alias policy {args.phase} passed: {json.dumps(observations, sort_keys=True)}")
        return 0
    except (AliasError, json.JSONDecodeError, OSError) as exc:
        print(f"python alias policy failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
