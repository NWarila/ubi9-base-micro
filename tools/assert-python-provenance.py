#!/usr/bin/env python3
# Purpose: Enforce exact source, subject, and ref policy on verified base-python SLSA provenance
# Role: gate
# Micro-container candidate: yes - pure-stdlib, slsa-verifier-output-in/exit-out, has --self-test

"""Validate only provenance already authenticated by pinned ``slsa-verifier``."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v0.2"
BUILDER_ID = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
REPOSITORY = "github.com/NWarila/ubi9-base-micro"
WORKFLOW = ".github/workflows/publish-python.yaml"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ProvenanceError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise ProvenanceError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate provenance object member: {key}")
        result[key] = value
    return result


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise ProvenanceError(f"verified provenance is invalid JSON: {exc}") from exc


def validate(statement: Any, *, image: str, digest: str, sha: str, ref: str) -> None:
    require(isinstance(statement, dict), "verified provenance must be one in-toto statement object")
    require(DIGEST.fullmatch(digest) is not None, "expected index digest must be sha256 plus 64 lowercase hex")
    require(SHA.fullmatch(sha) is not None, "expected source digest must be 40 lowercase hex")
    require(
        ref == "refs/heads/main" or ref.startswith("refs/tags/python/v"),
        "expected source ref is not a supported publish ref",
    )
    require(statement.get("_type") == STATEMENT_TYPE, "SLSA statement type mismatch")
    require(statement.get("predicateType") == PREDICATE_TYPE, "SLSA predicate type mismatch")

    subjects = statement.get("subject")
    require(isinstance(subjects, list) and len(subjects) == 1, "SLSA provenance must contain exactly one index subject")
    subject = subjects[0]
    require(isinstance(subject, dict) and set(subject) == {"name", "digest"}, "SLSA subject key set mismatch")
    require(subject.get("name") == image, "SLSA subject image name mismatch")
    subject_digest = subject.get("digest")
    require(
        isinstance(subject_digest, dict) and set(subject_digest) == {"sha256"}, "SLSA subject digest key set mismatch"
    )
    require(subject_digest.get("sha256") == digest.removeprefix("sha256:"), "SLSA subject index digest mismatch")

    predicate = statement.get("predicate")
    require(isinstance(predicate, dict), "SLSA predicate must be an object")
    builder = predicate.get("builder")
    require(isinstance(builder, dict) and builder.get("id") == BUILDER_ID, "SLSA builder id mismatch")
    invocation = predicate.get("invocation")
    require(isinstance(invocation, dict), "SLSA invocation must be an object")
    config_source = invocation.get("configSource")
    require(isinstance(config_source, dict), "SLSA configSource must be an object")
    source_uri = f"git+https://{REPOSITORY}@{ref}"
    require(config_source.get("uri") == source_uri, "SLSA configSource repository/ref mismatch")
    require(config_source.get("entryPoint") == WORKFLOW, "SLSA configSource workflow path mismatch")
    source_digest = config_source.get("digest")
    require(
        isinstance(source_digest, dict) and set(source_digest) == {"sha1"}, "SLSA configSource digest key set mismatch"
    )
    require(source_digest.get("sha1") == sha, "SLSA configSource source digest mismatch")

    environment = invocation.get("environment")
    require(isinstance(environment, dict), "SLSA invocation environment must be an object")
    require(environment.get("github_sha1") == sha, "SLSA github_sha1 mismatch")
    require(environment.get("github_ref") == ref, "SLSA github_ref mismatch")

    materials = predicate.get("materials")
    require(
        isinstance(materials, list) and len(materials) == 1, "SLSA materials must contain exactly one source material"
    )
    material = materials[0]
    require(isinstance(material, dict), "SLSA source material must be an object")
    require(material.get("uri") == source_uri, "SLSA material repository/ref mismatch")
    material_digest = material.get("digest")
    require(
        isinstance(material_digest, dict) and set(material_digest) == {"sha1"}, "SLSA material digest key set mismatch"
    )
    require(material_digest.get("sha1") == sha, "SLSA material source digest mismatch")


def sample(image: str, digest: str, sha: str, ref: str) -> dict[str, Any]:
    source_uri = f"git+https://{REPOSITORY}@{ref}"
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": image, "digest": {"sha256": digest.removeprefix("sha256:")}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "builder": {"id": BUILDER_ID},
            "invocation": {
                "configSource": {"uri": source_uri, "digest": {"sha1": sha}, "entryPoint": WORKFLOW},
                "environment": {"github_sha1": sha, "github_ref": ref},
            },
            "materials": [{"uri": source_uri, "digest": {"sha1": sha}}],
        },
    }


def self_test() -> None:
    image = "ghcr.io/nwarila/ubi9-base-python"
    digest = "sha256:" + "a" * 64
    sha = "b" * 40
    ref = "refs/heads/main"
    baseline = sample(image, digest, sha, ref)
    validate(baseline, image=image, digest=digest, sha=sha, ref=ref)
    mutations: list[tuple[str, str, Any]] = []

    def add(label: str, reason: str, mutate: Any) -> None:
        candidate = copy.deepcopy(baseline)
        mutate(candidate)
        mutations.append((label, reason, candidate))

    add(
        "missing subject",
        "SLSA provenance must contain exactly one index subject",
        lambda value: value.__setitem__("subject", []),
    )
    add(
        "duplicate subject",
        "SLSA provenance must contain exactly one index subject",
        lambda value: value["subject"].append(value["subject"][0]),
    )
    add(
        "wrong subject name",
        "SLSA subject image name mismatch",
        lambda value: value["subject"][0].__setitem__("name", "wrong"),
    )
    add(
        "wrong subject digest",
        "SLSA subject index digest mismatch",
        lambda value: value["subject"][0]["digest"].__setitem__("sha256", "c" * 64),
    )
    add(
        "wrong builder",
        "SLSA builder id mismatch",
        lambda value: value["predicate"]["builder"].__setitem__("id", "wrong"),
    )
    add(
        "wrong config repository",
        "SLSA configSource repository/ref mismatch",
        lambda value: value["predicate"]["invocation"]["configSource"].__setitem__(
            "uri", "git+https://github.com/other/repo@refs/heads/main"
        ),
    )
    add(
        "wrong config SHA",
        "SLSA configSource source digest mismatch",
        lambda value: value["predicate"]["invocation"]["configSource"]["digest"].__setitem__("sha1", "c" * 40),
    )
    add(
        "wrong config ref",
        "SLSA configSource repository/ref mismatch",
        lambda value: value["predicate"]["invocation"]["configSource"].__setitem__(
            "uri", f"git+https://{REPOSITORY}@refs/heads/other"
        ),
    )
    add(
        "wrong workflow",
        "SLSA configSource workflow path mismatch",
        lambda value: value["predicate"]["invocation"]["configSource"].__setitem__("entryPoint", "wrong"),
    )
    add(
        "missing github SHA",
        "SLSA github_sha1 mismatch",
        lambda value: value["predicate"]["invocation"]["environment"].pop("github_sha1"),
    )
    add(
        "conflicting github ref",
        "SLSA github_ref mismatch",
        lambda value: value["predicate"]["invocation"]["environment"].__setitem__("github_ref", "refs/heads/other"),
    )
    add(
        "missing material",
        "SLSA materials must contain exactly one source material",
        lambda value: value["predicate"].__setitem__("materials", []),
    )
    add(
        "duplicate material",
        "SLSA materials must contain exactly one source material",
        lambda value: value["predicate"]["materials"].append(value["predicate"]["materials"][0]),
    )
    add(
        "conflicting material ref",
        "SLSA material repository/ref mismatch",
        lambda value: value["predicate"]["materials"][0].__setitem__(
            "uri", f"git+https://{REPOSITORY}@refs/heads/other"
        ),
    )
    add(
        "conflicting material SHA",
        "SLSA material source digest mismatch",
        lambda value: value["predicate"]["materials"][0]["digest"].__setitem__("sha1", "c" * 40),
    )
    for label, expected_reason, candidate in mutations:
        try:
            validate(candidate, image=image, digest=digest, sha=sha, ref=ref)
        except ProvenanceError as exc:
            require(str(exc) == expected_reason, f"self-test {label} rejected for the wrong reason: {exc}")
            print(f"python provenance negative rejected [{label}] reason={exc}")
        else:
            raise ProvenanceError(f"self-test mutation unexpectedly passed: {label}")
    print(f"python provenance-policy self-test passed: baseline plus {len(mutations)} discriminating mutations")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--digest")
    parser.add_argument("--sha")
    parser.add_argument("--ref")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        require(
            args.provenance and args.image and args.digest and args.sha and args.ref,
            "provenance, image, digest, SHA, and ref are required",
        )
        validate(load(args.provenance), image=args.image, digest=args.digest, sha=args.sha, ref=args.ref)
        print(
            "python provenance policy passed: "
            f"image={args.image}@{args.digest} source={REPOSITORY}@{args.ref} sha={args.sha}"
        )
        return 0
    except (ProvenanceError, OSError) as exc:
        print(f"python provenance policy failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
