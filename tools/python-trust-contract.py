#!/usr/bin/env python3
# Purpose: Generate and validate the base-python digest-to-source trust-contract statement
# Role: tooling
# Micro-container candidate: yes - deterministic pure-stdlib JSON tooling with self-test

"""Generate and validate the closed base-python trust-contract wire format."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any, cast

STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
PREDICATE_TYPE = "https://nwarila.dev/attestations/python-trust-contract/v1"
PACKAGE = "ghcr.io/nwarila/ubi9-base-python"
WORKFLOW = ".github/workflows/publish-python.yaml"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")


class TrustError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise TrustError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise TrustError(f"invalid JSON in {path}: {exc}") from exc


def contract_predicate_type(contract: dict[str, Any]) -> str:
    try:
        image_name = contract["image"]["name"]
        predicate_type = contract["provenance"]["attestation_predicate_types"]["trust_contract"]
    except (KeyError, TypeError) as exc:
        raise TrustError("live image contract is missing the trust_contract binding") from exc
    require(image_name == "ubi9-base-python", "live image contract names the wrong package")
    require(predicate_type == PREDICATE_TYPE, "live image contract trust_contract URI mismatch")
    return cast(str, predicate_type)


def expected_statement(*, digest: str, tree: str, commit: str, workflow: str = WORKFLOW) -> dict[str, Any]:
    require(SHA256.fullmatch(digest) is not None, "index digest must be 64 lowercase hex characters without a prefix")
    require(SHA1.fullmatch(tree) is not None, "images/python tree must be a 40-character lowercase Git object id")
    require(SHA1.fullmatch(commit) is not None, "commit must be exactly 40 lowercase hex characters")
    require(workflow == WORKFLOW, f"workflow must be exactly {WORKFLOW}")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": PACKAGE, "digest": {"sha256": digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "package": PACKAGE,
            "tree": tree,
            "workflow": workflow,
            "commit": commit,
        },
    }


def validate_statement(
    statement: Any,
    *,
    contract: dict[str, Any],
    digest: str,
    tree: str,
    commit: str,
    workflow: str = WORKFLOW,
) -> None:
    contract_predicate_type(contract)
    expected = expected_statement(digest=digest, tree=tree, commit=commit, workflow=workflow)
    require(isinstance(statement, dict), "in-toto statement must be one top-level object")
    require(set(statement) == set(expected), "in-toto statement key set must be exact")
    require(statement.get("_type") == STATEMENT_TYPE, "in-toto statement type mismatch")
    subjects = statement.get("subject")
    require(isinstance(subjects, list) and len(subjects) == 1, "in-toto statement must contain exactly one subject")
    subject = subjects[0]
    require(isinstance(subject, dict) and set(subject) == {"name", "digest"}, "in-toto subject key set must be exact")
    require(subject.get("name") == PACKAGE, "in-toto subject name mismatch")
    subject_digest = subject.get("digest")
    require(
        isinstance(subject_digest, dict) and set(subject_digest) == {"sha256"},
        "in-toto subject digest must contain only the sha256 key",
    )
    require(subject_digest.get("sha256") == digest, "in-toto subject digest mismatch")
    require(SHA256.fullmatch(subject_digest["sha256"]) is not None, "in-toto subject digest encoding is invalid")
    require(statement.get("predicateType") == PREDICATE_TYPE, "trust-contract predicateType mismatch")
    predicate = statement.get("predicate")
    require(isinstance(predicate, dict), "trust-contract predicate must be one object")
    require(
        set(predicate) == {"package", "tree", "workflow", "commit"},
        "trust-contract predicate key set must be exactly package, tree, workflow, commit",
    )
    require(
        all(isinstance(value, str) for value in predicate.values()), "trust-contract predicate values must be strings"
    )
    for key, value in expected["predicate"].items():
        require(predicate.get(key) == value, f"trust-contract predicate {key} mismatch")


def self_test() -> None:
    digest = "a" * 64
    tree = "b" * 40
    commit = "c" * 40
    contract = {
        "image": {"name": "ubi9-base-python"},
        "provenance": {"attestation_predicate_types": {"trust_contract": PREDICATE_TYPE}},
    }
    baseline = expected_statement(digest=digest, tree=tree, commit=commit)
    validate_statement(baseline, contract=contract, digest=digest, tree=tree, commit=commit)

    mutations: list[tuple[str, str, Any]] = []

    def add(label: str, reason: str, mutate: Any) -> None:
        candidate = copy.deepcopy(baseline)
        mutate(candidate)
        mutations.append((label, reason, candidate))

    add("wrong statement type", "in-toto statement type mismatch", lambda value: value.__setitem__("_type", "wrong"))
    add(
        "wrong subject name",
        "in-toto subject name mismatch",
        lambda value: value["subject"][0].__setitem__("name", "wrong"),
    )
    add(
        "wrong digest key",
        "in-toto subject digest must contain only the sha256 key",
        lambda value: value["subject"][0].__setitem__("digest", {"sha512": digest}),
    )
    add(
        "uppercase digest",
        "in-toto subject digest mismatch",
        lambda value: value["subject"][0]["digest"].__setitem__("sha256", digest.upper()),
    )
    add(
        "duplicate subject",
        "in-toto statement must contain exactly one subject",
        lambda value: value["subject"].append(value["subject"][0]),
    )
    add(
        "extra subject",
        "in-toto statement must contain exactly one subject",
        lambda value: value["subject"].append({"name": "other", "digest": {"sha256": digest}}),
    )
    add(
        "child digest",
        "in-toto subject digest mismatch",
        lambda value: value["subject"][0]["digest"].__setitem__("sha256", "d" * 64),
    )
    add(
        "missing predicate field",
        "trust-contract predicate key set must be exactly package, tree, workflow, commit",
        lambda value: value["predicate"].pop("tree"),
    )
    add(
        "extra predicate field",
        "trust-contract predicate key set must be exactly package, tree, workflow, commit",
        lambda value: value["predicate"].__setitem__("extra", "x"),
    )
    add(
        "nested predicate",
        "trust-contract predicate values must be strings",
        lambda value: value["predicate"].__setitem__("tree", {"id": tree}),
    )
    add(
        "wrong package",
        "trust-contract predicate package mismatch",
        lambda value: value["predicate"].__setitem__("package", "wrong"),
    )
    add(
        "wrong tree",
        "trust-contract predicate tree mismatch",
        lambda value: value["predicate"].__setitem__("tree", "d" * 40),
    )
    add(
        "wrong workflow",
        "trust-contract predicate workflow mismatch",
        lambda value: value["predicate"].__setitem__("workflow", "wrong"),
    )
    add(
        "wrong commit",
        "trust-contract predicate commit mismatch",
        lambda value: value["predicate"].__setitem__("commit", "d" * 40),
    )

    for label, expected_reason, candidate in mutations:
        try:
            validate_statement(candidate, contract=contract, digest=digest, tree=tree, commit=commit)
        except TrustError as exc:
            require(str(exc) == expected_reason, f"self-test {label} rejected for the wrong reason: {exc}")
            print(f"python trust-contract negative rejected [{label}] reason={exc}")
        else:
            raise TrustError(f"self-test mutation unexpectedly passed: {label}")
    print(f"python trust-contract self-test passed: baseline plus {len(mutations)} discriminating mutations")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=Path("images/python/contracts/image-manifest.json"))
    parser.add_argument("--digest")
    parser.add_argument("--tree")
    parser.add_argument("--commit")
    parser.add_argument("--workflow", default=WORKFLOW)
    parser.add_argument("--predicate-out", type=Path)
    parser.add_argument("--statement-out", type=Path)
    parser.add_argument("--validate-statement", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        require(args.digest and args.tree and args.commit, "--digest, --tree, and --commit are required")
        contract = load_json(args.contract)
        require(isinstance(contract, dict), "live image contract must be a JSON object")
        statement = expected_statement(
            digest=args.digest,
            tree=args.tree,
            commit=args.commit,
            workflow=args.workflow,
        )
        contract_predicate_type(contract)
        if args.validate_statement:
            validate_statement(
                load_json(args.validate_statement),
                contract=contract,
                digest=args.digest,
                tree=args.tree,
                commit=args.commit,
                workflow=args.workflow,
            )
            print(f"trust-contract statement valid: {args.validate_statement}")
            return 0
        require(args.predicate_out and args.statement_out, "--predicate-out and --statement-out are required")
        args.predicate_out.parent.mkdir(parents=True, exist_ok=True)
        args.statement_out.parent.mkdir(parents=True, exist_ok=True)
        args.predicate_out.write_text(json.dumps(statement["predicate"], sort_keys=True) + "\n", encoding="utf-8")
        args.statement_out.write_text(json.dumps(statement, sort_keys=True) + "\n", encoding="utf-8")
        validate_statement(
            statement, contract=contract, digest=args.digest, tree=args.tree, commit=args.commit, workflow=args.workflow
        )
        print(f"wrote trust-contract predicate: {args.predicate_out}")
        print(f"wrote trust-contract statement: {args.statement_out}")
        return 0
    except (TrustError, OSError) as exc:
        print(f"python trust-contract failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
