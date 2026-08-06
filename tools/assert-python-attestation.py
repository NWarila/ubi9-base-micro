#!/usr/bin/env python3
# Purpose: Semantically validate Cosign-verified base-python attestation payloads
# Role: gate
# Micro-container candidate: yes - pure-stdlib, verified-JSON-in/exit-out, has --self-test

"""Bind verified DSSE statements to one exact image subject and predicate set."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any, cast

STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
WIRE_PREDICATE_TYPES = {
    "spdxjson": "https://spdx.dev/Document",
    "cyclonedx": "https://cyclonedx.org/bom",
    "openvex": "https://openvex.dev/ns",
    "slsaprovenance": "https://slsa.dev/provenance/v0.2",
}


class AttestationError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise AttestationError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def parse_json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AttestationError(f"{label} is not valid JSON: {exc}") from exc


def load_verified_records(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8").strip()
    require(bool(raw), "Cosign verification output is empty")
    try:
        loaded = parse_json(raw, "Cosign verification output")
        candidates = loaded if isinstance(loaded, list) else [loaded]
    except AttestationError:
        candidates = [parse_json(line, "Cosign verification JSONL record") for line in raw.splitlines() if line.strip()]
    require(bool(candidates), "Cosign verification output contains no records")
    records: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates):
        require(isinstance(candidate, dict), f"Cosign record {index} must be an object")
        records.append(candidate)
    return records


def decode_statements(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        payload = record.get("payload")
        signatures = record.get("signatures")
        require(isinstance(payload, str) and payload, f"Cosign record {index} has no DSSE payload")
        require(
            isinstance(signatures, list)
            and signatures
            and all(
                isinstance(signature, dict) and isinstance(signature.get("sig"), str) and signature["sig"]
                for signature in signatures
            ),
            f"Cosign record {index} has no DSSE signature",
        )
        try:
            decoded = base64.b64decode(cast(str, payload), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise AttestationError(f"Cosign record {index} payload is not valid base64 JSON") from exc
        statement = parse_json(decoded, f"Cosign record {index} statement")
        require(isinstance(statement, dict), f"Cosign record {index} statement must be an object")
        statements.append(statement)
    return statements


def validate_statement_subject(statement: dict[str, Any], image: str, digest: str, predicate_type: str) -> None:
    require(statement.get("_type") == STATEMENT_TYPE, "verified statement type mismatch")
    expected_wire_type = WIRE_PREDICATE_TYPES.get(predicate_type, predicate_type)
    require(statement.get("predicateType") == expected_wire_type, "verified predicateType mismatch")
    subjects = statement.get("subject")
    require(isinstance(subjects, list) and len(subjects) == 1, "verified statement must contain exactly one subject")
    subject = cast(list[Any], subjects)[0]
    require(isinstance(subject, dict) and set(subject) == {"name", "digest"}, "verified subject key set mismatch")
    require(subject.get("name") == image, "verified subject name mismatch")
    observed_digest = subject.get("digest")
    require(
        isinstance(observed_digest, dict) and set(observed_digest) == {"sha256"},
        "verified subject digest must contain only sha256",
    )
    require(observed_digest.get("sha256") == digest.removeprefix("sha256:"), "verified subject digest mismatch")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def verify(
    *,
    records: list[dict[str, Any]],
    image: str,
    digest: str,
    predicate_type: str,
    expected_predicates: list[Any] | None = None,
    expected_statement: dict[str, Any] | None = None,
    envelope_only: bool = False,
) -> list[Any]:
    require(DIGEST.fullmatch(digest) is not None, "expected subject digest must be sha256 plus 64 lowercase hex")
    statements = decode_statements(records)
    for statement in statements:
        validate_statement_subject(statement, image, digest, predicate_type)
    if envelope_only:
        predicates = [statement.get("predicate") for statement in statements]
        require(all(predicate is not None for predicate in predicates), "verified statement is missing its predicate")
        return predicates
    if expected_statement is not None:
        require(len(statements) == 1, "trust-contract verification must return exactly one statement")
        require(
            statements[0] == expected_statement,
            "verified trust-contract statement does not exactly match the generated statement",
        )
        return [statements[0].get("predicate")]

    require(expected_predicates is not None and expected_predicates, "at least one expected predicate is required")
    assert expected_predicates is not None
    observed_predicates = [statement.get("predicate") for statement in statements]
    require(
        all(predicate is not None for predicate in observed_predicates), "verified statement is missing its predicate"
    )
    expected_set = {canonical(predicate) for predicate in expected_predicates}
    observed_set = {canonical(predicate) for predicate in observed_predicates}
    require(len(expected_set) == len(expected_predicates), "expected predicate inputs contain a duplicate")
    require(observed_set == expected_set, "verified predicate set does not exactly match the generated predicates")
    return observed_predicates


def envelope(statement: dict[str, Any]) -> dict[str, Any]:
    payload = base64.b64encode(json.dumps(statement, sort_keys=True).encode()).decode()
    return {"payload": payload, "signatures": [{"sig": "c2ln"}]}


def self_test() -> None:
    image = "ghcr.io/nwarila/ubi9-base-python"
    digest = "sha256:" + "a" * 64
    predicate_type = "example/type"
    predicate = {"value": "expected"}
    baseline = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": image, "digest": {"sha256": digest.removeprefix("sha256:")}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }
    verify(
        records=[envelope(baseline)],
        image=image,
        digest=digest,
        predicate_type=predicate_type,
        expected_predicates=[predicate],
    )
    mutations: list[tuple[str, str, Any]] = []

    def add(label: str, reason: str, mutate: Any) -> None:
        candidate = copy.deepcopy(baseline)
        mutate(candidate)
        mutations.append((label, reason, envelope(candidate)))

    add("wrong statement type", "verified statement type mismatch", lambda value: value.__setitem__("_type", "wrong"))
    add(
        "wrong subject name",
        "verified subject name mismatch",
        lambda value: value["subject"][0].__setitem__("name", "wrong"),
    )
    add(
        "wrong digest key",
        "verified subject digest must contain only sha256",
        lambda value: value["subject"][0].__setitem__("digest", {"sha512": "a" * 64}),
    )
    add(
        "wrong digest",
        "verified subject digest mismatch",
        lambda value: value["subject"][0]["digest"].__setitem__("sha256", "b" * 64),
    )
    add(
        "duplicate subject",
        "verified statement must contain exactly one subject",
        lambda value: value["subject"].append(value["subject"][0]),
    )
    add(
        "extra subject",
        "verified statement must contain exactly one subject",
        lambda value: value["subject"].append({"name": "other", "digest": {"sha256": "a" * 64}}),
    )
    add(
        "wrong predicate type",
        "verified predicateType mismatch",
        lambda value: value.__setitem__("predicateType", "wrong"),
    )
    add(
        "wrong predicate",
        "verified predicate set does not exactly match the generated predicates",
        lambda value: value.__setitem__("predicate", {"value": "wrong"}),
    )
    for label, reason, record in mutations:
        try:
            verify(
                records=[record],
                image=image,
                digest=digest,
                predicate_type=predicate_type,
                expected_predicates=[predicate],
            )
        except AttestationError as exc:
            require(str(exc) == reason, f"self-test {label} rejected for the wrong reason: {exc}")
            print(f"python attestation negative rejected [{label}] reason={exc}")
        else:
            raise AttestationError(f"self-test mutation unexpectedly passed: {label}")

    try:
        verify(
            records=[{"payload": envelope(baseline)["payload"], "signatures": []}],
            image=image,
            digest=digest,
            predicate_type=predicate_type,
            expected_predicates=[predicate],
        )
    except AttestationError as exc:
        require(str(exc) == "Cosign record 0 has no DSSE signature", f"signature fixture wrong reason: {exc}")
        print(f"python attestation negative rejected [missing signature] reason={exc}")
    else:
        raise AttestationError("missing-signature fixture unexpectedly passed")
    print(f"python attestation semantic self-test passed: baseline plus {len(mutations) + 1} negative fixtures")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verified", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--digest")
    parser.add_argument("--predicate-type")
    parser.add_argument("--expected-predicate", type=Path, action="append", default=[])
    parser.add_argument("--expected-statement", type=Path)
    parser.add_argument("--write-predicate", type=Path)
    parser.add_argument("--envelope-only", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        require(
            args.verified and args.image and args.digest and args.predicate_type,
            "verified path, image, digest, and predicate type are required",
        )
        require(
            sum(bool(value) for value in (args.expected_predicate, args.expected_statement, args.envelope_only)) == 1,
            "provide exactly one expected-predicate set, expected statement, or --envelope-only",
        )
        expected_predicates = [
            parse_json(path.read_text(encoding="utf-8"), str(path)) for path in args.expected_predicate
        ]
        expected_statement = (
            parse_json(args.expected_statement.read_text(encoding="utf-8"), str(args.expected_statement))
            if args.expected_statement
            else None
        )
        require(
            expected_statement is None or isinstance(expected_statement, dict), "expected statement must be an object"
        )
        observed = verify(
            records=load_verified_records(args.verified),
            image=args.image,
            digest=args.digest,
            predicate_type=args.predicate_type,
            expected_predicates=expected_predicates or None,
            expected_statement=expected_statement,
            envelope_only=args.envelope_only,
        )
        if args.write_predicate:
            require(len(observed) == 1, "--write-predicate requires exactly one verified predicate")
            args.write_predicate.parent.mkdir(parents=True, exist_ok=True)
            args.write_predicate.write_text(json.dumps(observed[0], sort_keys=True) + "\n", encoding="utf-8")
        print(f"verified attestation semantics passed: type={args.predicate_type} predicates={len(observed)}")
        return 0
    except (AttestationError, OSError) as exc:
        print(f"python attestation semantic verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
