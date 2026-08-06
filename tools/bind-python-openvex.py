#!/usr/bin/env python3
# Purpose: Bind reviewed base-python OpenVEX source documents to one published child digest
# Role: tooling
# Micro-container candidate: yes - deterministic pure-stdlib JSON transformer with self-test

"""Create per-child OpenVEX predicates from the reviewed source documents."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

IMAGE_REF = re.compile(r"^ghcr\.io/nwarila/ubi9-base-python@sha256:[0-9a-f]{64}$")


class VexBindingError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise VexBindingError(message)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VexBindingError(f"invalid OpenVEX JSON in {path}: {exc}") from exc
    require(isinstance(value, dict), f"OpenVEX document must be an object: {path}")
    return cast(dict[str, Any], value)


def bind(document: dict[str, Any], image_ref: str) -> dict[str, Any]:
    require(IMAGE_REF.fullmatch(image_ref) is not None, "published OpenVEX image reference is invalid")
    require(document.get("@context") == "https://openvex.dev/ns/v0.2.0", "OpenVEX context mismatch")
    statements = document.get("statements")
    require(isinstance(statements, list) and statements, "OpenVEX document requires a non-empty statements array")
    result = copy.deepcopy(document)
    for index, statement in enumerate(result["statements"]):
        require(isinstance(statement, dict), f"OpenVEX statement {index} must be an object")
        require(isinstance(statement.get("vulnerability"), dict), f"OpenVEX statement {index} requires vulnerability")
        statement["products"] = [{"@id": image_ref}]
    validate_bound(result, image_ref)
    return result


def validate_bound(document: dict[str, Any], image_ref: str) -> None:
    require(IMAGE_REF.fullmatch(image_ref) is not None, "published OpenVEX image reference is invalid")
    statements = document.get("statements")
    require(isinstance(statements, list) and statements, "bound OpenVEX document requires statements")
    for index, statement in enumerate(cast(list[Any], statements)):
        require(isinstance(statement, dict), f"bound OpenVEX statement {index} must be an object")
        require(
            statement.get("products") == [{"@id": image_ref}],
            f"bound OpenVEX statement {index} products must contain only the published child digest",
        )


def self_test() -> None:
    image_ref = "ghcr.io/nwarila/ubi9-base-python@sha256:" + "a" * 64
    source: dict[str, Any] = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "example",
        "author": "example",
        "timestamp": "2026-01-01T00:00:00Z",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": "CVE-0000-0000"},
                "products": [{"@id": "local/example"}],
                "status": "affected",
            }
        ],
    }
    bound = bind(source, image_ref)
    require(source["statements"][0]["products"] == [{"@id": "local/example"}], "binding mutated its source")
    validate_bound(bound, image_ref)
    mutations: list[tuple[str, str, Callable[[dict[str, Any]], None]]] = [
        (
            "wrong product",
            "bound OpenVEX statement 0 products must contain only the published child digest",
            lambda value: value["statements"][0].__setitem__("products", [{"@id": "wrong"}]),
        ),
        (
            "extra product",
            "bound OpenVEX statement 0 products must contain only the published child digest",
            lambda value: value["statements"][0]["products"].append({"@id": "other"}),
        ),
        (
            "missing product",
            "bound OpenVEX statement 0 products must contain only the published child digest",
            lambda value: value["statements"][0].pop("products"),
        ),
    ]
    for label, expected, mutate in mutations:
        candidate = copy.deepcopy(bound)
        mutate(candidate)
        try:
            validate_bound(candidate, image_ref)
        except VexBindingError as exc:
            require(str(exc) == expected, f"self-test {label} rejected for the wrong reason: {exc}")
            print(f"python OpenVEX negative rejected [{label}] reason={exc}")
        else:
            raise VexBindingError(f"self-test mutation unexpectedly passed: {label}")
    try:
        bind({"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}, image_ref)
    except VexBindingError as exc:
        require(
            str(exc) == "OpenVEX document requires a non-empty statements array", f"empty fixture wrong reason: {exc}"
        )
        print(f"python OpenVEX negative rejected [empty statements] reason={exc}")
    else:
        raise VexBindingError("empty OpenVEX fixture unexpectedly passed")
    print(f"python OpenVEX binding self-test passed: baseline plus {len(mutations) + 1} negative fixtures")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=Path("images/python/vex"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--image-ref")
    parser.add_argument("--validate", type=Path, action="append", default=[])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        require(args.output_dir and args.image_ref, "--output-dir and --image-ref are required")
        source_files = sorted(args.source_dir.glob("*.json"))
        require(bool(source_files), "reviewed OpenVEX source directory contains no JSON documents")
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for source_path in source_files:
            output_path = args.output_dir / source_path.name
            output_path.write_text(
                json.dumps(bind(load(source_path), args.image_ref), indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            validate_bound(load(output_path), args.image_ref)
            print(f"wrote child-bound OpenVEX predicate: {output_path}")
        return 0
    except (VexBindingError, OSError) as exc:
        print(f"python OpenVEX binding failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
