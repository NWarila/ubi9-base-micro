#!/usr/bin/env python3
"""Assert verified SLSA provenance uses the expected builder ID."""

from __future__ import annotations

import argparse
import base64
import json
import tempfile
from pathlib import Path
from typing import Any, cast


def load_records(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        raise SystemExit(f"{path} is empty")
    try:
        loaded = json.loads(raw)
        records = loaded if isinstance(loaded, list) else [loaded]
    except json.JSONDecodeError:
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    return [record for record in records if isinstance(record, dict)]


def decode_statement(record: dict[str, Any]) -> dict[str, Any] | None:
    payload = record.get("payload")
    if not isinstance(payload, str) or not payload:
        return None
    payload += "=" * (-len(payload) % 4)
    decoded = json.loads(base64.b64decode(payload))
    if not isinstance(decoded, dict):
        return None
    return cast(dict[str, Any], decoded)


def builder_id_from_statement(statement: dict[str, Any]) -> str | None:
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return None
    legacy = predicate.get("builder")
    if isinstance(legacy, dict):
        legacy_id = legacy.get("id")
        if isinstance(legacy_id, str):
            return legacy_id
    run_details = predicate.get("runDetails")
    if isinstance(run_details, dict):
        builder = run_details.get("builder")
        if isinstance(builder, dict):
            builder_id = builder.get("id")
            if isinstance(builder_id, str):
                return builder_id
    return None


def assert_builder(path: Path, expected: str) -> None:
    found: list[str] = []
    for record in load_records(path):
        statement = decode_statement(record)
        if statement is None:
            continue
        builder_id = builder_id_from_statement(statement)
        if builder_id:
            found.append(builder_id)

    if expected not in found:
        raise SystemExit(
            "expected SLSA builderID not found: " + expected + "; found: " + (", ".join(found) if found else "<none>")
        )
    print(f"SLSA builderID verified: {expected}")


def statement_record(builder_id: str) -> dict[str, str]:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"runDetails": {"builder": {"id": builder_id}}},
    }
    payload = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    return {"payload": payload}


def run_self_test() -> None:
    expected = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        good = root / "good.json"
        bad = root / "bad.json"
        good.write_text(json.dumps([statement_record(expected)]), encoding="utf-8")
        bad.write_text(json.dumps([statement_record("https://example.invalid/builder")]), encoding="utf-8")
        assert_builder(good, expected)
        try:
            assert_builder(bad, expected)
        except SystemExit:
            pass
        else:
            raise SystemExit("self-test wrong builderID unexpectedly passed")
    print("SLSA builderID assertion self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--builder-id")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if args.attestation is None or not args.builder_id:
        raise SystemExit("--attestation and --builder-id are required unless --self-test is used")
    assert_builder(args.attestation, args.builder_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
