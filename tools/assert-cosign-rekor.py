#!/usr/bin/env python3
"""Assert cosign signature verification JSON includes Rekor tlog bundles."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any


def load_records(path: Path) -> list[Any]:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        raise SystemExit(f"{path} is empty")
    try:
        loaded = json.loads(raw)
        return loaded if isinstance(loaded, list) else [loaded]
    except json.JSONDecodeError:
        return [json.loads(line) for line in raw.splitlines() if line.strip()]


def get_key(mapping: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def has_rekor_bundle(value: Any) -> bool:
    if isinstance(value, list):
        return any(has_rekor_bundle(item) for item in value)
    if not isinstance(value, dict):
        return False

    payload = get_key(value, "Payload", "payload")
    set_value = get_key(value, "SignedEntryTimestamp", "signedEntryTimestamp")
    if isinstance(payload, dict) and set_value:
        has_log_index = get_key(payload, "logIndex", "log_index") is not None
        has_integrated_time = get_key(payload, "integratedTime", "integrated_time") is not None
        has_log_id = get_key(payload, "logID", "logId", "log_id") is not None
        if has_log_index and has_integrated_time and has_log_id:
            return True

    return any(has_rekor_bundle(child) for child in value.values())


def assert_rekor(path: Path, kind: str) -> None:
    records = load_records(path)
    if not records:
        raise SystemExit(f"{kind}: no cosign verification records")
    missing = [index for index, record in enumerate(records, start=1) if not has_rekor_bundle(record)]
    if missing:
        raise SystemExit(f"{kind}: missing Rekor bundle in record(s): {missing}")
    print(f"{kind}: Rekor tlog bundle present in {len(records)} cosign record(s)")


def expect_rekor_failure(path: Path, kind: str) -> None:
    try:
        assert_rekor(path, kind)
    except SystemExit:
        return
    raise SystemExit(f"{kind} unexpectedly passed without a Rekor bundle")


def run_self_test() -> None:
    signature_with_bundle = [
        {
            "critical": {
                "identity": {"docker-reference": "ghcr.io/nwarila/ubi9-base-micro"},
                "image": {"docker-manifest-digest": "sha256:" + "1" * 64},
                "type": "cosign container image signature",
            },
            "optional": {
                "Bundle": {
                    "Payload": {
                        "logIndex": 7,
                        "integratedTime": 1700000000,
                        "logID": "abc",
                    },
                    "SignedEntryTimestamp": "MEUCIQDbundle",
                }
            },
        }
    ]
    signature_without_bundle = [
        {
            "critical": {
                "identity": {"docker-reference": "ghcr.io/nwarila/ubi9-base-micro"},
                "image": {"docker-manifest-digest": "sha256:" + "2" * 64},
                "type": "cosign container image signature",
            },
            "optional": {},
        }
    ]
    dsse_attestation_envelope = [
        {
            "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEifQ",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"keyid": "", "sig": "MEUCIQDsse"}],
        }
    ]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        good_path = root / "good.json"
        missing_path = root / "missing.json"
        dsse_path = root / "dsse.jsonl"
        good_path.write_text(json.dumps(signature_with_bundle), encoding="utf-8")
        missing_path.write_text(json.dumps(signature_without_bundle), encoding="utf-8")
        dsse_path.write_text("\n".join(json.dumps(record) for record in dsse_attestation_envelope), encoding="utf-8")
        assert_rekor(good_path, "self-test-signature-with-bundle")
        expect_rekor_failure(missing_path, "self-test-signature-missing-bundle")
        expect_rekor_failure(dsse_path, "self-test-dsse-attestation-envelope")
    print("cosign Rekor assertion self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("--kind", default="cosign verification")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if args.path is None:
        raise SystemExit("path is required unless --self-test is used")
    assert_rekor(args.path, args.kind)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
