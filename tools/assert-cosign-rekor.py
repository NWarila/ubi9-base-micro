#!/usr/bin/env python3
"""Assert cosign verification JSON includes Rekor transparency-log bundles."""

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


def run_self_test() -> None:
    good = [
        {
            "optional": {
                "Bundle": {
                    "SignedEntryTimestamp": "set",
                    "Payload": {
                        "logIndex": 7,
                        "integratedTime": 1700000000,
                        "logID": "abc",
                    },
                }
            }
        }
    ]
    bad = [{"optional": {}}]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        good_path = root / "good.json"
        bad_path = root / "bad.json"
        good_path.write_text(json.dumps(good), encoding="utf-8")
        bad_path.write_text(json.dumps(bad), encoding="utf-8")
        assert_rekor(good_path, "self-test-good")
        try:
            assert_rekor(bad_path, "self-test-bad")
        except SystemExit:
            pass
        else:
            raise SystemExit("self-test missing Rekor bundle unexpectedly passed")
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
