#!/usr/bin/env python3
# Purpose: Fail unless scanner vulnerability databases are fresh and structurally usable
# Role: gate
# Micro-container candidate: yes - pure-stdlib, metadata-in/exit-out, has --self-test

"""Assert Trivy and Grype vulnerability database freshness."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, cast

DEFAULT_GRYPE_COMMAND = Path("dist/tools/grype")
DEFAULT_MAX_AGE_DAYS = 7
MIN_GRYPE_SCHEMA_MAJOR = 6
RFC3339_FRACTION = re.compile(r"^(?P<prefix>.+T\d\d:\d\d:\d\d)\.(?P<fraction>\d+)(?P<suffix>[+-]\d\d:\d\d)$")


class ScannerDbFreshnessError(Exception):
    pass


@dataclass(frozen=True)
class FreshnessResult:
    scanner: str
    timestamp_label: str
    timestamp: datetime
    age: timedelta
    detail: str

    def log_line(self, max_age: timedelta) -> str:
        return (
            f"{self.scanner} db: {self.timestamp_label}={format_timestamp(self.timestamp)} "
            f"age={format_duration(self.age)} max_age={format_duration(max_age)} {self.detail}"
        ).rstrip()


def fail(message: str) -> NoReturn:
    raise ScannerDbFreshnessError(message)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def format_duration(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    days, remainder = divmod(seconds, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f"{days}d{hours}h"
    if hours:
        return f"{hours}h{minutes}m"
    if minutes:
        return f"{minutes}m{seconds}s"
    return f"{seconds}s"


def normalize_rfc3339(value: str) -> str:
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    match = RFC3339_FRACTION.match(candidate)
    if match:
        fraction = match.group("fraction")[:6].ljust(6, "0")
        candidate = f"{match.group('prefix')}.{fraction}{match.group('suffix')}"
    return candidate


def parse_rfc3339(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        fail(f"{field} must be a non-empty RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(normalize_rfc3339(value))
    except ValueError as exc:
        raise ScannerDbFreshnessError(f"{field} is not parseable as RFC3339: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(f"{field} must include a timezone offset")
    return parsed.astimezone(UTC)


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            loaded = json.load(handle)
    except FileNotFoundError as exc:
        raise ScannerDbFreshnessError(f"{label} metadata file is missing: {path}") from exc
    except OSError as exc:
        raise ScannerDbFreshnessError(f"{label} metadata file is unreadable: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ScannerDbFreshnessError(f"{label} metadata file is malformed JSON: {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        fail(f"{label} metadata must be a JSON object: {path}")
    return cast(dict[str, Any], loaded)


def load_json_text(text: str, label: str) -> dict[str, Any]:
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScannerDbFreshnessError(f"{label} metadata output is malformed JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        fail(f"{label} metadata output must be a JSON object")
    return cast(dict[str, Any], loaded)


def run_grype_status(grype_command: Path) -> dict[str, Any]:
    result = subprocess.run(
        [str(grype_command), "db", "status", "-o", "json"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        detail = stderr or stdout or f"exit {result.returncode}"
        fail(f"grype db status failed: {detail}")
    return load_json_text(result.stdout, "grype")


def grype_schema_major(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        candidate = value.removeprefix("v").split(".", 1)[0]
        if candidate.isdecimal():
            return int(candidate)
    fail(f"grype schemaVersion is not parseable: {value!r}")


def assert_not_future(scanner: str, label: str, timestamp: datetime, now: datetime) -> timedelta:
    age = now - timestamp
    if age.total_seconds() < 0:
        fail(f"{scanner} {label} is in the future: {format_timestamp(timestamp)} > {format_timestamp(now)}")
    return age


def assert_age(scanner: str, label: str, timestamp: datetime, now: datetime, max_age: timedelta) -> timedelta:
    age = assert_not_future(scanner, label, timestamp, now)
    if age > max_age:
        fail(
            f"{scanner} DB is too old: {label}={format_timestamp(timestamp)} "
            f"age={format_duration(age)} max_age={format_duration(max_age)}"
        )
    return age


def assert_grype(status: dict[str, Any], now: datetime, max_age: timedelta) -> FreshnessResult:
    valid = status.get("valid")
    if valid is not True:
        fail(f"grype DB valid must be true, got {valid!r}")
    schema_value = status.get("schemaVersion")
    if schema_value is None:
        fail("grype DB status is missing schemaVersion")
    schema_major = grype_schema_major(schema_value)
    if schema_major < MIN_GRYPE_SCHEMA_MAJOR:
        fail(f"grype DB schema major {schema_major} is below required minimum {MIN_GRYPE_SCHEMA_MAJOR}")
    built = parse_rfc3339(status.get("built"), "grype built")
    age = assert_age("grype", "built", built, now, max_age)
    return FreshnessResult(
        scanner="grype",
        timestamp_label="built",
        timestamp=built,
        age=age,
        detail=f"schemaVersion={schema_value} valid=true",
    )


def assert_trivy(metadata: dict[str, Any], now: datetime, max_age: timedelta) -> FreshnessResult:
    downloaded_at = parse_rfc3339(metadata.get("DownloadedAt"), "trivy DownloadedAt")
    next_update = parse_rfc3339(metadata.get("NextUpdate"), "trivy NextUpdate")
    age = assert_age("trivy", "DownloadedAt", downloaded_at, now, max_age)
    if next_update <= now:
        fail(
            f"trivy NextUpdate is not in the future: "
            f"NextUpdate={format_timestamp(next_update)} now={format_timestamp(now)}"
        )
    return FreshnessResult(
        scanner="trivy",
        timestamp_label="DownloadedAt",
        timestamp=downloaded_at,
        age=age,
        detail=f"NextUpdate={format_timestamp(next_update)}",
    )


def default_trivy_metadata_path(cache_dir: Path | None) -> Path:
    if cache_dir is not None:
        return cache_dir / "db" / "metadata.json"
    env_cache = os.environ.get("TRIVY_CACHE_DIR")
    if env_cache:
        return Path(env_cache).expanduser() / "db" / "metadata.json"
    return Path.home() / ".cache" / "trivy" / "db" / "metadata.json"


def assert_databases(
    grype_status: dict[str, Any],
    trivy_metadata: dict[str, Any],
    now: datetime,
    max_age: timedelta,
) -> list[FreshnessResult]:
    return [
        assert_grype(grype_status, now, max_age),
        assert_trivy(trivy_metadata, now, max_age),
    ]


def positive_grype(now: datetime) -> dict[str, Any]:
    return {
        "valid": True,
        "schemaVersion": "v6.1.7",
        "built": format_timestamp(now - timedelta(hours=3)),
    }


def positive_trivy(now: datetime) -> dict[str, Any]:
    return {
        "DownloadedAt": format_timestamp(now - timedelta(hours=2)),
        "NextUpdate": format_timestamp(now + timedelta(hours=10)),
    }


def expect_failure(name: str, callback: Callable[[], object]) -> None:
    try:
        callback()
    except ScannerDbFreshnessError:
        return
    fail(f"{name}: negative self-test unexpectedly passed")


def run_self_test() -> None:
    now = datetime(2026, 7, 10, 0, 0, tzinfo=UTC)
    max_age = timedelta(days=DEFAULT_MAX_AGE_DAYS)
    assert_databases(positive_grype(now), positive_trivy(now), now, max_age)

    old_grype = positive_grype(now)
    old_grype["built"] = format_timestamp(now - timedelta(days=DEFAULT_MAX_AGE_DAYS + 1))
    expect_failure("back-dated grype built", lambda: assert_databases(old_grype, positive_trivy(now), now, max_age))

    old_trivy = positive_trivy(now)
    old_trivy["DownloadedAt"] = format_timestamp(now - timedelta(days=DEFAULT_MAX_AGE_DAYS + 1))
    expect_failure(
        "back-dated trivy DownloadedAt", lambda: assert_databases(positive_grype(now), old_trivy, now, max_age)
    )

    expired_trivy = positive_trivy(now)
    expired_trivy["NextUpdate"] = format_timestamp(now - timedelta(minutes=1))
    expect_failure(
        "trivy NextUpdate in past", lambda: assert_databases(positive_grype(now), expired_trivy, now, max_age)
    )

    invalid_grype = positive_grype(now)
    invalid_grype["valid"] = False
    expect_failure("grype valid false", lambda: assert_databases(invalid_grype, positive_trivy(now), now, max_age))

    missing_valid = positive_grype(now)
    del missing_valid["valid"]
    expect_failure("missing grype valid", lambda: assert_databases(missing_valid, positive_trivy(now), now, max_age))

    missing_schema = positive_grype(now)
    del missing_schema["schemaVersion"]
    expect_failure(
        "missing grype schemaVersion", lambda: assert_databases(missing_schema, positive_trivy(now), now, max_age)
    )

    old_schema = positive_grype(now)
    old_schema["schemaVersion"] = 5
    expect_failure("old grype schema", lambda: assert_databases(old_schema, positive_trivy(now), now, max_age))

    bad_timestamp = positive_trivy(now)
    bad_timestamp["DownloadedAt"] = "not-a-time"
    expect_failure(
        "unparseable trivy timestamp", lambda: assert_databases(positive_grype(now), bad_timestamp, now, max_age)
    )

    missing_next_update = positive_trivy(now)
    del missing_next_update["NextUpdate"]
    expect_failure(
        "missing trivy NextUpdate",
        lambda: assert_databases(positive_grype(now), missing_next_update, now, max_age),
    )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        malformed = root / "malformed.json"
        malformed.write_text("{", encoding="utf-8")
        expect_failure("malformed JSON", lambda: load_json_object(malformed, "test"))
        expect_failure("missing file", lambda: load_json_object(root / "missing.json", "test"))

    print("scanner DB freshness self-test: ok")


def positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected integer, got {value!r}") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("--max-age-days must be at least 1")
    return parsed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fail unless Trivy and Grype vulnerability DB metadata is fresh.")
    parser.add_argument(
        "--max-age-days",
        type=positive_int,
        default=DEFAULT_MAX_AGE_DAYS,
        help="maximum accepted DB age in days",
    )
    parser.add_argument(
        "--grype-command",
        type=Path,
        default=DEFAULT_GRYPE_COMMAND,
        help="grype executable used to emit db status JSON",
    )
    parser.add_argument(
        "--grype-status-json",
        type=Path,
        help="read Grype db status JSON from this file instead of invoking grype",
    )
    parser.add_argument(
        "--trivy-cache-dir",
        type=Path,
        help="Trivy cache directory containing db/metadata.json",
    )
    parser.add_argument(
        "--trivy-metadata-json",
        type=Path,
        help="read Trivy metadata JSON from this file instead of TRIVY_CACHE_DIR/db/metadata.json",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run built-in positive and negative parser checks",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0

        now = datetime.now(UTC)
        max_age = timedelta(days=cast(int, args.max_age_days))
        grype_status = (
            load_json_object(args.grype_status_json, "grype")
            if args.grype_status_json
            else run_grype_status(cast(Path, args.grype_command))
        )
        trivy_metadata_path = cast(Path | None, args.trivy_metadata_json) or default_trivy_metadata_path(
            cast(Path | None, args.trivy_cache_dir)
        )
        trivy_metadata = load_json_object(trivy_metadata_path, "trivy")
        for result in assert_databases(grype_status, trivy_metadata, now, max_age):
            print(result.log_line(max_age))
    except ScannerDbFreshnessError as exc:
        print(f"scanner DB freshness check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
