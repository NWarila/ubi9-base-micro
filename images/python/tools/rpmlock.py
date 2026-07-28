#!/usr/bin/env python3
# Purpose: Canonical RPM lock parser/validator for the base-python delta lock.
# Role: tooling
# Micro-container candidate: gate-adjacent - host/CI validation and discarded-stage filename emission.
# Build-process: yes - validates the python lock and emits RPM filenames in the python rootfs build stage.

"""Parse and validate the base-python runtime RPM lockfile."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Final, cast

COLUMNS: Final = "package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5"
DIRECT_PREFIX: Final = "# direct_rpm: "
RPM_ARCH_BY_PLATFORM: Final = {"amd64": "x86_64", "arm64": "aarch64"}
PLATFORM_BY_RPM_ARCH: Final = {rpm_arch: platform for platform, rpm_arch in RPM_ARCH_BY_PLATFORM.items()}
HEX64: Final = re.compile(r"^[0-9a-f]{64}$")
HEX32: Final = re.compile(r"^[0-9a-f]{32}$")
ASCII_DECIMAL: Final = re.compile(r"^[0-9]+$")


class LockError(Exception):
    """Raised when a runtime RPM lockfile is malformed."""


class CommonValidationMode(StrEnum):
    """Select aggregate diagnostic ordering for policy-independent validation."""

    STRICT = "strict"
    ASSERTION = "assertion"


@dataclass(frozen=True, slots=True)
class LockRow:
    package: str
    final_rpmdb: str
    name: str
    epoch: str
    version: str
    release: str
    arch: str
    sha256_header: str
    sigmd5: str

    def as_dict(self) -> dict[str, str]:
        return {
            "package": self.package,
            "final_rpmdb": self.final_rpmdb,
            "name": self.name,
            "epoch": self.epoch,
            "version": self.version,
            "release": self.release,
            "arch": self.arch,
            "sha256_header": self.sha256_header,
            "sigmd5": self.sigmd5,
        }


@dataclass(frozen=True, slots=True)
class DirectRpm:
    package: str
    url: str
    sha256: str

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.package, self.url, self.sha256)

    def as_dict(self) -> dict[str, str]:
        return {"package": self.package, "url": self.url, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class Lockfile:
    path: Path
    headers: dict[str, str]
    direct_entries: tuple[DirectRpm, ...]
    direct_map: dict[str, tuple[str, str]]
    rows: tuple[LockRow, ...]
    terminal_lf: bool
    direct_line_numbers: dict[str, int]
    row_line_numbers: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CommonValidationResult:
    """Counts produced by policy-independent runtime-lock validation."""

    row_count: int
    direct_count: int


@dataclass(frozen=True, slots=True)
class PythonLockPolicy:
    """Explicit base-python lock policy: no repository discovery, every expectation is a constructor argument."""

    rpm_arch: str
    source_date_epoch: str
    expected_shipped: list[str]
    floor_names: set[str]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LockError(message)


def _read_lock_text(lock_path: Path) -> str:
    try:
        raw = lock_path.read_bytes()
    except OSError as exc:
        raise LockError(f"RPM lockfile missing or empty: {lock_path}") from exc
    if not raw:
        raise LockError(f"RPM lockfile missing or empty: {lock_path}")
    if b"\r" in raw:
        raise LockError(f"{lock_path}: CR characters are not allowed in RPM lockfiles")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LockError(f"{lock_path}: RPM lockfile must be UTF-8") from exc
    forbidden_separators = {
        "\v",
        "\f",
        "\x1c",
        "\x1d",
        "\x1e",
        "\x85",
        "\u2028",
        "\u2029",
    }
    if any(separator in text for separator in forbidden_separators):
        raise LockError(f"{lock_path}: only LF line separators are allowed in RPM lockfiles")
    return text


def _positional_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    if len(lines) > 0 and lines[0].startswith("# arch: "):
        headers["arch"] = lines[0].removeprefix("# arch: ")
    if len(lines) > 1 and lines[1].startswith("# source_date_epoch: "):
        headers["source_date_epoch"] = lines[1].removeprefix("# source_date_epoch: ")
    if len(lines) > 2 and lines[2].startswith("# columns: "):
        headers["columns"] = lines[2].removeprefix("# columns: ")
    return headers


def parse(path: Path) -> Lockfile:
    lock_path = Path(path)
    text = _read_lock_text(lock_path)

    lines = text.splitlines()
    headers = _positional_headers(lines)
    direct_entries: list[DirectRpm] = []
    direct_map: dict[str, tuple[str, str]] = {}
    direct_line_numbers: dict[str, int] = {}
    rows: list[LockRow] = []
    row_line_numbers: list[int] = []

    for line_number, line in enumerate(lines, start=1):
        if not line:
            continue
        if line.startswith(DIRECT_PREFIX):
            entry = _parse_direct_entry(lock_path, line)
            if entry.package in direct_map:
                raise LockError(f"{lock_path}: duplicate direct RPM entry: {entry.package}")
            direct_entries.append(entry)
            direct_map[entry.package] = (entry.url, entry.sha256)
            direct_line_numbers[entry.package] = line_number
            continue
        if line.startswith("#"):
            continue
        rows.append(_parse_row(lock_path, line))
        row_line_numbers.append(line_number)

    return Lockfile(
        path=lock_path,
        headers=headers,
        direct_entries=tuple(direct_entries),
        direct_map=direct_map,
        rows=tuple(rows),
        terminal_lf=text.endswith("\n"),
        direct_line_numbers=direct_line_numbers,
        row_line_numbers=tuple(row_line_numbers),
    )


def _parse_direct_entry(path: Path, line: str) -> DirectRpm:
    payload = line.removeprefix(DIRECT_PREFIX)
    parts = payload.split("|")
    if len(parts) != 3 or not all(parts):
        raise LockError(f"{path}: invalid direct RPM entry: {line}")
    return DirectRpm(package=parts[0], url=parts[1], sha256=parts[2])


def _parse_row(path: Path, line: str) -> LockRow:
    parts = line.split("|")
    package = parts[0] if parts else ""
    if len(parts) > 9:
        raise LockError(f"{path}: too many columns for {package}")
    if len(parts) < 9:
        parts = [*parts, *([""] * (9 - len(parts)))]
    return LockRow(
        package=parts[0],
        final_rpmdb=parts[1],
        name=parts[2],
        epoch=parts[3],
        version=parts[4],
        release=parts[5],
        arch=parts[6],
        sha256_header=parts[7],
        sigmd5=parts[8],
    )


def _rpm_arch_for_platform(arch: str) -> str:
    try:
        return RPM_ARCH_BY_PLATFORM[arch]
    except KeyError as exc:
        raise LockError(f"unsupported architecture: {arch}") from exc


def _validate_direct_entry(path: Path, entry: DirectRpm, seen: set[str]) -> None:
    _require(entry.package not in seen, f"{path}: duplicate direct RPM entry: {entry.package}")
    _require(
        entry.url.startswith("https://cdn-ubi.redhat.com/"),
        f"{path}: direct RPM source must be cdn-ubi.redhat.com for {entry.package}: {entry.url}",
    )
    _require(
        HEX64.fullmatch(entry.sha256) is not None,
        f"{path}: invalid direct RPM sha256 for {entry.package}: {entry.sha256}",
    )
    seen.add(entry.package)


def _validate_row_fields(path: Path, row: LockRow) -> None:
    for field in [
        row.package,
        row.final_rpmdb,
        row.name,
        row.epoch,
        row.version,
        row.release,
        row.arch,
        row.sha256_header,
        row.sigmd5,
    ]:
        if not field:
            raise LockError(f"{path}: empty field in row {row.package}")


def _validate_common_direct_match(lockfile: Lockfile, row: LockRow) -> None:
    if row.package not in lockfile.direct_map:
        raise LockError(f"{lockfile.path}: missing direct RPM source pin for {row.package}")
    direct_url, _ = lockfile.direct_map[row.package]
    expected_filename = rpm_filename(row)
    direct_filename = direct_url.rsplit("/", 1)[-1]
    _require(
        direct_filename == expected_filename,
        f"{lockfile.path}: direct RPM URL filename mismatch for {row.package}: "
        f"expected {expected_filename}, got {direct_filename}",
    )


def validate_common(
    lockfile: Lockfile,
    *,
    mode: CommonValidationMode,
    before_hash_check: Callable[[LockRow], None] | None = None,
    after_direct_match_check: Callable[[LockRow], None] | None = None,
) -> CommonValidationResult:
    """Validate runtime-lock grammar and cross-row invariants without repository policy."""

    direct_seen: set[str] = set()
    for entry in lockfile.direct_entries:
        _validate_direct_entry(lockfile.path, entry, direct_seen)

    row_packages: set[str] = set()
    for row in lockfile.rows:
        _validate_row_fields(lockfile.path, row)
        if before_hash_check is not None:
            before_hash_check(row)
        _require(
            HEX64.fullmatch(row.sha256_header) is not None,
            f"{lockfile.path}: invalid SHA256HEADER for {row.package}",
        )
        _require(HEX32.fullmatch(row.sigmd5) is not None, f"{lockfile.path}: invalid SIGMD5 for {row.package}")
        _validate_common_direct_match(lockfile, row)
        if after_direct_match_check is not None:
            after_direct_match_check(row)
        row_packages.add(row.package)

    row_count = len(lockfile.rows)
    direct_count = len(lockfile.direct_entries)
    _require(row_count > 0, f"{lockfile.path}: lockfile has no package rows")
    if mode is CommonValidationMode.STRICT:
        _require(
            direct_count == row_count,
            f"{lockfile.path}: expected {row_count} direct RPM pins, got {direct_count}",
        )
    for direct_package in lockfile.direct_map:
        _require(
            direct_package in row_packages,
            f"{lockfile.path}: direct RPM entry has no matching package row: {direct_package}",
        )
    return CommonValidationResult(row_count=row_count, direct_count=direct_count)


def validate_assertion_compatibility(lockfile: Lockfile) -> None:
    """Preserve fail-closed source-order and terminal-LF behavior of the legacy assertion gate."""

    _require(lockfile.terminal_lf, f"{lockfile.path}: RPM lockfile must end with a line feed")
    for row, row_line_number in zip(lockfile.rows, lockfile.row_line_numbers, strict=True):
        direct_line_number = lockfile.direct_line_numbers.get(row.package)
        if direct_line_number is not None:
            _require(
                direct_line_number < row_line_number,
                f"{lockfile.path}: direct RPM source pin must precede package row for {row.package}",
            )


def validate_python(lockfile: Lockfile, *, policy: PythonLockPolicy) -> None:
    """Validate the base-python delta lock against the explicit shipped-set and parent-floor policy."""

    platform = PLATFORM_BY_RPM_ARCH.get(policy.rpm_arch)
    if platform is None:
        raise LockError(f"unsupported RPM architecture in policy: {policy.rpm_arch}")

    expected_shipped = set(policy.expected_shipped)
    _require(
        len(expected_shipped) == len(policy.expected_shipped),
        f"{lockfile.path}: policy expected_shipped contains duplicate NEVRAs",
    )
    _require(bool(expected_shipped), f"{lockfile.path}: policy expected_shipped must not be empty")

    _require(lockfile.headers.get("arch") == platform, f"{lockfile.path}: invalid arch header")
    _require(
        lockfile.headers.get("source_date_epoch") == policy.source_date_epoch,
        f"{lockfile.path}: invalid source_date_epoch header",
    )
    _require(lockfile.headers.get("columns") == COLUMNS, f"{lockfile.path}: invalid columns header")

    shipped_seen: set[str] = set()
    previous_package = ""
    row_seen: set[str] = set()

    def validate_policy_before_hashes(row: LockRow) -> None:
        if row.final_rpmdb == "yes":
            shipped_seen.add(row.package)
        elif row.final_rpmdb != "no":
            raise LockError(f"{lockfile.path}: invalid final_rpmdb={row.final_rpmdb} for {row.package}")
        if row.arch not in {"noarch", policy.rpm_arch}:
            raise LockError(f"{lockfile.path}: invalid arch={row.arch} for {row.package}")
        _require(
            ASCII_DECIMAL.fullmatch(row.epoch) is not None,
            f"{lockfile.path}: non-numeric epoch for {row.package}",
        )
        _require(
            row.name not in policy.floor_names,
            f"{lockfile.path}: row {row.package} overlaps the parent floor package {row.name}",
        )

    def validate_policy_after_direct_match(row: LockRow) -> None:
        nonlocal previous_package
        _require(
            row.package == lock_nevra(row),
            f"{lockfile.path}: package field does not match row NEVRA: {row.package}",
        )
        if previous_package and row.package < previous_package:
            raise LockError(f"{lockfile.path}: rows are not sorted by package: {row.package} after {previous_package}")
        if row.package in row_seen:
            raise LockError(f"{lockfile.path}: duplicate package row: {row.package}")
        row_seen.add(row.package)
        previous_package = row.package

    validate_common(
        lockfile,
        mode=CommonValidationMode.STRICT,
        before_hash_check=validate_policy_before_hashes,
        after_direct_match_check=validate_policy_after_direct_match,
    )
    validate_assertion_compatibility(lockfile)
    _require(
        shipped_seen == expected_shipped,
        f"{lockfile.path}: final_rpmdb=yes set does not equal the expected shipped NEVRAs: "
        f"missing {sorted(expected_shipped - shipped_seen)}, unexpected {sorted(shipped_seen - expected_shipped)}",
    )


def lock_nevra(row: LockRow) -> str:
    epoch = "" if row.epoch == "0" else f"{row.epoch}:"
    return f"{row.name}-{epoch}{row.version}-{row.release}.{row.arch}"


def rpm_filename(row: LockRow) -> str:
    return f"{row.name}-{row.version}-{row.release}.{row.arch}.rpm"


def shipped(lockfile: Lockfile) -> list[str]:
    return [row.package for row in lockfile.rows if row.final_rpmdb == "yes"]


def direct_rpms(lockfile: Lockfile) -> list[tuple[str, str, str]]:
    return [entry.as_tuple() for entry in lockfile.direct_entries]


_TEST_SHA256: Final = "0123456789abcdef" * 4
_TEST_SIGMD5: Final = "89abcdef01234567" * 2
_TEST_URL_BASE: Final = "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/appstream/os/Packages/p"


def _test_row(
    name: str,
    version: str,
    release: str,
    *,
    final: str = "yes",
    epoch: str = "0",
    arch: str = "x86_64",
    package: str | None = None,
) -> LockRow:
    row = LockRow(
        package="",
        final_rpmdb=final,
        name=name,
        epoch=epoch,
        version=version,
        release=release,
        arch=arch,
        sha256_header=_TEST_SHA256,
        sigmd5=_TEST_SIGMD5,
    )
    return replace(row, package=package if package is not None else lock_nevra(row))


def _row_line(row: LockRow) -> str:
    return "|".join(
        [
            row.package,
            row.final_rpmdb,
            row.name,
            row.epoch,
            row.version,
            row.release,
            row.arch,
            row.sha256_header,
            row.sigmd5,
        ]
    )


def _direct_line(row: LockRow) -> str:
    return f"{DIRECT_PREFIX}{row.package}|{_TEST_URL_BASE}/{rpm_filename(row)}|{_TEST_SHA256}"


def _lock_text(
    rows: Sequence[LockRow],
    *,
    header_arch: str = "amd64",
    header_sde: str = "1704067200",
    header_columns: str = COLUMNS,
    terminal_lf: bool = True,
    direct_rows: Sequence[LockRow] | None = None,
) -> str:
    direct_source = rows if direct_rows is None else direct_rows
    lines = [
        f"# arch: {header_arch}",
        f"# source_date_epoch: {header_sde}",
        f"# columns: {header_columns}",
    ]
    lines.extend(_direct_line(row) for row in direct_source)
    lines.extend(_row_line(row) for row in rows)
    text = "\n".join(lines)
    return f"{text}\n" if terminal_lf else text


def _expect_lock_error(
    tmp_path: Path,
    name: str,
    text: str,
    policy: PythonLockPolicy,
    needle: str,
) -> None:
    lock_path = tmp_path / f"{name}.lock"
    lock_path.write_text(text, encoding="utf-8")
    try:
        validate_python(parse(lock_path), policy=policy)
    except LockError as exc:
        message = str(exc)
        if needle not in message:
            raise LockError(f"self-test {name}: expected error containing {needle!r}, got: {message}") from exc
        return
    raise LockError(f"self-test {name}: expected LockError containing {needle!r}, got success")


def run_self_test() -> None:
    """Exercise every validate_python rule with one positive lock and one mutation per rule."""

    mpdecimal = _test_row("mpdecimal", "2.5.1", "3.el9", final="no")
    python = _test_row("python3.12", "3.12.5", "2.el9_5")
    python_libs = _test_row("python3.12-libs", "3.12.5", "2.el9_5")
    rows = [mpdecimal, python, python_libs]
    policy = PythonLockPolicy(
        rpm_arch="x86_64",
        source_date_epoch="1704067200",
        expected_shipped=[python.package, python_libs.package],
        floor_names={"glibc", "glibc-common", "openssl-libs"},
    )

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        valid_path = tmp_path / "valid.lock"
        valid_path.write_text(_lock_text(rows), encoding="utf-8")
        lockfile = parse(valid_path)
        validate_python(lockfile, policy=policy)
        if len(direct_rpms(lockfile)) != 3:
            raise LockError("self-test valid: expected 3 direct RPM pins")
        if shipped(lockfile) != [python.package, python_libs.package]:
            raise LockError("self-test valid: unexpected shipped set")
        if rpm_filename(mpdecimal) != "mpdecimal-2.5.1-3.el9.x86_64.rpm":
            raise LockError("self-test valid: unexpected rpm filename derivation")

        _expect_lock_error(
            tmp_path,
            "floor-overlap",
            _lock_text(rows),
            replace(policy, floor_names={*policy.floor_names, "mpdecimal"}),
            "overlaps the parent floor package",
        )
        _expect_lock_error(
            tmp_path,
            "shipped-mismatch-policy",
            _lock_text(rows),
            replace(policy, expected_shipped=[python.package]),
            "does not equal the expected shipped NEVRAs",
        )
        _expect_lock_error(
            tmp_path,
            "shipped-mismatch-lock",
            _lock_text([replace(mpdecimal, final_rpmdb="yes"), python, python_libs]),
            policy,
            "does not equal the expected shipped NEVRAs",
        )
        _expect_lock_error(
            tmp_path,
            "unsorted-rows",
            _lock_text([python, mpdecimal, python_libs], direct_rows=rows),
            policy,
            "rows are not sorted by package",
        )
        _expect_lock_error(
            tmp_path,
            "bad-epoch",
            _lock_text([_test_row("mpdecimal", "2.5.1", "3.el9", final="no", epoch="x"), python, python_libs]),
            policy,
            "non-numeric epoch",
        )
        _expect_lock_error(
            tmp_path,
            "wrong-sde-header",
            _lock_text(rows, header_sde="1704067201"),
            policy,
            "invalid source_date_epoch header",
        )
        _expect_lock_error(
            tmp_path,
            "duplicate-package",
            _lock_text([mpdecimal, mpdecimal, python, python_libs], direct_rows=rows),
            policy,
            "duplicate package row",
        )
        _expect_lock_error(
            tmp_path,
            "invalid-final-rpmdb",
            _lock_text([replace(mpdecimal, final_rpmdb="maybe"), python, python_libs]),
            policy,
            "invalid final_rpmdb=maybe",
        )
        _expect_lock_error(
            tmp_path,
            "wrong-row-arch",
            _lock_text([mpdecimal, _test_row("python3.12", "3.12.5", "2.el9_5", arch="aarch64"), python_libs]),
            replace(policy, expected_shipped=[python.package.replace("x86_64", "aarch64"), python_libs.package]),
            "invalid arch=aarch64",
        )
        _expect_lock_error(
            tmp_path,
            "wrong-arch-header",
            _lock_text(rows, header_arch="arm64"),
            policy,
            "invalid arch header",
        )
        _expect_lock_error(
            tmp_path,
            "wrong-columns-header",
            _lock_text(rows, header_columns="package|name|epoch|version|release|arch|sha256_header|sigmd5"),
            policy,
            "invalid columns header",
        )
        nevra_mismatch = _test_row("python3.12", "3.12.5", "2.el9_5", epoch="1", package=python.package)
        _expect_lock_error(
            tmp_path,
            "package-nevra-mismatch",
            _lock_text([mpdecimal, nevra_mismatch, python_libs]),
            policy,
            "does not match row NEVRA",
        )
        _expect_lock_error(
            tmp_path,
            "missing-terminal-lf",
            _lock_text(rows, terminal_lf=False),
            policy,
            "must end with a line feed",
        )
        _expect_lock_error(
            tmp_path,
            "duplicate-policy-shipped",
            _lock_text(rows),
            replace(policy, expected_shipped=[python.package, python.package]),
            "duplicate NEVRAs",
        )

    print("python lock self-test: ok")


def _policy_from_args(args: argparse.Namespace) -> PythonLockPolicy:
    return PythonLockPolicy(
        rpm_arch=_rpm_arch_for_platform(args.arch),
        source_date_epoch=args.source_date_epoch,
        expected_shipped=list(args.shipped_nevra),
        floor_names=set(args.floor_name),
    )


def _validated_lockfile(args: argparse.Namespace) -> Lockfile:
    lockfile = parse(args.lockfile)
    validate_python(lockfile, policy=_policy_from_args(args))
    return lockfile


def _cmd_validate(args: argparse.Namespace) -> int:
    _validated_lockfile(args)
    return 0


def _cmd_rpm_filenames(args: argparse.Namespace) -> int:
    lockfile = _validated_lockfile(args)
    for row in lockfile.rows:
        print(rpm_filename(row))
    return 0


def _cmd_direct_rpms(args: argparse.Namespace) -> int:
    lockfile = _validated_lockfile(args)
    for package, url, sha256 in direct_rpms(lockfile):
        print(f"{package}|{url}|{sha256}")
    return 0


def _cmd_summary(args: argparse.Namespace) -> int:
    lockfile = _validated_lockfile(args)
    summary = {
        "headers": lockfile.headers,
        "direct_rpms": [entry.as_dict() for entry in lockfile.direct_entries],
        "rows": [row.as_dict() for row in lockfile.rows],
        "shipped": shipped(lockfile),
        "rpm_filenames": [rpm_filename(row) for row in lockfile.rows],
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--lockfile", required=True, type=Path)
    parser.add_argument("--arch", required=True, choices=sorted(RPM_ARCH_BY_PLATFORM))
    parser.add_argument("--source-date-epoch", required=True)
    parser.add_argument(
        "--shipped-nevra",
        action="append",
        required=True,
        help="exact shipped NEVRA expected with final_rpmdb=yes (repeatable)",
    )
    parser.add_argument(
        "--floor-name",
        action="append",
        required=True,
        help="parent floor package name that must stay disjoint from the lock (repeatable)",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run offline lock validation checks")
    subparsers = parser.add_subparsers(dest="command")

    validate_parser = subparsers.add_parser("validate", help="validate the base-python RPM lockfile")
    _add_common_args(validate_parser)
    validate_parser.set_defaults(handler=_cmd_validate)

    filenames_parser = subparsers.add_parser("rpm-filenames", help="print derived RPM filenames in row order")
    _add_common_args(filenames_parser)
    filenames_parser.set_defaults(handler=_cmd_rpm_filenames)

    direct_parser = subparsers.add_parser("direct-rpms", help="print direct RPM pins in lockfile order")
    _add_common_args(direct_parser)
    direct_parser.set_defaults(handler=_cmd_direct_rpms)

    summary_parser = subparsers.add_parser("summary", help="print validated lockfile data as JSON")
    _add_common_args(summary_parser)
    summary_parser.set_defaults(handler=_cmd_summary)

    return parser


CommandHandler = Callable[[argparse.Namespace], int]


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        try:
            run_self_test()
        except LockError as exc:
            print(exc, file=sys.stderr)
            return 1
        return 0
    if args.command is None:
        parser.error("a command is required unless --self-test is given")
    handler = cast(CommandHandler, args.handler)
    try:
        return handler(args)
    except LockError as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
