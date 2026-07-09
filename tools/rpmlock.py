#!/usr/bin/env python3
# Purpose: Canonical parser and validator for rpm-lock/runtime.<arch>.txt.
# Role: tooling
# Micro-container candidate: gate-adjacent - host/CI lockfile contract validation, not copied into image stages.
# Build-process: no - validates generated lock artifacts; not executed inside image builds.

"""Parse and validate runtime RPM lockfiles."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

COLUMNS: Final = "package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5"
DIRECT_PREFIX: Final = "# direct_rpm: "
RPM_ARCH_BY_PLATFORM: Final = {"amd64": "x86_64", "arm64": "aarch64"}
HEX64: Final = re.compile(r"^[0-9a-f]{64}$")
HEX32: Final = re.compile(r"^[0-9a-f]{32}$")
ASCII_DECIMAL: Final = re.compile(r"^[0-9]+$")
REQUIRED_FINAL_NAMES: Final = (
    "basesystem",
    "ca-certificates",
    "crypto-policies",
    "filesystem",
    "glibc",
    "glibc-common",
    "glibc-minimal-langpack",
    "libgcc",
    "openssl-fips-provider",
    "openssl-fips-provider-so",
    "openssl-libs",
    "redhat-release",
    "setup",
    "tzdata",
    "zlib",
)
OPENSSL_FIPS_PROVIDER_PREFIX: Final = "openssl-fips-provider-so-"


class LockError(Exception):
    """Raised when a runtime RPM lockfile is malformed."""


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


@dataclass(frozen=True, slots=True)
class LockPolicy:
    source_date_epoch: str
    openssl_fips_provider_nevra: str
    openssl_fips_provider_rpm_base_url: str
    openssl_fips_provider_rpm_sha256_x86_64: str
    openssl_fips_provider_rpm_sha256_aarch64: str
    openssl_fips_provider_so_rpm_sha256_x86_64: str
    openssl_fips_provider_so_rpm_sha256_aarch64: str

    @classmethod
    def from_repo(cls, repo_root: Path | None = None) -> LockPolicy:
        root = repo_root if repo_root is not None else Path(__file__).resolve().parents[1]
        return cls(
            source_date_epoch=_dockerfile_arg_default(root, "SOURCE_DATE_EPOCH"),
            openssl_fips_provider_nevra=_dockerfile_arg_default(root, "OPENSSL_FIPS_PROVIDER_NEVRA"),
            openssl_fips_provider_rpm_base_url=_dockerfile_arg_default(
                root,
                "OPENSSL_FIPS_PROVIDER_RPM_BASE_URL",
            ),
            openssl_fips_provider_rpm_sha256_x86_64=_dockerfile_arg_default(
                root,
                "OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64",
            ),
            openssl_fips_provider_rpm_sha256_aarch64=_dockerfile_arg_default(
                root,
                "OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64",
            ),
            openssl_fips_provider_so_rpm_sha256_x86_64=_dockerfile_arg_default(
                root,
                "OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64",
            ),
            openssl_fips_provider_so_rpm_sha256_aarch64=_dockerfile_arg_default(
                root,
                "OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64",
            ),
        )

    def with_overrides(
        self,
        *,
        source_date_epoch: str | None = None,
        openssl_fips_provider_nevra: str | None = None,
        openssl_fips_provider_rpm_base_url: str | None = None,
        openssl_fips_provider_rpm_sha256_x86_64: str | None = None,
        openssl_fips_provider_rpm_sha256_aarch64: str | None = None,
        openssl_fips_provider_so_rpm_sha256_x86_64: str | None = None,
        openssl_fips_provider_so_rpm_sha256_aarch64: str | None = None,
    ) -> LockPolicy:
        return LockPolicy(
            source_date_epoch=source_date_epoch or self.source_date_epoch,
            openssl_fips_provider_nevra=openssl_fips_provider_nevra or self.openssl_fips_provider_nevra,
            openssl_fips_provider_rpm_base_url=(
                openssl_fips_provider_rpm_base_url or self.openssl_fips_provider_rpm_base_url
            ),
            openssl_fips_provider_rpm_sha256_x86_64=(
                openssl_fips_provider_rpm_sha256_x86_64 or self.openssl_fips_provider_rpm_sha256_x86_64
            ),
            openssl_fips_provider_rpm_sha256_aarch64=(
                openssl_fips_provider_rpm_sha256_aarch64 or self.openssl_fips_provider_rpm_sha256_aarch64
            ),
            openssl_fips_provider_so_rpm_sha256_x86_64=(
                openssl_fips_provider_so_rpm_sha256_x86_64 or self.openssl_fips_provider_so_rpm_sha256_x86_64
            ),
            openssl_fips_provider_so_rpm_sha256_aarch64=(
                openssl_fips_provider_so_rpm_sha256_aarch64 or self.openssl_fips_provider_so_rpm_sha256_aarch64
            ),
        )


def _dockerfile_arg_default(repo_root: Path, name: str) -> str:
    dockerfile = repo_root / "containers" / "Dockerfile"
    try:
        text = dockerfile.read_text(encoding="utf-8")
    except OSError as exc:
        raise LockError(f"could not read Dockerfile defaults: {dockerfile}") from exc
    prefix = f"ARG {name}="
    for line in text.splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix)
    raise LockError(f"containers/Dockerfile missing ARG {name}")


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
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LockError(f"{lock_path}: RPM lockfile must be UTF-8") from exc


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
    rows: list[LockRow] = []

    for line in lines:
        if not line:
            continue
        if line.startswith(DIRECT_PREFIX):
            entry = _parse_direct_entry(lock_path, line)
            if entry.package in direct_map:
                raise LockError(f"{lock_path}: duplicate direct RPM entry: {entry.package}")
            direct_entries.append(entry)
            direct_map[entry.package] = (entry.url, entry.sha256)
            continue
        if line.startswith("#"):
            continue
        rows.append(_parse_row(lock_path, line))

    return Lockfile(
        path=lock_path,
        headers=headers,
        direct_entries=tuple(direct_entries),
        direct_map=direct_map,
        rows=tuple(rows),
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


def validate(lockfile: Lockfile, *, arch: str, policy: LockPolicy | None = None) -> None:
    active_policy = policy if policy is not None else LockPolicy.from_repo()
    rpm_arch = _rpm_arch_for_platform(arch)
    provider_expectations = _provider_expectations(active_policy, arch, rpm_arch)

    _require(lockfile.headers.get("arch") == arch, f"{lockfile.path}: invalid arch header")
    _require(
        lockfile.headers.get("source_date_epoch") == active_policy.source_date_epoch,
        f"{lockfile.path}: invalid source_date_epoch header",
    )
    _require(lockfile.headers.get("columns") == COLUMNS, f"{lockfile.path}: invalid columns header")

    direct_seen: set[str] = set()
    for entry in lockfile.direct_entries:
        _validate_direct_entry(lockfile.path, entry, direct_seen)

    rows = 0
    final_rows = 0
    final_seen: set[str] = set()
    previous_package = ""
    row_seen: set[str] = set()
    direct_row_seen: set[str] = set()
    provider_pin_seen = False

    for row in lockfile.rows:
        _validate_row_fields(lockfile.path, row)
        if row.final_rpmdb == "yes":
            final_rows += 1
            final_seen.add(row.name)
        elif row.final_rpmdb != "no":
            raise LockError(f"{lockfile.path}: invalid final_rpmdb={row.final_rpmdb} for {row.package}")

        if row.arch not in {"noarch", rpm_arch}:
            raise LockError(f"{lockfile.path}: invalid arch={row.arch} for {row.package}")
        _require(
            ASCII_DECIMAL.fullmatch(row.epoch) is not None,
            f"{lockfile.path}: non-numeric epoch for {row.package}",
        )
        _require(
            HEX64.fullmatch(row.sha256_header) is not None,
            f"{lockfile.path}: invalid SHA256HEADER for {row.package}",
        )
        _require(HEX32.fullmatch(row.sigmd5) is not None, f"{lockfile.path}: invalid SIGMD5 for {row.package}")
        _validate_direct_match(lockfile, row, provider_expectations)

        direct_row_seen.add(row.package)
        if previous_package and row.package < previous_package:
            raise LockError(f"{lockfile.path}: rows are not sorted by package: {row.package} after {previous_package}")
        if row.package in row_seen:
            raise LockError(f"{lockfile.path}: duplicate package row: {row.package}")
        if row.package == provider_expectations.provider_so_package and row.name == "openssl-fips-provider-so":
            provider_pin_seen = True
        row_seen.add(row.package)
        previous_package = row.package
        rows += 1

    _require(rows > 0, f"{lockfile.path}: lockfile has no package rows")
    _require(
        len(lockfile.direct_entries) == rows,
        f"{lockfile.path}: expected {rows} direct RPM pins, got {len(lockfile.direct_entries)}",
    )
    for direct_package in lockfile.direct_map:
        _require(
            direct_package in direct_row_seen,
            f"{lockfile.path}: direct RPM entry has no matching package row: {direct_package}",
        )
    _require(
        final_rows == len(REQUIRED_FINAL_NAMES),
        f"{lockfile.path}: expected 15 final runtime RPMs, got {final_rows}",
    )
    for name in REQUIRED_FINAL_NAMES:
        _require(name in final_seen, f"{lockfile.path}: missing final runtime RPM {name}")
    _require(
        provider_pin_seen,
        f"{lockfile.path}: missing pinned OpenSSL FIPS provider {provider_expectations.provider_so_package}",
    )


def _rpm_arch_for_platform(arch: str) -> str:
    try:
        return RPM_ARCH_BY_PLATFORM[arch]
    except KeyError as exc:
        raise LockError(f"unsupported architecture: {arch}") from exc


@dataclass(frozen=True, slots=True)
class ProviderExpectations:
    provider_package: str
    provider_package_url: str
    provider_package_sha256: str
    provider_so_package: str
    provider_so_url: str
    provider_so_sha256: str


def _provider_expectations(policy: LockPolicy, platform_arch: str, rpm_arch: str) -> ProviderExpectations:
    provider_nvr = policy.openssl_fips_provider_nevra
    _require(
        provider_nvr.startswith(OPENSSL_FIPS_PROVIDER_PREFIX),
        f"invalid FIPS provider NEVRA pin: {provider_nvr}",
    )
    provider_package_nvr = provider_nvr.removeprefix(OPENSSL_FIPS_PROVIDER_PREFIX)
    provider_package = f"openssl-fips-provider-{provider_package_nvr}.{rpm_arch}"
    provider_so_package = f"{provider_nvr}.{rpm_arch}"
    base_url = policy.openssl_fips_provider_rpm_base_url.rstrip("/")
    provider_sha256 = (
        policy.openssl_fips_provider_rpm_sha256_x86_64
        if platform_arch == "amd64"
        else policy.openssl_fips_provider_rpm_sha256_aarch64
    )
    provider_so_sha256 = (
        policy.openssl_fips_provider_so_rpm_sha256_x86_64
        if platform_arch == "amd64"
        else policy.openssl_fips_provider_so_rpm_sha256_aarch64
    )
    return ProviderExpectations(
        provider_package=provider_package,
        provider_package_url=f"{base_url}/{rpm_arch}/baseos/os/Packages/o/{provider_package}.rpm",
        provider_package_sha256=provider_sha256,
        provider_so_package=provider_so_package,
        provider_so_url=f"{base_url}/{rpm_arch}/baseos/os/Packages/o/{provider_so_package}.rpm",
        provider_so_sha256=provider_so_sha256,
    )


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


def _validate_direct_match(lockfile: Lockfile, row: LockRow, expected: ProviderExpectations) -> None:
    if row.package not in lockfile.direct_map:
        raise LockError(f"{lockfile.path}: missing direct RPM source pin for {row.package}")
    direct_url, direct_sha256 = lockfile.direct_map[row.package]
    expected_filename = rpm_filename(row)
    direct_filename = direct_url.rsplit("/", 1)[-1]
    _require(
        direct_filename == expected_filename,
        f"{lockfile.path}: direct RPM URL filename mismatch for {row.package}: "
        f"expected {expected_filename}, got {direct_filename}",
    )
    if row.package == expected.provider_package:
        _require(
            (direct_url, direct_sha256) == (expected.provider_package_url, expected.provider_package_sha256),
            f"{lockfile.path}: FIPS provider package direct pin mismatch for {row.package}",
        )
    if row.package == expected.provider_so_package:
        _require(
            (direct_url, direct_sha256) == (expected.provider_so_url, expected.provider_so_sha256),
            f"{lockfile.path}: FIPS provider shared-object direct pin mismatch for {row.package}",
        )


def rpm_filename(row: LockRow) -> str:
    return f"{row.name}-{row.version}-{row.release}.{row.arch}.rpm"


def floor(lockfile: Lockfile) -> list[str]:
    return [row.package for row in lockfile.rows if row.final_rpmdb == "yes"]


def direct_rpms(lockfile: Lockfile) -> list[tuple[str, str, str]]:
    return [entry.as_tuple() for entry in lockfile.direct_entries]


def _policy_from_args(args: argparse.Namespace) -> LockPolicy:
    return LockPolicy.from_repo().with_overrides(
        source_date_epoch=args.source_date_epoch,
        openssl_fips_provider_nevra=args.openssl_fips_provider_nevra,
        openssl_fips_provider_rpm_base_url=args.openssl_fips_provider_rpm_base_url,
        openssl_fips_provider_rpm_sha256_x86_64=args.openssl_fips_provider_rpm_sha256_x86_64,
        openssl_fips_provider_rpm_sha256_aarch64=args.openssl_fips_provider_rpm_sha256_aarch64,
        openssl_fips_provider_so_rpm_sha256_x86_64=args.openssl_fips_provider_so_rpm_sha256_x86_64,
        openssl_fips_provider_so_rpm_sha256_aarch64=args.openssl_fips_provider_so_rpm_sha256_aarch64,
    )


def _validated_lockfile(args: argparse.Namespace) -> Lockfile:
    lockfile = parse(args.lockfile)
    validate(lockfile, arch=args.arch, policy=_policy_from_args(args))
    return lockfile


def _cmd_validate(args: argparse.Namespace) -> int:
    _validated_lockfile(args)
    return 0


def _cmd_floor(args: argparse.Namespace) -> int:
    lockfile = _validated_lockfile(args)
    field = args.field
    for row in lockfile.rows:
        if row.final_rpmdb != "yes":
            continue
        print(row.name if field == "name" else row.package)
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
        "floor": floor(lockfile),
        "rpm_filenames": [rpm_filename(row) for row in lockfile.rows],
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--lockfile", required=True, type=Path)
    parser.add_argument("--arch", required=True, choices=sorted(RPM_ARCH_BY_PLATFORM))
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--openssl-fips-provider-nevra")
    parser.add_argument("--openssl-fips-provider-rpm-base-url")
    parser.add_argument("--openssl-fips-provider-rpm-sha256-x86-64", dest="openssl_fips_provider_rpm_sha256_x86_64")
    parser.add_argument("--openssl-fips-provider-rpm-sha256-aarch64")
    parser.add_argument(
        "--openssl-fips-provider-so-rpm-sha256-x86-64",
        dest="openssl_fips_provider_so_rpm_sha256_x86_64",
    )
    parser.add_argument("--openssl-fips-provider-so-rpm-sha256-aarch64")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate a runtime RPM lockfile")
    _add_common_args(validate_parser)
    validate_parser.set_defaults(handler=_cmd_validate)

    floor_parser = subparsers.add_parser("floor", help="print final rpmdb packages in lockfile order")
    _add_common_args(floor_parser)
    floor_parser.add_argument("--field", choices=["package", "name"], default="package")
    floor_parser.set_defaults(handler=_cmd_floor)

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
    handler = cast(CommandHandler, args.handler)
    try:
        return handler(args)
    except LockError as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
