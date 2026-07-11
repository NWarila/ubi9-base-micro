#!/usr/bin/env python3
# Purpose: Validate capture snapshots, derive direct RPM candidates, and render runtime RPM lockfiles.
# Role: tooling
# Micro-container candidate: no - generation policy invoked inside the discarded capture stage.
# Build-process: yes - owns runtime-lock generation decisions while shell retains fetch/install orchestration.

"""Generate byte-exact runtime RPM locks from capture-stage snapshots."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from tools.rpmlock import (
        COLUMNS,
        REQUIRED_FINAL_NAMES,
        CommonValidationMode,
        DirectRpm,
        LockError,
        Lockfile,
        LockRow,
        rpm_filename,
        validate_common,
    )
else:
    from rpmlock import (
        COLUMNS,
        REQUIRED_FINAL_NAMES,
        CommonValidationMode,
        DirectRpm,
        LockError,
        Lockfile,
        LockRow,
        rpm_filename,
        validate_common,
    )

ASCII_DECIMAL: Final = re.compile(r"^[0-9]+$")
HEX64: Final = re.compile(r"^[0-9a-f]{64}$")
HEX32: Final = re.compile(r"^[0-9a-f]{32}$")
DIRECT_URL: Final = re.compile(
    r"^(?P<base>https://cdn-ubi\.redhat\.com/.+)/(?P<rpm_arch>x86_64|aarch64)/"
    r"(?P<repo>baseos|appstream)/os/Packages/(?P<letter>[^/]+)/(?P<filename>[^/]+)$"
)
RPM_ARCH_BY_PLATFORM: Final = {"amd64": "x86_64", "arm64": "aarch64"}
SIGNATURE_ACCEPTANCE: Final = "digests signatures OK"
FIPS_PROVIDER_PREFIX: Final = "openssl-fips-provider-so-"
RUNTIME_PACKAGE_SPECS: Final = (
    "basesystem",
    "ca-certificates",
    "crypto-policies",
    "filesystem",
    "glibc",
    "glibc-common",
    "glibc-minimal-langpack",
    "libgcc",
    "openssl-libs",
    "redhat-release",
    "setup",
    "tzdata",
    "zlib",
)


class GenerationError(Exception):
    """Raised when captured RPM data cannot produce a valid lockfile."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GenerationError(message)


def _read_lf_lines(path: Path, description: str) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise GenerationError(f"could not read {description}: {path}") from exc
    _require(bool(raw), f"{description} is empty: {path}")
    _require(b"\r" not in raw, f"{description} contains CR characters: {path}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GenerationError(f"{description} must be UTF-8: {path}") from exc
    _require(text.endswith("\n"), f"{description} must end with LF: {path}")
    _require(
        not any(separator in text for separator in ("\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")),
        f"{description} may contain only LF line separators: {path}",
    )
    return text.removesuffix("\n").split("\n")


def _row_nevra(row: LockRow) -> str:
    epoch = "" if row.epoch == "0" else f"{row.epoch}:"
    return f"{row.name}-{epoch}{row.version}-{row.release}.{row.arch}"


def _validate_full_row(row: LockRow) -> None:
    fields = (
        row.package,
        row.name,
        row.epoch,
        row.version,
        row.release,
        row.arch,
        row.sha256_header,
        row.sigmd5,
    )
    _require(all(fields), f"full RPM snapshot contains an empty field for {row.package or '<unknown>'}")
    _require(ASCII_DECIMAL.fullmatch(row.epoch) is not None, f"non-numeric epoch for {row.package}")
    _require(HEX64.fullmatch(row.sha256_header) is not None, f"invalid SHA256HEADER for {row.package}")
    _require(HEX32.fullmatch(row.sigmd5) is not None, f"invalid SIGMD5 for {row.package}")
    _require(row.package == _row_nevra(row), f"package field does not match snapshot row NEVRA: {row.package}")


def parse_full_rows(path: Path) -> tuple[LockRow, ...]:
    """Parse the frozen eight-column pre-strip RPM snapshot."""

    rows: list[LockRow] = []
    seen: set[str] = set()
    for line in _read_lf_lines(path, "full RPM snapshot"):
        parts = line.split("|")
        _require(len(parts) == 8, f"full RPM snapshot row must contain exactly 8 columns: {line}")
        row = LockRow(
            package=parts[0],
            final_rpmdb="no",
            name=parts[1],
            epoch=parts[2],
            version=parts[3],
            release=parts[4],
            arch=parts[5],
            sha256_header=parts[6],
            sigmd5=parts[7],
        )
        _validate_full_row(row)
        _require(row.package not in seen, f"duplicate full RPM snapshot row: {row.package}")
        seen.add(row.package)
        rows.append(row)
    return tuple(rows)


def parse_final_nevras(path: Path) -> tuple[str, ...]:
    """Parse the frozen post-strip survivor NEVRA snapshot."""

    final_nevras: list[str] = []
    seen: set[str] = set()
    for nevra in _read_lf_lines(path, "final RPM snapshot"):
        _require(bool(nevra), "final RPM snapshot contains an empty row")
        _require("|" not in nevra, f"malformed final RPM snapshot row: {nevra}")
        _require(nevra not in seen, f"duplicate final RPM snapshot row: {nevra}")
        seen.add(nevra)
        final_nevras.append(nevra)
    return tuple(final_nevras)


def parse_direct_results(path: Path) -> tuple[DirectRpm, ...]:
    """Parse shell-produced package, selected URL, and whole-RPM SHA results."""

    results: list[DirectRpm] = []
    seen: set[str] = set()
    for line in _read_lf_lines(path, "direct RPM result set"):
        parts = line.split("|")
        _require(len(parts) == 3 and all(parts), f"malformed direct RPM result: {line}")
        result = DirectRpm(package=parts[0], url=parts[1], sha256=parts[2])
        _require(result.package not in seen, f"duplicate direct RPM result: {result.package}")
        seen.add(result.package)
        results.append(result)
    return tuple(results)


def candidate_urls(row: LockRow, base_url: str, rpm_arch: str) -> tuple[str, str]:
    """Return the baseos-first, appstream-second CDN candidates for one row."""

    _validate_full_row(row)
    _require(row.arch in {"noarch", rpm_arch}, f"wrong RPM architecture for {row.package}: {row.arch}")
    _require(bool(row.name), f"empty RPM name for {row.package}")
    root = base_url.rstrip("/")
    filename = rpm_filename(row)
    package_directory = row.name[0]
    return (
        f"{root}/{rpm_arch}/baseos/os/Packages/{package_directory}/{filename}",
        f"{root}/{rpm_arch}/appstream/os/Packages/{package_directory}/{filename}",
    )


def signature_output_is_accepted(output: str) -> bool:
    """Judge the successful ``rpm -K`` output invariant."""

    return SIGNATURE_ACCEPTANCE in output


def _validate_selected_direct(row: LockRow, direct: DirectRpm) -> None:
    match = DIRECT_URL.fullmatch(direct.url)
    if match is None:
        raise GenerationError(f"selected direct RPM URL is not a supported UBI candidate for {row.package}")
    rpm_arch = match.group("rpm_arch")
    _require(row.arch in {"noarch", rpm_arch}, f"selected direct RPM URL architecture mismatch for {row.package}")
    candidates = candidate_urls(row, match.group("base"), rpm_arch)
    _require(direct.url in candidates, f"selected direct RPM URL does not match candidate policy for {row.package}")


def provider_nvr(provider_nevra: str) -> str:
    """Return the paired provider NVR from its required provider-so NEVRA pin."""

    _require(provider_nevra.startswith(FIPS_PROVIDER_PREFIX), f"invalid FIPS provider NEVRA pin: {provider_nevra}")
    value = provider_nevra.removeprefix(FIPS_PROVIDER_PREFIX)
    _require(bool(value), f"invalid FIPS provider NEVRA pin: {provider_nevra}")
    return value


def _validate_floor(full_rows: Iterable[LockRow], final_nevras: Iterable[str]) -> None:
    final_set = set(final_nevras)
    full_packages: set[str] = set()
    final_names: list[str] = []
    for row in full_rows:
        _validate_full_row(row)
        _require(row.package not in full_packages, f"duplicate full RPM snapshot row: {row.package}")
        full_packages.add(row.package)
        if row.package in final_set:
            final_names.append(row.name)
    missing_survivors = sorted(final_set - full_packages)
    if missing_survivors:
        raise GenerationError(f"final RPM snapshot contains survivor absent from full snapshot: {missing_survivors[0]}")
    _require(
        len(final_names) == len(REQUIRED_FINAL_NAMES) and set(final_names) == set(REQUIRED_FINAL_NAMES),
        "final RPM names differ from REQUIRED_FINAL_NAMES",
    )


def render(
    full_rows: Iterable[LockRow],
    final_nevras: Iterable[str],
    direct_results: Iterable[DirectRpm],
) -> bytes:
    """Render direct pins and classified rows, consuming ``full_rows`` exactly once in input order."""

    final_set = set(final_nevras)
    direct_by_package: dict[str, DirectRpm] = {}
    for result in direct_results:
        _require(result.package not in direct_by_package, f"duplicate direct RPM result: {result.package}")
        direct_by_package[result.package] = result

    seen_packages: set[str] = set()
    final_names: list[str] = []
    direct_lines: list[str] = []
    row_lines: list[str] = []
    rendered_rows: list[LockRow] = []
    ordered_direct: list[DirectRpm] = []
    for source_row in full_rows:
        _validate_full_row(source_row)
        _require(source_row.package not in seen_packages, f"duplicate full RPM snapshot row: {source_row.package}")
        seen_packages.add(source_row.package)
        _require(source_row.package in direct_by_package, f"missing direct RPM result for {source_row.package}")
        direct = direct_by_package[source_row.package]
        expected_filename = rpm_filename(source_row)
        _require(
            direct.url.rsplit("/", 1)[-1] == expected_filename,
            f"direct RPM result does not match row filename for {source_row.package}",
        )
        _validate_selected_direct(source_row, direct)
        final_rpmdb = "yes" if source_row.package in final_set else "no"
        if final_rpmdb == "yes":
            final_names.append(source_row.name)
        row = LockRow(
            package=source_row.package,
            final_rpmdb=final_rpmdb,
            name=source_row.name,
            epoch=source_row.epoch,
            version=source_row.version,
            release=source_row.release,
            arch=source_row.arch,
            sha256_header=source_row.sha256_header,
            sigmd5=source_row.sigmd5,
        )
        ordered_direct.append(direct)
        rendered_rows.append(row)
        direct_lines.append(f"# direct_rpm: {direct.package}|{direct.url}|{direct.sha256}")
        row_lines.append(
            "|".join(
                (
                    row.package,
                    row.final_rpmdb,
                    row.name,
                    row.epoch,
                    row.version,
                    row.release,
                    row.arch,
                    row.sha256_header,
                    row.sigmd5,
                )
            )
        )

    missing_survivors = sorted(final_set - seen_packages)
    if missing_survivors:
        raise GenerationError(f"final RPM snapshot contains survivor absent from full snapshot: {missing_survivors[0]}")
    extra_results = sorted(set(direct_by_package) - seen_packages)
    if extra_results:
        raise GenerationError(f"direct RPM result has no matching full row: {extra_results[0]}")
    _require(
        len(final_names) == len(REQUIRED_FINAL_NAMES) and set(final_names) == set(REQUIRED_FINAL_NAMES),
        "final RPM names differ from REQUIRED_FINAL_NAMES",
    )

    direct_map = {entry.package: (entry.url, entry.sha256) for entry in ordered_direct}
    generated = Lockfile(
        path=Path("<generated-runtime-lock>"),
        headers={},
        direct_entries=tuple(ordered_direct),
        direct_map=direct_map,
        rows=tuple(rendered_rows),
        terminal_lf=True,
        direct_line_numbers={},
        row_line_numbers=(),
    )
    try:
        validation = validate_common(generated, mode=CommonValidationMode.STRICT)
    except LockError as exc:
        raise GenerationError(str(exc)) from exc
    _require(validation.row_count == len(seen_packages), "rendered row count differs from the full RPM snapshot")
    return ("\n".join((*direct_lines, *row_lines)) + "\n").encode()


def render_lock(
    *,
    arch: str,
    source_date_epoch: str,
    full_rows: Iterable[LockRow],
    final_nevras: Iterable[str],
    direct_results: Iterable[DirectRpm],
) -> bytes:
    """Render a complete LF-terminated runtime lockfile."""

    _require(arch in RPM_ARCH_BY_PLATFORM, f"unsupported architecture: {arch}")
    _require(ASCII_DECIMAL.fullmatch(source_date_epoch) is not None, "SOURCE_DATE_EPOCH must be numeric")
    header = f"# arch: {arch}\n# source_date_epoch: {source_date_epoch}\n# columns: {COLUMNS}\n".encode()
    return header + render(full_rows, final_nevras, direct_results)


def _cmd_candidates(args: argparse.Namespace) -> int:
    rpm_arch = RPM_ARCH_BY_PLATFORM[cast(str, args.arch)]
    for row in parse_full_rows(args.full_rows):
        first, second = candidate_urls(row, args.base_url, rpm_arch)
        print(f"{row.package}|{first}|{second}")
    return 0


def _cmd_package_specs(_args: argparse.Namespace) -> int:
    print("\n".join(RUNTIME_PACKAGE_SPECS))
    return 0


def _cmd_provider_nvr(args: argparse.Namespace) -> int:
    print(provider_nvr(args.nevra))
    return 0


def _cmd_signature_output(args: argparse.Namespace) -> int:
    try:
        output = args.output.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise GenerationError(f"could not read rpm -K output: {args.output}") from exc
    _require(
        signature_output_is_accepted(output),
        "Red Hat RPM signature verification did not report digests signatures OK",
    )
    return 0


def _cmd_validate_floor(args: argparse.Namespace) -> int:
    _validate_floor(parse_full_rows(args.full_rows), parse_final_nevras(args.final_nevras))
    return 0


def _cmd_render(args: argparse.Namespace) -> int:
    rendered = render_lock(
        arch=args.arch,
        source_date_epoch=args.source_date_epoch,
        full_rows=iter(parse_full_rows(args.full_rows)),
        final_nevras=parse_final_nevras(args.final_nevras),
        direct_results=parse_direct_results(args.direct_results),
    )
    try:
        args.output.write_bytes(rendered)
    except OSError as exc:
        raise GenerationError(f"could not write generated runtime lock: {args.output}") from exc
    data_rows = [line for line in rendered.decode().splitlines() if line and not line.startswith("#")]
    no_set = sorted(line.split("|", 2)[0] for line in data_rows if line.split("|", 2)[1] == "no")
    print(f"rendered runtime lock rows={len(data_rows)} final={len(data_rows) - len(no_set)} discarded={len(no_set)}")
    print("rendered runtime lock no-set=" + ",".join(no_set))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    candidates = subparsers.add_parser("candidates", help="emit ordered CDN URL candidates")
    candidates.add_argument("--full-rows", required=True, type=Path)
    candidates.add_argument("--arch", required=True, choices=sorted(RPM_ARCH_BY_PLATFORM))
    candidates.add_argument("--base-url", required=True)
    candidates.set_defaults(handler=_cmd_candidates)

    package_specs = subparsers.add_parser("package-specs", help="emit the runtime installation package policy")
    package_specs.set_defaults(handler=_cmd_package_specs)

    provider = subparsers.add_parser("provider-nvr", help="derive the paired provider NVR")
    provider.add_argument("--nevra", required=True)
    provider.set_defaults(handler=_cmd_provider_nvr)

    signature = subparsers.add_parser("signature-output", help="validate successful rpm -K output")
    signature.add_argument("--output", required=True, type=Path)
    signature.set_defaults(handler=_cmd_signature_output)

    floor = subparsers.add_parser("validate-floor", help="validate the post-strip final RPM floor")
    floor.add_argument("--full-rows", required=True, type=Path)
    floor.add_argument("--final-nevras", required=True, type=Path)
    floor.set_defaults(handler=_cmd_validate_floor)

    render_parser = subparsers.add_parser("render", help="render the complete runtime RPM lock")
    render_parser.add_argument("--full-rows", required=True, type=Path)
    render_parser.add_argument("--final-nevras", required=True, type=Path)
    render_parser.add_argument("--direct-results", required=True, type=Path)
    render_parser.add_argument("--arch", required=True, choices=sorted(RPM_ARCH_BY_PLATFORM))
    render_parser.add_argument("--source-date-epoch", required=True)
    render_parser.add_argument("--output", required=True, type=Path)
    render_parser.set_defaults(handler=_cmd_render)
    return parser


CommandHandler = Callable[[argparse.Namespace], int]


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    handler = cast(CommandHandler, args.handler)
    try:
        return handler(args)
    except GenerationError as exc:
        print(f"runtime lock generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
