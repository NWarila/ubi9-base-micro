# Purpose: Validate the canonical runtime RPM lockfile parser and CLI.
# Role: test
# Micro-container candidate: gate-adjacent - pytest coverage for host/CI lockfile contract validation.
# Build-process: no - test-only coverage; not executed inside image builds.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from tools import rpmlock

ROOT = Path(__file__).resolve().parents[2]
AMD64_LOCK = ROOT / "rpm-lock" / "runtime.amd64.txt"
ARM64_LOCK = ROOT / "rpm-lock" / "runtime.arm64.txt"
BUILDER_AMD64_LOCK = ROOT / "rpm-lock" / "builder.amd64.txt"
BUILDER_ARM64_LOCK = ROOT / "rpm-lock" / "builder.arm64.txt"
EXPECTED_FINAL_NAMES = [
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
]


def _write_lock(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "runtime.txt"
    path.write_text(text, encoding="utf-8")
    return path


def _validate_text(tmp_path: Path, text: str, arch: str = "amd64") -> None:
    lockfile = rpmlock.parse(_write_lock(tmp_path, text))
    rpmlock.validate(lockfile, arch=arch)


def _lock_text() -> str:
    return AMD64_LOCK.read_text(encoding="utf-8")


def _builder_lock_text() -> str:
    return BUILDER_AMD64_LOCK.read_text(encoding="utf-8")


def _replace_first_data_row(text: str, replacement: list[str]) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line and not line.startswith("#"):
            lines[index] = "|".join(replacement)
            return "\n".join(lines) + "\n"
    raise AssertionError("fixture has no data row")


def _first_data_parts(text: str) -> list[str]:
    for line in text.splitlines():
        if line and not line.startswith("#"):
            return line.split("|")
    raise AssertionError("fixture has no data row")


def _replace_first_arch_data_row(text: str, arch: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if parts[6] != "noarch":
            parts[6] = arch
            lines[index] = "|".join(parts)
            return "\n".join(lines) + "\n"
    raise AssertionError("fixture has no architecture-specific data row")


def _replace_first_direct_line(text: str, replacement: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(rpmlock.DIRECT_PREFIX):
            lines[index] = replacement
            return "\n".join(lines) + "\n"
    raise AssertionError("fixture has no direct RPM line")


def _first_direct_line(text: str) -> str:
    for line in text.splitlines():
        if line.startswith(rpmlock.DIRECT_PREFIX):
            return line
    raise AssertionError("fixture has no direct RPM line")


@pytest.mark.parametrize(("arch", "path"), [("amd64", AMD64_LOCK), ("arm64", ARM64_LOCK)])
def test_committed_lockfiles_parse_and_validate(arch: str, path: Path) -> None:
    lockfile = rpmlock.parse(path)
    rpmlock.validate(lockfile, arch=arch)

    assert lockfile.headers["arch"] == arch
    assert len(lockfile.rows) == 38
    assert len(lockfile.direct_entries) == len(lockfile.rows)


@pytest.mark.parametrize(
    ("arch", "path"),
    [("amd64", BUILDER_AMD64_LOCK), ("arm64", BUILDER_ARM64_LOCK)],
)
def test_committed_builder_lockfiles_parse_and_validate(arch: str, path: Path) -> None:
    lockfile = rpmlock.parse_builder(path)
    rpmlock.validate_builder(lockfile, arch=arch)

    assert lockfile.headers == {"arch": arch, "columns": rpmlock.BUILDER_COLUMNS}
    assert [row.name for row in lockfile.rows] == list(rpmlock.BUILDER_PYTHON_NAMES)
    assert len(lockfile.direct_entries) == len(lockfile.rows) == 7


def test_floor_extracts_final_packages_in_input_order() -> None:
    lockfile = rpmlock.parse(AMD64_LOCK)
    rpmlock.validate(lockfile, arch="amd64")

    assert rpmlock.floor(lockfile) == [row.package for row in lockfile.rows if row.final_rpmdb == "yes"]
    assert [row.name for row in lockfile.rows if row.final_rpmdb == "yes"] == EXPECTED_FINAL_NAMES


def test_rpm_filename_derivation_omits_epoch() -> None:
    lockfile = rpmlock.parse(AMD64_LOCK)
    row = next(row for row in lockfile.rows if row.name == "findutils")

    assert row.epoch == "1"
    assert row.package.startswith("findutils-1:")
    assert rpmlock.rpm_filename(row) == "findutils-4.8.0-7.el9.x86_64.rpm"


def test_direct_rpms_parse_and_preserve_order() -> None:
    lockfile = rpmlock.parse(AMD64_LOCK)
    expected: list[tuple[str, str, str]] = []
    for line in _lock_text().splitlines():
        if not line.startswith(rpmlock.DIRECT_PREFIX):
            continue
        parts = line.removeprefix(rpmlock.DIRECT_PREFIX).split("|")
        assert len(parts) == 3
        expected.append((parts[0], parts[1], parts[2]))

    assert rpmlock.direct_rpms(lockfile) == expected


def test_row_input_order_is_preserved() -> None:
    lockfile = rpmlock.parse(AMD64_LOCK)
    row_packages = [line.split("|", 1)[0] for line in _lock_text().splitlines() if line and not line.startswith("#")]

    assert [row.package for row in lockfile.rows] == row_packages


@pytest.mark.parametrize(
    ("mutated_text", "message"),
    [
        (
            _replace_first_data_row(_lock_text(), _first_data_parts(_lock_text())[:-1]),
            "empty field in row",
        ),
        (
            _replace_first_data_row(_lock_text(), [*_first_data_parts(_lock_text()), "extra"]),
            "too many columns",
        ),
        (
            _replace_first_data_row(
                _lock_text(),
                [
                    _first_data_parts(_lock_text())[0],
                    "maybe",
                    *_first_data_parts(_lock_text())[2:],
                ],
            ),
            "invalid final_rpmdb=maybe",
        ),
        (_replace_first_arch_data_row(_lock_text(), "s390x"), "invalid arch=s390x"),
    ],
)
def test_rejects_bad_data_rows(tmp_path: Path, mutated_text: str, message: str) -> None:
    with pytest.raises(rpmlock.LockError, match=message):
        _validate_text(tmp_path, mutated_text)


def test_rejects_duplicate_direct_rpm(tmp_path: Path) -> None:
    lines = _lock_text().splitlines()
    first_direct = _first_direct_line(_lock_text())
    insert_at = lines.index(first_direct) + 1
    lines.insert(insert_at, first_direct)

    with pytest.raises(rpmlock.LockError, match="duplicate direct RPM entry"):
        _validate_text(tmp_path, "\n".join(lines) + "\n")


def test_rejects_row_without_direct_rpm(tmp_path: Path) -> None:
    first_direct = _first_direct_line(_lock_text())
    mutated = "\n".join(line for line in _lock_text().splitlines() if line != first_direct) + "\n"

    with pytest.raises(rpmlock.LockError, match="missing direct RPM source pin"):
        _validate_text(tmp_path, mutated)


def test_rejects_direct_rpm_without_row(tmp_path: Path) -> None:
    first_direct = _first_direct_line(_lock_text())
    payload = first_direct.removeprefix(rpmlock.DIRECT_PREFIX).split("|")
    extra_direct = f"{rpmlock.DIRECT_PREFIX}ghost-1-1.el9.noarch|{payload[1]}|{payload[2]}"
    lines = _lock_text().splitlines()
    lines.insert(lines.index(first_direct) + 1, extra_direct)

    with pytest.raises(rpmlock.LockError, match="expected 38 direct RPM pins"):
        _validate_text(tmp_path, "\n".join(lines) + "\n")


def test_rejects_direct_rpm_filename_mismatch(tmp_path: Path) -> None:
    first_direct = _first_direct_line(_lock_text())
    mutated_direct = first_direct.replace(".rpm|", ".wrong.rpm|", 1)
    mutated = _replace_first_direct_line(_lock_text(), mutated_direct)

    with pytest.raises(rpmlock.LockError, match="direct RPM URL filename mismatch"):
        _validate_text(tmp_path, mutated)


def test_rejects_empty_file(tmp_path: Path) -> None:
    path = _write_lock(tmp_path, "")

    with pytest.raises(rpmlock.LockError, match="missing or empty"):
        rpmlock.parse(path)


@pytest.mark.parametrize(
    ("mutated_text", "message"),
    [
        (_lock_text().replace("# arch: amd64", "# arch: arm64", 1), "invalid arch header"),
        (
            _lock_text().replace("# source_date_epoch: 1704067200", "# source_date_epoch: 1", 1),
            "invalid source_date_epoch header",
        ),
        (_lock_text().replace(rpmlock.COLUMNS, "package|final_rpmdb", 1), "invalid columns header"),
        (
            _replace_first_data_row(
                _lock_text(),
                [
                    *_first_data_parts(_lock_text())[:3],
                    "epoch",
                    *_first_data_parts(_lock_text())[4:],
                ],
            ),
            "non-numeric epoch",
        ),
        (
            _replace_first_data_row(
                _lock_text(),
                [
                    *_first_data_parts(_lock_text())[:7],
                    "0" * 63,
                    _first_data_parts(_lock_text())[8],
                ],
            ),
            "invalid SHA256HEADER",
        ),
        (
            _replace_first_data_row(
                _lock_text(),
                [
                    *_first_data_parts(_lock_text())[:8],
                    "0" * 31,
                ],
            ),
            "invalid SIGMD5",
        ),
    ],
)
def test_rejects_other_mirrored_validator_failures(tmp_path: Path, mutated_text: str, message: str) -> None:
    with pytest.raises(rpmlock.LockError, match=message):
        _validate_text(tmp_path, mutated_text)


def test_rejects_arch_header_at_eof(tmp_path: Path) -> None:
    lines = _lock_text().splitlines()
    arch_header = lines.pop(0)
    lines.append(arch_header)

    with pytest.raises(rpmlock.LockError, match="invalid arch header"):
        _validate_text(tmp_path, "\n".join(lines) + "\n")


def test_rejects_wrong_arch_header_even_with_later_correct_duplicate(tmp_path: Path) -> None:
    lines = _lock_text().splitlines()
    lines[0] = "# arch: arm64"
    lines.insert(3, "# arch: amd64")

    with pytest.raises(rpmlock.LockError, match="invalid arch header"):
        _validate_text(tmp_path, "\n".join(lines) + "\n")


def test_rejects_non_ascii_digit_epoch(tmp_path: Path) -> None:
    parts = _first_data_parts(_lock_text())
    mutated = _replace_first_data_row(_lock_text(), [*parts[:3], "\u0661", *parts[4:]])

    with pytest.raises(rpmlock.LockError, match="non-numeric epoch"):
        _validate_text(tmp_path, mutated)


def test_rejects_crlf_lockfile(tmp_path: Path) -> None:
    path = tmp_path / "runtime.txt"
    path.write_bytes(_lock_text().replace("\n", "\r\n").encode("utf-8"))

    with pytest.raises(rpmlock.LockError, match="CR characters are not allowed"):
        rpmlock.parse(path)


def test_inert_stray_header_comment_after_positional_headers_validates(tmp_path: Path) -> None:
    lines = _lock_text().splitlines()
    lines.insert(3, "# arch: arm64")

    _validate_text(tmp_path, "\n".join(lines) + "\n")


def test_rejects_unsorted_and_duplicate_rows(tmp_path: Path) -> None:
    lines = _lock_text().splitlines()
    row_indexes = [index for index, line in enumerate(lines) if line and not line.startswith("#")]
    lines[row_indexes[0]], lines[row_indexes[1]] = lines[row_indexes[1]], lines[row_indexes[0]]
    with pytest.raises(rpmlock.LockError, match="rows are not sorted by package"):
        _validate_text(tmp_path, "\n".join(lines) + "\n")

    lines = _lock_text().splitlines()
    lines[row_indexes[1]] = lines[row_indexes[0]]
    with pytest.raises(rpmlock.LockError, match="duplicate package row"):
        _validate_text(tmp_path, "\n".join(lines) + "\n")


def test_rejects_provider_pin_mismatch(tmp_path: Path) -> None:
    mutated = _lock_text().replace(
        "bbf25303def8e1270675531c47bdad432f6ad8ef4c327556ae65bd6abaf8edb5",
        "0" * 64,
        1,
    )

    with pytest.raises(rpmlock.LockError, match="FIPS provider package direct pin mismatch"):
        _validate_text(tmp_path, mutated)


def test_builder_lock_rejects_degenerate_runtime_grammar(tmp_path: Path) -> None:
    path = tmp_path / "builder.txt"
    path.write_text(
        _builder_lock_text().replace(rpmlock.BUILDER_COLUMNS, rpmlock.COLUMNS, 1),
        encoding="utf-8",
    )

    with pytest.raises(rpmlock.LockError, match="invalid columns header"):
        rpmlock.validate_builder(rpmlock.parse_builder(path), arch="amd64")


def test_builder_lock_rejects_incomplete_closure(tmp_path: Path) -> None:
    path = tmp_path / "builder.txt"
    lines = [line for line in _builder_lock_text().splitlines() if "python3.12-pip-wheel" not in line]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(rpmlock.LockError, match="builder Python closure must contain exactly"):
        rpmlock.validate_builder(rpmlock.parse_builder(path), arch="amd64")


def test_builder_lock_rejects_package_field_that_is_not_row_nevra(tmp_path: Path) -> None:
    path = tmp_path / "builder.txt"
    lines = _builder_lock_text().splitlines()
    row_index = next(index for index, line in enumerate(lines) if line and not line.startswith("#"))
    parts = lines[row_index].split("|")
    parts[0] = "expat-0-0.x86_64"
    lines[row_index] = "|".join(parts)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(rpmlock.LockError, match="package field does not match builder row NEVRA"):
        rpmlock.validate_builder(rpmlock.parse_builder(path), arch="amd64")


def test_cli_validate_and_summary() -> None:
    command = [
        sys.executable,
        str(ROOT / "tools" / "rpmlock.py"),
        "summary",
        "--lockfile",
        str(AMD64_LOCK),
        "--arch",
        "amd64",
    ]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)

    assert result.returncode == 0, result.stderr
    summary = cast(dict[str, Any], json.loads(result.stdout))
    assert len(cast(list[object], summary["rows"])) == 38
    assert len(cast(list[object], summary["direct_rpms"])) == 38
    assert len(cast(list[object], summary["floor"])) == 15


def test_cli_builder_validate_and_summary() -> None:
    validate_command = [
        sys.executable,
        str(ROOT / "tools" / "rpmlock.py"),
        "builder-validate",
        "--lockfile",
        str(BUILDER_AMD64_LOCK),
        "--arch",
        "amd64",
    ]
    validate_result = subprocess.run(validate_command, cwd=ROOT, text=True, capture_output=True, check=False)
    assert validate_result.returncode == 0, validate_result.stderr

    summary_command = [*validate_command[:2], "builder-summary", *validate_command[3:]]
    summary_result = subprocess.run(summary_command, cwd=ROOT, text=True, capture_output=True, check=False)
    assert summary_result.returncode == 0, summary_result.stderr
    summary = cast(dict[str, Any], json.loads(summary_result.stdout))
    assert len(cast(list[object], summary["rows"])) == 7
    assert len(cast(list[object], summary["direct_rpms"])) == 7
