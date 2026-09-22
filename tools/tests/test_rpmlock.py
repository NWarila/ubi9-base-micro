# Purpose: Validate the canonical runtime, FIPS-verification, and builder RPM lockfile parser and CLI.
# Role: test
# Micro-container candidate: gate-adjacent - pytest coverage for host/CI lockfile contract validation.
# Build-process: no - test-only coverage; not executed inside image builds.

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from tools import rpmlock

ROOT = Path(__file__).resolve().parents[2]
AMD64_LOCK = ROOT / "rpm-lock" / "runtime.amd64.txt"
ARM64_LOCK = ROOT / "rpm-lock" / "runtime.arm64.txt"
BUILDER_AMD64_LOCK = ROOT / "rpm-lock" / "builder.amd64.txt"
BUILDER_ARM64_LOCK = ROOT / "rpm-lock" / "builder.arm64.txt"
FIPS_AMD64_LOCK = ROOT / "rpm-lock" / "fips-verify.amd64.txt"
FIPS_ARM64_LOCK = ROOT / "rpm-lock" / "fips-verify.arm64.txt"
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


def _policy_cli_args(policy: rpmlock.LockPolicy) -> list[str]:
    return [
        "--source-date-epoch",
        policy.source_date_epoch,
        "--openssl-fips-provider-nevra",
        policy.openssl_fips_provider_nevra,
        "--openssl-fips-provider-rpm-base-url",
        policy.openssl_fips_provider_rpm_base_url,
        "--openssl-fips-provider-rpm-sha256-x86-64",
        policy.openssl_fips_provider_rpm_sha256_x86_64,
        "--openssl-fips-provider-rpm-sha256-aarch64",
        policy.openssl_fips_provider_rpm_sha256_aarch64,
        "--openssl-fips-provider-so-rpm-sha256-x86-64",
        policy.openssl_fips_provider_so_rpm_sha256_x86_64,
        "--openssl-fips-provider-so-rpm-sha256-aarch64",
        policy.openssl_fips_provider_so_rpm_sha256_aarch64,
    ]


def _expected_rpm_filename_bytes(path: Path) -> bytes:
    filenames: list[bytes] = []
    for line in path.read_bytes().splitlines():
        if not line or line.startswith(b"#"):
            continue
        columns = line.split(b"|")
        filenames.append(b"-".join((columns[2], columns[4], columns[5])) + b"." + columns[6] + b".rpm")
    return b"\n".join(filenames) + b"\n"


def _rpm_filenames_command(path: Path, arch: str, policy: rpmlock.LockPolicy) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "tools" / "rpmlock.py"),
        "rpm-filenames",
        "--lockfile",
        str(path),
        "--arch",
        arch,
        *_policy_cli_args(policy),
    ]


def _fips_rpm_filenames_command(
    fips_path: Path,
    runtime_path: Path,
    arch: str,
    policy: rpmlock.LockPolicy,
) -> list[str]:
    return [
        sys.executable,
        str(ROOT / "tools" / "rpmlock.py"),
        "fips-rpm-filenames",
        "--fips-lockfile",
        str(fips_path),
        "--runtime-lockfile",
        str(runtime_path),
        "--arch",
        arch,
        *_policy_cli_args(policy),
    ]


def _write_lock(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "runtime.txt"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _validate_text(tmp_path: Path, text: str, arch: str = "amd64") -> None:
    lockfile = rpmlock.parse(_write_lock(tmp_path, text))
    rpmlock.validate(lockfile, arch=arch)


def _lock_text() -> str:
    return AMD64_LOCK.read_text(encoding="utf-8")


def _builder_lock_text() -> str:
    return BUILDER_AMD64_LOCK.read_text(encoding="utf-8")


def _fips_lock_text() -> str:
    return FIPS_AMD64_LOCK.read_text(encoding="utf-8")


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


def _lock_row_line(row: rpmlock.LockRow) -> str:
    return "|".join(
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


def _direct_rpm_line(entry: rpmlock.DirectRpm) -> str:
    return f"{rpmlock.DIRECT_PREFIX}{entry.package}|{entry.url}|{entry.sha256}"


def _replace_once(text: str, needle: str, replacement: str) -> str:
    return text.replace(needle, replacement, 1)


def _mutate_lock_fields(
    tmp_path: Path,
    original_text: str,
    *,
    filename: str,
    field_name: str,
    replacements: tuple[tuple[str, str], ...],
    field_value: Callable[[rpmlock.Lockfile], object],
    expected_value: object,
    replace_once: Callable[[str, str, str], str] = _replace_once,
) -> tuple[str, rpmlock.Lockfile, rpmlock.Lockfile]:
    original_path = tmp_path / f"original-{filename}"
    original_path.write_text(original_text, encoding="utf-8", newline="\n")
    original = rpmlock.parse(original_path)
    original_value = field_value(original)

    mutated_text = original_text
    for needle, replacement in replacements:
        mutated_text = replace_once(mutated_text, needle, replacement)

    mutated_path = tmp_path / filename
    mutated_path.write_text(mutated_text, encoding="utf-8", newline="\n")
    mutated = rpmlock.parse(mutated_path)
    actual_value = field_value(mutated)
    if actual_value == original_value:
        raise AssertionError(f"{field_name} field mutation did not change the original value {original_value!r}")
    if actual_value != expected_value:
        raise AssertionError(f"{field_name} field mutation produced {actual_value!r}; expected {expected_value!r}")
    return mutated_text, original, mutated


def _only_fips_row(lockfile: rpmlock.Lockfile) -> rpmlock.LockRow:
    assert len(lockfile.rows) == 1
    return lockfile.rows[0]


def _only_direct_entry(lockfile: rpmlock.Lockfile) -> rpmlock.DirectRpm:
    assert len(lockfile.direct_entries) == 1
    return lockfile.direct_entries[0]


def _fips_identity_fields(lockfile: rpmlock.Lockfile) -> tuple[str, str, str, str]:
    row = _only_fips_row(lockfile)
    direct = _only_direct_entry(lockfile)
    return (row.release, row.package, direct.package, direct.url.rsplit("/", 1)[-1])


def _mutate_fips_release(
    tmp_path: Path,
    original_text: str,
    *,
    replace_once: Callable[[str, str, str], str] = _replace_once,
) -> tuple[str, rpmlock.Lockfile, rpmlock.Lockfile]:
    source_path = tmp_path / "fips-release-source.txt"
    source_path.write_text(original_text, encoding="utf-8", newline="\n")
    source = rpmlock.parse(source_path)
    source_row = _only_fips_row(source)
    source_direct = _only_direct_entry(source)

    mutated_release = f"{source_row.release}.fixture"
    mutated_row = replace(source_row, release=mutated_release)
    mutated_package = rpmlock.lock_nevra(mutated_row)
    mutated_row = replace(mutated_row, package=mutated_package)
    source_filename = rpmlock.rpm_filename(source_row)
    assert source_direct.url.endswith(f"/{source_filename}")
    mutated_url = source_direct.url.removesuffix(source_filename) + rpmlock.rpm_filename(mutated_row)
    mutated_direct = replace(source_direct, package=mutated_package, url=mutated_url)

    mutated_text, original, mutated = _mutate_lock_fields(
        tmp_path,
        original_text,
        filename="fips-release-fixture.txt",
        field_name="FIPS release identity",
        replacements=(
            (_direct_rpm_line(source_direct), _direct_rpm_line(mutated_direct)),
            (_lock_row_line(source_row), _lock_row_line(mutated_row)),
        ),
        field_value=_fips_identity_fields,
        expected_value=(
            mutated_release,
            mutated_package,
            mutated_package,
            rpmlock.rpm_filename(mutated_row),
        ),
        replace_once=replace_once,
    )

    original_row = _only_fips_row(original)
    original_direct = _only_direct_entry(original)
    assert mutated.headers == original.headers
    assert _only_fips_row(mutated) == replace(
        original_row,
        package=mutated_package,
        release=mutated_release,
    )
    assert _only_direct_entry(mutated) == replace(
        original_direct,
        package=mutated_package,
        url=mutated_url,
    )
    assert mutated.terminal_lf == original.terminal_lf
    return mutated_text, original, mutated


def _mutate_fips_package_nevra(
    tmp_path: Path,
    original_text: str,
) -> tuple[rpmlock.Lockfile, rpmlock.Lockfile]:
    source_path = tmp_path / "fips-package-source.txt"
    source_path.write_text(original_text, encoding="utf-8", newline="\n")
    source = rpmlock.parse(source_path)
    source_row = _only_fips_row(source)
    source_direct = _only_direct_entry(source)

    mismatched_package = rpmlock.lock_nevra(replace(source_row, release=f"{source_row.release}.fixture"))
    mutated_row = replace(source_row, package=mismatched_package)
    mutated_direct = replace(source_direct, package=mismatched_package)
    _, original, mutated = _mutate_lock_fields(
        tmp_path,
        original_text,
        filename="fips-package-fixture.txt",
        field_name="FIPS package NEVRA",
        replacements=(
            (_direct_rpm_line(source_direct), _direct_rpm_line(mutated_direct)),
            (_lock_row_line(source_row), _lock_row_line(mutated_row)),
        ),
        field_value=lambda lockfile: (
            _only_fips_row(lockfile).package,
            _only_direct_entry(lockfile).package,
        ),
        expected_value=(mismatched_package, mismatched_package),
    )

    original_row = _only_fips_row(original)
    original_direct = _only_direct_entry(original)
    assert mutated.headers == original.headers
    assert _only_fips_row(mutated) == replace(original_row, package=mismatched_package)
    assert _only_direct_entry(mutated) == replace(original_direct, package=mismatched_package)
    assert mutated.terminal_lf == original.terminal_lf
    return original, mutated


def _assert_cross_lock_evr_mismatch(
    fips_lockfile: rpmlock.Lockfile,
    runtime_lockfile: rpmlock.Lockfile,
) -> None:
    rpmlock.validate_fips(fips_lockfile, arch="amd64")
    expected = f"{fips_lockfile.path}: openssl EVR does not match {runtime_lockfile.path} openssl-libs EVR"
    with pytest.raises(rpmlock.LockError, match=rf"^{re.escape(expected)}$") as exc:
        rpmlock.fips_verification_filenames(fips_lockfile, runtime_lockfile)
    assert str(exc.value) == expected


def _mutation_literal_needles(source: str) -> list[str]:
    needles: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "replace"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            needles.append(node.args[0].value)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_mutate_lock_fields":
            replacements = next((item.value for item in node.keywords if item.arg == "replacements"), None)
            if replacements is not None:
                needles.extend(
                    child.value
                    for child in ast.walk(replacements)
                    if isinstance(child, ast.Constant) and isinstance(child.value, str)
                )
    return needles


def _committed_mutation_values() -> set[str]:
    values: set[str] = set()
    for path in (AMD64_LOCK, ARM64_LOCK, FIPS_AMD64_LOCK, FIPS_ARM64_LOCK):
        lockfile = rpmlock.parse(path)
        source_date_epoch = lockfile.headers.get("source_date_epoch")
        if source_date_epoch is not None:
            values.add(f"# source_date_epoch: {source_date_epoch}")
        for row in lockfile.rows:
            if not row.name.startswith("openssl"):
                continue
            values.update(
                {
                    row.package,
                    row.version,
                    row.release,
                    row.sha256_header,
                    row.sigmd5,
                    f"{row.epoch}:{row.version}",
                }
            )
        for entry in lockfile.direct_entries:
            if entry.package.startswith("openssl"):
                values.update({entry.package, entry.sha256})
    return values


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


@pytest.mark.parametrize(
    ("arch", "path", "rpm_arch"),
    [
        ("amd64", FIPS_AMD64_LOCK, "x86_64"),
        ("arm64", FIPS_ARM64_LOCK, "aarch64"),
    ],
)
def test_committed_fips_lockfiles_parse_and_validate(arch: str, path: Path, rpm_arch: str) -> None:
    lockfile = rpmlock.parse(path)
    rpmlock.validate_fips(lockfile, arch=arch)

    assert lockfile.headers == {
        "arch": arch,
        "source_date_epoch": "1704067200",
        "columns": rpmlock.COLUMNS,
    }
    assert len(lockfile.direct_entries) == len(lockfile.rows) == 1
    assert lockfile.rows[0].name == "openssl"
    assert lockfile.rows[0].final_rpmdb == "no"
    assert lockfile.rows[0].arch == rpm_arch


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


@pytest.mark.parametrize(
    ("arch", "runtime_path", "fips_path"),
    [
        ("amd64", AMD64_LOCK, FIPS_AMD64_LOCK),
        ("arm64", ARM64_LOCK, FIPS_ARM64_LOCK),
    ],
)
def test_cli_fips_rpm_filenames_selects_exact_identities(
    arch: str,
    runtime_path: Path,
    fips_path: Path,
) -> None:
    result = subprocess.run(
        _fips_rpm_filenames_command(fips_path, runtime_path, arch, rpmlock.LockPolicy.from_repo()),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    fips_lockfile = rpmlock.parse(fips_path)
    runtime_lockfile = rpmlock.parse(runtime_path)
    expected_rows = (
        next(row for row in fips_lockfile.rows if row.name == "openssl"),
        next(row for row in runtime_lockfile.rows if row.name == "openssl-libs"),
        next(row for row in runtime_lockfile.rows if row.name == "crypto-policies"),
    )
    assert result.stdout.splitlines() == [rpmlock.rpm_filename(row) for row in expected_rows]


def test_fips_filename_selection_rejects_missing_and_duplicate_identities() -> None:
    fips_lockfile = rpmlock.parse(FIPS_AMD64_LOCK)
    runtime_lockfile = rpmlock.parse(AMD64_LOCK)
    crypto = next(row for row in runtime_lockfile.rows if row.name == "crypto-policies")
    without_crypto = replace(runtime_lockfile, rows=tuple(row for row in runtime_lockfile.rows if row is not crypto))
    duplicate_crypto = replace(runtime_lockfile, rows=(*runtime_lockfile.rows, crypto))

    with pytest.raises(rpmlock.LockError, match="exactly one crypto-policies row, got 0"):
        rpmlock.fips_verification_filenames(fips_lockfile, without_crypto)
    with pytest.raises(rpmlock.LockError, match="exactly one crypto-policies row, got 2"):
        rpmlock.fips_verification_filenames(fips_lockfile, duplicate_crypto)


def test_crypto_policies_filename_is_derived_from_fixture_identity() -> None:
    fips_lockfile = rpmlock.parse(FIPS_AMD64_LOCK)
    runtime_lockfile = rpmlock.parse(AMD64_LOCK)
    crypto = next(row for row in runtime_lockfile.rows if row.name == "crypto-policies")
    changed_crypto = replace(
        crypto,
        package="crypto-policies-20991231-2.example.el9.noarch",
        version="20991231",
        release="2.example.el9",
    )
    fixture = replace(
        runtime_lockfile,
        rows=tuple(changed_crypto if row is crypto else row for row in runtime_lockfile.rows),
    )

    assert rpmlock.fips_verification_filenames(fips_lockfile, fixture)[2] == (
        "crypto-policies-20991231-2.example.el9.noarch.rpm"
    )


def test_cli_fips_filename_selection_rejects_cross_lock_evr_mismatch(tmp_path: Path) -> None:
    _, _, fips_lockfile = _mutate_fips_release(tmp_path, _fips_lock_text())
    runtime_lockfile = rpmlock.parse(AMD64_LOCK)

    _assert_cross_lock_evr_mismatch(fips_lockfile, runtime_lockfile)


def test_fips_release_mutation_derives_from_synthetic_generation(tmp_path: Path) -> None:
    source_path = tmp_path / "synthetic-source.txt"
    source_path.write_text(_fips_lock_text(), encoding="utf-8", newline="\n")
    source = rpmlock.parse(source_path)
    source_row = _only_fips_row(source)
    source_direct = _only_direct_entry(source)
    synthetic_release = "42.preview_el9"
    assert synthetic_release != source_row.release

    synthetic_row = replace(source_row, release=synthetic_release)
    synthetic_package = rpmlock.lock_nevra(synthetic_row)
    synthetic_row = replace(synthetic_row, package=synthetic_package)
    source_filename = rpmlock.rpm_filename(source_row)
    assert source_direct.url.endswith(f"/{source_filename}")
    synthetic_url = source_direct.url.removesuffix(source_filename) + rpmlock.rpm_filename(synthetic_row)
    synthetic_direct = replace(source_direct, package=synthetic_package, url=synthetic_url)
    synthetic_text = _fips_lock_text()
    synthetic_text = _replace_once(
        synthetic_text,
        _direct_rpm_line(source_direct),
        _direct_rpm_line(synthetic_direct),
    )
    synthetic_text = _replace_once(
        synthetic_text,
        _lock_row_line(source_row),
        _lock_row_line(synthetic_row),
    )

    _, original, mutated = _mutate_fips_release(tmp_path, synthetic_text)

    assert _only_fips_row(original).release == synthetic_release
    assert _only_fips_row(mutated).release == f"{synthetic_release}.fixture"


def test_cross_lock_guard_binding_rejects_wrong_guard(tmp_path: Path) -> None:
    mutated_text, _, release_mutated = _mutate_fips_release(tmp_path, _fips_lock_text())
    release_row = _only_fips_row(release_mutated)
    wrong_guard_row = replace(release_row, final_rpmdb="yes")
    _, _, wrong_guard = _mutate_lock_fields(
        tmp_path,
        mutated_text,
        filename="openssl EVR does not match.txt",
        field_name="FIPS final_rpmdb",
        replacements=((_lock_row_line(release_row), _lock_row_line(wrong_guard_row)),),
        field_value=lambda lockfile: _only_fips_row(lockfile).final_rpmdb,
        expected_value="yes",
    )
    expected = f"{wrong_guard.path}: FIPS verification RPM must use final_rpmdb=no for {wrong_guard_row.package}"

    with pytest.raises(rpmlock.LockError, match=rf"^{re.escape(expected)}$") as exc:
        _assert_cross_lock_evr_mismatch(wrong_guard, rpmlock.parse(AMD64_LOCK))
    assert str(exc.value) == expected


def test_fips_release_mutation_rejects_noop_replacement(tmp_path: Path) -> None:
    def no_op(text: str, _needle: str, _replacement: str) -> str:
        return text

    with pytest.raises(AssertionError, match="FIPS release identity field mutation did not change"):
        _mutate_fips_release(tmp_path, _fips_lock_text(), replace_once=no_op)


def test_mutation_needles_do_not_pin_committed_values() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    needles = _mutation_literal_needles(source)
    violations = sorted(
        (needle, value) for needle in needles for value in _committed_mutation_values() if value in needle
    )

    assert not violations, f"committed lock value used as a mutation needle: {violations}"


def test_cli_fips_filename_selection_rejects_wrong_arch(tmp_path: Path) -> None:
    fips_path = tmp_path / "fips-verify.amd64.txt"
    fips_path.write_text(
        _fips_lock_text().replace("x86_64", "aarch64"),
        encoding="utf-8",
        newline="\n",
    )

    result = subprocess.run(
        _fips_rpm_filenames_command(fips_path, AMD64_LOCK, "amd64", rpmlock.LockPolicy.from_repo()),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "invalid arch=aarch64" in result.stderr


@pytest.mark.parametrize(("arch", "path"), [("amd64", AMD64_LOCK), ("arm64", ARM64_LOCK)])
def test_cli_rpm_filenames_matches_independent_lock_projection(arch: str, path: Path) -> None:
    result = subprocess.run(
        _rpm_filenames_command(path, arch, rpmlock.LockPolicy.from_repo()),
        cwd=ROOT,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == _expected_rpm_filename_bytes(path)
    assert len(result.stdout.splitlines()) == 38


def test_cli_rpm_filenames_includes_final_row_without_terminal_lf(tmp_path: Path) -> None:
    path = tmp_path / "runtime.amd64.txt"
    path.write_bytes(AMD64_LOCK.read_bytes().removesuffix(b"\n"))

    result = subprocess.run(
        _rpm_filenames_command(path, "amd64", rpmlock.LockPolicy.from_repo()),
        cwd=ROOT,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode()
    assert result.stdout == _expected_rpm_filename_bytes(path)
    assert result.stdout.splitlines()[-1] == _expected_rpm_filename_bytes(path).splitlines()[-1]


def test_cli_full_explicit_policy_bypasses_repo_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = rpmlock.LockPolicy.from_repo()

    def fail_from_repo(_cls: type[rpmlock.LockPolicy], _repo_root: Path | None = None) -> rpmlock.LockPolicy:
        raise AssertionError("LockPolicy.from_repo must not run for a fully explicit policy")

    monkeypatch.setattr(rpmlock.LockPolicy, "from_repo", classmethod(fail_from_repo))

    assert rpmlock.main(_rpm_filenames_command(AMD64_LOCK, "amd64", policy)[2:]) == 0


def test_cli_incomplete_policy_uses_and_enforces_repo_fallback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mismatched_policy = rpmlock.LockPolicy.from_repo().with_overrides(source_date_epoch="1")
    calls = 0

    def fallback_policy(_cls: type[rpmlock.LockPolicy], _repo_root: Path | None = None) -> rpmlock.LockPolicy:
        nonlocal calls
        calls += 1
        return mismatched_policy

    monkeypatch.setattr(rpmlock.LockPolicy, "from_repo", classmethod(fallback_policy))

    result = rpmlock.main(["validate", "--lockfile", str(AMD64_LOCK), "--arch", "amd64"])

    assert result == 1
    assert calls == 1
    assert "invalid source_date_epoch header" in capsys.readouterr().err


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


def test_common_validation_modes_preserve_strict_and_named_orphan_order(tmp_path: Path) -> None:
    first_direct = _first_direct_line(_lock_text())
    payload = first_direct.removeprefix(rpmlock.DIRECT_PREFIX).split("|")
    extra_direct = f"{rpmlock.DIRECT_PREFIX}ghost-1-1.el9.noarch|{payload[1]}|{payload[2]}"
    lines = _lock_text().splitlines()
    lines.insert(lines.index(first_direct) + 1, extra_direct)
    lockfile = rpmlock.parse(_write_lock(tmp_path, "\n".join(lines) + "\n"))

    with pytest.raises(rpmlock.LockError, match="expected 38 direct RPM pins"):
        rpmlock.validate_common(lockfile, mode=rpmlock.CommonValidationMode.STRICT)
    with pytest.raises(rpmlock.LockError, match="direct RPM entry has no matching package row: ghost"):
        rpmlock.validate_common(lockfile, mode=rpmlock.CommonValidationMode.ASSERTION)


def test_assertion_compatibility_rejects_pin_after_row(tmp_path: Path) -> None:
    lines = _lock_text().splitlines()
    first_direct = _first_direct_line(_lock_text())
    direct_index = lines.index(first_direct)
    package = first_direct.removeprefix(rpmlock.DIRECT_PREFIX).split("|", 1)[0]
    row_index = next(index for index, line in enumerate(lines) if line.startswith(f"{package}|"))
    lines.pop(direct_index)
    lines.insert(row_index, first_direct)
    lockfile = rpmlock.parse(_write_lock(tmp_path, "\n".join(lines) + "\n"))

    with pytest.raises(rpmlock.LockError, match="direct RPM source pin must precede package row"):
        rpmlock.validate_assertion_compatibility(lockfile)


def test_assertion_compatibility_requires_terminal_lf(tmp_path: Path) -> None:
    path = tmp_path / "runtime.txt"
    path.write_bytes(AMD64_LOCK.read_bytes().removesuffix(b"\n"))

    with pytest.raises(rpmlock.LockError, match="must end with a line feed"):
        rpmlock.validate_assertion_compatibility(rpmlock.parse(path))


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


def test_rejects_source_date_epoch_mismatch(tmp_path: Path) -> None:
    committed = rpmlock.parse(AMD64_LOCK)
    source_date_epoch = committed.headers["source_date_epoch"]
    mutated_epoch = f"{source_date_epoch}0"
    _, _, mutated = _mutate_lock_fields(
        tmp_path,
        _lock_text(),
        filename="source-date-epoch-fixture.txt",
        field_name="source_date_epoch header",
        replacements=(
            (
                f"# source_date_epoch: {source_date_epoch}",
                f"# source_date_epoch: {mutated_epoch}",
            ),
        ),
        field_value=lambda lockfile: lockfile.headers.get("source_date_epoch"),
        expected_value=mutated_epoch,
    )
    expected = f"{mutated.path}: invalid source_date_epoch header"

    with pytest.raises(rpmlock.LockError, match=rf"^{re.escape(expected)}$") as exc:
        rpmlock.validate(mutated, arch="amd64")
    assert str(exc.value) == expected


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


@pytest.mark.parametrize(
    "separator",
    ["\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"],
)
def test_rejects_non_lf_unicode_line_separators(tmp_path: Path, separator: str) -> None:
    path = tmp_path / "runtime.txt"
    path.write_bytes(_lock_text().replace("\n", separator, 1).encode("utf-8"))

    with pytest.raises(rpmlock.LockError, match="only LF line separators are allowed"):
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
    committed = rpmlock.parse(AMD64_LOCK)
    provider_row = next(row for row in committed.rows if row.name == "openssl-fips-provider")
    provider_direct = next(entry for entry in committed.direct_entries if entry.package == provider_row.package)
    replacement_prefix = "0" if provider_direct.sha256[0] != "0" else "1"
    mutated_digest = replacement_prefix + provider_direct.sha256[1:]
    mutated_direct = replace(provider_direct, sha256=mutated_digest)
    _, original, mutated = _mutate_lock_fields(
        tmp_path,
        _lock_text(),
        filename="provider-digest-fixture.txt",
        field_name="OpenSSL FIPS provider direct RPM sha256",
        replacements=((_direct_rpm_line(provider_direct), _direct_rpm_line(mutated_direct)),),
        field_value=lambda lockfile: lockfile.direct_map[provider_row.package][1],
        expected_value=mutated_digest,
    )
    assert mutated.headers == original.headers
    assert mutated.rows == original.rows
    assert mutated.direct_entries == tuple(
        mutated_direct if entry.package == provider_row.package else entry for entry in original.direct_entries
    )
    expected = f"{mutated.path}: FIPS provider package direct pin mismatch for {provider_row.package}"

    with pytest.raises(rpmlock.LockError, match=rf"^{re.escape(expected)}$") as exc:
        rpmlock.validate(mutated, arch="amd64")
    assert str(exc.value) == expected


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


def test_fips_lock_rejects_runtime_closure() -> None:
    with pytest.raises(rpmlock.LockError, match="exactly one openssl CLI row"):
        rpmlock.validate_fips(rpmlock.parse(AMD64_LOCK), arch="amd64")


def test_fips_lock_requires_build_only_row(tmp_path: Path) -> None:
    path = _write_lock(tmp_path, _fips_lock_text().replace("|no|openssl|", "|yes|openssl|", 1))

    with pytest.raises(rpmlock.LockError, match="must use final_rpmdb=no"):
        rpmlock.validate_fips(rpmlock.parse(path), arch="amd64")


def test_fips_lock_requires_terminal_lf(tmp_path: Path) -> None:
    path = tmp_path / "fips.txt"
    path.write_bytes(FIPS_AMD64_LOCK.read_bytes().removesuffix(b"\n"))

    with pytest.raises(rpmlock.LockError, match="must end with a line feed"):
        rpmlock.validate_fips(rpmlock.parse(path), arch="amd64")


def test_fips_lock_requires_package_field_to_match_nevra(tmp_path: Path) -> None:
    original, mutated = _mutate_fips_package_nevra(tmp_path, _fips_lock_text())
    original_row = _only_fips_row(original)
    mutated_row = _only_fips_row(mutated)
    original_direct = _only_direct_entry(original)
    mutated_direct = _only_direct_entry(mutated)

    rpmlock.validate_common(mutated, mode=rpmlock.CommonValidationMode.STRICT)
    assert mutated_row.package != rpmlock.lock_nevra(mutated_row)
    assert mutated_row.release == original_row.release
    assert mutated_direct.url == original_direct.url
    expected = f"{mutated.path}: package field does not match FIPS verification row NEVRA: {mutated_row.package}"

    with pytest.raises(rpmlock.LockError, match=rf"^{re.escape(expected)}$") as exc:
        rpmlock.validate_fips(mutated, arch="amd64")
    assert str(exc.value) == expected


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


@pytest.mark.parametrize("path", [FIPS_AMD64_LOCK, FIPS_ARM64_LOCK])
def test_cli_fips_validate_and_summary_infers_arch(path: Path) -> None:
    validate_command = [
        sys.executable,
        str(ROOT / "tools" / "rpmlock.py"),
        "fips-validate",
        "--lockfile",
        str(path),
    ]
    validate_result = subprocess.run(validate_command, cwd=ROOT, text=True, capture_output=True, check=False)
    assert validate_result.returncode == 0, validate_result.stderr

    summary_command = [*validate_command[:2], "fips-summary", *validate_command[3:]]
    summary_result = subprocess.run(summary_command, cwd=ROOT, text=True, capture_output=True, check=False)
    assert summary_result.returncode == 0, summary_result.stderr
    summary = cast(dict[str, Any], json.loads(summary_result.stdout))
    rows = cast(list[dict[str, str]], summary["rows"])
    assert len(rows) == 1
    assert rows[0]["name"] == "openssl"
    assert rows[0]["final_rpmdb"] == "no"
    assert len(cast(list[object], summary["direct_rpms"])) == 1


def test_public_dockerfile_arg_default_and_cli() -> None:
    expected = "1704067200"

    assert rpmlock.dockerfile_arg_default(ROOT, "SOURCE_DATE_EPOCH") == expected
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/rpmlock.py"),
            "arg-default",
            "--repo-root",
            str(ROOT),
            "--name",
            "SOURCE_DATE_EPOCH",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{expected}\n"
