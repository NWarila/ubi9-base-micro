#!/usr/bin/env python3
# Purpose: Materialize and apply the exact retained-RPM payload trim shared by lock and image assembly.
# Role: build policy
# Micro-container candidate: yes - pure-stdlib contract/rootfs logic with a --self-test entrypoint

"""Materialize and apply an exact, fail-closed retained-package payload trim."""

from __future__ import annotations

import argparse
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final, cast

ARCHITECTURES: Final = ("amd64", "arm64")
KINDS: Final = ("directory", "file", "symlink")
TOP_LEVEL_KEYS: Final = frozenset({"_comment", "version", "architectures"})
ARCHITECTURE_KEYS: Final = frozenset({"build_id_link", "entries"})
ENTRY_KEYS: Final = frozenset({"package", "path", "kind"})
BUILD_ID_LINK_KEYS: Final = frozenset({"package", "target"})
BUILD_ID_PREFIX: Final = "/usr/lib/.build-id/"
ELF_MACHINE: Final = {"amd64": 62, "arm64": 183}
SQLITE_EXTENSION: Final = {
    "amd64": "/usr/lib64/python3.12/lib-dynload/_sqlite3.cpython-312-x86_64-linux-gnu.so",
    "arm64": "/usr/lib64/python3.12/lib-dynload/_sqlite3.cpython-312-aarch64-linux-gnu.so",
}


class TrimError(RuntimeError):
    """Raised when the retained-payload trim contract or rootfs does not match."""


@dataclass(frozen=True, slots=True)
class TrimEntry:
    package: str
    path: str
    kind: str


@dataclass(frozen=True, slots=True)
class BuildIdLink:
    package: str
    target: str


@dataclass(frozen=True, slots=True)
class TrimContract:
    arch: str
    entries: tuple[TrimEntry, ...]
    build_id_link: BuildIdLink


@dataclass(frozen=True, slots=True)
class RpmFileRecord:
    path: str
    link_target: str


def _require(condition: object, message: str) -> None:
    if not condition:
        raise TrimError(message)


def _normalized_absolute_path(value: Any, message: str) -> str:
    _require(isinstance(value, str) and value.startswith("/"), message)
    assert isinstance(value, str)
    path = PurePosixPath(value)
    _require(value != "/" and str(path) == value and ".." not in path.parts, f"{message}: {value!r}")
    return value


def _entry_from_json(raw: Any, *, arch: str, index: int) -> TrimEntry:
    _require(isinstance(raw, dict), f"trim entry {arch}[{index}] must be an object")
    item = cast(dict[str, Any], raw)
    _require(set(item) == ENTRY_KEYS, f"trim entry {arch}[{index}] must contain exactly {sorted(ENTRY_KEYS)}")
    package = item.get("package")
    _require(isinstance(package, str) and bool(package), f"trim entry {arch}[{index}] has invalid package")
    path = _normalized_absolute_path(item.get("path"), f"trim entry {arch}[{index}] has invalid path")
    kind = item.get("kind")
    _require(kind in KINDS, f"trim entry {arch}[{index}] has invalid kind: {kind!r}")
    assert isinstance(package, str) and isinstance(kind, str)
    return TrimEntry(package=package, path=path, kind=kind)


def _build_id_link_from_json(raw: Any, *, arch: str) -> BuildIdLink:
    _require(isinstance(raw, dict), f"trim build_id_link {arch} must be an object")
    item = cast(dict[str, Any], raw)
    _require(
        set(item) == BUILD_ID_LINK_KEYS,
        f"trim build_id_link {arch} must contain exactly {sorted(BUILD_ID_LINK_KEYS)}",
    )
    package = item.get("package")
    _require(isinstance(package, str) and bool(package), f"trim build_id_link {arch} has invalid package")
    target = _normalized_absolute_path(
        item.get("target"),
        f"trim build_id_link {arch} has invalid target",
    )
    _require(
        target == SQLITE_EXTENSION[arch],
        f"trim build_id_link {arch} must target the architecture-specific _sqlite3 extension",
    )
    assert isinstance(package, str)
    return BuildIdLink(package=package, target=target)


def load_trim_contract(path: Path, arch: str) -> TrimContract:
    """Load and validate the payload-independent semantic trim declaration."""
    _require(arch in ARCHITECTURES, f"unsupported trim architecture: {arch}")
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrimError(f"could not load retained-payload trim contract {path}: {exc}") from exc
    _require(isinstance(loaded, dict), "retained-payload trim contract must be a JSON object")
    document = cast(dict[str, Any], loaded)
    _require(set(document) == TOP_LEVEL_KEYS, f"trim contract must contain exactly {sorted(TOP_LEVEL_KEYS)}")
    comments = document.get("_comment")
    _require(
        isinstance(comments, list) and bool(comments) and all(isinstance(line, str) and line for line in comments),
        "trim contract _comment must be a non-empty string list",
    )
    _require(document.get("version") == 2, "trim contract version must be 2")
    architectures = document.get("architectures")
    _require(isinstance(architectures, dict), "trim contract architectures must be an object")
    assert isinstance(architectures, dict)
    _require(set(architectures) == set(ARCHITECTURES), "trim contract must define exactly amd64 and arm64")
    raw_arch = architectures.get(arch)
    _require(isinstance(raw_arch, dict), f"trim contract {arch} declaration must be an object")
    arch_declaration = cast(dict[str, Any], raw_arch)
    _require(
        set(arch_declaration) == ARCHITECTURE_KEYS,
        f"trim contract {arch} must contain exactly {sorted(ARCHITECTURE_KEYS)}",
    )
    raw_entries = arch_declaration.get("entries")
    _require(isinstance(raw_entries, list) and bool(raw_entries), f"trim contract {arch} entries must be non-empty")
    assert isinstance(raw_entries, list)
    entries = tuple(_entry_from_json(raw, arch=arch, index=index) for index, raw in enumerate(raw_entries))
    paths = [entry.path for entry in entries]
    _require(len(paths) == len(set(paths)), f"trim contract {arch} contains duplicate static paths")
    build_id_link = _build_id_link_from_json(arch_declaration.get("build_id_link"), arch=arch)
    matching_targets = [
        entry
        for entry in entries
        if entry.path == build_id_link.target and entry.package == build_id_link.package and entry.kind == "file"
    ]
    _require(
        len(matching_targets) == 1,
        f"trim build_id_link {arch} target must be exactly one matching static file entry",
    )
    return TrimContract(arch=arch, entries=entries, build_id_link=build_id_link)


def parse_rpm_file_records(output: str) -> tuple[RpmFileRecord, ...]:
    """Parse the exact ``FILENAMES``/``FILELINKTOS`` query format used by both consumers."""
    records: list[RpmFileRecord] = []
    for index, line in enumerate(output.splitlines()):
        fields = line.split("\t")
        _require(len(fields) == 2, f"malformed RPM file/link record at line {index + 1}")
        path = _normalized_absolute_path(fields[0], f"RPM file record {index + 1} has invalid path")
        _require("\x00" not in fields[1], f"RPM file record {index + 1} has an invalid link target")
        records.append(RpmFileRecord(path=path, link_target=fields[1]))
    _require(bool(records), "RPM file/link query returned no records")
    return tuple(records)


def _rooted(rootfs: Path, absolute_path: str) -> Path:
    return rootfs / absolute_path.removeprefix("/")


def _path_kind(path: Path) -> str:
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


def _bounded_region(data: bytes, offset: int, size: int, description: str) -> bytes:
    _require(offset >= 0 and size >= 0 and offset <= len(data) and size <= len(data) - offset, description)
    return data[offset : offset + size]


def _elf_note_regions(data: bytes, byte_order: str, elf_class: int) -> tuple[tuple[int, bytes], ...]:
    if elf_class == 2:
        header_format = byte_order + "HHIQQQIHHHHHH"
        program_format = byte_order + "IIQQQQQQ"
        section_format = byte_order + "IIQQQQIIQQ"
        program_offset_index, program_size_index = 2, 5
    else:
        header_format = byte_order + "HHIIIIIHHHHHH"
        program_format = byte_order + "IIIIIIII"
        section_format = byte_order + "IIIIIIIIII"
        program_offset_index, program_size_index = 1, 4
    header_size = struct.calcsize(header_format)
    header_bytes = _bounded_region(data, 16, header_size, "truncated ELF header")
    header = struct.unpack(header_format, header_bytes)
    program_offset, section_offset = int(header[4]), int(header[5])
    program_entry_size, program_count = int(header[8]), int(header[9])
    section_entry_size, section_count = int(header[10]), int(header[11])
    _require(program_count != 0xFFFF, "extended ELF program-header counts are unsupported")
    _require(section_count != 0 or section_offset == 0, "extended ELF section-header counts are unsupported")

    regions: dict[tuple[int, int], bytes] = {}
    if program_count:
        expected_size = struct.calcsize(program_format)
        _require(program_entry_size == expected_size, "malformed ELF program-header entry size")
        table = _bounded_region(
            data,
            program_offset,
            program_entry_size * program_count,
            "truncated ELF program-header table",
        )
        for index in range(program_count):
            fields = struct.unpack_from(program_format, table, index * program_entry_size)
            if int(fields[0]) == 4:
                offset = int(fields[program_offset_index])
                size = int(fields[program_size_index])
                regions[(offset, size)] = _bounded_region(data, offset, size, "truncated ELF PT_NOTE segment")
    if section_count:
        expected_size = struct.calcsize(section_format)
        _require(section_entry_size == expected_size, "malformed ELF section-header entry size")
        table = _bounded_region(
            data,
            section_offset,
            section_entry_size * section_count,
            "truncated ELF section-header table",
        )
        for index in range(section_count):
            fields = struct.unpack_from(section_format, table, index * section_entry_size)
            if int(fields[1]) == 7:
                offset, size = int(fields[4]), int(fields[5])
                regions[(offset, size)] = _bounded_region(data, offset, size, "truncated ELF SHT_NOTE section")
    _require(bool(regions), "ELF contains no note segment or section")
    return tuple((offset, region) for (offset, _size), region in sorted(regions.items()))


def _gnu_build_id(path: Path, expected_machine: int) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise TrimError(f"could not read semantic trim target {path}: {exc}") from exc
    _require(len(data) >= 16 and data[:4] == b"\x7fELF", "semantic trim target is not an ELF file")
    elf_class = data[4]
    _require(elf_class == 2, "semantic trim target must be a 64-bit ELF file")
    _require(data[5] in (1, 2), "semantic trim target has an invalid ELF byte order")
    _require(data[6] == 1, "semantic trim target has an invalid ELF identification version")
    byte_order = "<" if data[5] == 1 else ">"
    machine = struct.unpack_from(byte_order + "H", data, 18)[0]
    _require(machine == expected_machine, f"semantic trim target ELF machine mismatch: {machine}")

    build_ids: dict[int, bytes] = {}
    for region_offset, region in _elf_note_regions(data, byte_order, elf_class):
        cursor = 0
        while cursor < len(region):
            if not any(region[cursor:]):
                break
            _require(len(region) - cursor >= 12, "truncated ELF note header")
            namesz, descsz, note_type = struct.unpack_from(byte_order + "III", region, cursor)
            note_offset = region_offset + cursor
            cursor += 12
            name_end = cursor + namesz
            _require(name_end <= len(region), "truncated ELF note name")
            name = region[cursor:name_end]
            cursor = (name_end + 3) & ~3
            desc_end = cursor + descsz
            _require(desc_end <= len(region), "truncated ELF note descriptor")
            descriptor = region[cursor:desc_end]
            cursor = (desc_end + 3) & ~3
            _require(cursor <= len(region), "truncated ELF note padding")
            if note_type == 3 and name.rstrip(b"\x00") == b"GNU":
                _require(namesz == 4 and name == b"GNU\x00", "malformed GNU build-ID note name")
                _require(len(descriptor) >= 2, "empty or malformed GNU build-ID note")
                build_ids[note_offset] = descriptor
    _require(
        len(build_ids) == 1,
        f"semantic trim target must contain exactly one GNU build-ID note, got {len(build_ids)}",
    )
    return next(iter(build_ids.values()))


def _normalize_link_target(link_path: str, link_target: str) -> str:
    _require(bool(link_target) and "\x00" not in link_target, f"build-ID link has an invalid target: {link_path}")
    target = PurePosixPath(link_target)
    parts: list[str] = [] if target.is_absolute() else list(PurePosixPath(link_path).parent.parts[1:])
    for part in target.parts:
        if part in ("", "/", "."):
            continue
        if part == "..":
            _require(bool(parts), f"build-ID link target escapes the rootfs: {link_path} -> {link_target}")
            parts.pop()
        else:
            parts.append(part)
    return "/" + "/".join(parts)


def materialize_trim_contract(
    rootfs: Path,
    contract: TrimContract,
    owner_for_path: Callable[[str], str],
    rpm_files_for_package: Callable[[str], Sequence[RpmFileRecord]],
) -> tuple[TrimEntry, ...]:
    """Derive and prove the concrete build-ID link from an installed candidate rootfs."""
    declaration = contract.build_id_link
    target = _rooted(rootfs, declaration.target)
    candidates = sorted(
        "/" + str(path.relative_to(rootfs)) for path in target.parent.glob("_sqlite3*.so") if os.path.lexists(path)
    )
    _require(
        candidates == [declaration.target],
        f"semantic _sqlite3 target must exist uniquely: observed={candidates} expected={[declaration.target]}",
    )
    _require(_path_kind(target) == "file", f"semantic trim target must be a regular file: {declaration.target}")
    target_owner = owner_for_path(declaration.target)
    _require(
        target_owner == declaration.package,
        f"semantic trim target owner mismatch for {declaration.target}: "
        f"expected {declaration.package}, got {target_owner}",
    )

    records = tuple(rpm_files_for_package(declaration.package))
    target_records = [record for record in records if record.path == declaration.target]
    _require(len(target_records) == 1, "RPM metadata must contain the semantic trim target exactly once")
    _require(not target_records[0].link_target, "RPM metadata records semantic trim target as a symlink")

    build_id = _gnu_build_id(target, ELF_MACHINE[contract.arch]).hex()
    derived_path = f"{BUILD_ID_PREFIX}{build_id[:2]}/{build_id[2:]}"
    derived = _rooted(rootfs, derived_path)
    _require(os.path.lexists(derived), f"derived build-ID link is missing: {derived_path}")
    _require(_path_kind(derived) == "symlink", f"derived build-ID path is not a symlink: {derived_path}")
    derived_owner = owner_for_path(derived_path)
    _require(
        derived_owner == declaration.package,
        f"derived build-ID link owner mismatch for {derived_path}: expected {declaration.package}, got {derived_owner}",
    )

    derived_records = [record for record in records if record.path == derived_path]
    _require(len(derived_records) == 1, "RPM metadata must contain the derived build-ID link exactly once")
    rpm_link_target = derived_records[0].link_target
    _require(bool(rpm_link_target), f"RPM metadata does not record the derived path as a symlink: {derived_path}")
    actual_link_target = str(derived.readlink())
    _require(
        actual_link_target == rpm_link_target,
        f"derived build-ID link target differs from RPM metadata: {derived_path}",
    )
    normalized_target = _normalize_link_target(derived_path, actual_link_target)
    _require(
        _rooted(rootfs, normalized_target).exists(),
        f"derived build-ID link target is dangling: {derived_path} -> {actual_link_target}",
    )
    _require(
        normalized_target == declaration.target,
        f"derived build-ID link resolves to the wrong target: {derived_path} -> {normalized_target}",
    )

    actual_candidates: list[str] = []
    build_id_root = _rooted(rootfs, BUILD_ID_PREFIX)
    if build_id_root.is_dir():
        for path in sorted(build_id_root.glob("*/*")):
            if not path.is_symlink():
                continue
            candidate_path = "/" + str(path.relative_to(rootfs))
            if _normalize_link_target(candidate_path, str(path.readlink())) == declaration.target:
                actual_candidates.append(candidate_path)
    _require(
        actual_candidates == [derived_path],
        "installed rootfs contains an additional or ambiguous build-ID link for the semantic trim target",
    )

    candidate_records = [
        record
        for record in records
        if record.path.startswith(BUILD_ID_PREFIX)
        and record.link_target
        and _normalize_link_target(record.path, record.link_target) == declaration.target
    ]
    _require(
        candidate_records == derived_records,
        "RPM metadata contains an additional or ambiguous build-ID link for the semantic trim target",
    )

    materialized = (*contract.entries, TrimEntry(declaration.package, derived_path, "symlink"))
    paths = [entry.path for entry in materialized]
    _require(len(paths) == len(set(paths)), "materialized trim contains duplicate concrete paths")
    return materialized


def apply_retained_payload_trim(
    rootfs: Path,
    entries: Sequence[TrimEntry],
    owner_for_path: Callable[[str], str],
) -> None:
    """Remove exactly the materialized paths after proving their kind and RPM owner."""
    _require(bool(entries), "retained-payload trim may not be empty")
    for entry in entries:
        target = _rooted(rootfs, entry.path)
        _require(os.path.lexists(target), f"contracted trim path is missing before trim: {entry.path}")
        observed_kind = _path_kind(target)
        _require(
            observed_kind == entry.kind,
            f"contracted trim path kind mismatch for {entry.path}: expected {entry.kind}, got {observed_kind}",
        )
        owner = owner_for_path(entry.path)
        _require(
            owner == entry.package,
            f"contracted trim path owner mismatch for {entry.path}: expected {entry.package}, got {owner}",
        )

    for entry in entries:
        if entry.kind != "directory":
            _rooted(rootfs, entry.path).unlink()
    directories = sorted(
        (entry for entry in entries if entry.kind == "directory"),
        key=lambda item: len(PurePosixPath(item.path).parts),
        reverse=True,
    )
    for entry in directories:
        target = _rooted(rootfs, entry.path)
        try:
            target.rmdir()
        except OSError as exc:
            raise TrimError(f"contracted trim directory is not empty: {entry.path}: {exc}") from exc
    remaining = [entry.path for entry in entries if os.path.lexists(_rooted(rootfs, entry.path))]
    _require(not remaining, "contracted trim paths survived: " + ", ".join(remaining))


def _missing_path(line: str) -> str | None:
    if not line.startswith("missing"):
        return None
    fields = line.split()
    paths = [field for field in fields[1:] if field.startswith("/")]
    return paths[0] if len(paths) == 1 else None


def assert_exact_rpm_verify_deviations(
    entries: Sequence[TrimEntry],
    verify_package: Callable[[str], subprocess.CompletedProcess[str]],
) -> None:
    """Require rpm -V --nodeps to report only the materialized missing paths."""
    packages = sorted({entry.package for entry in entries})
    _require(bool(packages), "retained-payload trim verification requires at least one package")
    for package in packages:
        result = verify_package(package)
        _require(result.returncode == 1, f"rpm -V --nodeps {package} must report the contracted deviations")
        _require(not result.stderr.strip(), f"rpm -V --nodeps {package} emitted stderr: {result.stderr.strip()}")
        observed: list[str] = []
        for line in result.stdout.splitlines():
            missing = _missing_path(line)
            _require(missing is not None, f"rpm -V --nodeps {package} reported an uncontracted deviation: {line}")
            assert missing is not None
            observed.append(missing)
        expected = sorted(entry.path for entry in entries if entry.package == package)
        _require(
            sorted(observed) == expected and len(observed) == len(expected),
            f"rpm -V --nodeps {package} deviation mismatch: observed={sorted(observed)} expected={expected}",
        )


def _elf_fixture(build_ids: Sequence[bytes], *, machine: int = 62, malformed: bool = False) -> bytes:
    notes = bytearray()
    for build_id in build_ids:
        descriptor_size = len(build_id) + (8 if malformed else 0)
        notes.extend(struct.pack("<III", 4, descriptor_size, 3))
        notes.extend(b"GNU\x00")
        notes.extend(build_id)
        notes.extend(b"\x00" * ((-len(build_id)) % 4))
    note_offset = 64 + 56
    identity = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\x00" * 7
    header = struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    program = struct.pack("<IIQQQQQQ", 4, 4, note_offset, 0, 0, len(notes), len(notes), 4)
    return identity + header + program + notes


def self_test() -> None:
    package = "python3.12-libs"
    target_path = SQLITE_EXTENSION["amd64"]
    build_id = bytes.fromhex("25d179ab0964692e50f739c920f84b862d9d827f")
    derived_path = f"{BUILD_ID_PREFIX}{build_id.hex()[:2]}/{build_id.hex()[2:]}"
    rpm_link_target = "../../../../usr/lib64/python3.12/lib-dynload/_sqlite3.cpython-312-x86_64-linux-gnu.so"

    def write_contract(path: Path, *, duplicate_derived: bool = False) -> TrimContract:
        architecture_declarations: dict[str, Any] = {}
        for arch in ARCHITECTURES:
            arch_target = SQLITE_EXTENSION[arch]
            entries = [
                {"package": package, "path": arch_target, "kind": "file"},
                {"package": package, "path": "/usr/lib64/python3.12/sqlite3", "kind": "directory"},
                {"package": package, "path": "/usr/lib64/python3.12/sqlite3/dbapi2.py", "kind": "file"},
            ]
            if duplicate_derived and arch == "amd64":
                entries.append({"package": package, "path": derived_path, "kind": "symlink"})
            architecture_declarations[arch] = {
                "build_id_link": {"package": package, "target": arch_target},
                "entries": entries,
            }
        path.write_text(
            json.dumps(
                {
                    "_comment": ["self-test"],
                    "version": 2,
                    "architectures": architecture_declarations,
                }
            ),
            encoding="utf-8",
        )
        return load_trim_contract(path, "amd64")

    def make_root(base: Path, *, elf: bytes | None = None, link_target: str = rpm_link_target) -> Path:
        rootfs = base / "rootfs"
        target = _rooted(rootfs, target_path)
        target.parent.mkdir(parents=True)
        target.write_bytes(_elf_fixture((build_id,)) if elf is None else elf)
        sqlite_dir = _rooted(rootfs, "/usr/lib64/python3.12/sqlite3")
        sqlite_dir.mkdir(parents=True)
        (sqlite_dir / "dbapi2.py").write_bytes(b"sqlite policy probe")
        link = _rooted(rootfs, derived_path)
        link.parent.mkdir(parents=True)
        link.symlink_to(link_target)
        return rootfs

    def records(
        *, extra: Sequence[RpmFileRecord] = (), link_target: str = rpm_link_target
    ) -> tuple[RpmFileRecord, ...]:
        return (
            RpmFileRecord(target_path, ""),
            RpmFileRecord(derived_path, link_target),
            *extra,
        )

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        contract_path = base / "trim.json"
        contract = write_contract(contract_path)
        rootfs = make_root(base / "passing")
        entries = materialize_trim_contract(rootfs, contract, lambda _path: package, lambda _package: records())
        _require(len(entries) == 4 and entries[-1].path == derived_path, "self-test materialized the wrong trim set")
        apply_retained_payload_trim(rootfs, entries, lambda _path: package)
        verify_output = "\n".join(f"missing     {entry.path}" for entry in entries) + "\n"
        assert_exact_rpm_verify_deviations(
            entries,
            lambda _package: subprocess.CompletedProcess([], 1, verify_output, ""),
        )

        rejected: list[str] = []

        def reject(label: str, probe: Callable[[], object]) -> None:
            try:
                probe()
            except TrimError:
                rejected.append(label)
            else:
                raise TrimError(f"self-test mutation unexpectedly passed: {label}")

        missing_extension = make_root(base / "missing-extension")
        _rooted(missing_extension, target_path).unlink()
        reject(
            "missing semantic extension",
            lambda: materialize_trim_contract(
                missing_extension, contract, lambda _path: package, lambda _package: records()
            ),
        )

        wrong_kind_extension = make_root(base / "wrong-kind-extension")
        _rooted(wrong_kind_extension, target_path).unlink()
        _rooted(wrong_kind_extension, target_path).mkdir()
        reject(
            "semantic extension wrong kind",
            lambda: materialize_trim_contract(
                wrong_kind_extension, contract, lambda _path: package, lambda _package: records()
            ),
        )

        wrong_arch = make_root(base / "wrong-architecture", elf=_elf_fixture((build_id,), machine=183))
        reject(
            "semantic extension wrong architecture",
            lambda: materialize_trim_contract(wrong_arch, contract, lambda _path: package, lambda _package: records()),
        )

        wrong_target_owner = make_root(base / "wrong-target-owner")
        reject(
            "semantic extension wrong owner",
            lambda: materialize_trim_contract(
                wrong_target_owner,
                contract,
                lambda path: "other-libs" if path == target_path else package,
                lambda _package: records(),
            ),
        )

        missing_note = make_root(base / "missing-note", elf=_elf_fixture(()))
        reject(
            "missing build-ID note",
            lambda: materialize_trim_contract(
                missing_note, contract, lambda _path: package, lambda _package: records()
            ),
        )

        malformed_note = make_root(base / "malformed-note", elf=_elf_fixture((build_id,), malformed=True))
        reject(
            "malformed build-ID note",
            lambda: materialize_trim_contract(
                malformed_note, contract, lambda _path: package, lambda _package: records()
            ),
        )

        empty_note = make_root(base / "empty-note", elf=_elf_fixture((b"",)))
        reject(
            "empty build-ID note",
            lambda: materialize_trim_contract(empty_note, contract, lambda _path: package, lambda _package: records()),
        )

        ambiguous_note = make_root(base / "ambiguous-note", elf=_elf_fixture((build_id, b"other-build-id")))
        reject(
            "ambiguous build-ID note",
            lambda: materialize_trim_contract(
                ambiguous_note, contract, lambda _path: package, lambda _package: records()
            ),
        )

        missing_link = make_root(base / "missing-link")
        _rooted(missing_link, derived_path).unlink()
        reject(
            "missing derived link",
            lambda: materialize_trim_contract(
                missing_link, contract, lambda _path: package, lambda _package: records()
            ),
        )

        wrong_kind_link = make_root(base / "wrong-kind-link")
        _rooted(wrong_kind_link, derived_path).unlink()
        _rooted(wrong_kind_link, derived_path).write_bytes(b"not a link")
        reject(
            "derived link wrong kind",
            lambda: materialize_trim_contract(
                wrong_kind_link, contract, lambda _path: package, lambda _package: records()
            ),
        )

        wrong_link_owner = make_root(base / "wrong-link-owner")
        reject(
            "derived link wrong owner",
            lambda: materialize_trim_contract(
                wrong_link_owner,
                contract,
                lambda path: "other-libs" if path == derived_path else package,
                lambda _package: records(),
            ),
        )

        wrong_link_target = "../../../../usr/lib64/python3.12/lib-dynload/other.so"
        wrong_target = make_root(base / "wrong-target", link_target=wrong_link_target)
        _rooted(wrong_target, "/usr/lib64/python3.12/lib-dynload/other.so").write_bytes(b"other")
        reject(
            "derived link wrong target",
            lambda: materialize_trim_contract(
                wrong_target,
                contract,
                lambda _path: package,
                lambda _package: records(link_target=wrong_link_target),
            ),
        )

        dangling_link_target = "../../../../usr/lib64/python3.12/lib-dynload/missing.so"
        dangling_target = make_root(base / "dangling-target", link_target=dangling_link_target)
        reject(
            "derived link dangling target",
            lambda: materialize_trim_contract(
                dangling_target,
                contract,
                lambda _path: package,
                lambda _package: records(link_target=dangling_link_target),
            ),
        )

        escaping_link_target = "../../../../../.."
        escaping_target = make_root(base / "escaping-target", link_target=escaping_link_target)
        reject(
            "derived link escaping target",
            lambda: materialize_trim_contract(
                escaping_target,
                contract,
                lambda _path: package,
                lambda _package: records(link_target=escaping_link_target),
            ),
        )

        additional_path = "/usr/lib/.build-id/ff/ffffffffffffffffffffffffffffffffffffff"
        additional_target = make_root(base / "additional-candidate")
        additional_link = _rooted(additional_target, additional_path)
        additional_link.parent.mkdir(parents=True, exist_ok=True)
        additional_link.symlink_to(rpm_link_target)
        reject(
            "additional build-ID candidate",
            lambda: materialize_trim_contract(
                additional_target,
                contract,
                lambda _path: package,
                lambda _package: records(extra=(RpmFileRecord(additional_path, rpm_link_target),)),
            ),
        )

        duplicate_contract = write_contract(base / "duplicate-trim.json", duplicate_derived=True)
        duplicate_root = make_root(base / "duplicate-concrete")
        reject(
            "duplicate concrete path",
            lambda: materialize_trim_contract(
                duplicate_root, duplicate_contract, lambda _path: package, lambda _package: records()
            ),
        )

        reject(
            "extra rpm -V deviation",
            lambda: assert_exact_rpm_verify_deviations(
                entries,
                lambda _package: subprocess.CompletedProcess([], 1, verify_output + "missing     /extra\n", ""),
            ),
        )
        reject(
            "missing rpm -V deviation",
            lambda: assert_exact_rpm_verify_deviations(
                entries,
                lambda _package: subprocess.CompletedProcess([], 1, verify_output.splitlines()[0] + "\n", ""),
            ),
        )

        malformed = json.loads(contract_path.read_text(encoding="utf-8"))
        malformed["architectures"]["amd64"]["build_id_link"]["path"] = derived_path
        contract_path.write_text(json.dumps(malformed), encoding="utf-8")
        reject("contract broadening", lambda: load_trim_contract(contract_path, "amd64"))
        print(
            "retained-payload trim self-test: semantic materialization and exact application ok; "
            f"{len(rejected)}/19 mutations rejected"
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize and apply the retained-RPM payload trim contract.")
    parser.add_argument("--self-test", action="store_true", help="run the offline self-test")
    args = parser.parse_args(argv)
    if not args.self_test:
        parser.error("only --self-test is supported; build and lock helpers import this module")
    self_test()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TrimError as error:
        print(f"retained-payload trim failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
