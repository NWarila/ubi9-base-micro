#!/usr/bin/env python3
# Purpose: Parse and apply the exact retained-RPM payload trim shared by lock derivation and image assembly.
# Role: build policy
# Micro-container candidate: yes - pure-stdlib contract/rootfs logic with a --self-test entrypoint

"""Apply an exact, fail-closed retained-package payload trim."""

from __future__ import annotations

import argparse
import json
import os
import stat
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
ENTRY_KEYS: Final = frozenset({"package", "path", "kind"})


class TrimError(RuntimeError):
    """Raised when the retained-payload trim contract or rootfs does not match."""


@dataclass(frozen=True, slots=True)
class TrimEntry:
    package: str
    path: str
    kind: str


def _require(condition: object, message: str) -> None:
    if not condition:
        raise TrimError(message)


def _entry_from_json(raw: Any, *, arch: str, index: int) -> TrimEntry:
    _require(isinstance(raw, dict), f"trim entry {arch}[{index}] must be an object")
    item = cast(dict[str, Any], raw)
    _require(set(item) == ENTRY_KEYS, f"trim entry {arch}[{index}] must contain exactly {sorted(ENTRY_KEYS)}")
    package = item.get("package")
    path = item.get("path")
    kind = item.get("kind")
    _require(isinstance(package, str) and bool(package), f"trim entry {arch}[{index}] has invalid package")
    _require(isinstance(path, str) and path.startswith("/"), f"trim entry {arch}[{index}] has invalid path")
    assert isinstance(path, str)
    _require(path != "/", f"trim entry {arch}[{index}] may not name the root directory")
    _require(
        str(PurePosixPath(path)) == path and ".." not in PurePosixPath(path).parts,
        f"trim entry {arch}[{index}] path is not normalized: {path}",
    )
    _require(kind in KINDS, f"trim entry {arch}[{index}] has invalid kind: {kind!r}")
    assert isinstance(package, str) and isinstance(kind, str)
    return TrimEntry(package=package, path=path, kind=kind)


def load_trim_contract(path: Path, arch: str) -> tuple[TrimEntry, ...]:
    """Load and validate the architecture-specific exact trim entries."""
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
    _require(document.get("version") == 1, "trim contract version must be 1")
    architectures = document.get("architectures")
    _require(isinstance(architectures, dict), "trim contract architectures must be an object")
    assert isinstance(architectures, dict)
    _require(set(architectures) == set(ARCHITECTURES), "trim contract must define exactly amd64 and arm64")
    raw_entries = architectures.get(arch)
    _require(isinstance(raw_entries, list) and bool(raw_entries), f"trim contract {arch} list must be non-empty")
    assert isinstance(raw_entries, list)
    entries = tuple(_entry_from_json(raw, arch=arch, index=index) for index, raw in enumerate(raw_entries))
    paths = [entry.path for entry in entries]
    _require(len(paths) == len(set(paths)), f"trim contract {arch} contains duplicate paths")
    return entries


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


def apply_retained_payload_trim(
    rootfs: Path,
    entries: Sequence[TrimEntry],
    owner_for_path: Callable[[str], str],
) -> None:
    """Remove exactly the contracted paths after proving their kind and RPM owner."""
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
    """Require rpm -V --nodeps to report only the contracted missing paths."""
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


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        rootfs = base / "rootfs"
        (rootfs / "opt/demo/cache").mkdir(parents=True)
        (rootfs / "opt/demo/module.so").write_bytes(b"\x7fELFdemo")
        (rootfs / "opt/demo/cache/module.pyc").write_bytes(b"pyc")
        (rootfs / "opt/demo/link").symlink_to("module.so")
        contract = base / "trim.json"
        contract.write_text(
            json.dumps(
                {
                    "_comment": ["self-test"],
                    "version": 1,
                    "architectures": {
                        arch: [
                            {"package": "demo-libs", "path": "/opt/demo/cache", "kind": "directory"},
                            {
                                "package": "demo-libs",
                                "path": "/opt/demo/cache/module.pyc",
                                "kind": "file",
                            },
                            {"package": "demo-libs", "path": "/opt/demo/link", "kind": "symlink"},
                            {"package": "demo-libs", "path": "/opt/demo/module.so", "kind": "file"},
                        ]
                        for arch in ARCHITECTURES
                    },
                }
            ),
            encoding="utf-8",
        )
        entries = load_trim_contract(contract, "amd64")
        apply_retained_payload_trim(rootfs, entries, lambda _path: "demo-libs")
        verify_output = "\n".join(f"missing     {entry.path}" for entry in entries) + "\n"
        assert_exact_rpm_verify_deviations(
            entries,
            lambda _package: subprocess.CompletedProcess([], 1, verify_output, ""),
        )

        rejected = 0
        bad_owner_root = base / "bad-owner"
        (bad_owner_root / "opt").mkdir(parents=True)
        (bad_owner_root / "opt/file").write_bytes(b"x")
        bad_entry = (TrimEntry("demo-libs", "/opt/file", "file"),)
        try:
            apply_retained_payload_trim(bad_owner_root, bad_entry, lambda _path: "other-libs")
        except TrimError:
            rejected += 1
        else:
            raise TrimError("self-test wrong-owner mutation unexpectedly passed")

        try:
            assert_exact_rpm_verify_deviations(
                bad_entry,
                lambda _package: subprocess.CompletedProcess([], 1, "missing     /opt/other\n", ""),
            )
        except TrimError:
            rejected += 1
        else:
            raise TrimError("self-test extra/missing rpm -V mutation unexpectedly passed")

        malformed = json.loads(contract.read_text(encoding="utf-8"))
        malformed["architectures"]["amd64"][0]["extra"] = True
        contract.write_text(json.dumps(malformed), encoding="utf-8")
        try:
            load_trim_contract(contract, "amd64")
        except TrimError:
            rejected += 1
        else:
            raise TrimError("self-test contract-broadening mutation unexpectedly passed")
        print(f"retained-payload trim self-test: exact application ok; {rejected}/3 mutations rejected")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply the exact retained-RPM payload trim contract.")
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
