#!/usr/bin/env python3
# Purpose: Assert the exported final image contains the exported parent byte-for-byte, outside an exact
#          exception set, and ships no rpmdb sidecars
# Role: gate
# Micro-container candidate: yes - pure-stdlib, tars-in/exit-out, has --self-test

"""Final-image parent-invariance gate.

Compares a ``crane export`` tar of the built image against the same export of
the pinned parent child: every parent entry must be present and identical
(type, mode, owner, linkname, content, hardlink group, xattrs) except the
exact allowed set (the combined rpmdb, the regenerated linker cache, and the
parent's rpmdb sidecars, which must be ABSENT from the final image).
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import sys
import tarfile
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ALLOWED_CHANGED = frozenset({"var/lib/rpm/rpmdb.sqlite", "etc/ld.so.cache"})
REQUIRED_ABSENT = frozenset({"var/lib/rpm/rpmdb.sqlite-shm", "var/lib/rpm/rpmdb.sqlite-wal"})
IDENTITY_FILES = ("etc/passwd", "etc/group")


def _load_repro_module() -> Any:
    module_path = Path(__file__).resolve().parent / "assert-reproducible.py"
    spec = importlib.util.spec_from_file_location("python_assert_reproducible", module_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def compare(parent_entries: dict[str, Any], final_entries: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    errors.extend(
        f"rpmdb sidecar shipped in the final image: {path}" for path in sorted(REQUIRED_ABSENT & set(final_entries))
    )
    for path, parent_entry in sorted(parent_entries.items()):
        if path in REQUIRED_ABSENT:
            continue
        final_entry = final_entries.get(path)
        if final_entry is None:
            errors.append(f"parent path missing from the final image: {path}")
            continue
        if path in ALLOWED_CHANGED:
            continue
        for field in ("type", "mode", "uid", "gid", "linkname", "sha256", "nlink_group", "xattrs"):
            parent_value = getattr(parent_entry, field, None)
            final_value = getattr(final_entry, field, None)
            if parent_value != final_value:
                errors.append(f"parent path altered in the final image: {path} ({field})")
                break
    for identity in IDENTITY_FILES:
        parent_entry = parent_entries.get(identity)
        final_entry = final_entries.get(identity)
        if parent_entry is None or final_entry is None:
            errors.append(f"identity file missing: /{identity}")
        elif parent_entry.sha256 != final_entry.sha256:
            errors.append(f"identity file changed: /{identity}")
    return errors


def self_test() -> None:
    repro = _load_repro_module()

    def tar_bytes(members: Sequence[tuple[str, bytes | str | None]]) -> io.BytesIO:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, content in members:
                if isinstance(content, bytes):
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mode = 0o644
                    archive.addfile(info, io.BytesIO(content))
                else:
                    info = tarfile.TarInfo(name)
                    info.type = tarfile.FIFOTYPE if content == "fifo" else tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
        buffer.seek(0)
        return buffer

    base = [
        ("etc", None),
        ("etc/passwd", b"nonroot"),
        ("etc/group", b"nonroot"),
        ("etc/ld.so.cache", b"cache-v1"),
        ("usr", None),
        ("usr/lib64", None),
        ("usr/lib64/libc.so.6", b"glibc"),
        ("var", None),
        ("var/lib", None),
        ("var/lib/rpm", None),
        ("var/lib/rpm/rpmdb.sqlite", b"parent-db"),
        ("var/lib/rpm/rpmdb.sqlite-shm", b"shm"),
    ]
    final_ok = [entry for entry in base if entry[0] != "var/lib/rpm/rpmdb.sqlite-shm"] + [
        ("var/lib/rpm/rpmdb.sqlite", b"combined-db"),
        ("etc/ld.so.cache", b"cache-v2"),
        ("usr/bin", None),
        ("usr/bin/python3.12", b"cpython"),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        parent_tar = Path(tmp) / "parent.tar"
        final_tar = Path(tmp) / "final.tar"
        parent_tar.write_bytes(tar_bytes(base).getvalue())
        final_tar.write_bytes(tar_bytes(final_ok).getvalue())
        parent_entries = repro.load_tar(parent_tar)
        final_entries = repro.load_tar(final_tar)
        errors = compare(parent_entries, final_entries)
        if errors:
            raise SystemExit("self-test: valid final image rejected: " + "; ".join(errors))

        rejected = 0
        mutations: list[tuple[str, Sequence[tuple[str, bytes | str | None]]]] = [
            ("parent file deleted", [e for e in final_ok if e[0] != "usr/lib64/libc.so.6"]),
            ("parent file altered", [(n, (b"tampered" if n == "usr/lib64/libc.so.6" else c)) for n, c in final_ok]),
            ("identity changed", [(n, (b"evil" if n == "etc/passwd" else c)) for n, c in final_ok]),
            ("sidecar shipped", [*final_ok, ("var/lib/rpm/rpmdb.sqlite-shm", b"shm")]),
            (
                "type flipped",
                [(n, c) for n, c in final_ok if n != "usr/lib64"] + [("usr/lib64", "fifo")],
            ),
        ]
        for label, members in mutations:
            final_tar.write_bytes(tar_bytes(members).getvalue())
            if compare(parent_entries, repro.load_tar(final_tar)):
                rejected += 1
            else:
                raise SystemExit(f"self-test: mutation unexpectedly passed: {label}")
    print(f"assert-parent-subset self-test: valid case ok; {rejected}/5 mutation probes rejected")


def main() -> int:
    parser = argparse.ArgumentParser(description="Assert the final image preserves the parent byte-for-byte.")
    parser.add_argument("--parent-tar", help="crane export of the pinned parent child")
    parser.add_argument("--final-tar", help="crane export of the built final image child")
    parser.add_argument("--self-test", action="store_true", help="run the offline self-test")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.parent_tar or not args.final_tar:
        parser.error("--parent-tar and --final-tar are required")
    repro = _load_repro_module()
    errors = compare(repro.load_tar(Path(args.parent_tar)), repro.load_tar(Path(args.final_tar)))
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("parent subset invariance ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
