#!/usr/bin/env python3
# Purpose: Verify installed and downloaded runtime RPMs against canonical lockfile hashes, filenames, and signatures.
# Role: gate
# Micro-container candidate: yes - RPM supply-chain hash and GPG gate; run inside a pinned image with rpm.
# Build-process: yes - read-only assertion in the discarded rpm-rootfs build stage.

"""Assert installed and downloaded runtime RPMs match the canonical lockfile."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from tools import rpmlock
else:
    import rpmlock

QUERY_FORMAT: Final = "%{SHA256HEADER}|%{SIGMD5}\n"
SIGNATURE_OK: Final = "digests signatures OK"
RpmRunner = Callable[[list[str]], subprocess.CompletedProcess[bytes]]


class GateError(Exception):
    """Raised when an RPM hash or signature assertion fails."""


def _run_rpm(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["rpm", *arguments],
            stdout=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise GateError(f"could not execute rpm: {exc}") from exc


def _command_substitution_output(output: bytes, *, context: str) -> str:
    try:
        return output.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise GateError(f"{context} produced non-UTF-8 output") from exc


def _query_installed_hashes(rootfs: Path, row: rpmlock.LockRow, rpm_runner: RpmRunner) -> None:
    result = rpm_runner([f"--root={rootfs}", "-q", "--qf", QUERY_FORMAT, row.package])
    if result.returncode != 0:
        raise GateError(f"locked RPM missing from installroot after transaction: {row.package}")
    actual = _command_substitution_output(result.stdout, context=f"RPM hash query for {row.package}")
    if "\n" in actual or "|" not in actual:
        raise GateError(f"unexpected RPM hash query output for {row.package}: {actual}")

    actual_sha256_header, actual_sigmd5 = actual.split("|", 1)
    if actual_sha256_header != row.sha256_header:
        raise GateError(
            f"SHA256HEADER mismatch for {row.package}: expected {row.sha256_header}, got {actual_sha256_header}"
        )
    if actual_sigmd5 != row.sigmd5:
        raise GateError(f"SIGMD5 mismatch for {row.package}: expected {row.sigmd5}, got {actual_sigmd5}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise GateError(f"could not hash direct RPM file {path}: {exc}") from exc
    return digest.hexdigest()


def _verify_direct_rpm(directory: Path, entry: rpmlock.DirectRpm, rpm_runner: RpmRunner) -> None:
    filename = entry.url.rsplit("/", 1)[-1]
    direct_path = directory / filename
    try:
        nonempty = direct_path.stat().st_size > 0
    except OSError:
        nonempty = False
    if not nonempty:
        raise GateError(f"direct RPM file missing or empty: {direct_path}")

    actual_sha256 = _sha256(direct_path)
    if actual_sha256 != entry.sha256:
        raise GateError(f"direct RPM sha256 mismatch for {entry.package}: expected {entry.sha256}, got {actual_sha256}")

    result = rpm_runner(["-K", str(direct_path)])
    signature_output = _command_substitution_output(
        result.stdout,
        context=f"RPM signature query for {entry.package}",
    )
    if result.returncode != 0:
        raise GateError(f"direct RPM GPG verification failed for {entry.package}: rpm -K exited {result.returncode}")
    if signature_output:
        print(signature_output)
    if SIGNATURE_OK not in signature_output:
        raise GateError(f"direct RPM GPG verification failed for {entry.package}")


def verify_lock_hashes(
    rootfs: Path,
    lockfile_path: Path,
    direct_rpm_dir: Path | None = None,
    *,
    rpm_runner: RpmRunner = _run_rpm,
) -> None:
    """Run the complete RPM lock hash assertion."""

    lockfile = rpmlock.parse(lockfile_path)
    rpmlock.validate_assertion_compatibility(lockfile)
    common = rpmlock.validate_common(lockfile, mode=rpmlock.CommonValidationMode.ASSERTION)

    for row in lockfile.rows:
        _query_installed_hashes(rootfs, row, rpm_runner)

    if direct_rpm_dir is not None:
        for entry in lockfile.direct_entries:
            _verify_direct_rpm(direct_rpm_dir, entry, rpm_runner)

    print(f"runtime RPM content hashes verified with %{{SHA256HEADER}}/%{{SIGMD5}}: {common.row_count} packages")
    print(f"direct RPM source pins verified from lockfile: {common.direct_count} packages")


def run_self_test() -> None:
    sha256_header = "1" * 64
    mutated_sha256_header = "2" * 64
    sigmd5 = "a" * 32
    package = "fixture-1-1.x86_64"
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        lockfile = temporary / "runtime.txt"
        direct_url = f"https://cdn-ubi.redhat.com/content/public/ubi/fixture/{package}.rpm"
        lockfile.write_text(
            f"{rpmlock.DIRECT_PREFIX}{package}|{direct_url}|{'3' * 64}\n"
            f"{package}|yes|fixture|0|1|1|x86_64|{sha256_header}|{sigmd5}\n",
            encoding="utf-8",
        )

        def fake_run_rpm(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess(
                ["rpm", *arguments],
                returncode=0,
                stdout=f"{sha256_header}|{sigmd5}\n".encode(),
            )

        with contextlib.redirect_stdout(io.StringIO()):
            verify_lock_hashes(Path("/fake-root"), lockfile, rpm_runner=fake_run_rpm)
        lockfile.write_text(
            lockfile.read_text(encoding="utf-8").replace(sha256_header, mutated_sha256_header, 1),
            encoding="utf-8",
        )
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                verify_lock_hashes(Path("/fake-root"), lockfile, rpm_runner=fake_run_rpm)
        except GateError as exc:
            if f"SHA256HEADER mismatch for {package}" not in str(exc):
                raise GateError(f"self-test returned the wrong mutation failure: {exc}") from exc
        else:
            raise GateError("self-test installed SHA256HEADER mutation unexpectedly passed")
    print("RPM lock hash assertion self-test: ok (positive fixture and installed hash mutation)")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        usage=("%(prog)s --root ROOTFS --lockfile LOCKFILE [--direct-rpm-dir DIR]\n       %(prog)s --self-test")
    )
    parser.add_argument("--root", type=Path)
    parser.add_argument("--lockfile", type=Path)
    parser.add_argument("--direct-rpm-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0
        if args.root is None or args.lockfile is None:
            parser.error("--root and --lockfile are required unless --self-test is used")
        verify_lock_hashes(args.root, args.lockfile, args.direct_rpm_dir)
    except (GateError, rpmlock.LockError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
