#!/usr/bin/env python3
# Purpose: Clone-parent python rootfs pipeline — pinned transaction, guarded strip, parent-invariance and
#          combined-rpmdb assertions, deterministic normalization
# Role: build
# Micro-container candidate: yes - stdlib + rpm/ldd orchestration, path-in/exit-out, has --self-test

"""Build the base-python rootfs on a cloned parent, fail-closed at every step.

Pipeline order is load-bearing (see the step names in ``build``): every
rpm-based assertion runs BEFORE the rpmdb sidecars are deleted, because any rpm
invocation recreates them; the finalized database bytes are re-validated in a
disposable scratch root afterwards.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from unittest.mock import patch

from retained_payload_trim import (  # type: ignore[import-not-found]
    TrimError,
    apply_retained_payload_trim,
    assert_exact_rpm_verify_deviations,
    load_trim_contract,
    materialize_trim_contract,
    parse_rpm_file_records,
)

EXECUTABLE_DIRS: Final = ("usr/bin", "usr/sbin", "bin", "sbin")
FORBIDDEN_EXECUTABLES: Final = (
    "bash",
    "sh",
    "dash",
    "ksh",
    "zsh",
    "microdnf",
    "dnf",
    "yum",
    "rpm",
    "pip",
    "pip3",
    "pip3.12",
    "gawk",
    "awk",
    "grep",
    "sed",
    "coreutils",
)
RPMDB_SQLITE: Final = "var/lib/rpm/rpmdb.sqlite"
RPMDB_SIDECARS: Final = ("var/lib/rpm/rpmdb.sqlite-shm", "var/lib/rpm/rpmdb.sqlite-wal")
LD_SO_CACHE: Final = "etc/ld.so.cache"
GENERATED_PATH_ALLOWLIST: Final = frozenset({LD_SO_CACHE})
ALTERNATIVES_DIRS: Final = ("etc/alternatives", "var/lib/alternatives")
IDENTITY_FILES: Final = ("etc/passwd", "etc/group")
REQUIRES_SELF_PREFIXES: Final = ("rpmlib(", "config(")


class BuildError(RuntimeError):
    """Raised when a python-rootfs invariant is not satisfied."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def _run(
    command: Sequence[str],
    *,
    capture_output: bool = False,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), check=check, capture_output=capture_output, text=True, env=env)


def _rpm(rootfs: Path, arguments: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["rpm", f"--root={rootfs}", *arguments], capture_output=True, check=check)


def _rpm_output(rootfs: Path, arguments: Sequence[str]) -> str:
    return _rpm(rootfs, arguments).stdout.rstrip("\n")


def _rooted(rootfs: Path, absolute_path: str) -> Path:
    return rootfs / absolute_path.removeprefix("/")


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    mtime: int
    size: int
    linkname: str
    sha256: str
    nlink_group: str
    xattrs: str

    def line(self) -> str:
        return "|".join(
            (
                self.path,
                self.kind,
                oct(self.mode),
                str(self.uid),
                str(self.gid),
                str(self.mtime),
                str(self.size),
                self.linkname,
                self.sha256,
                self.nlink_group,
                self.xattrs,
            )
        )

    def metadata_line(self) -> str:
        return "|".join(
            (
                self.path,
                self.kind,
                oct(self.mode),
                str(self.uid),
                str(self.gid),
                self.linkname,
                self.sha256,
                self.nlink_group,
                self.xattrs,
            )
        )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entry_xattrs(path: Path) -> str:
    try:
        names = sorted(os.listxattr(path, follow_symlinks=False))
    except OSError:
        return ""
    pairs: list[str] = []
    for name in names:
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
        except OSError:
            continue
        pairs.append(f"{name}={hashlib.sha256(value).hexdigest()}")
    return ";".join(pairs)


def walk_root(rootfs: Path) -> dict[str, Entry]:
    inode_paths: dict[tuple[int, int], list[str]] = {}
    stats: dict[str, os.stat_result] = {}
    for dirpath, dirnames, filenames in os.walk(rootfs, topdown=True):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(rootfs).as_posix()
            st = path.lstat()
            stats[rel] = st
            if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                inode_paths.setdefault((st.st_dev, st.st_ino), []).append(rel)

    groups = {key: min(paths) for key, paths in inode_paths.items() if len(paths) > 1}
    entries: dict[str, Entry] = {}
    for rel, st in stats.items():
        path = rootfs / rel
        if stat.S_ISLNK(st.st_mode):
            kind, linkname, sha, size = "l", str(path.readlink()), "", 0
        elif stat.S_ISREG(st.st_mode):
            kind, linkname, sha, size = "f", "", _file_sha256(path), st.st_size
        elif stat.S_ISDIR(st.st_mode):
            kind, linkname, sha, size = "d", "", "", 0
        else:
            kind, linkname, sha, size = "o", "", "", 0
        entries[rel] = Entry(
            path=rel,
            kind=kind,
            mode=st.st_mode & 0o7777,
            uid=st.st_uid,
            gid=st.st_gid,
            mtime=int(st.st_mtime),
            size=size,
            linkname=linkname,
            sha256=sha,
            nlink_group=groups.get((st.st_dev, st.st_ino), ""),
            xattrs=_entry_xattrs(path),
        )
    return entries


def write_manifest(entries: dict[str, Entry], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(entries[key].line() for key in sorted(entries)) + "\n", encoding="utf-8")


def _read_lock_rows(lock_module_dir: Path, lockfile: Path) -> tuple[list[dict[str, str]], dict[str, str]]:
    sys.path.insert(0, str(lock_module_dir))
    try:
        import rpmlock  # type: ignore[import-not-found]  # noqa: PLC0415
    finally:
        sys.path.pop(0)
    parsed = rpmlock.parse(lockfile)
    rows = [
        {
            "package": row.package,
            "final_rpmdb": row.final_rpmdb,
            "name": row.name,
            "filename": rpmlock.rpm_filename(row),
        }
        for row in parsed.rows
    ]
    return rows, dict(parsed.headers)


def load_micro_floor(path: Path, arch: str) -> tuple[str, list[str], list[str]]:
    """Return (parent digest, floor NEVRAs, txn-writer NEVRAs) for the requested arch."""
    loaded = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(loaded, dict), "micro-floor.json must be a JSON object")
    parent = loaded.get("parent")
    _require(isinstance(parent, dict), "micro-floor.json missing parent section")
    assert isinstance(parent, dict)
    floor = parent.get("floor", {}).get(arch)
    _require(isinstance(floor, list) and bool(floor), f"micro-floor.json missing parent floor for {arch}")
    assert isinstance(floor, list)
    writer = loaded.get("txn_writer", {}).get(arch)
    _require(
        isinstance(writer, list) and len(writer) == 5,
        f"micro-floor.json txn_writer must pin exactly five NEVRAs for {arch}",
    )
    assert isinstance(writer, list)
    return str(parent.get("digest", "")), [str(item) for item in floor], [str(item) for item in writer]


def assert_txn_writer(snapshot_path: Path, expected_nevras: list[str]) -> None:
    observed = sorted(
        line.split("|", 1)[1] for line in snapshot_path.read_text(encoding="utf-8").splitlines() if "|" in line
    )
    _require(
        observed == sorted(expected_nevras),
        "builder rpmdb-writing toolchain does not match micro-floor.json txn_writer: "
        f"observed={observed} expected={sorted(expected_nevras)}",
    )


def assert_clone_matches_parent(rootfs: Path, floor_nevras: list[str]) -> None:
    installed = sorted(_rpm_output(rootfs, ["-qa", "--qf", "%{NEVRA}\n"]).splitlines())
    _require(
        installed == sorted(floor_nevras),
        "cloned parent rootfs does not match micro-floor.json parent floor: "
        f"installed={installed} expected={sorted(floor_nevras)}",
    )


def assert_parent_has_no_cache(pre: dict[str, Entry]) -> None:
    cached = [path for path in pre if path.startswith("var/cache/")]
    _require(
        not cached,
        "pinned parent unexpectedly ships var/cache content; refresh micro-floor.json and re-audit: "
        + ", ".join(sorted(cached)[:10]),
    )


def run_transaction(rootfs: Path, blob_dir: Path, rows: list[dict[str, str]]) -> None:
    blobs = [blob_dir / row["filename"] for row in rows]
    for blob in blobs:
        _require(blob.is_file(), f"missing pinned RPM blob: {blob}")
    _rpm(
        rootfs,
        [
            "-Uvh",
            "--noscripts",
            "--notriggers",
            "--oldpackage",
            "--replacepkgs",
            "--excludedocs",
            *[str(blob) for blob in blobs],
        ],
    )


def _ldd_dependencies(output: str) -> list[str]:
    dependencies: list[str] = []
    for line in output.splitlines():
        fields = line.split()
        if "=> /" in line and len(fields) >= 3:
            dependencies.append(fields[2])
        elif line[:1].isspace() and fields and fields[0].startswith("/"):
            dependencies.append(fields[0])
    return dependencies


def protected_paths(rootfs: Path) -> set[str]:
    roots: list[Path] = [
        _rooted(rootfs, "/usr/bin/python3.12"),
        _rooted(rootfs, "/usr/lib64/libpython3.12.so.1.0"),
        _rooted(rootfs, "/usr/lib64/libcrypto.so.3"),
        _rooted(rootfs, "/usr/lib64/libssl.so.3"),
        _rooted(rootfs, "/usr/lib64/ossl-modules/fips.so"),
        _rooted(rootfs, "/usr/lib64/libc.so.6"),
    ]
    dynload = _rooted(rootfs, "/usr/lib64/python3.12/lib-dynload")
    _require(dynload.is_dir(), "python lib-dynload directory missing after transaction")
    roots.extend(sorted(dynload.glob("*.so")))
    ldd_env = os.environ.copy()
    ldd_env["LD_LIBRARY_PATH"] = str(_rooted(rootfs, "/usr/lib64"))
    protected: set[str] = set()
    for object_path in roots:
        _require(object_path.exists(), f"required ldd root missing: {object_path}")
        protected.add(str(object_path.resolve(strict=True)))
        ldd = _run(["ldd", str(object_path)], capture_output=True, check=False, env=ldd_env)
        for dependency in _ldd_dependencies(ldd.stdout):
            resolved = _rooted(rootfs, dependency)
            if not resolved.exists():
                resolved = Path(dependency)
            if resolved.exists():
                protected.add(str(resolved.resolve(strict=True)))
    return protected


def strip_packages(
    rootfs: Path,
    rows: list[dict[str, str]],
    floor_names: set[str],
    pre: dict[str, Entry],
    protected: set[str],
) -> list[str]:
    strip_names = sorted(row["name"] for row in rows if row["final_rpmdb"] == "no")
    overlap = sorted(set(strip_names) & floor_names)
    _require(not overlap, "strip candidates may never include parent floor packages: " + ", ".join(overlap))
    preserved: dict[str, tuple[Entry, bytes | None]] = {}
    for name in strip_names:
        owned = _rpm_output(rootfs, ["-ql", name]).splitlines()
        for owned_path in owned:
            rooted = _rooted(rootfs, owned_path)
            if rooted.exists() and str(rooted.resolve()) in protected:
                raise BuildError(f"strip candidate {name} owns protected runtime path {owned_path}")
            rel = owned_path.removeprefix("/")
            previous = pre.get(rel)
            if previous is not None and rel not in preserved:
                # the parent ships this path as an unowned base-image remnant; erasing the
                # package must not delete parent state, so restore it afterwards byte-exact
                content = rooted.read_bytes() if previous.kind == "f" and rooted.is_file() else None
                preserved[rel] = (previous, content)
    _rpm(rootfs, ["-e", "--nodeps", "--noscripts", "--notriggers", *strip_names])
    for name in strip_names:
        result = _rpm(rootfs, ["-q", name], check=False)
        _require(result.returncode != 0, f"stripped package still present in rpmdb: {name}")
    for rel in sorted(preserved):
        previous, content = preserved[rel]
        target = rootfs / rel
        if target.exists() or target.is_symlink():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if previous.kind == "d":
            target.mkdir(mode=previous.mode, exist_ok=True)
        elif previous.kind == "l":
            target.symlink_to(previous.linkname)
        elif previous.kind == "f":
            _require(content is not None, f"no preserved content for parent remnant: /{rel}")
            target.write_bytes(content if content is not None else b"")
            target.chmod(previous.mode)
        os.chown(target, previous.uid, previous.gid, follow_symlinks=False)
    return strip_names


def assert_no_sqlite_elf_dependencies(rootfs: Path) -> int:
    """Prove no ELF object still declares or resolves the removed SQLite soname."""
    ldd_env = os.environ.copy()
    ldd_env["LD_LIBRARY_PATH"] = str(_rooted(rootfs, "/usr/lib64"))
    scanned = 0
    consumers: list[str] = []
    for path in sorted(rootfs.rglob("*")):
        if not path.is_file() or path.is_symlink() or not _is_elf(path):
            continue
        scanned += 1
        result = _run(["ldd", str(path)], capture_output=True, check=False, env=ldd_env)
        if "libsqlite3.so.0" in result.stdout or "libsqlite3.so.0" in result.stderr:
            consumers.append("/" + path.relative_to(rootfs).as_posix())
    _require(scanned > 0, "post-trim ELF dependency scan found no ELF objects")
    _require(
        not consumers,
        "post-trim ELF objects still need libsqlite3.so.0: " + ", ".join(consumers),
    )
    return scanned


def assert_set_exactness(rootfs: Path, floor_nevras: list[str], shipped_nevras: list[str]) -> None:
    installed = sorted(_rpm_output(rootfs, ["-qa", "--qf", "%{NEVRA}\n"]).splitlines())
    expected = sorted([*floor_nevras, *shipped_nevras])
    _require(
        installed == expected,
        f"final package set mismatch: installed={installed} expected={expected}",
    )


def load_requires_exceptions(path: Path) -> set[tuple[str, str]]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(loaded, dict), "requires-exceptions.json must be a JSON object")
    pairs: set[tuple[str, str]] = set()
    for package, tokens in loaded.items():
        if package.startswith("_"):
            continue
        _require(isinstance(tokens, list), f"requires-exceptions entry for {package} must be a list")
        for token in tokens:
            pairs.add((package, str(token)))
    return pairs


SCRIPTLET_DEP_KINDS: Final = ("pre", "post", "preun", "postun", "verify", "interp")


def collect_unsatisfied_requires(rootfs: Path) -> set[tuple[str, str]]:
    """Unsatisfied runtime-kind Requires pairs; scriptlet-kind deps are excluded because every
    scriptlet is suppressed and classified (see rpm-lock/scriptlet-classification.md)."""
    packages = sorted(set(_rpm_output(rootfs, ["-qa", "--qf", "%{NAME}\n"]).splitlines()))
    broken: set[tuple[str, str]] = set()
    for package in packages:
        table = _rpm_output(rootfs, ["-q", "--qf", "[%{REQUIRENAME}\t%{REQUIREFLAGS:deptype}\n]", package])
        for line in table.splitlines():
            if "\t" not in line:
                continue
            token, deptype = line.split("\t", 1)
            if any(kind in deptype for kind in SCRIPTLET_DEP_KINDS):
                continue
            if not token or token.startswith((*REQUIRES_SELF_PREFIXES, "(")):
                continue
            probe = _rpm(rootfs, ["-q", "--whatprovides", token], check=False)
            if probe.returncode != 0:
                broken.add((package, token))
    return broken


def assert_requires_satisfied(
    rootfs: Path,
    exceptions: set[tuple[str, str]],
    baseline: set[tuple[str, str]],
) -> None:
    """The python transaction and strip may add exactly the committed exception pairs to the
    parent's pre-existing (micro-ratified) unsatisfied set, nothing else."""
    broken = collect_unsatisfied_requires(rootfs)
    installed = set(_rpm_output(rootfs, ["-qa", "--qf", "%{NAME}\n"]).splitlines())
    introduced = set(broken - baseline)
    expected = {pair for pair in exceptions if pair[0] in installed}
    unexpected = sorted(introduced - expected)
    stale = sorted(expected - introduced)
    _require(
        not unexpected,
        "the python transaction introduced unsatisfied requirements outside the committed exceptions: "
        + "; ".join(f"{p} needs {t}" for p, t in unexpected),
    )
    _require(
        not stale,
        "committed requires-exceptions are unexpectedly satisfied (stale entries): "
        + "; ".join(f"{p} -> {t}" for p, t in stale),
    )


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def assert_new_paths_owned(
    rootfs: Path,
    pre: dict[str, Entry],
    current: dict[str, Entry],
) -> None:
    new_paths = {rel: entry for rel, entry in current.items() if rel not in pre}
    ownership: dict[str, bool] = {}
    for rel in new_paths:
        if rel in GENERATED_PATH_ALLOWLIST or rel.startswith("var/cache/"):
            ownership[rel] = True
            continue
        ownership[rel] = _rpm(rootfs, ["-qf", f"/{rel}"], check=False).returncode == 0
    owned_content = sorted(rel for rel, owned in ownership.items() if owned and new_paths[rel].kind != "d")
    orphans: list[str] = []
    for rel, entry in new_paths.items():
        if ownership[rel]:
            continue
        if entry.kind == "d":
            # unowned directories are acceptable only as scaffolding for rpm-owned content
            # (e.g. the content-derived /usr/lib/.build-id hash-prefix directories)
            prefix = rel + "/"
            if any(owned.startswith(prefix) for owned in owned_content):
                continue
        orphans.append(rel)
    stray_pyc = sorted(
        rel for rel, owned in ownership.items() if not owned and "__pycache__" in rel and rel.endswith(".pyc")
    )
    unowned_elves = sorted(
        rel for rel, owned in ownership.items() if not owned and new_paths[rel].kind == "f" and _is_elf(rootfs / rel)
    )
    _require(not unowned_elves, "new ELF objects lack rpm ownership: " + ", ".join(unowned_elves[:10]))
    _require(not stray_pyc, "build-generated pyc files detected: " + ", ".join(stray_pyc[:10]))
    _require(
        not orphans,
        "new paths lack rpm ownership and are not allowlisted: " + ", ".join(sorted(orphans)[:10]),
    )


def assert_collisions(rootfs: Path, pre: dict[str, Entry], current: dict[str, Entry], shipped_names: list[str]) -> None:
    conflicts: list[str] = []
    for name in shipped_names:
        for owned_path in _rpm_output(rootfs, ["-ql", name]).splitlines():
            rel = owned_path.removeprefix("/")
            previous = pre.get(rel)
            if previous is None:
                continue
            if previous.kind != "d":
                # the parent carries unowned base-image remnants (license/tabset files, dangling
                # build-id links for libraries the parent trimmed); a new RPM may own such a path
                # only when the overwrite is byte- and metadata-neutral (step 9 re-proves this)
                now = current.get(rel)
                if now is None or previous.metadata_line() != now.metadata_line():
                    conflicts.append(f"{name} altered pre-existing non-directory path {owned_path}")
                continue
            now = current.get(rel)
            if now is None or now.kind != "d":
                conflicts.append(f"{name} changed pre-existing directory type at {owned_path}")
            elif (now.mode, now.uid, now.gid, now.xattrs) != (
                previous.mode,
                previous.uid,
                previous.gid,
                previous.xattrs,
            ):
                conflicts.append(f"{name} altered shared directory metadata at {owned_path}")
    _require(not conflicts, "payload collisions with the parent detected: " + "; ".join(sorted(conflicts)[:10]))


def assert_no_alternatives(current: dict[str, Entry]) -> None:
    additions = [path for path in current if any(path == d or path.startswith(d + "/") for d in ALTERNATIVES_DIRS)]
    _require(not additions, "alternatives state must not appear: " + ", ".join(sorted(additions)[:10]))


def run_ldconfig(rootfs: Path) -> None:
    _run(["ldconfig", "-r", str(rootfs)])
    cache = _rooted(rootfs, f"/{LD_SO_CACHE}")
    _require(cache.is_file() and cache.stat().st_size > 0, "ld.so.cache missing or empty after ldconfig")


def assert_sqlite_absent(rootfs: Path) -> None:
    package = _rpm(rootfs, ["-q", "sqlite-libs"], check=False)
    _require(package.returncode != 0, "sqlite-libs still present in the final rpmdb")
    libraries = sorted("/" + path.relative_to(rootfs).as_posix() for path in rootfs.rglob("libsqlite3*"))
    _require(not libraries, "SQLite libraries survived: " + ", ".join(libraries))
    extensions = sorted(
        "/" + path.relative_to(rootfs).as_posix()
        for path in _rooted(rootfs, "/usr/lib64/python3.12/lib-dynload").glob("_sqlite3*")
    )
    _require(not extensions, "CPython _sqlite3 extension survived: " + ", ".join(extensions))
    package_dir = _rooted(rootfs, "/usr/lib64/python3.12/sqlite3")
    _require(not os.path.lexists(package_dir), "CPython sqlite3 package directory survived")
    build_id_links: list[str] = []
    build_id_root = _rooted(rootfs, "/usr/lib/.build-id")
    if build_id_root.is_dir():
        for path in build_id_root.rglob("*"):
            if path.is_symlink():
                target = path.readlink().as_posix()
                if "_sqlite3" in target or "libsqlite3" in target:
                    build_id_links.append("/" + path.relative_to(rootfs).as_posix())
    _require(
        not build_id_links,
        "SQLite build-id links survived: " + ", ".join(sorted(build_id_links)),
    )


def final_cleanup(rootfs: Path, pre: dict[str, Entry], current: dict[str, Entry]) -> list[str]:
    removed: list[str] = []
    for sidecar in RPMDB_SIDECARS:
        target = rootfs / sidecar
        if target.exists():
            target.unlink()
            removed.append(sidecar)
    for rel in sorted(current):
        if rel.startswith("var/cache/") and rel not in pre:
            target = rootfs / rel
            if target.is_symlink() or target.is_file():
                target.unlink(missing_ok=True)
                removed.append(rel)
    for rel in sorted((p for p in current if p.startswith("var/cache/") and p not in pre), reverse=True):
        target = rootfs / rel
        if target.is_dir():
            with os.scandir(target) as scandir:
                if next(scandir, None) is None:
                    target.rmdir()
                    removed.append(rel)
    return removed


def normalize_mtimes(rootfs: Path, source_date_epoch: int) -> None:
    for dirpath, dirnames, filenames in os.walk(rootfs, topdown=False):
        for name in dirnames + filenames:
            os.utime(Path(dirpath) / name, (source_date_epoch, source_date_epoch), follow_symlinks=False)
    os.utime(rootfs, (source_date_epoch, source_date_epoch), follow_symlinks=False)


def assert_parent_invariance(
    pre: dict[str, Entry],
    post: dict[str, Entry],
    allowed_changed: set[str],
    allowed_deleted: set[str],
) -> None:
    deleted: list[str] = []
    mutated: list[str] = []
    for rel, previous in pre.items():
        if rel in allowed_deleted:
            continue
        now = post.get(rel)
        if now is None:
            deleted.append(rel)
            continue
        if rel in allowed_changed:
            continue
        if previous.metadata_line() != now.metadata_line():
            mutated.append(rel)
    _require(not deleted, "parent paths deleted outside the exception set: " + ", ".join(sorted(deleted)[:10]))
    _require(not mutated, "parent paths mutated outside the exception set: " + ", ".join(sorted(mutated)[:10]))
    for identity in IDENTITY_FILES:
        _require(
            pre[identity].sha256 == post[identity].sha256,
            f"identity file changed: /{identity}",
        )


def validate_shipped_rpmdb(
    rootfs: Path,
    floor_nevras: list[str],
    shipped_nevras: list[str],
    exceptions: set[tuple[str, str]],
    baseline: set[tuple[str, str]],
) -> None:
    with tempfile.TemporaryDirectory() as scratch:
        scratch_root = Path(scratch) / "validate-root"
        (scratch_root / "var/lib/rpm").mkdir(parents=True)
        shutil.copy2(rootfs / RPMDB_SQLITE, scratch_root / RPMDB_SQLITE)
        assert_set_exactness(scratch_root, floor_nevras, shipped_nevras)
        assert_requires_satisfied(scratch_root, exceptions, baseline)


def build(args: argparse.Namespace) -> None:
    rootfs = Path(args.rootfs)
    rows, headers = _read_lock_rows(Path(__file__).resolve().parent, Path(args.lockfile))
    _, floor_nevras, txn_writer_nevras = load_micro_floor(Path(args.micro_floor), args.target_arch)
    floor_names = {nevra.rsplit("-", 2)[0] for nevra in floor_nevras}
    shipped_rows = [row for row in rows if row["final_rpmdb"] == "yes"]
    shipped_nevras = [row["package"] for row in shipped_rows]
    shipped_names = [row["name"] for row in shipped_rows]
    exceptions = load_requires_exceptions(Path(args.requires_exceptions))
    trim_contract = load_trim_contract(Path(args.retained_payload_trim), args.target_arch)
    source_date_epoch = int(headers.get("source_date_epoch", "0"))
    _require(source_date_epoch > 0, "lock header missing source_date_epoch")

    print("step 1: pre-transaction manifest", flush=True)
    pre = walk_root(rootfs)
    write_manifest(pre, Path(args.manifest_dir) / "pre.manifest")
    print("step 2: parent identity + writer-toolchain + no-cache assertions", flush=True)
    assert_clone_matches_parent(rootfs, floor_nevras)
    assert_txn_writer(Path(args.txn_writer_snapshot), txn_writer_nevras)
    assert_parent_has_no_cache(pre)
    baseline_requires = collect_unsatisfied_requires(rootfs)
    print(f"  parent baseline: {len(baseline_requires)} pre-existing unsatisfied require(s)", flush=True)
    print("step 3: pinned transaction", flush=True)
    run_transaction(rootfs, Path(args.rpm_dir), rows)
    print("step 4: exact retained-package payload trim", flush=True)
    trim_entries = materialize_trim_contract(
        rootfs,
        trim_contract,
        lambda path: _rpm_output(rootfs, ["-qf", "--qf", "%{NAME}\n", path]),
        lambda package: parse_rpm_file_records(
            _rpm_output(rootfs, ["-q", "--qf", "[%{FILENAMES}\t%{FILELINKTOS}\n]", package])
        ),
    )
    apply_retained_payload_trim(
        rootfs,
        trim_entries,
        lambda path: _rpm_output(rootfs, ["-qf", "--qf", "%{NAME}\n", path]),
    )
    assert_exact_rpm_verify_deviations(
        trim_entries,
        lambda package: _rpm(rootfs, ["-V", "--nodeps", package], check=False),
    )
    print(f"  trimmed: {len(trim_entries)} exact python3.12-libs payload paths", flush=True)
    print("step 5: compute protected runtime paths", flush=True)
    protected = protected_paths(rootfs)
    print(f"  protected: {len(protected)} resolved runtime paths", flush=True)
    print("step 6: guarded final_rpmdb=no package erase", flush=True)
    stripped = strip_packages(rootfs, rows, floor_names, pre, protected)
    print(f"  stripped: {' '.join(stripped)}", flush=True)
    print("step 7: set, Requires, ownership, collision, and ELF-honesty assertions", flush=True)
    mid = walk_root(rootfs)
    assert_set_exactness(rootfs, floor_nevras, shipped_nevras)
    assert_requires_satisfied(rootfs, exceptions, baseline_requires)
    assert_new_paths_owned(rootfs, pre, mid)
    assert_collisions(rootfs, pre, mid, shipped_names)
    assert_no_alternatives({k: v for k, v in mid.items() if k not in pre})
    elf_count = assert_no_sqlite_elf_dependencies(rootfs)
    print(f"  post-trim ELF scan: {elf_count} object(s), no libsqlite3.so.0 consumers", flush=True)
    for executable in FORBIDDEN_EXECUTABLES:
        for directory in EXECUTABLE_DIRS:
            _require(
                not _rooted(rootfs, f"/{directory}/{executable}").exists(),
                f"forbidden executable survived: /{directory}/{executable}",
            )
    print("step 8: ldconfig", flush=True)
    run_ldconfig(rootfs)
    print("step 9: SQLite component absence assertions", flush=True)
    assert_sqlite_absent(rootfs)
    print("step 10: final cleanup (no rpm calls beyond this point)", flush=True)
    mid = walk_root(rootfs)
    removed = final_cleanup(rootfs, pre, mid)
    print(f"  removed: {' '.join(removed) if removed else 'nothing'}", flush=True)
    print("step 11: mtime normalization", flush=True)
    normalize_mtimes(rootfs, source_date_epoch)
    print("step 12: post manifest + parent invariance", flush=True)
    post = walk_root(rootfs)
    write_manifest(post, Path(args.manifest_dir) / "post.manifest")
    allowed_changed = {RPMDB_SQLITE, LD_SO_CACHE}
    allowed_deleted = {*RPMDB_SIDECARS, *(rel for rel in removed if rel.startswith("var/cache/"))}
    assert_parent_invariance(pre, post, allowed_changed, allowed_deleted)
    print("step 13: shipped-rpmdb validation in a disposable root", flush=True)
    validate_shipped_rpmdb(rootfs, floor_nevras, shipped_nevras, exceptions, baseline_requires)
    print("build-python-rootfs: all invariants satisfied", flush=True)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "root"
        (root / "etc").mkdir(parents=True)
        (root / "usr/lib64").mkdir(parents=True)
        (root / "etc/passwd").write_text("root:x:0:0::/root:/sbin/nologin\n", encoding="utf-8")
        (root / "etc/group").write_text("root:x:0:\n", encoding="utf-8")
        (root / "usr/lib64/libdemo.so").write_bytes(b"\x7fELFdemo")
        os.link(root / "usr/lib64/libdemo.so", root / "usr/lib64/libdemo-alias.so")
        (root / "usr/lib64/libother.so").symlink_to("libdemo.so")
        xattr_probe = True
        try:
            os.setxattr(root / "etc/passwd", "user.step034", b"probe")
        except OSError:
            xattr_probe = False

        pre = walk_root(root)
        assert pre["usr/lib64/libdemo.so"].nlink_group == pre["usr/lib64/libdemo-alias.so"].nlink_group != ""
        assert pre["usr/lib64/libother.so"].kind == "l"
        if xattr_probe:
            assert "user.step034=" in pre["etc/passwd"].xattrs

        identical = walk_root(root)
        assert_parent_invariance(pre, identical, set(), set())

        rejected = 0
        mutations: list[tuple[str, str]] = [
            ("delete", "usr/lib64/libdemo.so"),
            ("chmod", "etc/group"),
            ("rewrite", "etc/passwd"),
        ]
        for label, rel in mutations:
            target = root / rel
            saved = target.read_bytes() if label != "delete" else b""
            saved_mode = target.stat().st_mode
            if label == "delete":
                hoisted = target.read_bytes()
                target.unlink()
            elif label == "chmod":
                target.chmod(0o750)
            else:
                target.write_bytes(b"tampered\n")
            try:
                assert_parent_invariance(pre, walk_root(root), set(), set())
            except BuildError:
                rejected += 1
            else:
                raise SystemExit(f"self-test: parent-invariance mutation unexpectedly passed: {label}")
            finally:
                if label == "delete":
                    target.write_bytes(hoisted)
                    # restore the hardlink relationship destroyed by the delete probe
                    (root / "usr/lib64/libdemo-alias.so").unlink()
                    os.link(target, root / "usr/lib64/libdemo-alias.so")
                elif label == "chmod":
                    target.chmod(saved_mode)
                else:
                    target.write_bytes(saved)
                pre = walk_root(root)

        assert_parent_has_no_cache(pre)
        (root / "var/cache/demo").mkdir(parents=True)
        (root / "var/cache/demo/file").write_text("x", encoding="utf-8")
        try:
            assert_parent_has_no_cache(walk_root(root))
        except BuildError:
            rejected += 1
        else:
            raise SystemExit("self-test: parent-cache mutation unexpectedly passed")

        alternatives = walk_root(root)
        try:
            assert_no_alternatives(
                {
                    "etc/alternatives/python": Entry(
                        path="etc/alternatives/python",
                        kind="l",
                        mode=0o777,
                        uid=0,
                        gid=0,
                        mtime=0,
                        size=0,
                        linkname="/usr/bin/python3.12",
                        sha256="",
                        nlink_group="",
                        xattrs="",
                    )
                }
            )
        except BuildError:
            rejected += 1
        else:
            raise SystemExit("self-test: alternatives mutation unexpectedly passed")
        assert alternatives is not None

        normalize_mtimes(root, 1704067200)
        swept = walk_root(root)
        assert all(entry.mtime == 1704067200 for entry in swept.values())

        def write_probe(probe_root: Path, relative_path: str, content: bytes = b"probe") -> None:
            target = probe_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

        def add_sqlite_library(probe_root: Path) -> None:
            write_probe(probe_root, "usr/lib64/libsqlite3.so.0")

        def add_sqlite_extension(probe_root: Path) -> None:
            write_probe(
                probe_root,
                "usr/lib64/python3.12/lib-dynload/_sqlite3.cpython-312-x86_64-linux-gnu.so",
            )

        def add_sqlite_package_dir(probe_root: Path) -> None:
            (probe_root / "usr/lib64/python3.12/sqlite3").mkdir(parents=True)

        def add_sqlite_build_id_link(probe_root: Path) -> None:
            link = probe_root / "usr/lib/.build-id/aa/sqlite-probe"
            link.parent.mkdir(parents=True)
            link.symlink_to("../../../lib64/libsqlite3.so.0")

        def no_files(_probe_root: Path) -> None:
            return

        clean_sqlite_root = Path(tmp) / "sqlite-clean"
        clean_sqlite_root.mkdir()
        absent_rpm = subprocess.CompletedProcess(["rpm"], 1, "", "")
        with patch.object(sys.modules[__name__], "_rpm", return_value=absent_rpm):
            assert_sqlite_absent(clean_sqlite_root)

        sqlite_rejected = 0
        sqlite_mutations: list[tuple[str, Callable[[Path], None], int, str]] = [
            (
                "SQLite library",
                add_sqlite_library,
                1,
                "SQLite libraries survived: /usr/lib64/libsqlite3.so.0",
            ),
            (
                "CPython _sqlite3 extension",
                add_sqlite_extension,
                1,
                "CPython _sqlite3 extension survived: "
                "/usr/lib64/python3.12/lib-dynload/_sqlite3.cpython-312-x86_64-linux-gnu.so",
            ),
            (
                "CPython sqlite3 package directory",
                add_sqlite_package_dir,
                1,
                "CPython sqlite3 package directory survived",
            ),
            (
                "SQLite build-id link",
                add_sqlite_build_id_link,
                1,
                "SQLite build-id links survived: /usr/lib/.build-id/aa/sqlite-probe",
            ),
            (
                "sqlite-libs rpmdb entry",
                no_files,
                0,
                "sqlite-libs still present in the final rpmdb",
            ),
        ]
        for label, populate, rpm_returncode, expected_reason in sqlite_mutations:
            probe_root = Path(tmp) / f"sqlite-{sqlite_rejected}"
            probe_root.mkdir()
            populate(probe_root)
            rpm_result = subprocess.CompletedProcess(["rpm"], rpm_returncode, "", "")
            with patch.object(sys.modules[__name__], "_rpm", return_value=rpm_result):
                try:
                    assert_sqlite_absent(probe_root)
                except BuildError as exc:
                    if str(exc) != expected_reason:
                        raise SystemExit(
                            f"self-test: SQLite absence mutation rejected for the wrong reason: {label}: {exc}"
                        ) from exc
                    sqlite_rejected += 1
                else:
                    raise SystemExit(f"self-test: SQLite absence mutation unexpectedly passed: {label}")

        elf_root = Path(tmp) / "sqlite-elf-consumer"
        write_probe(elf_root, "usr/bin/consumer", b"\x7fELFprobe")
        clean_ldd = subprocess.CompletedProcess(["ldd"], 0, "libc.so.6 => /usr/lib64/libc.so.6\n", "")
        with patch.object(sys.modules[__name__], "_run", return_value=clean_ldd):
            assert assert_no_sqlite_elf_dependencies(elf_root) == 1
        sqlite_ldd = subprocess.CompletedProcess(
            ["ldd"],
            0,
            "libsqlite3.so.0 => /usr/lib64/libsqlite3.so.0\n",
            "",
        )
        with patch.object(sys.modules[__name__], "_run", return_value=sqlite_ldd):
            try:
                assert_no_sqlite_elf_dependencies(elf_root)
            except BuildError as exc:
                expected_reason = "post-trim ELF objects still need libsqlite3.so.0: /usr/bin/consumer"
                if str(exc) != expected_reason:
                    raise SystemExit(
                        f"self-test: SQLite DT_NEEDED consumer mutation rejected for the wrong reason: {exc}"
                    ) from exc
                sqlite_rejected += 1
            else:
                raise SystemExit("self-test: SQLite DT_NEEDED consumer mutation unexpectedly passed")

        print(
            "build-python-rootfs self-test: walker+invariance ok; "
            f"{rejected + sqlite_rejected}/11 mutation probes rejected "
            "(5 general, 6 SQLite absence)"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the base-python rootfs on a cloned parent.")
    parser.add_argument("--rootfs", help="cloned parent rootfs to transform")
    parser.add_argument("--lockfile", help="python RPM lock file")
    parser.add_argument("--micro-floor", help="micro-floor.json path")
    parser.add_argument("--rpm-dir", help="directory holding the fetched pinned RPM blobs")
    parser.add_argument("--manifest-dir", help="directory receiving pre/post manifests")
    parser.add_argument("--target-arch", choices=("amd64", "arm64"), help="target architecture")
    parser.add_argument("--txn-writer-snapshot", help="pkg|NEVRA snapshot of the builder's rpmdb-writing toolchain")
    parser.add_argument("--requires-exceptions", help="committed intentional-unsatisfied-Requires JSON")
    parser.add_argument("--retained-payload-trim", help="exact retained-RPM payload trim JSON")
    parser.add_argument("--self-test", action="store_true", help="run the offline self-test")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    for required in (
        "rootfs",
        "lockfile",
        "micro_floor",
        "rpm_dir",
        "manifest_dir",
        "target_arch",
        "txn_writer_snapshot",
        "requires_exceptions",
        "retained_payload_trim",
    ):
        if not getattr(args, required):
            parser.error(f"--{required.replace('_', '-')} is required in build mode")
    build(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BuildError, TrimError) as error:
        print(f"build-python-rootfs failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
