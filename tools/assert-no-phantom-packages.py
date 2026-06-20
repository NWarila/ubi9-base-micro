#!/usr/bin/env python3
"""Fail unless runtime rpmdb ownership matches functional rootfs payload.

The package pass uses `rpm -ql --dump --dbpath /var/lib/rpm` from the
runtime rpmdb as the authoritative package-to-path source. A package with rpmdb-owned paths must
retain at least one non-excluded regular file, or a symlink resolving to one;
directories, build-id residue, docs, manpages, and licenses do not count.

The orphan pass fails if any non-excluded shared object (`*.so*`) or executable
ELF file in the rootfs is not owned by a runtime rpmdb package. Legitimately
unowned copied config/status files are documented below, but no shared object
or executable is allowed on that list.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import posixpath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


EXCLUDED_PREFIXES = (
    "/usr/lib/.build-id/",
    "/usr/share/doc/",
    "/usr/share/man/",
    "/usr/share/licenses/",
)

DOCUMENTED_UNOWNED_PATHS = {
    "/etc/pki/tls/openssl-fips.cnf",
    "/etc/ld.so.cache",
}

DOCUMENTED_UNOWNED_PREFIXES = (
    "/etc/nwarila/",
)

RUNTIME_RPMDB_PATH = "/var/lib/rpm"


class PhantomPackageError(Exception):
    pass


@dataclass(frozen=True)
class RootfsEntry:
    kind: str
    linkname: str | None = None
    mode: int = 0


@dataclass(frozen=True)
class RpmOwnedPath:
    path: str
    kind: str
    linkname: str | None = None


@dataclass(frozen=True)
class RpmPackage:
    name: str
    nevra: str
    files: list[RpmOwnedPath]


@dataclass(frozen=True)
class PackageStatus:
    name: str
    nevra: str
    owned_files: int
    functional_files: int
    sample_functional_files: list[str]


def normalize_path(path: str) -> str:
    normalized = "/" + posixpath.normpath(path.replace("\\", "/")).lstrip("/")
    return "/" if normalized == "/." else normalized


def is_excluded(path: str) -> bool:
    normalized = normalize_path(path)
    for prefix in EXCLUDED_PREFIXES:
        if normalized == prefix[:-1] or normalized.startswith(prefix):
            return True
    return False


def is_documented_unowned(path: str) -> bool:
    normalized = normalize_path(path)
    if normalized in DOCUMENTED_UNOWNED_PATHS:
        return True
    return any(normalized.startswith(prefix) for prefix in DOCUMENTED_UNOWNED_PREFIXES)


def resolve_link(current_path: str, linkname: str) -> str:
    if linkname.startswith("/"):
        return normalize_path(linkname)
    return normalize_path(posixpath.join(posixpath.dirname(current_path), linkname))


def canonicalize_path(
    path: str,
    entries: dict[str, RootfsEntry],
    seen: tuple[str, ...] = (),
    *,
    follow_final: bool = True,
) -> str:
    normalized = normalize_path(path)
    if normalized in seen:
        return normalized
    parts = [part for part in normalized.strip("/").split("/") if part]
    prefix = ""
    for index, part in enumerate(parts):
        prefix = normalize_path(posixpath.join(prefix, part))
        if not follow_final and index == len(parts) - 1:
            break
        entry = entries.get(prefix)
        if entry and entry.kind == "symlink" and entry.linkname:
            target = resolve_link(prefix, entry.linkname)
            rest = "/".join(parts[index + 1 :])
            rewritten = normalize_path(posixpath.join(target, rest)) if rest else target
            return canonicalize_path(
                rewritten,
                entries,
                seen + (normalized,),
                follow_final=follow_final,
            )
    return normalized


def rootfs_path(rootfs: Path, path: str) -> Path:
    return rootfs / normalize_path(path).lstrip("/")


def tar_member_target(rootfs: Path, member_name: str) -> Path:
    target = rootfs / member_name
    resolved_root = rootfs.resolve()
    resolved_parent = target.parent.resolve()
    if resolved_parent != resolved_root and resolved_root not in resolved_parent.parents:
        raise PhantomPackageError(f"tar member escapes rootfs: {member_name}")
    return target


def extract_tar_to_rootfs(tar_path: Path, rootfs: Path) -> None:
    with tarfile.open(tar_path, mode="r:*") as archive:
        for member in archive:
            normalized_name = normalize_path(member.name).lstrip("/")
            if not normalized_name:
                continue
            target = tar_member_target(rootfs, normalized_name)
            if member.isdir():
                # Keep directories writable while staging; tarfiles can carry
                # restrictive modes such as /root before their children.
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, 0o755)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise PhantomPackageError(f"tar member has no file body: {member.name}")
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, member.mode & 0o777)
            elif member.issym():
                target.parent.mkdir(parents=True, exist_ok=True)
                if os.path.lexists(target):
                    target.unlink()
                os.symlink(member.linkname, target)
            elif member.islnk():
                target.parent.mkdir(parents=True, exist_ok=True)
                link_name = normalize_path(member.linkname).lstrip("/")
                link_target = tar_member_target(rootfs, link_name)
                if not link_target.exists():
                    raise PhantomPackageError(
                        f"tar hardlink target missing: {member.name} -> {member.linkname}"
                    )
                if os.path.lexists(target):
                    target.unlink()
                os.link(link_target, target)


def run_checked(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise PhantomPackageError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout.strip()


def export_image_to_rootfs(image_ref: str, platform: str | None, rootfs: Path) -> None:
    create_command = ["docker", "create"]
    if platform:
        create_command.extend(["--platform", platform])
    create_command.extend([image_ref, "/phantom-package-export"])

    container_id = run_checked(create_command)
    try:
        tar_path = rootfs.parent / "rootfs.tar"
        run_checked(["docker", "export", "--output", str(tar_path), container_id])
        extract_tar_to_rootfs(tar_path, rootfs)
    finally:
        subprocess.run(["docker", "rm", container_id], text=True, capture_output=True, check=False)


def stage_rootfs(args: argparse.Namespace, tempdir: Path) -> Path:
    if args.rootfs:
        rootfs = args.rootfs
        if not rootfs.is_dir():
            raise PhantomPackageError(f"rootfs directory does not exist: {rootfs}")
        return rootfs

    rootfs = tempdir / "rootfs"
    rootfs.mkdir()
    if args.tar:
        extract_tar_to_rootfs(args.tar, rootfs)
    elif args.image:
        export_image_to_rootfs(args.image, args.platform, rootfs)
    else:
        raise PhantomPackageError("provide --image, --tar, --rootfs, or --self-test")
    return rootfs


def entries_from_rootfs(rootfs: Path) -> dict[str, RootfsEntry]:
    entries: dict[str, RootfsEntry] = {}
    for path in rootfs.rglob("*"):
        relative = "/" + path.relative_to(rootfs).as_posix()
        st = os.lstat(path)
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            entries[relative] = RootfsEntry(kind="symlink", linkname=os.readlink(path), mode=mode)
        elif stat.S_ISDIR(mode):
            entries[relative] = RootfsEntry(kind="dir", mode=mode)
        elif stat.S_ISREG(mode):
            entries[relative] = RootfsEntry(kind="file", mode=mode)
        else:
            entries[relative] = RootfsEntry(kind="other", mode=mode)
    if not entries:
        raise PhantomPackageError(f"rootfs directory is empty: {rootfs}")
    return entries


def entries_from_tar(fileobj: io.BufferedIOBase) -> dict[str, RootfsEntry]:
    entries: dict[str, RootfsEntry] = {}
    with tarfile.open(fileobj=fileobj, mode="r|*") as archive:
        for member in archive:
            path = normalize_path(member.name)
            if member.isfile():
                kind = "file"
            elif member.isdir():
                kind = "dir"
            elif member.issym():
                kind = "symlink"
            elif member.islnk():
                kind = "hardlink"
            else:
                kind = "other"
            entries[path] = RootfsEntry(kind=kind, linkname=member.linkname or None, mode=member.mode)
    return entries


def rpm_file_kind(mode_text: str) -> str:
    try:
        mode = int(mode_text, 8)
    except ValueError as exc:
        raise PhantomPackageError(f"invalid rpm file mode: {mode_text}") from exc
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def parse_rpm_dump(output: str) -> list[RpmOwnedPath]:
    files: list[RpmOwnedPath] = []
    for line in output.splitlines():
        if not line:
            continue
        if line == "(contains no files)":
            continue
        parts = line.split(maxsplit=10)
        if len(parts) != 11:
            raise PhantomPackageError(f"unexpected rpm --dump line: {line}")
        path, _size, _mtime, _digest, mode, _owner, _group, _isconfig, _isdoc, _rdev, linkto = parts
        linkname = None if linkto in {"", "X", "(none)"} else linkto
        files.append(RpmOwnedPath(path=normalize_path(path), kind=rpm_file_kind(mode), linkname=linkname))
    return files


def rpm_command(rootfs: Path, *args: str) -> list[str]:
    return ["rpm", "--root", str(rootfs), "--dbpath", RUNTIME_RPMDB_PATH, *args]


def query_rpm_packages(rootfs: Path) -> dict[str, RpmPackage]:
    if shutil.which("rpm") is None:
        raise PhantomPackageError("rpm CLI is required for authoritative runtime rpmdb ownership checks")

    package_lines = run_checked(
        rpm_command(rootfs, "-qa", "--qf", "%{NAME}\t%{NEVRA}\n")
    ).splitlines()
    packages: dict[str, RpmPackage] = {}
    for line in package_lines:
        if not line:
            continue
        try:
            name, nevra = line.split("\t", 1)
        except ValueError as exc:
            raise PhantomPackageError(f"unexpected rpm package query line: {line}") from exc
        dump = run_checked(rpm_command(rootfs, "-q", "--dump", name))
        packages[name] = RpmPackage(name=name, nevra=nevra, files=parse_rpm_dump(dump))
    if not packages:
        raise PhantomPackageError("runtime rpmdb did not contain rpm packages")
    return packages


def load_syft_packages(path: Path) -> dict[str, set[str]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PhantomPackageError(f"{path}: invalid JSON: {exc}") from exc

    packages: dict[str, set[str]] = {}
    for artifact in document.get("artifacts") or []:
        if artifact.get("type") != "rpm":
            continue
        name = artifact.get("name")
        if not isinstance(name, str) or not name:
            raise PhantomPackageError(f"{path}: rpm artifact missing package name")
        metadata = artifact.get("metadata") or {}
        files: set[str] = set()
        for item in metadata.get("files") or []:
            if isinstance(item, str):
                files.add(normalize_path(item))
            elif isinstance(item, dict) and item.get("path"):
                files.add(normalize_path(str(item["path"])))
        packages[name] = files

    if not packages:
        raise PhantomPackageError(f"{path}: Syft JSON did not contain rpm artifacts")
    return packages


def cross_check_syft_names(syft_packages: dict[str, set[str]], rpm_packages: dict[str, RpmPackage]) -> None:
    syft_names = set(syft_packages)
    rpm_names = set(rpm_packages)
    missing = sorted(rpm_names - syft_names)
    extra = sorted(syft_names - rpm_names)
    problems = []
    if missing:
        problems.append("missing from Syft rpm inventory: " + ", ".join(missing))
    if extra:
        problems.append("extra in Syft rpm inventory: " + ", ".join(extra))
    if problems:
        raise PhantomPackageError("; ".join(problems))


def rootfs_resolves_to_kind(
    path: str,
    entries: dict[str, RootfsEntry],
    allowed_kinds: set[str],
    seen: tuple[str, ...] = (),
) -> bool:
    canonical = canonicalize_path(path, entries)
    if canonical in seen:
        return False
    entry = entries.get(canonical)
    if entry is None:
        return False
    if entry.kind in allowed_kinds:
        return True
    if entry.kind == "hardlink" and entry.linkname:
        target = normalize_path(entry.linkname)
        if target not in entries:
            target = resolve_link(canonical, entry.linkname)
        return rootfs_resolves_to_kind(target, entries, allowed_kinds, seen + (canonical,))
    if entry.kind == "symlink" and entry.linkname:
        return rootfs_resolves_to_kind(
            resolve_link(canonical, entry.linkname),
            entries,
            allowed_kinds,
            seen + (canonical,),
        )
    return False


def rootfs_resolves_to_regular(path: str, entries: dict[str, RootfsEntry]) -> bool:
    return rootfs_resolves_to_kind(path, entries, {"file", "hardlink"})


def is_functional(path: str, entries: dict[str, RootfsEntry]) -> bool:
    normalized = normalize_path(path)
    if is_excluded(normalized):
        return False
    parent_canonical = canonicalize_path(normalized, entries, follow_final=False)
    if is_excluded(parent_canonical):
        return False
    return rootfs_resolves_to_regular(parent_canonical, entries)


def owned_path_aliases(path: str, entries: dict[str, RootfsEntry]) -> set[str]:
    normalized = normalize_path(path)
    return {
        normalized,
        canonicalize_path(normalized, entries, follow_final=False),
    }


def package_statuses(
    packages: dict[str, RpmPackage],
    entries: dict[str, RootfsEntry],
    expected_absent: set[str],
) -> tuple[list[PackageStatus], list[str]]:
    present_expected_absent = sorted(expected_absent & packages.keys())
    if present_expected_absent:
        raise PhantomPackageError(
            "expected absent rpm package(s) still present: " + ", ".join(present_expected_absent)
        )

    statuses: list[PackageStatus] = []
    fileless_packages: list[str] = []
    phantoms: list[str] = []
    for name, package in sorted(packages.items()):
        functional = sorted(path.path for path in package.files if is_functional(path.path, entries))
        status = PackageStatus(
            name=name,
            nevra=package.nevra,
            owned_files=len(package.files),
            functional_files=len(functional),
            sample_functional_files=functional[:5],
        )
        statuses.append(status)
        if not package.files:
            fileless_packages.append(name)
        elif not functional:
            phantoms.append(name)

    if phantoms:
        raise PhantomPackageError(
            "rpm package(s) have no present non-excluded regular payload files: "
            + ", ".join(phantoms)
        )
    return statuses, fileless_packages


def collect_owned_aliases(packages: dict[str, RpmPackage], entries: dict[str, RootfsEntry]) -> set[str]:
    owned: set[str] = set()
    for package in packages.values():
        for item in package.files:
            owned.update(owned_path_aliases(item.path, entries))
    return owned


def path_is_owned(path: str, entries: dict[str, RootfsEntry], owned_paths: set[str]) -> bool:
    aliases = owned_path_aliases(path, entries)
    return bool(aliases & owned_paths)


def is_shared_object_path(path: str) -> bool:
    normalized = normalize_path(path)
    if normalized == "/etc/ld.so.cache":
        return False
    name = posixpath.basename(normalized)
    return name.endswith(".so") or ".so." in name


def is_executable_elf(rootfs: Path, path: str, entry: RootfsEntry) -> bool:
    if entry.kind not in {"file", "hardlink"}:
        return False
    if entry.mode & 0o111 == 0:
        return False
    try:
        with rootfs_path(rootfs, path).open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError as exc:
        raise PhantomPackageError(f"cannot inspect executable candidate {path}: {exc}") from exc


def orphan_binary_paths(
    rootfs: Path,
    entries: dict[str, RootfsEntry],
    owned_paths: set[str],
) -> list[str]:
    orphans: list[str] = []
    for path, entry in sorted(entries.items()):
        normalized = normalize_path(path)
        if is_excluded(normalized):
            continue
        is_candidate = False
        if entry.kind in {"file", "hardlink", "symlink"} and is_shared_object_path(normalized):
            is_candidate = True
        elif is_executable_elf(rootfs, normalized, entry):
            is_candidate = True
        if not is_candidate:
            continue
        if is_documented_unowned(normalized):
            raise PhantomPackageError(
                "documented unowned allowlist must not contain shared objects or executable ELF files: "
                + normalized
            )
        if not path_is_owned(normalized, entries, owned_paths):
            orphans.append(normalized)
    return orphans


def write_report(
    output: Path | None,
    statuses: list[PackageStatus],
    fileless_packages: list[str],
    orphan_count: int,
) -> None:
    report = {
        "package_count": len(statuses),
        "functional_package_count": sum(1 for status in statuses if status.functional_files > 0),
        "fileless_rpm_packages": fileless_packages,
        "orphan_binary_files": orphan_count,
        "documented_unowned_paths": sorted(DOCUMENTED_UNOWNED_PATHS),
        "documented_unowned_prefixes": sorted(DOCUMENTED_UNOWNED_PREFIXES),
        "packages": [asdict(status) for status in statuses],
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "phantom package assertion: "
        f"package_count={report['package_count']} "
        f"functional_package_count={report['functional_package_count']} "
        f"fileless_rpm_packages={len(fileless_packages)} "
        f"orphan_binary_files={orphan_count}"
    )


def synthetic_entries() -> dict[str, RootfsEntry]:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for dirname in ["usr", "usr/lib64", "etc", "etc/dir-only"]:
            info = tarfile.TarInfo(dirname)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)

        payload = b"ok"
        good = tarfile.TarInfo("usr/lib64/libgood.so.1")
        good.size = len(payload)
        good.mode = 0o755
        archive.addfile(good, io.BytesIO(payload))

        orphan = tarfile.TarInfo("usr/lib64/liborphan.so.1")
        orphan.size = len(payload)
        orphan.mode = 0o755
        archive.addfile(orphan, io.BytesIO(payload))

        lib64 = tarfile.TarInfo("lib64")
        lib64.type = tarfile.SYMTYPE
        lib64.linkname = "usr/lib64"
        archive.addfile(lib64)
    tar_buffer.seek(0)
    return entries_from_tar(tar_buffer)


def run_self_test() -> None:
    entries = synthetic_entries()
    good_packages = {
        "good-lib": RpmPackage(
            name="good-lib",
            nevra="good-lib-1-1.noarch",
            files=[RpmOwnedPath(path="/lib64/libgood.so.1", kind="file")],
        ),
        "fileless-meta": RpmPackage(
            name="fileless-meta",
            nevra="fileless-meta-1-1.noarch",
            files=[],
        ),
    }

    statuses, fileless = package_statuses(good_packages, entries, set())
    if len(statuses) != 2 or fileless != ["fileless-meta"]:
        raise PhantomPackageError("positive self-test status mismatch")

    dir_only = {
        **good_packages,
        "dir-only": RpmPackage(
            name="dir-only",
            nevra="dir-only-1-1.noarch",
            files=[RpmOwnedPath(path="/etc/dir-only", kind="dir")],
        ),
    }
    try:
        package_statuses(dir_only, entries, set())
    except PhantomPackageError as exc:
        if "dir-only" not in str(exc):
            raise
    else:
        raise PhantomPackageError("dir-only negative self-test unexpectedly passed")

    with tempfile.TemporaryDirectory() as tmp:
        rootfs = Path(tmp)
        libdir = rootfs / "usr" / "lib64"
        libdir.mkdir(parents=True)
        (libdir / "libgood.so.1").write_bytes(b"\x7fELF")
        (libdir / "liborphan.so.1").write_bytes(b"\x7fELF")
        root_entries = {
            "/usr": RootfsEntry(kind="dir", mode=0o755),
            "/usr/lib64": RootfsEntry(kind="dir", mode=0o755),
            "/lib64": RootfsEntry(kind="symlink", linkname="usr/lib64", mode=0o777),
            "/usr/lib64/libgood.so.1": RootfsEntry(kind="file", mode=0o755),
            "/usr/lib64/liborphan.so.1": RootfsEntry(kind="file", mode=0o755),
        }
        owned = collect_owned_aliases(good_packages, root_entries)
        orphans = orphan_binary_paths(rootfs, root_entries, owned)
        if orphans != ["/usr/lib64/liborphan.so.1"]:
            raise PhantomPackageError(f"orphan .so negative self-test mismatch: {orphans}")
    print("phantom package assertion self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail unless runtime rpmdb packages and binary files have honest rootfs ownership."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--image", help="container image reference to export with docker")
    source.add_argument("--tar", type=Path, help="pre-exported rootfs tar")
    source.add_argument("--rootfs", type=Path, help="pre-extracted rootfs directory")
    parser.add_argument("--platform", help="optional docker create --platform value")
    parser.add_argument("--syft-json", type=Path, help="optional Syft JSON rpm inventory to cross-check")
    parser.add_argument("--expect-absent", action="append", default=[], help="rpm package name that must be absent")
    parser.add_argument("--output", type=Path, help="write a JSON package status report")
    parser.add_argument("--self-test", action="store_true", help="run built-in positive and negative checks")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = stage_rootfs(args, Path(tmp))
            entries = entries_from_rootfs(rootfs)
            packages = query_rpm_packages(rootfs)
            if args.syft_json:
                cross_check_syft_names(load_syft_packages(args.syft_json), packages)
            statuses, fileless_packages = package_statuses(packages, entries, set(args.expect_absent))
            owned_paths = collect_owned_aliases(packages, entries)
            orphans = orphan_binary_paths(rootfs, entries, owned_paths)
            if orphans:
                raise PhantomPackageError(
                    "unowned shared object or executable ELF file(s): " + ", ".join(orphans)
                )
            write_report(args.output, statuses, fileless_packages, len(orphans))
    except PhantomPackageError as exc:
        print(f"phantom package assertion failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))