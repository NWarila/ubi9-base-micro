#!/usr/bin/env python3
"""Fail when rpmdb package file ownership no longer matches the rootfs."""

from __future__ import annotations

import argparse
import io
import json
import posixpath
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


class PhantomPackageError(Exception):
    pass


@dataclass(frozen=True)
class RootfsEntry:
    kind: str
    linkname: str | None = None


@dataclass(frozen=True)
class PackageStatus:
    name: str
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


def resolve_link(current_path: str, linkname: str) -> str:
    if linkname.startswith("/"):
        return normalize_path(linkname)
    return normalize_path(posixpath.join(posixpath.dirname(current_path), linkname))


def canonicalize_path(
    path: str,
    entries: dict[str, RootfsEntry],
    seen: tuple[str, ...] = (),
) -> str:
    normalized = normalize_path(path)
    if normalized in seen:
        return normalized
    parts = [part for part in normalized.strip("/").split("/") if part]
    prefix = ""
    for index, part in enumerate(parts):
        prefix = normalize_path(posixpath.join(prefix, part))
        entry = entries.get(prefix)
        if entry and entry.kind == "symlink" and entry.linkname:
            target = resolve_link(prefix, entry.linkname)
            rest = "/".join(parts[index + 1 :])
            rewritten = normalize_path(posixpath.join(target, rest)) if rest else target
            return canonicalize_path(rewritten, entries, seen + (normalized,))
    return normalized


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
            entries[path] = RootfsEntry(kind=kind, linkname=member.linkname or None)
    return entries


def entries_from_rootfs(rootfs: Path) -> dict[str, RootfsEntry]:
    if not rootfs.is_dir():
        raise PhantomPackageError(f"rootfs directory does not exist: {rootfs}")

    entries: dict[str, RootfsEntry] = {}
    for path in rootfs.rglob("*"):
        relative = "/" + path.relative_to(rootfs).as_posix()
        if path.is_symlink():
            entries[relative] = RootfsEntry(kind="symlink", linkname=path.readlink().as_posix())
        elif path.is_dir():
            entries[relative] = RootfsEntry(kind="dir")
        elif path.is_file():
            entries[relative] = RootfsEntry(kind="file")
        else:
            entries[relative] = RootfsEntry(kind="other")
    if not entries:
        raise PhantomPackageError(f"rootfs directory is empty: {rootfs}")
    return entries


def run_checked(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise PhantomPackageError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout.strip()


def entries_from_image(image_ref: str, platform: str | None) -> dict[str, RootfsEntry]:
    create_command = ["docker", "create"]
    if platform:
        create_command.extend(["--platform", platform])
    create_command.extend([image_ref, "/phantom-package-export"])

    container_id = run_checked(create_command)
    try:
        export = subprocess.Popen(
            ["docker", "export", container_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if export.stdout is None:
            raise PhantomPackageError("docker export did not expose stdout")
        entries = entries_from_tar(export.stdout)
        stderr = export.stderr.read().decode("utf-8", errors="replace") if export.stderr else ""
        rc = export.wait()
        if rc != 0:
            raise PhantomPackageError(f"docker export failed ({rc}): {stderr}")
        return entries
    finally:
        subprocess.run(["docker", "rm", container_id], text=True, capture_output=True, check=False)


def target_exists(
    path: str,
    entries: dict[str, RootfsEntry],
    seen: tuple[str, ...] = (),
) -> bool:
    canonical = canonicalize_path(path, entries)
    if canonical in seen:
        return False
    entry = entries.get(canonical)
    if entry is None:
        return False
    if entry.kind in {"file", "dir", "other"}:
        return True
    if entry.kind == "hardlink" and entry.linkname:
        target = normalize_path(entry.linkname)
        if target not in entries:
            target = resolve_link(canonical, entry.linkname)
        return target_exists(target, entries, seen + (canonical,))
    if entry.kind == "symlink" and entry.linkname:
        return target_exists(resolve_link(canonical, entry.linkname), entries, seen + (canonical,))
    return False


def is_functional(path: str, entries: dict[str, RootfsEntry]) -> bool:
    normalized = normalize_path(path)
    canonical = canonicalize_path(normalized, entries)
    if is_excluded(normalized) or is_excluded(canonical):
        return False
    return target_exists(canonical, entries)


def package_statuses(
    packages: dict[str, set[str]],
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
    for name, owned in sorted(packages.items()):
        functional = sorted(path for path in owned if is_functional(path, entries))
        status = PackageStatus(
            name=name,
            owned_files=len(owned),
            functional_files=len(functional),
            sample_functional_files=functional[:5],
        )
        statuses.append(status)
        if not owned:
            fileless_packages.append(name)
        elif not functional:
            phantoms.append(name)

    if phantoms:
        raise PhantomPackageError(
            "rpm package(s) have no present functional payload files: " + ", ".join(phantoms)
        )
    return statuses, fileless_packages


def write_report(output: Path | None, statuses: list[PackageStatus], fileless_packages: list[str]) -> None:
    report = {
        "package_count": len(statuses),
        "functional_package_count": sum(1 for status in statuses if status.functional_files > 0),
        "fileless_rpm_packages": fileless_packages,
        "packages": [asdict(status) for status in statuses],
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "phantom package assertion: "
        f"package_count={report['package_count']} "
        f"functional_package_count={report['functional_package_count']} "
        f"fileless_rpm_packages={len(fileless_packages)}"
    )


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        syft_path = tmp_path / "syft.json"
        tar_path = tmp_path / "rootfs.tar"

        syft_doc = {
            "artifacts": [
                {
                    "name": "good-lib",
                    "type": "rpm",
                    "metadata": {"files": [{"path": "/lib64/libgood.so.1"}]},
                },
                {
                    "name": "config-dir",
                    "type": "rpm",
                    "metadata": {"files": [{"path": "/etc/config-dir"}]},
                },
                {
                    "name": "fileless-meta",
                    "type": "rpm",
                    "metadata": {"files": []},
                },
                {
                    "name": "phantom-lib",
                    "type": "rpm",
                    "metadata": {
                        "files": [
                            {"path": "/usr/lib/.build-id/aa"},
                            {"path": "/usr/share/licenses/phantom-lib/COPYING"},
                        ]
                    },
                },
            ]
        }
        syft_path.write_text(json.dumps(syft_doc), encoding="utf-8")

        with tarfile.open(tar_path, "w") as archive:
            usr = tarfile.TarInfo("usr")
            usr.type = tarfile.DIRTYPE
            archive.addfile(usr)

            lib64 = tarfile.TarInfo("lib64")
            lib64.type = tarfile.SYMTYPE
            lib64.linkname = "usr/lib64"
            archive.addfile(lib64)

            usr_lib64 = tarfile.TarInfo("usr/lib64")
            usr_lib64.type = tarfile.DIRTYPE
            archive.addfile(usr_lib64)

            payload = b"ok"
            lib = tarfile.TarInfo("usr/lib64/libgood.so.1")
            lib.size = len(payload)
            archive.addfile(lib, io.BytesIO(payload))

            etc = tarfile.TarInfo("etc")
            etc.type = tarfile.DIRTYPE
            archive.addfile(etc)

            config_dir = tarfile.TarInfo("etc/config-dir")
            config_dir.type = tarfile.DIRTYPE
            archive.addfile(config_dir)

            build_id = tarfile.TarInfo("usr/lib/.build-id/aa")
            build_id.type = tarfile.DIRTYPE
            archive.addfile(build_id)

        packages = load_syft_packages(syft_path)
        with tar_path.open("rb") as handle:
            entries = entries_from_tar(handle)
        try:
            package_statuses(packages, entries, set())
        except PhantomPackageError:
            pass
        else:
            raise PhantomPackageError("negative self-test unexpectedly passed")

        del packages["phantom-lib"]
        statuses, fileless = package_statuses(packages, entries, {"phantom-lib"})
        if len(statuses) != 3 or fileless != ["fileless-meta"]:
            raise PhantomPackageError("positive self-test status count mismatch")
        print("phantom package assertion self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail unless rpmdb-listed packages retain present non-doc payload files."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--image", help="container image reference to export with docker")
    source.add_argument("--tar", type=Path, help="pre-exported rootfs tar")
    source.add_argument("--rootfs", type=Path, help="pre-extracted rootfs directory")
    parser.add_argument("--platform", help="optional docker create --platform value")
    parser.add_argument("--syft-json", type=Path, help="Syft JSON inventory with rpm file metadata")
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
        if not args.syft_json:
            raise PhantomPackageError("provide --syft-json or --self-test")
        packages = load_syft_packages(args.syft_json)
        if args.image:
            entries = entries_from_image(args.image, args.platform)
        elif args.tar:
            with args.tar.open("rb") as handle:
                entries = entries_from_tar(handle)
        elif args.rootfs:
            entries = entries_from_rootfs(args.rootfs)
        else:
            raise PhantomPackageError("provide --image, --tar, --rootfs, or --self-test")
        statuses, fileless_packages = package_statuses(packages, entries, set(args.expect_absent))
        write_report(args.output, statuses, fileless_packages)
    except PhantomPackageError as exc:
        print(f"phantom package assertion failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
