#!/usr/bin/env python3
# Purpose: Build the base-python image twice and diff exported runtime rootfs bytes to prove reproducibility
# Role: gate
# Micro-container candidate: no - orchestrates a full double-build of images/python, not a thin file-in gate

"""Build the base-python image twice and compare exported runtime rootfs bytes."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

DEFAULT_IMAGE_PREFIX = "local/ubi9-base-python-repro"
DEFAULT_REPORT_RELATIVE_TEMPLATE = "dist/reproducibility/base-python.{arch}.reproducibility.json"
DEFAULT_SUMMARY_RELATIVE_TEMPLATE = "dist/reproducibility/base-python.{arch}.reproducibility.txt"
DEFAULT_WORKDIR_RELATIVE = "dist/reproducibility/work"
DEFAULT_BAKE_FILE_RELATIVE = "images/python/docker-bake.json"
DEFAULT_CONTRACT_RELATIVE = "images/python/contracts/image-manifest.json"
BAKE_TARGET = "repro"
CONTRACT_DEFAULT = Path("@base-python-contract-default@")
RPMDB_PATH = "var/lib/rpm/rpmdb.sqlite"
FIPS_SO_PATH = "usr/lib64/ossl-modules/fips.so"
XATTR_PAX_PREFIX = "SCHILY.xattr."
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class ReproError(Exception):
    pass


@dataclass(frozen=True)
class BakeInvocation:
    bake_file: Path
    target: str
    variables: tuple[tuple[str, str], ...]
    overrides: tuple[str, ...]
    progress: str

    def command(self, *, print_only: bool = False) -> list[str]:
        command = [
            "docker",
            "buildx",
            "bake",
            "--file",
            str(self.bake_file),
            self.target,
            "--progress",
            self.progress,
        ]
        for override in self.overrides:
            command.extend(["--set", override])
        if print_only:
            command.append("--print")
        return command

    def environment(self) -> dict[str, str]:
        return dict(self.variables)


@dataclass(frozen=True)
class Entry:
    path: str
    type: str
    mode: int
    uid: int
    gid: int
    uname: str
    gname: str
    mtime: int
    size: int
    linkname: str
    nlink_group: str
    xattrs: str
    sha256: str | None
    data: bytes | None
    xattr_pairs: tuple[tuple[str, str], ...]


def run(
    command: list[str],
    *,
    cwd: Path,
    capture: bool = False,
    environment: Mapping[str, str] | None = None,
) -> str:
    process_environment = os.environ.copy()
    if environment is not None:
        process_environment.update(environment)
    if capture:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=process_environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise ReproError(
                f"command failed ({result.returncode}): {' '.join(command)}\n"
                f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )
        return result.stdout.strip()

    result = subprocess.run(command, cwd=cwd, env=process_environment, text=True, check=False)
    if result.returncode != 0:
        raise ReproError(f"command failed ({result.returncode}): {' '.join(command)}")
    return ""


def normalize_path(name: str) -> str:
    normalized = name.replace("\\", "/").lstrip("/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized or "."


def entry_type(member: tarfile.TarInfo) -> str:
    if member.isfile():
        return "file"
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    if member.ischr():
        return "character-device"
    if member.isblk():
        return "block-device"
    if member.isfifo():
        return "fifo"
    return "other"


def xattr_pairs_from_pax(pax_headers: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    pairs = [
        (key.removeprefix(XATTR_PAX_PREFIX), value)
        for key, value in pax_headers.items()
        if key.startswith(XATTR_PAX_PREFIX)
    ]
    return tuple(sorted(pairs))


def xattrs_field(pairs: tuple[tuple[str, str], ...]) -> str:
    return ";".join(
        f"{name}={hashlib.sha256(value.encode('utf-8', 'surrogateescape')).hexdigest()}" for name, value in pairs
    )


def entry_from_member(member: tarfile.TarInfo, *, data: bytes | None, digest: str | None) -> Entry:
    pairs = xattr_pairs_from_pax(member.pax_headers)
    return Entry(
        path=normalize_path(member.name),
        type=entry_type(member),
        mode=member.mode & 0o7777,
        uid=member.uid,
        gid=member.gid,
        uname=member.uname or "",
        gname=member.gname or "",
        mtime=int(member.mtime),
        size=member.size if member.isfile() else 0,
        linkname=member.linkname or "",
        nlink_group=member.linkname if member.islnk() else "",
        xattrs=xattrs_field(pairs),
        sha256=digest,
        data=data,
        xattr_pairs=pairs,
    )


def load_tar(path: Path) -> dict[str, Entry]:
    entries: dict[str, Entry] = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            data: bytes | None = None
            digest: str | None = None
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReproError(f"{path}: could not read regular file {member.name}")
                data = extracted.read()
                digest = hashlib.sha256(data).hexdigest()
            elif member.issym() or member.islnk():
                digest = hashlib.sha256((member.linkname or "").encode("utf-8")).hexdigest()

            entry = entry_from_member(member, data=data, digest=digest)
            entries[entry.path] = entry
    return entries


def apply_whiteout(entries: dict[str, Entry], path: str) -> bool:
    parts = path.split("/")
    basename = parts[-1]
    directory = "/".join(parts[:-1])
    if basename == ".wh..wh..opq":
        prefix = f"{directory}/" if directory else ""
        for existing in list(entries):
            if existing.startswith(prefix) and existing != directory:
                del entries[existing]
        return True
    if basename.startswith(".wh."):
        target_name = basename[4:]
        target = f"{directory}/{target_name}" if directory else target_name
        target_prefix = f"{target}/"
        for existing in list(entries):
            if existing == target or existing.startswith(target_prefix):
                del entries[existing]
        return True
    return False


def load_image_rootfs(image_tar: Path) -> dict[str, Entry]:
    entries: dict[str, Entry] = {}
    with tarfile.open(image_tar, "r:*") as image:
        manifest_member = image.extractfile("manifest.json")
        if manifest_member is None:
            raise ReproError(f"{image_tar}: missing manifest.json")
        manifest = json.loads(manifest_member.read().decode("utf-8"))
        if not isinstance(manifest, list) or not manifest:
            raise ReproError(f"{image_tar}: invalid manifest.json")
        layers = manifest[0].get("Layers")
        if not isinstance(layers, list) or not layers:
            raise ReproError(f"{image_tar}: manifest contains no layers")

        for layer_name in layers:
            layer_file = image.extractfile(layer_name)
            if layer_file is None:
                raise ReproError(f"{image_tar}: missing layer {layer_name}")
            layer_bytes = layer_file.read()
            with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer:
                for member in layer:
                    normalized = normalize_path(member.name)
                    if apply_whiteout(entries, normalized):
                        continue
                    data: bytes | None = None
                    digest: str | None = None
                    if member.isfile():
                        extracted = layer.extractfile(member)
                        if extracted is None:
                            raise ReproError(f"{image_tar}: could not read {member.name} from {layer_name}")
                        data = extracted.read()
                        digest = hashlib.sha256(data).hexdigest()
                    elif member.issym() or member.islnk():
                        digest = hashlib.sha256((member.linkname or "").encode("utf-8")).hexdigest()
                    entries[normalized] = entry_from_member(member, data=data, digest=digest)
    return entries


def write_rootfs_tar(entries: dict[str, Entry], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(entries):
            entry = entries[path]
            info = tarfile.TarInfo(path)
            info.mode = entry.mode
            info.uid = entry.uid
            info.gid = entry.gid
            info.uname = entry.uname
            info.gname = entry.gname
            info.mtime = entry.mtime
            if entry.xattr_pairs:
                info.pax_headers = {f"{XATTR_PAX_PREFIX}{name}": value for name, value in entry.xattr_pairs}
            if entry.type == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif entry.type == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry.linkname
                archive.addfile(info)
            elif entry.type == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = entry.linkname
                archive.addfile(info)
            elif entry.type == "file":
                payload = entry.data or b""
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            else:
                archive.addfile(info)


def canonical_rootfs_digest(entries: dict[str, Entry]) -> str:
    """Hash the sorted rootfs entry manifest, not tar bytes.

    Each line is derived only from the Entry dataclass fields:
    path|type|mode-octal|uid|gid|uname|gname|mtime|size|linkname|sha256-or-empty|nlink-group|xattrs.
    The joined UTF-8 text is stable across tarfile format changes because it
    depends on the normalized rootfs entry set rather than archive encoding.
    """

    lines = []
    for path in sorted(entries):
        entry = entries[path]
        lines.append(
            "|".join(
                [
                    entry.path,
                    entry.type,
                    f"{entry.mode:o}",
                    str(entry.uid),
                    str(entry.gid),
                    entry.uname,
                    entry.gname,
                    str(entry.mtime),
                    str(entry.size),
                    entry.linkname,
                    entry.sha256 or "",
                    entry.nlink_group,
                    entry.xattrs,
                ]
            )
        )
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def entry_digest(entries: dict[str, Entry], path: str) -> str | None:
    entry = entries.get(path)
    if entry is None or entry.sha256 is None:
        return None
    return entry.sha256


def rootfs_facts(entries: dict[str, Entry]) -> dict[str, str | None]:
    return {
        "rootfs_digest": canonical_rootfs_digest(entries),
        "rpmdb_sha256": entry_digest(entries, RPMDB_PATH),
        "fips_so_sha256": entry_digest(entries, FIPS_SO_PATH),
    }


def add_rootfs_facts(builds: list[dict[str, object]], left: dict[str, Entry], right: dict[str, Entry]) -> None:
    for side, build, entries in zip(("left", "right"), builds, (left, right), strict=True):
        build["side"] = side
        build.update(rootfs_facts(entries))


def require_sha256(value: str, source: str) -> str:
    if SHA256_HEX.fullmatch(value) is None:
        raise ReproError(f"{source} must be a 64-character lowercase sha256")
    return value


def platform_arch(platform: str) -> str:
    prefix = "linux/"
    if not platform.startswith(prefix) or platform == prefix:
        raise ReproError(f"platform must have linux/<arch> form for contract lookup: {platform}")
    return platform.removeprefix(prefix)


def read_contract_expectations(path: Path, platform: str) -> list[tuple[str, str, str]]:
    contract_path = path
    try:
        loaded = json.loads(contract_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReproError(f"missing expectation contract: {contract_path}") from exc
    except OSError as exc:
        raise ReproError(f"could not read expectation contract {contract_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReproError(f"expectation contract {contract_path} is malformed JSON: {exc}") from exc

    if not isinstance(loaded, dict):
        raise ReproError(f"expectation contract {contract_path} must contain a JSON object")

    arch = platform_arch(platform)
    repro = loaded.get("reproducibility")
    if not isinstance(repro, dict):
        raise ReproError(f"missing expected digest for {platform}: reproducibility")

    checks: list[tuple[str, str, str]] = []
    for contract_key, fact_key in [
        ("canonical_rootfs_digest", "rootfs_digest"),
        ("rpmdb_sha256", "rpmdb_sha256"),
    ]:
        values = repro.get(contract_key)
        if not isinstance(values, dict):
            raise ReproError(f"missing expected digest for {platform}: reproducibility.{contract_key}")
        value = values.get(arch)
        if not isinstance(value, str):
            raise ReproError(f"missing expected digest for {platform}: reproducibility.{contract_key}.{arch}")
        source = f"{contract_path}:reproducibility.{contract_key}.{arch}"
        checks.append((fact_key, require_sha256(value, source), str(contract_path)))
    return checks


def collect_expectations(args: argparse.Namespace, contract: Path | None) -> list[tuple[str, str, str]]:
    checks: list[tuple[str, str, str]] = []
    if args.expect_rootfs_digest is not None:
        checks.append(("rootfs_digest", require_sha256(args.expect_rootfs_digest, "--expect-rootfs-digest"), "cli"))
    if args.expect_rpmdb_sha256 is not None:
        checks.append(("rpmdb_sha256", require_sha256(args.expect_rpmdb_sha256, "--expect-rpmdb-sha256"), "cli"))
    if contract is not None:
        checks.extend(read_contract_expectations(contract, args.platform))
    return checks


def assert_expectations(builds: list[dict[str, object]], checks: list[tuple[str, str, str]]) -> None:
    for build in builds:
        side = str(build.get("side", "unknown"))
        for fact_key, expected, source in checks:
            actual = build.get(fact_key)
            if not isinstance(actual, str):
                if fact_key == "rpmdb_sha256":
                    raise ReproError(f"{fact_key} is uncomputable for {side}: missing {RPMDB_PATH}")
                raise ReproError(f"{fact_key} is uncomputable for {side}")
            if actual != expected:
                raise ReproError(f"{fact_key} mismatch for {side}: expected {expected} from {source}, actual {actual}")


def assert_single_rootfs(rootfs_tar: Path, arch: str, contract: Path) -> None:
    try:
        entries = load_tar(rootfs_tar)
    except FileNotFoundError as exc:
        raise ReproError(f"missing rootfs tar: {rootfs_tar}") from exc
    except (OSError, tarfile.TarError) as exc:
        raise ReproError(f"could not read rootfs tar {rootfs_tar}: {exc}") from exc

    facts = rootfs_facts(entries)
    build: dict[str, object] = {"side": f"single rootfs linux/{arch}", **facts}
    assert_expectations([build], read_contract_expectations(contract, f"linux/{arch}"))

    rootfs_digest = facts["rootfs_digest"]
    rpmdb_sha256 = facts["rpmdb_sha256"]
    if not isinstance(rootfs_digest, str) or not isinstance(rpmdb_sha256, str):
        raise ReproError(f"rootfs facts are uncomputable for linux/{arch}")
    print(f"single-rootfs contract assertion passed for linux/{arch}")
    print(f"canonical_rootfs_digest: {rootfs_digest} (matched)")
    print(f"rpmdb_sha256: {rpmdb_sha256} (matched)")


def first_diff(left: bytes, right: bytes) -> dict[str, object]:
    limit = min(len(left), len(right))
    offset = limit
    for index in range(limit):
        if left[index] != right[index]:
            offset = index
            break
    sample_left = left[offset : offset + 16]
    sample_right = right[offset : offset + 16]
    return {
        "offset": offset,
        "left_hex": sample_left.hex(),
        "right_hex": sample_right.hex(),
    }


def content_bytes(entry: Entry) -> bytes:
    if entry.data is not None:
        return entry.data
    if entry.type in {"symlink", "hardlink"}:
        return entry.linkname.encode("utf-8")
    return b""


def compare_entries(left: dict[str, Entry], right: dict[str, Entry]) -> dict[str, Any]:
    differences: list[dict[str, Any]] = []
    identical = 0

    for path in sorted(set(left) | set(right)):
        left_entry = left.get(path)
        right_entry = right.get(path)
        if left_entry is None or right_entry is None:
            present_entry = left_entry or right_entry
            assert present_entry is not None
            differences.append(
                {
                    "path": path,
                    "classification": "present-in-one-only",
                    "reasons": ["present-in-one-only"],
                    "left_present": left_entry is not None,
                    "right_present": right_entry is not None,
                    "differing_bytes": present_entry.size,
                }
            )
            continue

        reasons: list[str] = []
        detail: dict[str, Any] = {}
        differing_bytes = 0

        if left_entry.type != right_entry.type:
            reasons.append("type-differs")
            detail["left_type"] = left_entry.type
            detail["right_type"] = right_entry.type

        if (
            left_entry.mode != right_entry.mode
            or left_entry.uid != right_entry.uid
            or left_entry.gid != right_entry.gid
            or left_entry.uname != right_entry.uname
            or left_entry.gname != right_entry.gname
        ):
            reasons.append("mode-or-owner-differs")
            detail["left_mode"] = oct(left_entry.mode)
            detail["right_mode"] = oct(right_entry.mode)
            detail["left_uid"] = left_entry.uid
            detail["right_uid"] = right_entry.uid
            detail["left_gid"] = left_entry.gid
            detail["right_gid"] = right_entry.gid
            detail["left_uname"] = left_entry.uname
            detail["right_uname"] = right_entry.uname
            detail["left_gname"] = left_entry.gname
            detail["right_gname"] = right_entry.gname

        if left_entry.sha256 != right_entry.sha256 or left_entry.size != right_entry.size:
            reasons.append("content-differs")
            left_bytes = content_bytes(left_entry)
            right_bytes = content_bytes(right_entry)
            detail["left_size"] = len(left_bytes)
            detail["right_size"] = len(right_bytes)
            detail["left_sha256"] = hashlib.sha256(left_bytes).hexdigest()
            detail["right_sha256"] = hashlib.sha256(right_bytes).hexdigest()
            detail["first_diff"] = first_diff(left_bytes, right_bytes)
            differing_bytes = max(len(left_bytes), len(right_bytes))

        if left_entry.nlink_group != right_entry.nlink_group:
            reasons.append("hardlink-group-differs")
            detail["left_nlink_group"] = left_entry.nlink_group
            detail["right_nlink_group"] = right_entry.nlink_group

        if left_entry.xattrs != right_entry.xattrs:
            reasons.append("xattrs-differ")
            detail["left_xattrs"] = left_entry.xattrs
            detail["right_xattrs"] = right_entry.xattrs

        if left_entry.mtime != right_entry.mtime:
            reasons.append("mtime-differs")
            detail["left_mtime"] = left_entry.mtime
            detail["right_mtime"] = right_entry.mtime

        if reasons:
            if "present-in-one-only" in reasons:
                classification = "present-in-one-only"
            elif "type-differs" in reasons:
                classification = "type-differs"
            elif "content-differs" in reasons:
                classification = "content-differs"
            elif "hardlink-group-differs" in reasons:
                classification = "hardlink-group-differs"
            elif "xattrs-differ" in reasons:
                classification = "xattrs-differ"
            elif "mode-or-owner-differs" in reasons:
                classification = "mode-or-owner-differs"
            else:
                classification = "mtime-differs"
            differences.append(
                {
                    "path": path,
                    "classification": classification,
                    "reasons": reasons,
                    "differing_bytes": differing_bytes,
                    **detail,
                }
            )
        else:
            identical += 1

    class_counts: dict[str, int] = {}
    reason_counts: dict[str, int] = {}
    for item in differences:
        classification = str(item["classification"])
        class_counts[classification] = class_counts.get(classification, 0) + 1
        for reason in item["reasons"]:
            reason_counts[str(reason)] = reason_counts.get(str(reason), 0) + 1

    differing_bytes_total = sum(int(item["differing_bytes"]) for item in differences)
    return {
        "byte_identical": not differences,
        "summary": {
            "total_paths": len(set(left) | set(right)),
            "identical_paths": identical,
            "differing_paths": len(differences),
            "total_differing_bytes": differing_bytes_total,
            "classification_counts": class_counts,
            "reason_counts": reason_counts,
        },
        "differences": differences,
    }


def resolve_default(explicit: Path | None, repo_root: Path | None, relative: str, option: str) -> Path:
    if explicit is not None:
        return explicit
    if repo_root is None:
        raise ReproError(f"--repo-root is required when {option} falls back to its default ({relative})")
    return repo_root / relative


def resolve_contract(args: argparse.Namespace) -> Path | None:
    contract = cast("Path | None", args.expect_from_contract)
    if contract is None:
        return None
    if contract is CONTRACT_DEFAULT:
        return resolve_default(None, args.repo_root, DEFAULT_CONTRACT_RELATIVE, "--expect-from-contract")
    return contract


def resolve_report_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    arch = platform_arch(args.platform)
    report = resolve_default(
        args.report,
        args.repo_root,
        DEFAULT_REPORT_RELATIVE_TEMPLATE.format(arch=arch),
        "--report",
    )
    summary = resolve_default(
        args.summary,
        args.repo_root,
        DEFAULT_SUMMARY_RELATIVE_TEMPLATE.format(arch=arch),
        "--summary",
    )
    return report, summary


def resolve_bake_target(invocation: BakeInvocation, *, repo_root: Path) -> dict[str, Any]:
    raw = run(
        invocation.command(print_only=True),
        cwd=repo_root,
        capture=True,
        environment=invocation.environment(),
    )
    try:
        resolved = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReproError(f"bake --print returned invalid JSON: {exc}") from exc
    targets = resolved.get("target")
    if not isinstance(targets, dict):
        raise ReproError("bake --print output has no target object")
    target = targets.get(invocation.target)
    if not isinstance(target, dict):
        raise ReproError(f"bake --print output has no resolved {invocation.target!r} target")
    return cast("dict[str, Any]", target)


def bake_report(invocation: BakeInvocation, resolved_target: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": str(invocation.bake_file),
        "target": invocation.target,
        "variables": invocation.environment(),
        "overrides": list(invocation.overrides),
        "progress": invocation.progress,
        "resolved_target": resolved_target,
    }


def build_image(tag: str, args: argparse.Namespace, image_tar: Path) -> dict[str, Any]:
    image_tar.parent.mkdir(parents=True, exist_ok=True)
    if image_tar.exists():
        image_tar.unlink()
    repo_root = args.repo_root if args.repo_root is not None else Path.cwd()
    bake_file = resolve_default(None, args.repo_root, DEFAULT_BAKE_FILE_RELATIVE, "Bake file")
    variables = [("REPRO_DEST", str(image_tar))]
    if args.ubi_minimal_image is not None:
        variables.append(("UBI_MINIMAL_IMAGE", args.ubi_minimal_image))
    if args.base_micro_image is not None:
        variables.append(("BASE_MICRO_IMAGE", args.base_micro_image))
    invocation = BakeInvocation(
        bake_file=bake_file,
        target=BAKE_TARGET,
        variables=tuple(variables),
        overrides=(
            f"repro.platform={args.platform}",
            f"repro.tags={tag}",
        ),
        progress=args.progress,
    )
    resolved_target = resolve_bake_target(invocation, repo_root=repo_root)
    run(invocation.command(), cwd=repo_root, environment=invocation.environment())
    return {
        "image": tag,
        "image_tar": str(image_tar),
        "bake": bake_report(invocation, resolved_target),
    }


def build_and_export(args: argparse.Namespace) -> tuple[Path, Path, list[dict[str, object]]]:
    workdir = resolve_default(args.workdir, args.repo_root, DEFAULT_WORKDIR_RELATIVE, "--workdir")
    workdir.mkdir(parents=True, exist_ok=True)
    left_tag = f"{args.image_prefix}:a"
    right_tag = f"{args.image_prefix}:b"
    left_tar = workdir / "rootfs.a.tar"
    right_tar = workdir / "rootfs.b.tar"
    left_image_tar = workdir / "image.a.tar"
    right_image_tar = workdir / "image.b.tar"

    for tar_path in (left_tar, right_tar):
        if tar_path.exists():
            tar_path.unlink()

    left_build = build_image(left_tag, args, left_image_tar)
    write_rootfs_tar(load_image_rootfs(left_image_tar), left_tar)
    right_build = build_image(right_tag, args, right_image_tar)
    write_rootfs_tar(load_image_rootfs(right_image_tar), right_tar)
    left_build["rootfs_tar"] = str(left_tar)
    right_build["rootfs_tar"] = str(right_tar)
    return (
        left_tar,
        right_tar,
        [
            left_build,
            right_build,
        ],
    )


def write_reports(report: dict[str, Any], output: Path, summary_path: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = cast("dict[str, Any]", report["summary"])
    differences = cast("list[dict[str, Any]]", report["differences"])
    builds = cast("list[dict[str, Any]]", report["builds"])
    lines = [
        f"byte-identical: {str(report['byte_identical']).lower()}",
        f"total_paths: {summary['total_paths']}",
        f"identical_paths: {summary['identical_paths']}",
        f"differing_paths: {summary['differing_paths']}",
        f"total_differing_bytes: {summary['total_differing_bytes']}",
        f"classification_counts: {json.dumps(summary['classification_counts'], sort_keys=True)}",
        "rootfs facts:",
    ]
    for build in builds:
        side = str(build["side"])
        lines.extend(
            [
                f"- {side}.rootfs_digest: {build['rootfs_digest']}",
                f"- {side}.rpmdb_sha256: {build['rpmdb_sha256']}",
                f"- {side}.fips_so_sha256: {build['fips_so_sha256']}",
            ]
        )
    lines.append("differences:")
    for item in differences:
        assert isinstance(item, dict)
        reasons = ",".join(str(reason) for reason in item["reasons"])
        line = f"- {item['path']}: {item['classification']} reasons={reasons} differing_bytes={item['differing_bytes']}"
        first = item.get("first_diff")
        if isinstance(first, dict):
            line += f" first_diff_offset={first['offset']} left_hex={first['left_hex']} right_hex={first['right_hex']}"
        if "left_mtime" in item or "right_mtime" in item:
            line += f" left_mtime={item.get('left_mtime')} right_mtime={item.get('right_mtime')}"
        lines.append(line)

    text = "\n".join(lines) + "\n"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(text, encoding="utf-8")
    print(text, end="")
    print(f"wrote JSON report: {output}")
    print(f"wrote text summary: {summary_path}")


def resolved_report_fields(builds: list[dict[str, object]], fallback_platform: str) -> dict[str, object]:
    if not builds or "bake" not in builds[0]:
        return {
            "platform": fallback_platform,
            "source_date_epoch": None,
            "oci_created": None,
        }
    bake = builds[0]["bake"]
    if not isinstance(bake, dict):
        raise ReproError("first build has malformed Bake report data")
    resolved = bake.get("resolved_target")
    if not isinstance(resolved, dict):
        raise ReproError("first build has no resolved Bake target")
    platforms = resolved.get("platforms")
    args = resolved.get("args")
    if not isinstance(platforms, list) or len(platforms) != 1 or not isinstance(platforms[0], str):
        raise ReproError("resolved repro target must contain exactly one platform")
    if not isinstance(args, dict):
        raise ReproError("resolved repro target has no args object")
    source_date_epoch = args.get("SOURCE_DATE_EPOCH")
    oci_created = args.get("OCI_CREATED")
    if not isinstance(source_date_epoch, str) or not source_date_epoch.isdigit():
        raise ReproError("resolved repro target has an invalid SOURCE_DATE_EPOCH")
    if not isinstance(oci_created, str):
        raise ReproError("resolved repro target has an invalid OCI_CREATED")
    return {
        "platform": platforms[0],
        "source_date_epoch": int(source_date_epoch),
        "oci_created": oci_created,
    }


FixtureEntry = tuple[str, bytes | None, str, int, int, int, int, str, dict[str, str]]


def make_tar(path: Path, entries: list[FixtureEntry]) -> None:
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for name, data, kind, mode, uid, gid, mtime, linkname, xattrs in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.uid = uid
            info.gid = gid
            info.mtime = mtime
            if xattrs:
                info.pax_headers = {f"{XATTR_PAX_PREFIX}{key}": value for key, value in xattrs.items()}
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = linkname
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = linkname
                archive.addfile(info)
            else:
                payload = data or b""
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))


def flipped_sha256(value: str) -> str:
    replacement = "0" if value[0] != "0" else "1"
    return replacement + value[1:]


def run_main_silently(argv: list[str]) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(argv)


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        left_tar = tmp_path / "left.tar"
        right_tar = tmp_path / "right.tar"
        make_tar(
            left_tar,
            [
                ("etc", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("etc/identical", b"same", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/content", b"abcdef", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/mtime", b"same-time-body", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/mode", b"same-mode-body", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/left-only", b"left", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/xattr", b"cap-body", "file", 0o644, 0, 0, 10, "", {"security.capability": "\x01\x00\x02"}),
                ("lib64/link", None, "symlink", 0o777, 0, 0, 10, "../usr/lib64/libx.so", {}),
                ("usr", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("usr/bin", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("usr/bin/python3.12", b"elf-bytes", "file", 0o755, 0, 0, 10, "", {}),
                ("usr/bin/python3", None, "hardlink", 0o755, 0, 0, 10, "usr/bin/python3.12", {}),
                (RPMDB_PATH, b"rpmdb", "file", 0o644, 0, 0, 10, "", {}),
                (FIPS_SO_PATH, b"fips", "file", 0o755, 0, 0, 10, "", {}),
            ],
        )
        make_tar(
            right_tar,
            [
                ("etc", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("etc/identical", b"same", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/content", b"abcxef", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/mtime", b"same-time-body", "file", 0o644, 0, 0, 11, "", {}),
                ("etc/mode", b"same-mode-body", "file", 0o600, 0, 0, 10, "", {}),
                ("etc/right-only", b"right", "file", 0o644, 0, 0, 10, "", {}),
                ("etc/xattr", b"cap-body", "file", 0o644, 0, 0, 10, "", {"security.capability": "\x01\x00\x03"}),
                ("lib64/link", None, "symlink", 0o777, 0, 0, 10, "../usr/lib64/liby.so", {}),
                ("usr", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("usr/bin", None, "directory", 0o755, 0, 0, 10, "", {}),
                ("usr/bin/python3.12", b"elf-bytes", "file", 0o755, 0, 0, 10, "", {}),
                ("usr/bin/python3", None, "hardlink", 0o755, 0, 0, 10, "usr/bin/python3.12", {}),
                (RPMDB_PATH, b"rpmdb", "file", 0o644, 0, 0, 10, "", {}),
                (FIPS_SO_PATH, b"fips", "file", 0o755, 0, 0, 10, "", {}),
            ],
        )
        result = compare_entries(load_tar(left_tar), load_tar(right_tar))
        summary = result["summary"]
        assert isinstance(summary, dict)
        if summary["differing_paths"] != 7:
            raise ReproError(f"self-test differing path count mismatch: {summary}")
        classes = summary["classification_counts"]
        assert isinstance(classes, dict)
        expected = {
            "content-differs": 2,
            "mtime-differs": 1,
            "mode-or-owner-differs": 1,
            "present-in-one-only": 2,
            "xattrs-differ": 1,
        }
        if classes != expected:
            raise ReproError(f"self-test classification mismatch: {classes}")

        identical_tar = tmp_path / "identical.tar"
        shutil.copyfile(left_tar, identical_tar)
        identical = compare_entries(load_tar(left_tar), load_tar(identical_tar))
        if not identical["byte_identical"]:
            raise ReproError("self-test identical tar comparison failed")

        left_entries = load_tar(left_tar)
        hardlink_entry = left_entries["usr/bin/python3"]
        if hardlink_entry.nlink_group != "usr/bin/python3.12":
            raise ReproError("self-test hardlink member did not carry its hardlink-group identity")
        xattr_entry = left_entries["etc/xattr"]
        if not xattr_entry.xattrs.startswith("security.capability="):
            raise ReproError("self-test xattr member did not carry a hashed xattr map")
        if left_entries["etc/identical"].xattrs != "":
            raise ReproError("self-test xattr-free member must carry an empty xattr map")

        base_digest = canonical_rootfs_digest(left_entries)
        content_entry = left_entries["etc/identical"]
        content_mutated = dict(left_entries)
        content_bytes_mutated = b"tame"
        content_mutated["etc/identical"] = replace(
            content_entry,
            sha256=hashlib.sha256(content_bytes_mutated).hexdigest(),
            data=content_bytes_mutated,
        )
        if canonical_rootfs_digest(content_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored file content changes")

        mode_mutated = dict(left_entries)
        mode_mutated["etc/identical"] = replace(content_entry, mode=content_entry.mode ^ 0o100)
        if canonical_rootfs_digest(mode_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored mode changes")

        mtime_mutated = dict(left_entries)
        mtime_mutated["etc/identical"] = replace(content_entry, mtime=content_entry.mtime + 1)
        if canonical_rootfs_digest(mtime_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored mtime changes")

        nlink_mutated = dict(left_entries)
        nlink_mutated["usr/bin/python3"] = replace(hardlink_entry, nlink_group="usr/bin/python3-other")
        if canonical_rootfs_digest(nlink_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored hardlink-group changes")
        nlink_compare = compare_entries(left_entries, nlink_mutated)
        nlink_diffs = cast("list[dict[str, Any]]", nlink_compare["differences"])
        if len(nlink_diffs) != 1 or nlink_diffs[0]["classification"] != "hardlink-group-differs":
            raise ReproError(f"self-test hardlink-group classification mismatch: {nlink_diffs}")

        xattr_mutated = dict(left_entries)
        xattr_mutated["etc/xattr"] = replace(xattr_entry, xattrs="security.capability=" + "0" * 64)
        if canonical_rootfs_digest(xattr_mutated) == base_digest:
            raise ReproError("self-test rootfs digest ignored xattr changes")
        xattr_compare = compare_entries(left_entries, xattr_mutated)
        xattr_diffs = cast("list[dict[str, Any]]", xattr_compare["differences"])
        if len(xattr_diffs) != 1 or xattr_diffs[0]["classification"] != "xattrs-differ":
            raise ReproError(f"self-test xattrs classification mismatch: {xattr_diffs}")

        roundtrip_tar = tmp_path / "roundtrip.tar"
        write_rootfs_tar(left_entries, roundtrip_tar)
        if canonical_rootfs_digest(load_tar(roundtrip_tar)) != base_digest:
            raise ReproError("self-test write_rootfs_tar did not preserve hardlink/xattr fidelity")

        facts = rootfs_facts(left_entries)
        rootfs_digest = facts["rootfs_digest"]
        rpmdb_sha256 = facts["rpmdb_sha256"]
        if not isinstance(rootfs_digest, str) or not isinstance(rpmdb_sha256, str):
            raise ReproError("self-test could not compute rootfs facts")

        valid_contract = tmp_path / "contract.valid.json"
        valid_contract.write_text(
            json.dumps(
                {
                    "reproducibility": {
                        "canonical_rootfs_digest": {"amd64": rootfs_digest, "arm64": rootfs_digest},
                        "rpmdb_sha256": {"amd64": rpmdb_sha256, "arm64": rpmdb_sha256},
                    }
                }
            ),
            encoding="utf-8",
        )
        common_args = [
            "--left-tar",
            str(left_tar),
            "--right-tar",
            str(identical_tar),
            "--assert-byte-identical",
            "--report",
            str(tmp_path / "report.json"),
            "--summary",
            str(tmp_path / "summary.txt"),
        ]
        if (
            run_main_silently(
                [
                    *common_args,
                    "--expect-from-contract",
                    str(valid_contract),
                    "--platform",
                    "linux/amd64",
                ]
            )
            != 0
        ):
            raise ReproError("self-test expected contract assertion to pass")

        single_args = [
            "--rootfs-tar",
            str(left_tar),
            "--arch",
            "amd64",
            "--expect-from-contract",
            str(valid_contract),
        ]
        if run_main_silently(single_args) != 0:
            raise ReproError("self-test expected single-rootfs contract assertion to pass")
        print("single-rootfs contract self-test (positive): ok")

        mutated_contract = tmp_path / "contract.mutated.json"
        mutated_contract.write_text(
            json.dumps(
                {
                    "reproducibility": {
                        "canonical_rootfs_digest": {"amd64": rootfs_digest},
                        "rpmdb_sha256": {"amd64": flipped_sha256(rpmdb_sha256)},
                    }
                }
            ),
            encoding="utf-8",
        )
        mutated_args = [
            "--rootfs-tar",
            str(left_tar),
            "--arch",
            "amd64",
            "--expect-from-contract",
            str(mutated_contract),
        ]
        if run_main_silently(mutated_args) == 0:
            raise ReproError("self-test expected mutated single-rootfs contract assertion to fail")
        print("single-rootfs contract self-test (mutated negative): ok")

        if run_main_silently([*common_args, "--expect-rootfs-digest", flipped_sha256(rootfs_digest)]) == 0:
            raise ReproError("self-test expected rootfs digest mismatch to fail")

        if run_main_silently([*common_args, "--expect-from-contract", str(tmp_path / "missing.json")]) == 0:
            raise ReproError("self-test expected missing contract to fail")

        missing_key_contract = tmp_path / "contract.missing-key.json"
        missing_key_contract.write_text(
            json.dumps(
                {
                    "reproducibility": {
                        "canonical_rootfs_digest": {"amd64": rootfs_digest},
                        "rpmdb_sha256": {"amd64": rpmdb_sha256},
                    }
                }
            ),
            encoding="utf-8",
        )
        if (
            run_main_silently(
                [
                    *common_args,
                    "--expect-from-contract",
                    str(missing_key_contract),
                    "--platform",
                    "linux/arm64",
                ]
            )
            == 0
        ):
            raise ReproError("self-test expected missing platform contract key to fail")

        if run_main_silently(["--left-tar", str(left_tar), "--right-tar", str(identical_tar)]) == 0:
            raise ReproError("self-test expected default path resolution without --repo-root to fail")
    print("reproducibility assertion self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assert one exported rootfs against the contract, or build/export two rootfs trees and compare."
    )
    parser.add_argument("--self-test", action="store_true", help="run Docker-free comparison checks")
    parser.add_argument("--assert-byte-identical", action="store_true", help="exit non-zero if any rootfs path differs")
    parser.add_argument("--expect-rootfs-digest", help="exit non-zero unless both rootfs digests match this sha256")
    parser.add_argument(
        "--expect-rpmdb-sha256",
        help="exit non-zero unless both rpmdb.sqlite digests match this sha256",
    )
    parser.add_argument(
        "--expect-from-contract",
        nargs="?",
        const=CONTRACT_DEFAULT,
        type=Path,
        help=f"load expected reproducibility digests from a contract file (default {DEFAULT_CONTRACT_RELATIVE})",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        help="repository root used to resolve default report/workdir/context/dockerfile/contract paths",
    )
    parser.add_argument("--left-tar", type=Path, help="compare an existing left exported rootfs tar")
    parser.add_argument("--right-tar", type=Path, help="compare an existing right exported rootfs tar")
    parser.add_argument("--rootfs-tar", type=Path, help="assert one exported rootfs tar against the contract")
    parser.add_argument("--arch", choices=("amd64", "arm64"), help="contract architecture for --rootfs-tar")
    parser.add_argument(
        "--report",
        type=Path,
        help=f"write JSON diff report (default {DEFAULT_REPORT_RELATIVE_TEMPLATE} under --repo-root)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        help=f"write human-readable report (default {DEFAULT_SUMMARY_RELATIVE_TEMPLATE} under --repo-root)",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        help=f"working directory for rootfs exports (default {DEFAULT_WORKDIR_RELATIVE} under --repo-root)",
    )
    parser.add_argument(
        "--platform", default=os.environ.get("PLATFORM", "linux/amd64"), help="single platform to build and export"
    )
    parser.add_argument("--image-prefix", default=DEFAULT_IMAGE_PREFIX, help="temporary local image name prefix")
    parser.add_argument("--ubi-minimal-image", help="forwarded to the build as --build-arg UBI_MINIMAL_IMAGE")
    parser.add_argument("--base-micro-image", help="forwarded to the build as --build-arg BASE_MICRO_IMAGE")
    parser.add_argument("--progress", default=os.environ.get("BUILDKIT_PROGRESS", "plain"))
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0

        contract = resolve_contract(args)

        if args.rootfs_tar is not None:
            if args.left_tar is not None or args.right_tar is not None:
                raise ReproError("--rootfs-tar cannot be combined with --left-tar or --right-tar")
            if args.arch is None:
                raise ReproError("--arch is required with --rootfs-tar")
            if contract is None:
                raise ReproError("--expect-from-contract is required with --rootfs-tar")
            if args.assert_byte_identical:
                raise ReproError("--assert-byte-identical cannot be combined with --rootfs-tar")
            if args.expect_rootfs_digest is not None or args.expect_rpmdb_sha256 is not None:
                raise ReproError("single-rootfs mode accepts expectations only from --expect-from-contract")
            assert_single_rootfs(args.rootfs_tar, args.arch, contract)
            return 0

        if args.arch is not None:
            raise ReproError("--arch requires --rootfs-tar")

        if bool(args.left_tar) != bool(args.right_tar):
            raise ReproError("--left-tar and --right-tar must be provided together")

        report_path, summary_path = resolve_report_paths(args)
        if args.left_tar and args.right_tar:
            left_tar = args.left_tar
            right_tar = args.right_tar
            builds: list[dict[str, object]] = [
                {"rootfs_tar": str(left_tar)},
                {"rootfs_tar": str(right_tar)},
            ]
        else:
            left_tar, right_tar, builds = build_and_export(args)

        left_entries = load_tar(left_tar)
        right_entries = load_tar(right_tar)
        comparison = compare_entries(left_entries, right_entries)
        add_rootfs_facts(builds, left_entries, right_entries)
        report: dict[str, Any] = {
            "schema_version": 1,
            "mode": "assert" if args.assert_byte_identical else "report",
            "builds": builds,
            **resolved_report_fields(builds, args.platform),
            **comparison,
        }
        write_reports(report, report_path, summary_path)

        assert_expectations(builds, collect_expectations(args, contract))
        if args.assert_byte_identical and not report["byte_identical"]:
            return 1
        return 0
    except ReproError as exc:
        print(f"reproducibility assertion failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
