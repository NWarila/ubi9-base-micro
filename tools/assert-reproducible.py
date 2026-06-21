#!/usr/bin/env python3
"""Build twice and compare exported runtime rootfs bytes."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_DATE_EPOCH = "1704067200"
DEFAULT_OCI_CREATED = "2024-01-01T00:00:00Z"
DEFAULT_REPORT = ROOT / "dist/reproducibility/base-micro.amd64.reproducibility.json"
DEFAULT_SUMMARY = ROOT / "dist/reproducibility/base-micro.amd64.reproducibility.txt"
DEFAULT_IMAGE_PREFIX = "local/ubi9-base-micro-repro"


class ReproError(Exception):
    pass


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
    sha256: str | None
    data: bytes | None


def run(command: list[str], *, capture: bool = False) -> str:
    if capture:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        if result.returncode != 0:
            raise ReproError(
                f"command failed ({result.returncode}): {' '.join(command)}\n"
                f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )
        return result.stdout.strip()

    result = subprocess.run(command, cwd=ROOT, text=True, check=False)
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


def load_tar(path: Path) -> dict[str, Entry]:
    entries: dict[str, Entry] = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            normalized = normalize_path(member.name)
            data: bytes | None = None
            digest: str | None = None
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ReproError(f"{path}: could not read regular file {member.name}")
                data = extracted.read()
                digest = hashlib.sha256(data).hexdigest()
            elif member.issym() or member.islnk():
                digest = hashlib.sha256(member.linkname.encode("utf-8")).hexdigest()

            entries[normalized] = Entry(
                path=normalized,
                type=entry_type(member),
                mode=member.mode & 0o7777,
                uid=member.uid,
                gid=member.gid,
                uname=member.uname or "",
                gname=member.gname or "",
                mtime=int(member.mtime),
                size=member.size if member.isfile() else 0,
                linkname=member.linkname or "",
                sha256=digest,
                data=data,
            )
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
                    entries[normalized] = Entry(
                        path=normalized,
                        type=entry_type(member),
                        mode=member.mode & 0o7777,
                        uid=member.uid,
                        gid=member.gid,
                        uname=member.uname or "",
                        gname=member.gname or "",
                        mtime=int(member.mtime),
                        size=member.size if member.isfile() else 0,
                        linkname=member.linkname or "",
                        sha256=digest,
                        data=data,
                    )
    return entries


def write_rootfs_tar(entries: dict[str, Entry], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w") as archive:
        for path in sorted(entries):
            entry = entries[path]
            info = tarfile.TarInfo(path)
            info.mode = entry.mode
            info.uid = entry.uid
            info.gid = entry.gid
            info.uname = entry.uname
            info.gname = entry.gname
            info.mtime = entry.mtime
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


def build_image(tag: str, args: argparse.Namespace, image_tar: Path) -> None:
    image_tar.parent.mkdir(parents=True, exist_ok=True)
    if image_tar.exists():
        image_tar.unlink()
    output = f"type=docker,dest={image_tar},rewrite-timestamp=true"
    command = [
        "docker",
        "buildx",
        "build",
        "--progress",
        args.progress,
        "--no-cache",
        "--platform",
        args.platform,
        "--target",
        "runtime",
        "--build-arg",
        f"SOURCE_DATE_EPOCH={args.source_date_epoch}",
        "--build-arg",
        f"OCI_CREATED={args.oci_created}",
        "--build-arg",
        "OCI_REVISION=reproducibility-harness",
        "--build-arg",
        "OCI_VERSION=dev",
        "--provenance=false",
        "--sbom=false",
        "--file",
        str(args.dockerfile),
        "--tag",
        tag,
        "--output",
        output,
        str(args.context),
    ]
    run(command)


def build_and_export(args: argparse.Namespace) -> tuple[Path, Path, list[dict[str, str]]]:
    workdir = args.workdir
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

    build_image(left_tag, args, left_image_tar)
    write_rootfs_tar(load_image_rootfs(left_image_tar), left_tar)
    build_image(right_tag, args, right_image_tar)
    write_rootfs_tar(load_image_rootfs(right_image_tar), right_tar)
    return (
        left_tar,
        right_tar,
        [
            {"image": left_tag, "image_tar": str(left_image_tar), "rootfs_tar": str(left_tar)},
            {"image": right_tag, "image_tar": str(right_image_tar), "rootfs_tar": str(right_tar)},
        ],
    )


def write_reports(report: dict[str, Any], output: Path, summary_path: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = cast(dict[str, Any], report["summary"])
    differences = cast(list[dict[str, Any]], report["differences"])
    lines = [
        f"byte-identical: {str(report['byte_identical']).lower()}",
        f"total_paths: {summary['total_paths']}",
        f"identical_paths: {summary['identical_paths']}",
        f"differing_paths: {summary['differing_paths']}",
        f"total_differing_bytes: {summary['total_differing_bytes']}",
        f"classification_counts: {json.dumps(summary['classification_counts'], sort_keys=True)}",
        "differences:",
    ]
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


def make_tar(path: Path, entries: list[tuple[str, bytes | None, str, int, int, int, int, str]]) -> None:
    with tarfile.open(path, "w") as archive:
        for name, data, kind, mode, uid, gid, mtime, linkname in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.uid = uid
            info.gid = gid
            info.mtime = mtime
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = linkname
                archive.addfile(info)
            else:
                payload = data or b""
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        left_tar = tmp_path / "left.tar"
        right_tar = tmp_path / "right.tar"
        make_tar(
            left_tar,
            [
                ("etc", None, "directory", 0o755, 0, 0, 10, ""),
                ("etc/identical", b"same", "file", 0o644, 0, 0, 10, ""),
                ("etc/content", b"abcdef", "file", 0o644, 0, 0, 10, ""),
                ("etc/mtime", b"same-time-body", "file", 0o644, 0, 0, 10, ""),
                ("etc/mode", b"same-mode-body", "file", 0o644, 0, 0, 10, ""),
                ("etc/left-only", b"left", "file", 0o644, 0, 0, 10, ""),
                ("lib64/link", None, "symlink", 0o777, 0, 0, 10, "../usr/lib64/libx.so"),
            ],
        )
        make_tar(
            right_tar,
            [
                ("etc", None, "directory", 0o755, 0, 0, 10, ""),
                ("etc/identical", b"same", "file", 0o644, 0, 0, 10, ""),
                ("etc/content", b"abcxef", "file", 0o644, 0, 0, 10, ""),
                ("etc/mtime", b"same-time-body", "file", 0o644, 0, 0, 11, ""),
                ("etc/mode", b"same-mode-body", "file", 0o600, 0, 0, 10, ""),
                ("etc/right-only", b"right", "file", 0o644, 0, 0, 10, ""),
                ("lib64/link", None, "symlink", 0o777, 0, 0, 10, "../usr/lib64/liby.so"),
            ],
        )
        result = compare_entries(load_tar(left_tar), load_tar(right_tar))
        summary = result["summary"]
        assert isinstance(summary, dict)
        if summary["differing_paths"] != 6:
            raise ReproError(f"self-test differing path count mismatch: {summary}")
        classes = summary["classification_counts"]
        assert isinstance(classes, dict)
        expected = {
            "content-differs": 2,
            "mtime-differs": 1,
            "mode-or-owner-differs": 1,
            "present-in-one-only": 2,
        }
        if classes != expected:
            raise ReproError(f"self-test classification mismatch: {classes}")

        identical_tar = tmp_path / "identical.tar"
        shutil.copyfile(left_tar, identical_tar)
        identical = compare_entries(load_tar(left_tar), load_tar(identical_tar))
        if not identical["byte_identical"]:
            raise ReproError("self-test identical tar comparison failed")
    print("reproducibility assertion self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build runtime twice, export rootfs twice, and report byte differences."
    )
    parser.add_argument("--self-test", action="store_true", help="run Docker-free comparison checks")
    parser.add_argument("--assert-byte-identical", action="store_true", help="exit non-zero if any rootfs path differs")
    parser.add_argument("--left-tar", type=Path, help="compare an existing left exported rootfs tar")
    parser.add_argument("--right-tar", type=Path, help="compare an existing right exported rootfs tar")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT, help="write JSON diff report")
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY, help="write human-readable report")
    parser.add_argument(
        "--workdir", type=Path, default=ROOT / "dist/reproducibility/work", help="working directory for rootfs exports"
    )
    parser.add_argument("--context", type=Path, default=ROOT, help="Docker build context")
    parser.add_argument("--dockerfile", type=Path, default=ROOT / "containers/Dockerfile", help="Dockerfile path")
    parser.add_argument(
        "--platform", default=os.environ.get("PLATFORM", "linux/amd64"), help="single platform to build and export"
    )
    parser.add_argument("--image-prefix", default=DEFAULT_IMAGE_PREFIX, help="temporary local image name prefix")
    parser.add_argument("--source-date-epoch", default=os.environ.get("SOURCE_DATE_EPOCH", DEFAULT_SOURCE_DATE_EPOCH))
    parser.add_argument("--oci-created", default=os.environ.get("OCI_CREATED", DEFAULT_OCI_CREATED))
    parser.add_argument("--progress", default=os.environ.get("BUILDKIT_PROGRESS", "plain"))
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0

        if bool(args.left_tar) != bool(args.right_tar):
            raise ReproError("--left-tar and --right-tar must be provided together")
        if args.left_tar and args.right_tar:
            left_tar = args.left_tar
            right_tar = args.right_tar
            builds: list[dict[str, str]] = [
                {"rootfs_tar": str(left_tar)},
                {"rootfs_tar": str(right_tar)},
            ]
        else:
            left_tar, right_tar, builds = build_and_export(args)

        comparison = compare_entries(load_tar(left_tar), load_tar(right_tar))
        report: dict[str, Any] = {
            "schema_version": 1,
            "mode": "assert" if args.assert_byte_identical else "report",
            "platform": args.platform,
            "source_date_epoch": int(args.source_date_epoch),
            "oci_created": args.oci_created,
            "builds": builds,
            **comparison,
        }
        write_reports(report, args.report, args.summary)

        if args.assert_byte_identical and not report["byte_identical"]:
            return 1
        return 0
    except ReproError as exc:
        print(f"reproducibility assertion failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
