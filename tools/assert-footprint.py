#!/usr/bin/env python3
"""Assert the exported runtime rootfs stays within the H2 footprint ceiling."""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


DEFAULT_LIMIT_BYTES = 25 * 1024 * 1024


class FootprintError(Exception):
    pass


@dataclass(frozen=True)
class Footprint:
    regular_file_bytes: int
    regular_files: int
    hardlinks: int
    symlinks: int
    directories: int
    entries: int

    @property
    def mib(self) -> float:
        return self.regular_file_bytes / (1024 * 1024)


def measure_tar(fileobj: io.BufferedIOBase) -> Footprint:
    regular_file_bytes = 0
    regular_files = 0
    hardlinks = 0
    symlinks = 0
    directories = 0
    entries = 0

    with tarfile.open(fileobj=fileobj, mode="r|*") as archive:
        for member in archive:
            entries += 1
            if member.isfile():
                regular_files += 1
                regular_file_bytes += member.size
            elif member.islnk():
                hardlinks += 1
            elif member.issym():
                symlinks += 1
            elif member.isdir():
                directories += 1

    return Footprint(
        regular_file_bytes=regular_file_bytes,
        regular_files=regular_files,
        hardlinks=hardlinks,
        symlinks=symlinks,
        directories=directories,
        entries=entries,
    )


def run_checked(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise FootprintError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout.strip()


def measure_image(image_ref: str, platform: str | None) -> Footprint:
    create_command = ["docker", "create"]
    if platform:
        create_command.extend(["--platform", platform])
    create_command.extend([image_ref, "/footprint-export"])

    container_id = run_checked(create_command)
    try:
        export = subprocess.Popen(
            ["docker", "export", container_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if export.stdout is None:
            raise FootprintError("docker export did not expose stdout")
        footprint = measure_tar(export.stdout)
        stderr = export.stderr.read().decode("utf-8", errors="replace") if export.stderr else ""
        rc = export.wait()
        if rc != 0:
            raise FootprintError(f"docker export failed ({rc}): {stderr}")
        return footprint
    finally:
        subprocess.run(["docker", "rm", container_id], text=True, capture_output=True, check=False)


def measure_tar_path(path: Path) -> Footprint:
    with path.open("rb") as handle:
        return measure_tar(handle)


def assert_limit(footprint: Footprint, limit_bytes: int) -> None:
    if footprint.regular_file_bytes > limit_bytes:
        raise FootprintError(
            "uncompressed runtime rootfs is "
            f"{footprint.regular_file_bytes} bytes ({footprint.mib:.2f} MiB), "
            f"above limit {limit_bytes} bytes ({limit_bytes / (1024 * 1024):.2f} MiB)"
        )


def write_report(
    output: Path | None,
    footprint: Footprint,
    limit_bytes: int,
    image_ref: str | None,
    platform: str | None,
) -> None:
    report = {
        "image": image_ref,
        "platform": platform,
        "metric": "exported-rootfs-regular-file-bytes",
        "limit_bytes": limit_bytes,
        "limit_mib": round(limit_bytes / (1024 * 1024), 4),
        "passed": footprint.regular_file_bytes <= limit_bytes,
        **asdict(footprint),
        "regular_file_mib": round(footprint.mib, 4),
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "footprint: "
        f"regular_file_bytes={footprint.regular_file_bytes} "
        f"regular_file_mib={footprint.mib:.2f} "
        f"limit_bytes={limit_bytes} "
        f"entries={footprint.entries} "
        f"regular_files={footprint.regular_files}"
    )


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "rootfs.tar"
        with tarfile.open(tar_path, "w") as archive:
            directory = tarfile.TarInfo("etc")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)

            first = b"abc"
            first_info = tarfile.TarInfo("etc/first")
            first_info.size = len(first)
            first_info.mode = 0o644
            archive.addfile(first_info, io.BytesIO(first))

            second = b"12345"
            second_info = tarfile.TarInfo("usr/lib64/second")
            second_info.size = len(second)
            second_info.mode = 0o644
            archive.addfile(second_info, io.BytesIO(second))

            symlink = tarfile.TarInfo("lib64/second-link")
            symlink.type = tarfile.SYMTYPE
            symlink.linkname = "../usr/lib64/second"
            archive.addfile(symlink)

            hardlink = tarfile.TarInfo("usr/lib64/second-hardlink")
            hardlink.type = tarfile.LNKTYPE
            hardlink.linkname = "usr/lib64/second"
            archive.addfile(hardlink)

        footprint = measure_tar_path(tar_path)
        if footprint.regular_file_bytes != 8:
            raise FootprintError(f"self-test byte count mismatch: {footprint.regular_file_bytes}")
        if footprint.regular_files != 2 or footprint.symlinks != 1 or footprint.hardlinks != 1:
            raise FootprintError(f"self-test entry counts mismatch: {footprint}")
        assert_limit(footprint, 8)
        try:
            assert_limit(footprint, 7)
        except FootprintError:
            print("footprint assertion self-test: ok")
            return
        raise FootprintError("negative self-test unexpectedly passed")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail unless an exported runtime rootfs is within the H2 byte ceiling."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--image", help="container image reference to export with docker")
    source.add_argument("--tar", type=Path, help="pre-exported rootfs tar to measure")
    parser.add_argument("--platform", help="optional docker create --platform value")
    parser.add_argument("--limit-bytes", type=int, default=DEFAULT_LIMIT_BYTES)
    parser.add_argument("--output", type=Path, help="write a JSON measurement report")
    parser.add_argument("--self-test", action="store_true", help="run built-in parser checks")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            run_self_test()
            return 0

        if args.image:
            footprint = measure_image(args.image, args.platform)
            image_ref = args.image
        elif args.tar:
            footprint = measure_tar_path(args.tar)
            image_ref = None
        else:
            raise FootprintError("provide --image, --tar, or --self-test")

        assert_limit(footprint, args.limit_bytes)
        write_report(args.output, footprint, args.limit_bytes, image_ref, args.platform)
    except FootprintError as exc:
        print(f"footprint assertion failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))