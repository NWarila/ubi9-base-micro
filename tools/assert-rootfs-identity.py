#!/usr/bin/env python3
"""Assert identity and file-owner invariants from an exported rootfs tar."""

from __future__ import annotations

import argparse
import io
import json
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

COVERED_RULES = {
    "accounts_no_uid_except_zero": "no_uid0_accounts_except_root",
    "no_files_unowned_by_user": "no_unknown_file_uids",
    "file_permissions_ungroupowned": "no_unknown_file_gids",
}


class RootfsIdentityError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise RootfsIdentityError(message)


def normalized_name(name: str) -> str:
    return name.lstrip("/").removeprefix("./")


def parse_passwd(raw: bytes) -> dict[int, list[str]]:
    users_by_uid: dict[int, list[str]] = {}
    for line_number, raw_line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        require(len(parts) >= 7, f"/etc/passwd line {line_number} is malformed")
        name = parts[0]
        require(name, f"/etc/passwd line {line_number} has an empty account name")
        try:
            uid = int(parts[2])
        except ValueError as exc:
            raise RootfsIdentityError(f"/etc/passwd line {line_number} has non-numeric UID") from exc
        require(uid >= 0, f"/etc/passwd line {line_number} has negative UID")
        users_by_uid.setdefault(uid, []).append(name)
    require(users_by_uid, "/etc/passwd contains no accounts")
    return users_by_uid


def parse_group(raw: bytes) -> set[int]:
    gids: set[int] = set()
    for line_number, raw_line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        require(len(parts) >= 3, f"/etc/group line {line_number} is malformed")
        try:
            gid = int(parts[2])
        except ValueError as exc:
            raise RootfsIdentityError(f"/etc/group line {line_number} has non-numeric GID") from exc
        require(gid >= 0, f"/etc/group line {line_number} has negative GID")
        gids.add(gid)
    require(gids, "/etc/group contains no groups")
    return gids


def read_tar_member(tar: tarfile.TarFile, wanted: str) -> bytes:
    wanted = normalized_name(wanted)
    for member in tar.getmembers():
        if normalized_name(member.name) != wanted:
            continue
        require(member.isfile(), f"/{wanted} is not a regular file in the exported rootfs")
        handle = tar.extractfile(member)
        if handle is None:
            raise RootfsIdentityError(f"unable to read /{wanted} from exported rootfs")
        return handle.read()
    raise RootfsIdentityError(f"exported rootfs is missing /{wanted}")


def assert_identity(rootfs_tar: Path) -> dict[str, Any]:
    require(rootfs_tar.is_file() and rootfs_tar.stat().st_size > 0, f"rootfs tar is missing or empty: {rootfs_tar}")

    with tarfile.open(rootfs_tar, "r:*") as tar:
        members = tar.getmembers()
        require(members, "rootfs tar contains no filesystem entries")
        passwd = parse_passwd(read_tar_member(tar, "etc/passwd"))
        group_gids = parse_group(read_tar_member(tar, "etc/group"))

        uid0_accounts = sorted(passwd.get(0, []))
        require("root" in uid0_accounts, "/etc/passwd must contain root with UID 0")
        unexpected_uid0 = [name for name in uid0_accounts if name != "root"]
        unknown_uid_entries: list[dict[str, int | str]] = []
        unknown_gid_entries: list[dict[str, int | str]] = []

        valid_uids = set(passwd)
        for member in members:
            name = "/" + normalized_name(member.name)
            if member.uid not in valid_uids:
                unknown_uid_entries.append({"path": name, "uid": member.uid})
            if member.gid not in group_gids:
                unknown_gid_entries.append({"path": name, "gid": member.gid})

    require(not unexpected_uid0, "UID 0 is assigned to non-root account(s): " + ", ".join(unexpected_uid0))
    require(
        not unknown_uid_entries,
        "rootfs entries owned by UID(s) absent from /etc/passwd: "
        + json.dumps(unknown_uid_entries[:20], sort_keys=True),
    )
    require(
        not unknown_gid_entries,
        "rootfs entries owned by GID(s) absent from /etc/group: "
        + json.dumps(unknown_gid_entries[:20], sort_keys=True),
    )

    return {
        "coveredRules": sorted(COVERED_RULES),
        "assertions": {
            assertion_id: {"result": "pass", "coveredRules": [rule]}
            for rule, assertion_id in sorted(COVERED_RULES.items())
        },
        "checked": {
            "filesystemEntries": len(members),
            "groupIds": len(group_gids),
            "passwdUids": len(passwd),
            "uid0Accounts": uid0_accounts,
        },
    }


def add_tar_file(tar: tarfile.TarFile, name: str, data: bytes, uid: int = 0, gid: int = 0, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.uid = uid
    info.gid = gid
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


def write_test_tar(path: Path, *, passwd: bytes, group: bytes, file_uid: int = 0, file_gid: int = 0) -> None:
    with tarfile.open(path, "w") as tar:
        add_tar_file(tar, "etc/passwd", passwd, uid=0, gid=0, mode=0o644)
        add_tar_file(tar, "etc/group", group, uid=0, gid=0, mode=0o644)
        add_tar_file(tar, "usr/lib64/libexample.so", b"example\n", uid=file_uid, gid=file_gid, mode=0o644)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        passwd = b"root:x:0:0:root:/root:/sbin/nologin\napp:x:65532:65532:app:/nonexistent:/sbin/nologin\n"
        group = b"root:x:0:\napp:x:65532:\n"

        passing = root / "passing.tar"
        write_test_tar(passing, passwd=passwd, group=group, file_uid=65532, file_gid=65532)
        report = assert_identity(passing)
        require(set(report["coveredRules"]) == set(COVERED_RULES), "self-test coverage mismatch")

        bad_uid0 = root / "bad-uid0.tar"
        write_test_tar(bad_uid0, passwd=passwd + b"toor:x:0:0:root:/root:/sbin/nologin\n", group=group)
        bad_uid = root / "bad-uid.tar"
        write_test_tar(bad_uid, passwd=passwd, group=group, file_uid=12345)
        bad_gid = root / "bad-gid.tar"
        write_test_tar(bad_gid, passwd=passwd, group=group, file_gid=12345)

        for path in [bad_uid0, bad_uid, bad_gid]:
            try:
                assert_identity(path)
            except RootfsIdentityError:
                pass
            else:
                raise AssertionError(f"self-test failed to reject {path.name}")

    print("rootfs identity assertion self-test passed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs-tar", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        if args.self_test:
            self_test()
            return 0
        require(args.rootfs_tar is not None, "--rootfs-tar is required unless --self-test is used")
        report = assert_identity(args.rootfs_tar)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            "rootfs identity assertions passed: "
            f"entries={report['checked']['filesystemEntries']} "
            f"passwd_uids={report['checked']['passwdUids']} "
            f"group_gids={report['checked']['groupIds']}"
        )
        return 0
    except (RootfsIdentityError, tarfile.TarError, UnicodeDecodeError) as exc:
        print(f"rootfs identity assertion failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
