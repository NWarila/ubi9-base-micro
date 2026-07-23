# Purpose: Validate runtime-rootfs package stripping, production trims, and fail-closed critical-file guards.
# Role: test
# Micro-container candidate: gate-adjacent - pytest coverage for builder-stage rootfs assembly logic.
# Build-process: no - test-only synthetic installroot and fake external tools.

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tools/build-runtime-rootfs.py"
PROVIDER_NEVRA = "openssl-fips-provider-so-3.0.7-8.el9"
PROVIDER_FULL_NEVRA = f"{PROVIDER_NEVRA}.x86_64"
LIBS_NEVRA = "openssl-libs-1:3.2.2-6.el9_5.1.x86_64"
MODULE_VERSION = "3.0.7-cda111b5812c30d4"


def _load_helper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_runtime_rootfs", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ROOTFS_BUILDER = _load_helper()


@dataclass(frozen=True)
class RuntimeFixture:
    rootfs: Path
    lockfile: Path
    proof: Path
    fips_openssl: Path
    fips_lib64: Path
    state: Path
    mutation_log: Path
    env: dict[str, str]


def _write_executable(path: Path, source: str) -> None:
    path.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
    path.chmod(0o755)


def _write_file(rootfs: Path, relative: str, data: bytes = b"fixture\n", mode: int = 0o644) -> Path:
    path = rootfs / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)
    return path


def _symlink(rootfs: Path, relative: str, target: str) -> Path:
    path = rootfs / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    return path


def _fake_rpm_source() -> str:
    return r"""
import json
import os
import shutil
import sys
from pathlib import Path

state_path = Path(os.environ["FAKE_RPM_STATE"])
log_path = Path(os.environ["FAKE_RPM_MUTATION_LOG"])
state = json.loads(state_path.read_text(encoding="utf-8"))
arguments = sys.argv[1:]
root_argument = next(argument for argument in arguments if argument.startswith("--root="))
rootfs = Path(root_argument.split("=", 1)[1])
rpm_arguments = [argument for argument in arguments if argument != root_argument]

if rpm_arguments[0] == "-q":
    package = rpm_arguments[-1]
    if package not in state:
        raise SystemExit(1)
    if "--qf" in rpm_arguments:
        print(state[package]["nevra"])
    else:
        print(package)
elif rpm_arguments[0] == "-ql":
    package = rpm_arguments[1]
    if package not in state:
        raise SystemExit(1)
    for owned_path in state[package]["files"]:
        print(owned_path)
elif rpm_arguments[0] == "-qa":
    for package in state.values():
        print(package["nevra"])
elif rpm_arguments[0] == "-e":
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(rpm_arguments) + "\n")
    for package_name in rpm_arguments[3:]:
        package = state.pop(package_name, None)
        if package is None:
            raise SystemExit(1)
        for owned_path in package["files"]:
            rooted = rootfs / owned_path.removeprefix("/")
            if rooted.is_symlink() or rooted.is_file():
                rooted.unlink()
            elif rooted.is_dir():
                shutil.rmtree(rooted)
    state_path.write_text(json.dumps(state), encoding="utf-8")
else:
    raise SystemExit(f"unsupported fake rpm arguments: {rpm_arguments}")
"""


def _fake_ldd_source() -> str:
    return r"""
import sys
from pathlib import Path

object_path = Path(sys.argv[-1])
rootfs = str(object_path).split("/usr/lib64/", 1)[0]
print(f"libc.so.6 => {rootfs}/usr/lib64/libc.so.6 (0x00000000)")
print("    /lib64/ld-linux-x86-64.so.2 (0x00000000)")
"""


def _fake_ldconfig_source() -> str:
    return r"""
import sys
from pathlib import Path

rootfs = Path(sys.argv[sys.argv.index("-r") + 1])
cache = rootfs / "etc/ld.so.cache"
cache.parent.mkdir(parents=True, exist_ok=True)
cache.write_bytes(b"synthetic ld.so.cache\n")
cache.chmod(0o644)
"""


def _fake_openssl_source() -> str:
    return r"""
import os
import sys

if os.environ.get("LD_LIBRARY_PATH") != os.environ["EXPECTED_FIPS_LIB64"]:
    raise SystemExit("unexpected LD_LIBRARY_PATH")
if len(sys.argv) != 5 or sys.argv[1] != "verify" or sys.argv[2] != "-CAfile":
    raise SystemExit(f"unexpected verify arguments: {sys.argv[1:]}")
"""


def _runtime_fixture(tmp_path: Path) -> RuntimeFixture:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state_path = tmp_path / "rpm-state.json"
    mutation_log = tmp_path / "rpm-mutations.jsonl"
    mutation_log.write_text("", encoding="utf-8")
    _write_executable(fake_bin / "rpm", _fake_rpm_source())
    _write_executable(fake_bin / "ldd", _fake_ldd_source())
    _write_executable(fake_bin / "ldconfig", _fake_ldconfig_source())

    _write_file(rootfs, "etc/passwd", b"root:x:0:0:root:/root:/sbin/nologin\n", 0o644)
    _write_file(rootfs, "etc/group", b"root:x:0:\n", 0o644)
    _write_file(rootfs, "var/lib/rpm/rpmdb.sqlite", b"rpmdb\n", 0o644)
    _write_file(rootfs, "usr/lib64/libcrypto.so.3", b"libcrypto\n", 0o755)
    _write_file(rootfs, "usr/lib64/libssl.so.3", b"libssl\n", 0o755)
    fips_so = _write_file(rootfs, "usr/lib64/ossl-modules/fips.so", b"fips-provider\n", 0o755)
    _write_file(rootfs, "usr/lib64/ossl-modules/legacy.so", b"legacy\n", 0o755)
    _symlink(rootfs, "usr/lib64/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6")
    _write_file(rootfs, "usr/lib64/ld-linux-x86-64.so.2", b"loader\n", 0o755)
    _symlink(rootfs, "lib64", "usr/lib64")

    pem = b"header\n-----BEGIN CERTIFICATE-----\nfixture-certificate\n-----END CERTIFICATE-----\ntrailer\n"
    _write_file(rootfs, "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", pem, 0o644)
    _symlink(
        rootfs,
        "etc/pki/tls/certs/ca-bundle.crt",
        "../../ca-trust/extracted/pem/tls-ca-bundle.pem",
    )
    _write_file(rootfs, "etc/pki/tls/certs/remove-me.pem")
    _write_file(rootfs, "etc/pki/tls/fipsmodule.cnf")
    for relative in (
        "etc/pki/ca-trust/extracted/openssl/remove",
        "etc/pki/ca-trust/extracted/java/remove",
        "etc/pki/ca-trust/extracted/edk2/remove",
        "etc/pki/ca-trust/extracted/email/remove",
        "etc/pki/ca-trust/extracted/pem/directory-hash/remove",
        "etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem",
        "etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem",
        "usr/share/pki/ca-trust-source/remove",
        "usr/lib64/engines-3/remove",
    ):
        _write_file(rootfs, relative)

    (rootfs / "usr/lib/locale/C.utf8").mkdir(parents=True)
    (rootfs / "usr/lib/locale/C.utf8").chmod(0o755)
    _write_file(rootfs, "usr/lib/locale/C.utf8/LC_CTYPE", mode=0o644)
    _write_file(rootfs, "usr/lib/locale/en_US/remove")
    _write_file(rootfs, "var/lib/dnf/remove")
    _write_file(rootfs, "var/lib/rhsm/remove")
    _write_file(rootfs, "var/lib/alternatives/remove")
    _write_file(rootfs, "usr/lib/rpm/remove")
    _write_file(rootfs, "var/cache/remove")
    _write_file(rootfs, "usr/share/terminfo/remove")
    _write_file(rootfs, "etc/terminfo/remove")
    _write_file(rootfs, "usr/share/crypto-policies/remove")

    _write_file(rootfs, "usr/share/zoneinfo/Etc/UTC", b"UTC\n", 0o640)
    _symlink(rootfs, "usr/share/zoneinfo/UTC", "Etc/UTC")
    _write_file(rootfs, "usr/share/zoneinfo/leapseconds", b"leaps\n", 0o600)
    _symlink(rootfs, "usr/share/zoneinfo/leap-seconds.list", "leapseconds")
    _write_file(rootfs, "usr/share/zoneinfo/America/New_York")

    for executable in ("sh", "grep", "ldconfig", "localedef", "iconv", "zic", "getconf"):
        _write_file(rootfs, f"usr/bin/{executable}", b"executable\n", 0o755)
    _symlink(rootfs, "usr/bin/dangling-owned", "removed-target")

    package_state: dict[str, dict[str, Any]] = {
        "bash": {"nevra": "bash-0:5.1-1.x86_64", "files": ["/usr/bin/sh"]},
        "coreutils-single": {
            "nevra": "coreutils-single-0:9.1-1.x86_64",
            "files": ["/usr/bin/dangling-owned"],
        },
        "grep": {"nevra": "grep-0:3.6-1.x86_64", "files": ["/usr/bin/grep"]},
        "basesystem": {"nevra": "basesystem-0:11-1.noarch", "files": []},
        "openssl-fips-provider-so": {"nevra": PROVIDER_FULL_NEVRA, "files": []},
        "openssl-libs": {"nevra": LIBS_NEVRA, "files": []},
    }
    state_path.write_text(json.dumps(package_state), encoding="utf-8")

    lockfile = tmp_path / "runtime.txt"
    lockfile.write_text(
        "\n".join(
            [
                "# fixture",
                "basesystem-0:11-1.noarch|yes|basesystem|0|11|1|noarch|sha|sig",
                f"{PROVIDER_FULL_NEVRA}|yes|openssl-fips-provider-so|0|3.0.7|8.el9|x86_64|sha|sig",
                f"{LIBS_NEVRA}|yes|openssl-libs|1|3.2.2|6.el9_5.1|x86_64|sha|sig",
                "bash-0:5.1-1.x86_64|no|bash|0|5.1|1|x86_64|sha|sig",
                "coreutils-single-0:9.1-1.x86_64|no|coreutils-single|0|9.1|1|x86_64|sha|sig",
                "grep-0:3.6-1.x86_64|no|grep|0|3.6|1|x86_64|sha|sig",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    proof = tmp_path / "fips-proof"
    proof.mkdir()
    (proof / "provider.nevra").write_text(f"{PROVIDER_FULL_NEVRA}\n", encoding="utf-8")
    (proof / "libs.nevra").write_text(f"{LIBS_NEVRA}\n", encoding="utf-8")
    (proof / "fips.so.sha256").write_text(f"{hashlib.sha256(fips_so.read_bytes()).hexdigest()}\n", encoding="utf-8")
    (proof / "module.version").write_text(f"{MODULE_VERSION}\n", encoding="utf-8")
    fips_lib64 = tmp_path / "fips-lib64"
    fips_lib64.mkdir()
    fips_openssl = tmp_path / "fips-openssl"
    _write_executable(fips_openssl, _fake_openssl_source())
    temp_dir = tmp_path / "tmp"
    temp_dir.mkdir()

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_RPM_STATE"] = str(state_path)
    env["FAKE_RPM_MUTATION_LOG"] = str(mutation_log)
    env["EXPECTED_FIPS_LIB64"] = str(fips_lib64)
    env["TMPDIR"] = str(temp_dir)
    return RuntimeFixture(
        rootfs=rootfs,
        lockfile=lockfile,
        proof=proof,
        fips_openssl=fips_openssl,
        fips_lib64=fips_lib64,
        state=state_path,
        mutation_log=mutation_log,
        env=env,
    )


def _command(fixture: RuntimeFixture, command: str = "build") -> list[str]:
    base = [sys.executable, str(HELPER), command, "--rootfs", str(fixture.rootfs)]
    if command == "strip-packages":
        return base
    return [
        *base,
        "--runtime-lockfile",
        str(fixture.lockfile),
        "--fips-proof",
        str(fixture.proof),
        "--fips-openssl",
        str(fixture.fips_openssl),
        "--fips-lib64",
        str(fixture.fips_lib64),
        "--target-arch",
        "amd64",
        "--provider-nevra",
        PROVIDER_NEVRA,
        "--module-version",
        MODULE_VERSION,
    ]


def _run_fixture(fixture: RuntimeFixture, command: str = "build") -> subprocess.CompletedProcess[str]:
    previous_umask = os.umask(0o022)
    try:
        stdout = io.StringIO()
        stderr = io.StringIO()
        owners: dict[Path, tuple[int, int]] = {}
        actual_owner_ids = cast(
            Callable[[Path], tuple[int, int]],
            ROOTFS_BUILDER._owner_ids,
        )
        actual_run = subprocess.run

        def set_owner(path: Path, uid: int, gid: int) -> None:
            owners[path] = (uid, gid)

        def owner_ids(path: Path) -> tuple[int, int]:
            return owners.get(path, actual_owner_ids(path))

        def run_executable(
            command: list[str],
            *args: Any,
            **kwargs: Any,
        ) -> subprocess.CompletedProcess[str]:
            executable = command[0]
            if executable in {"rpm", "ldd", "ldconfig"}:
                script = Path(fixture.env["PATH"].split(":", 1)[0]) / executable
                command = [sys.executable, str(script), *command[1:]]
            elif executable == str(fixture.fips_openssl):
                command = [sys.executable, executable, *command[1:]]
            return actual_run(command, *args, **kwargs)

        with pytest.MonkeyPatch.context() as monkeypatch:
            for name, value in fixture.env.items():
                monkeypatch.setenv(name, value)
            monkeypatch.setattr(ROOTFS_BUILDER, "_set_owner", set_owner)
            monkeypatch.setattr(ROOTFS_BUILDER, "_owner_ids", owner_ids)
            monkeypatch.setattr(ROOTFS_BUILDER.subprocess, "run", run_executable)
            with redirect_stdout(stdout), redirect_stderr(stderr):
                returncode = ROOTFS_BUILDER.main(_command(fixture, command)[2:])
        return subprocess.CompletedProcess(
            _command(fixture, command),
            returncode,
            stdout.getvalue(),
            stderr.getvalue(),
        )
    finally:
        os.umask(previous_umask)


def _metadata(path: Path) -> tuple[str, int, str]:
    entry_stat = path.lstat()
    mode = stat.S_IMODE(entry_stat.st_mode)
    if stat.S_ISLNK(entry_stat.st_mode):
        return ("symlink", mode, str(path.readlink()))
    if stat.S_ISDIR(entry_stat.st_mode):
        return ("directory", mode, "")
    if stat.S_ISREG(entry_stat.st_mode):
        return ("file", mode, "")
    raise AssertionError(f"unexpected entry type: {path}")


def _mutations(fixture: RuntimeFixture) -> list[list[str]]:
    return [json.loads(line) for line in fixture.mutation_log.read_text(encoding="utf-8").splitlines()]


def _identity_fixture(tmp_path: Path) -> Path:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    _write_file(
        rootfs,
        "etc/passwd",
        b"root:x:0:0:root:/root:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n",
        0o600,
    )
    _write_file(rootfs, "etc/group", b"root:x:0:\nnobody:x:65534:\n", 0o600)
    return rootfs


def _mock_ownership(monkeypatch: pytest.MonkeyPatch) -> dict[Path, tuple[int, int]]:
    owners: dict[Path, tuple[int, int]] = {}
    actual_owner_ids = cast(
        Callable[[Path], tuple[int, int]],
        ROOTFS_BUILDER._owner_ids,
    )

    def set_owner(path: Path, uid: int, gid: int) -> None:
        owners[path] = (uid, gid)

    def owner_ids(path: Path) -> tuple[int, int]:
        return owners.get(path, actual_owner_ids(path))

    monkeypatch.setattr(ROOTFS_BUILDER, "_set_owner", set_owner)
    monkeypatch.setattr(ROOTFS_BUILDER, "_owner_ids", owner_ids)
    return owners


def test_nonroot_identity_creation_is_exact_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rootfs = _identity_fixture(tmp_path)
    owners = _mock_ownership(monkeypatch)

    ROOTFS_BUILDER._ensure_nonroot_identity(rootfs)

    passwd = rootfs / "etc/passwd"
    group = rootfs / "etc/group"
    home = rootfs / "home/nonroot"
    expected_passwd = "nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin"
    expected_group = "nonroot:x:65532:"
    assert passwd.read_text(encoding="utf-8").splitlines() == [
        "root:x:0:0:root:/root:/sbin/nologin",
        "nobody:x:65534:65534:nobody:/:/sbin/nologin",
        expected_passwd,
    ]
    assert group.read_text(encoding="utf-8").splitlines() == [
        "root:x:0:",
        "nobody:x:65534:",
        expected_group,
    ]
    assert stat.S_IMODE(passwd.stat().st_mode) == 0o644
    assert stat.S_IMODE(group.stat().st_mode) == 0o644
    assert home.is_dir()
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    assert owners == {
        passwd: (0, 0),
        group: (0, 0),
        home: (65532, 65532),
    }
    first_state = (
        passwd.read_bytes(),
        group.read_bytes(),
        _metadata(home),
        owners.copy(),
    )

    ROOTFS_BUILDER._ensure_nonroot_identity(rootfs)

    assert (
        passwd.read_bytes(),
        group.read_bytes(),
        _metadata(home),
        owners,
    ) == first_state


@pytest.mark.parametrize(
    ("relative", "conflicting_line", "message"),
    [
        (
            "etc/passwd",
            "other:x:65532:65532:other:/home/other:/sbin/nologin",
            "conflicting runtime account already uses UID 65532",
        ),
        (
            "etc/group",
            "other:x:65532:",
            "conflicting runtime group already uses GID 65532",
        ),
    ],
)
def test_nonroot_identity_rejects_conflicting_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    conflicting_line: str,
    message: str,
) -> None:
    rootfs = _identity_fixture(tmp_path)
    conflict_path = rootfs / relative
    conflict_path.write_text(
        conflict_path.read_text(encoding="utf-8") + f"{conflicting_line}\n",
        encoding="utf-8",
    )
    before = {
        "passwd": (rootfs / "etc/passwd").read_bytes(),
        "group": (rootfs / "etc/group").read_bytes(),
    }
    _mock_ownership(monkeypatch)

    with pytest.raises(ROOTFS_BUILDER.BuildError, match=message):
        ROOTFS_BUILDER._ensure_nonroot_identity(rootfs)

    assert (rootfs / "etc/passwd").read_bytes() == before["passwd"]
    assert (rootfs / "etc/group").read_bytes() == before["group"]
    assert not (rootfs / "home/nonroot").exists()


def test_build_preserves_ordered_rpm_mutations_and_trimmed_tree_metadata(tmp_path: Path) -> None:
    fixture = _runtime_fixture(tmp_path)

    result = _run_fixture(fixture)

    assert result.returncode == 0, result.stderr
    assert _mutations(fixture) == [
        ["-e", "--nodeps", "--noscripts", "bash"],
        ["-e", "--nodeps", "--noscripts", "coreutils-single", "grep"],
    ]
    expected_metadata = {
        "bin": ("symlink", 0o777, "usr/bin"),
        "sbin": ("symlink", 0o777, "usr/sbin"),
        "lib": ("symlink", 0o777, "usr/lib"),
        "lib64": ("symlink", 0o777, "usr/lib64"),
        "etc/localtime": ("symlink", 0o777, "/usr/share/zoneinfo/UTC"),
        "etc/ld.so.cache": ("file", 0o644, ""),
        "etc/pki/tls/certs/ca-bundle.crt": (
            "symlink",
            0o777,
            "../../ca-trust/extracted/pem/tls-ca-bundle.pem",
        ),
        "usr/lib/locale/C.utf8": ("directory", 0o755, ""),
        "usr/share/zoneinfo": ("directory", 0o700, ""),
        "usr/share/zoneinfo/Etc": ("directory", 0o755, ""),
        "usr/share/zoneinfo/Etc/UTC": ("file", 0o640, ""),
        "usr/share/zoneinfo/UTC": ("symlink", 0o777, "Etc/UTC"),
        "usr/share/zoneinfo/leapseconds": ("file", 0o600, ""),
        "usr/share/zoneinfo/leap-seconds.list": ("symlink", 0o777, "leapseconds"),
    }
    assert {relative: _metadata(fixture.rootfs / relative) for relative in expected_metadata} == expected_metadata
    for relative in (
        "usr/bin/sh",
        "usr/bin/grep",
        "usr/bin/dangling-owned",
        "usr/lib/locale/en_US",
        "var/lib/dnf/remove",
        "var/lib/rhsm",
        "var/lib/alternatives",
        "usr/lib/rpm",
        "var/cache/remove",
        "usr/share/zoneinfo/America",
        "usr/share/terminfo",
        "etc/terminfo",
        "usr/share/crypto-policies",
        "usr/lib64/ossl-modules/legacy.so",
        "etc/pki/tls/fipsmodule.cnf",
    ):
        assert not os.path.lexists(fixture.rootfs / relative), relative


@pytest.mark.parametrize(
    ("relative", "message"),
    [
        ("var/lib/rpm/rpmdb.sqlite", "rpm database missing"),
        ("usr/lib64/ossl-modules/fips.so", "OpenSSL FIPS provider missing"),
        ("usr/lib64/libcrypto.so.3", "OpenSSL libcrypto missing"),
    ],
)
def test_build_rejects_empty_critical_file(tmp_path: Path, relative: str, message: str) -> None:
    fixture = _runtime_fixture(tmp_path)
    (fixture.rootfs / relative).write_bytes(b"")

    result = _run_fixture(fixture)

    assert result.returncode != 0
    assert message in result.stderr


def test_strip_packages_keeps_ca_bundle_guard_at_exists_semantics(tmp_path: Path) -> None:
    fixture = _runtime_fixture(tmp_path)
    (fixture.rootfs / "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem").write_bytes(b"")

    result = _run_fixture(fixture, "strip-packages")

    assert result.returncode == 0, result.stderr


def test_strip_packages_rejects_candidate_owned_protected_dependency(tmp_path: Path) -> None:
    fixture = _runtime_fixture(tmp_path)
    state = json.loads(fixture.state.read_text(encoding="utf-8"))
    state["libcap"] = {
        "nevra": "libcap-0:2.48-1.x86_64",
        "files": ["/usr/lib64/libc.so.6"],
    }
    fixture.state.write_text(json.dumps(state), encoding="utf-8")

    result = _run_fixture(fixture, "strip-packages")

    assert result.returncode != 0
    assert "owns protected FIPS/glibc runtime dependency /usr/lib64/libc.so.6" in result.stderr
    assert _mutations(fixture) == [["-e", "--nodeps", "--noscripts", "bash"]]


def test_build_requires_production_cross_check_inputs(tmp_path: Path) -> None:
    fixture = _runtime_fixture(tmp_path)

    result = subprocess.run(
        [sys.executable, str(HELPER), "build", "--rootfs", str(fixture.rootfs)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    for option in ("--runtime-lockfile", "--fips-proof", "--fips-openssl"):
        assert option in result.stderr
