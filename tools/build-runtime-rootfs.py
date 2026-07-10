#!/usr/bin/env python3
# Purpose: Assemble the production runtime rootfs by applying the protected RPM strip and filesystem trims.
# Role: build
# Micro-container candidate: no - runs inside the discarded rpm-rootfs builder stage and mutates its installroot.
# Build-process: yes - shared package-strip core plus the fail-closed production rootfs build entrypoint.

"""Strip packages and finish the production runtime rootfs."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final

FORBIDDEN_EXECUTABLES: Final = (
    "sh",
    "bash",
    "dash",
    "ash",
    "busybox",
    "ksh",
    "zsh",
    "tcsh",
    "csh",
    "dnf",
    "microdnf",
    "rpm",
    "yum",
)
STRIP_CANDIDATES: Final = (
    "coreutils-single",
    "coreutils",
    "findutils",
    "grep",
    "sed",
    "p11-kit",
    "p11-kit-trust",
    "libsepol",
    "libselinux",
    "gmp",
    "pcre2",
    "pcre",
    "libpcre",
    "ncurses-libs",
    "ncurses-base",
    "libsigsegv",
    "libffi",
    "libtasn1",
    "libacl",
    "libattr",
    "libcap",
    "coreutils-common",
    "pcre2-syntax",
    "alternatives",
)
TRIMMED_EXECUTABLES: Final = (
    "coreutils",
    "find",
    "xargs",
    "grep",
    "sed",
    "p11-kit",
    "trust",
    "ldconfig",
    "localedef",
    "iconv",
    "zic",
    "getconf",
    "alternatives",
    "update-alternatives",
)
EXECUTABLE_DIRS: Final = ("usr/bin", "usr/sbin", "bin", "sbin")
RPM_ARCH_BY_TARGET: Final = {"amd64": "x86_64", "arm64": "aarch64"}


class BuildError(RuntimeError):
    """Raised when a runtime-rootfs invariant is not satisfied."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def _run(
    command: Sequence[str],
    *,
    capture_output: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=True,
        capture_output=capture_output,
        text=True,
        env=env,
    )


def _rpm(rootfs: Path, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return _run(
        ["rpm", f"--root={rootfs}", *arguments],
        capture_output=True,
    )


def _rpm_query(rootfs: Path, package: str) -> bool:
    return (
        subprocess.run(
            ["rpm", f"--root={rootfs}", "-q", package],
            check=False,
            capture_output=True,
            text=True,
        ).returncode
        == 0
    )


def _rpm_output(rootfs: Path, arguments: Sequence[str]) -> str:
    return _rpm(rootfs, arguments).stdout.rstrip("\n")


def _rooted(rootfs: Path, absolute_path: str) -> Path:
    return rootfs / absolute_path.removeprefix("/")


def _is_nonempty_file(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def _remove_path(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        path.unlink(missing_ok=True)
    else:
        shutil.rmtree(path)


def _remove_shell_glob_contents(directory: Path) -> None:
    if not directory.is_dir():
        return
    for child in directory.iterdir():
        if not child.name.startswith("."):
            _remove_path(child)


def _replace_symlink(target: str, link: Path) -> None:
    if os.path.lexists(link):
        _require(not (link.is_dir() and not link.is_symlink()), f"symlink destination is a directory: {link}")
        link.unlink()
    link.symlink_to(target)


def _remove_executables(rootfs: Path, executables: Sequence[str]) -> None:
    for executable in executables:
        for directory in EXECUTABLE_DIRS:
            _rooted(rootfs, f"/{directory}/{executable}").unlink(missing_ok=True)


def _assert_executables_absent(rootfs: Path, executables: Sequence[str], adjective: str) -> None:
    for executable in executables:
        for directory in EXECUTABLE_DIRS:
            if _rooted(rootfs, f"/{directory}/{executable}").exists():
                raise BuildError(f"{adjective} executable '{executable}' survived in runtime rootfs")


def _assert_critical_runtime_files(rootfs: Path) -> None:
    rpmdb_sqlite = _rooted(rootfs, "/var/lib/rpm/rpmdb.sqlite")
    rpmdb_packages = _rooted(rootfs, "/var/lib/rpm/Packages")
    _require(
        _is_nonempty_file(rpmdb_sqlite) or _is_nonempty_file(rpmdb_packages),
        "rpm database missing from rootfs; scanners would see zero packages",
    )
    _require(
        _rooted(rootfs, "/etc/pki/tls/certs/ca-bundle.crt").exists(),
        "RHEL CA bundle path missing from runtime rootfs",
    )
    _require(
        _is_nonempty_file(_rooted(rootfs, "/usr/lib64/ossl-modules/fips.so")),
        "OpenSSL FIPS provider missing from runtime rootfs",
    )
    _require(
        _is_nonempty_file(_rooted(rootfs, "/usr/lib64/libcrypto.so.3")),
        "OpenSSL libcrypto missing from runtime rootfs",
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


def _protected_dependencies(rootfs: Path) -> set[str]:
    objects = (
        _rooted(rootfs, "/usr/lib64/libcrypto.so.3"),
        _rooted(rootfs, "/usr/lib64/libssl.so.3"),
        _rooted(rootfs, "/usr/lib64/ossl-modules/fips.so"),
        _rooted(rootfs, "/usr/lib64/libc.so.6"),
    )
    protected: set[str] = set()
    ldd_env = os.environ.copy()
    ldd_env["LD_LIBRARY_PATH"] = str(_rooted(rootfs, "/usr/lib64"))
    for object_path in objects:
        _require(object_path.exists(), f"required ldd root missing: {object_path}")
        protected.add(str(object_path.resolve(strict=True)))
        ldd = _run(["ldd", str(object_path)], capture_output=True, env=ldd_env)
        for dependency in _ldd_dependencies(ldd.stdout):
            if dependency.startswith(f"{rootfs}/"):
                dependency_path = Path(dependency)
            elif dependency.startswith(("/usr/lib64/", "/lib64/")):
                dependency_path = _rooted(rootfs, dependency)
            else:
                continue
            if dependency_path.exists():
                protected.add(os.path.realpath(dependency_path))

    for pattern in ("usr/lib64/ld-linux*.so.*", "lib64/ld-linux*.so.*"):
        for loader in rootfs.glob(pattern):
            if loader.exists():
                protected.add(os.path.realpath(loader))

    print("ldd-protected FIPS/glibc runtime dependency paths:")
    for path in sorted(protected):
        print(path)
    return protected


def _removable_packages(rootfs: Path, protected: set[str]) -> list[str]:
    removable: list[str] = []
    for candidate in STRIP_CANDIDATES:
        if not _rpm_query(rootfs, candidate):
            continue
        candidate_nevra = _rpm_output(rootfs, ["-q", "--qf", "%{NEVRA}\\n", candidate])
        print(f"strip candidate installed: {candidate_nevra}")
        for owned_path in _rpm_output(rootfs, ["-ql", candidate]).splitlines():
            rooted = Path(f"{rootfs}{owned_path}")
            if not os.path.exists(rooted):  # noqa: PTH110 - must match shell `test -e` symlink semantics.
                continue
            owned_real = os.path.realpath(rooted)
            if owned_real in protected:
                raise BuildError(
                    f"strip candidate {candidate_nevra} owns protected FIPS/glibc runtime dependency {owned_path}"
                )
        removable.append(candidate)
    return removable


def strip_packages(rootfs: Path) -> list[str]:
    """Apply the reusable protected-dependency package strip to an installroot."""
    if _rpm_query(rootfs, "bash"):
        _rpm(rootfs, ["-e", "--nodeps", "--noscripts", "bash"])

    _remove_executables(rootfs, FORBIDDEN_EXECUTABLES)
    _assert_executables_absent(rootfs, FORBIDDEN_EXECUTABLES, "forbidden")
    _assert_critical_runtime_files(rootfs)

    removable = _removable_packages(rootfs, _protected_dependencies(rootfs))
    if removable:
        print(f"removing runtime packages via rpmdb:{' '.join(removable)}")
        _rpm(rootfs, ["-e", "--nodeps", "--noscripts", *removable])
        for removed_package in removable:
            _require(
                not _rpm_query(rootfs, removed_package),
                f"runtime package survived rpm removal: {removed_package}",
            )
    return removable


def _verify_runtime_lock_floor(rootfs: Path, runtime_lockfile: Path) -> None:
    actual_output = _rpm_output(rootfs, ["-qa", "--qf", "%{NEVRA}\\n"])
    actual_nevras = actual_output.splitlines() if actual_output else []
    actual_set = set(actual_nevras)
    expected: list[str] = []
    for line in runtime_lockfile.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        _require(len(fields) == 9, f"runtime lockfile row must contain 9 fields: {line}")
        package, final_rpmdb = fields[:2]
        if final_rpmdb != "yes":
            continue
        expected.append(package)
        if package not in actual_set:
            raise BuildError(
                f"locked final runtime RPM missing after strip: {package}\nactual final runtime RPMs:\n{actual_output}"
            )
    _require(
        len(actual_nevras) == len(expected),
        f"final runtime RPM count mismatch: expected {len(expected)}, got {len(actual_nevras)}\n"
        f"actual final runtime RPMs:\n{actual_output}",
    )
    print(f"final runtime RPM lock floor verified: {len(actual_nevras)} packages")


def _proof_value(fips_proof: Path, name: str) -> str:
    return (fips_proof / name).read_text(encoding="utf-8").rstrip("\n")


def _verify_fips(
    rootfs: Path,
    *,
    fips_proof: Path,
    target_arch: str,
    provider_nevra: str,
    module_version: str,
) -> None:
    rpm_arch = RPM_ARCH_BY_TARGET[target_arch]
    shipped_provider_nevra = _rpm_output(
        rootfs,
        ["-q", "--qf", "%{NEVRA}\\n", "openssl-fips-provider-so"],
    )
    shipped_libs_nevra = _rpm_output(rootfs, ["-q", "--qf", "%{NEVRA}\\n", "openssl-libs"])
    fips_so = _rooted(rootfs, "/usr/lib64/ossl-modules/fips.so")
    shipped_fips_so_sha256 = hashlib.sha256(fips_so.read_bytes()).hexdigest()
    expected_provider_nevra = f"{provider_nevra}.{rpm_arch}"
    verified_provider_nevra = _proof_value(fips_proof, "provider.nevra")
    verified_libs_nevra = _proof_value(fips_proof, "libs.nevra")
    verified_fips_so_sha256 = _proof_value(fips_proof, "fips.so.sha256")
    verified_module_version = _proof_value(fips_proof, "module.version")

    print(f"runtime rootfs openssl-fips-provider-so NEVRA={shipped_provider_nevra}")
    print(f"runtime rootfs openssl-libs NEVRA={shipped_libs_nevra}")
    print(f"runtime rootfs fips.so sha256={shipped_fips_so_sha256}")
    _require(
        verified_provider_nevra == expected_provider_nevra,
        f"verified provider NEVRA does not match pin: {verified_provider_nevra}",
    )
    _require(
        verified_module_version == module_version,
        f"verified module version does not match pin: {verified_module_version}",
    )
    _require(
        shipped_provider_nevra == expected_provider_nevra,
        f"runtime rootfs provider NEVRA does not match pin: {shipped_provider_nevra}",
    )
    _require(
        shipped_provider_nevra == verified_provider_nevra,
        "runtime rootfs provider NEVRA does not match verified stage: "
        f"{shipped_provider_nevra} != {verified_provider_nevra}",
    )
    _require(
        shipped_libs_nevra == verified_libs_nevra,
        "runtime rootfs openssl-libs NEVRA does not match verified stage: "
        f"{shipped_libs_nevra} != {verified_libs_nevra}",
    )
    _require(
        shipped_fips_so_sha256 == verified_fips_so_sha256,
        "runtime rootfs fips.so sha256 does not match verified stage: "
        f"{shipped_fips_so_sha256} != {verified_fips_so_sha256}",
    )


def _extract_first_certificate(bundle: Path, destination: Path) -> None:
    certificate: list[str] = []
    emitting = False
    for line in bundle.read_text(encoding="utf-8").splitlines():
        if "-----BEGIN CERTIFICATE-----" in line:
            emitting = True
        if emitting:
            certificate.append(line)
        if emitting and "-----END CERTIFICATE-----" in line:
            break
    destination.write_text("\n".join(certificate) + ("\n" if certificate else ""), encoding="utf-8")
    _require(_is_nonempty_file(destination), "could not extract a CA certificate for trust verification")


def _trim_ca_trust(rootfs: Path, *, fips_openssl: Path, fips_lib64: Path) -> None:
    pem_bundle = _rooted(rootfs, "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
    _require(_is_nonempty_file(pem_bundle), "TLS CA PEM bundle missing before CA trust trim")
    _remove_shell_glob_contents(_rooted(rootfs, "/usr/share/pki/ca-trust-source"))
    for relative in (
        "/etc/pki/ca-trust/extracted/openssl",
        "/etc/pki/ca-trust/extracted/java",
        "/etc/pki/ca-trust/extracted/edk2",
        "/etc/pki/ca-trust/extracted/email",
        "/etc/pki/ca-trust/extracted/pem/directory-hash",
        "/usr/lib64/engines-3",
    ):
        _remove_path(_rooted(rootfs, relative))
    pem_dir = _rooted(rootfs, "/etc/pki/ca-trust/extracted/pem")
    for pattern in ("objsign*", "email*"):
        for path in pem_dir.glob(pattern):
            _remove_path(path)

    certs = _rooted(rootfs, "/etc/pki/tls/certs")
    if certs.is_dir():
        for path in certs.iterdir():
            if path.name != "ca-bundle.crt":
                _remove_path(path)
    ca_bundle = certs / "ca-bundle.crt"
    _require(ca_bundle.is_symlink(), "CA bundle path must remain a symlink")
    _require(_is_nonempty_file(ca_bundle), "CA bundle symlink target is empty after CA trust trim")

    first_certificate = Path("/tmp/ca-first.pem")
    _extract_first_certificate(pem_bundle, first_certificate)
    verify_env = os.environ.copy()
    verify_env["LD_LIBRARY_PATH"] = str(fips_lib64)
    _run(
        [str(fips_openssl), "verify", "-CAfile", str(ca_bundle), str(first_certificate)],
        env=verify_env,
    )


def _trim_zoneinfo(rootfs: Path) -> None:
    zoneinfo = _rooted(rootfs, "/usr/share/zoneinfo")
    if zoneinfo.is_dir():
        raw_zone_tmp = tempfile.mkdtemp()
        zone_tmp = Path(raw_zone_tmp)
        moved = False
        try:
            (zone_tmp / "Etc").mkdir(parents=True)
            _run(["cp", "-a", str(zoneinfo / "UTC"), str(zone_tmp / "UTC")])
            _run(["cp", "-a", str(zoneinfo / "Etc/UTC"), str(zone_tmp / "Etc/UTC")])
            for leap_file in sorted(zoneinfo.glob("leap*")):
                if leap_file.exists():
                    _run(["cp", "-a", str(leap_file), f"{zone_tmp}/"])
            shutil.rmtree(zoneinfo)
            _rooted(rootfs, "/usr/share").mkdir(parents=True, exist_ok=True)
            zone_tmp.rename(zoneinfo)
            moved = True
        finally:
            if not moved and zone_tmp.exists():
                shutil.rmtree(zone_tmp)

    localtime = _rooted(rootfs, "/etc/localtime")
    _replace_symlink("/usr/share/zoneinfo/UTC", localtime)
    _require((zoneinfo / "UTC").exists(), "UTC zoneinfo missing from runtime rootfs")
    _require((zoneinfo / "Etc/UTC").exists(), "Etc/UTC zoneinfo missing from runtime rootfs")
    _require(str(localtime.readlink()) == "/usr/share/zoneinfo/UTC", "runtime localtime symlink target is invalid")


def _trim_filesystem(rootfs: Path, *, fips_openssl: Path, fips_lib64: Path) -> None:
    for relative in ("usr/bin", "usr/sbin", "usr/lib", "usr/lib64"):
        _rooted(rootfs, f"/{relative}").mkdir(parents=True, exist_ok=True)
    for link, target in (("bin", "usr/bin"), ("sbin", "usr/sbin"), ("lib", "usr/lib"), ("lib64", "usr/lib64")):
        _replace_symlink(target, rootfs / link)
    _require(str((rootfs / "lib64").readlink()) == "usr/lib64", "runtime lib64 symlink target is invalid")

    _run(["ldconfig", "-r", str(rootfs)])
    _require(
        _is_nonempty_file(_rooted(rootfs, "/etc/ld.so.cache")),
        "ld.so.cache was not populated before removing ldconfig",
    )
    _remove_executables(rootfs, ("ldconfig", "localedef", "iconv", "zic", "getconf"))

    locale_dir = _rooted(rootfs, "/usr/lib/locale")
    if locale_dir.is_dir():
        _require((locale_dir / "C.utf8").exists(), "C.utf8 locale missing from runtime rootfs")
        for locale in locale_dir.iterdir():
            if locale.name != "C.utf8":
                _remove_path(locale)

    _trim_ca_trust(rootfs, fips_openssl=fips_openssl, fips_lib64=fips_lib64)
    _remove_shell_glob_contents(_rooted(rootfs, "/var/lib/dnf"))
    for relative in ("/var/lib/rhsm", "/var/lib/alternatives", "/usr/lib/rpm"):
        _remove_path(_rooted(rootfs, relative))
    _remove_shell_glob_contents(_rooted(rootfs, "/var/cache"))

    _trim_zoneinfo(rootfs)
    for relative in ("/usr/share/terminfo", "/etc/terminfo", "/usr/share/crypto-policies"):
        _remove_path(_rooted(rootfs, relative))

    _assert_executables_absent(rootfs, TRIMMED_EXECUTABLES, "trimmed")
    _require(
        not _rooted(rootfs, "/usr/bin/openssl").exists(),
        "runtime rootfs must not include the openssl CLI",
    )
    legacy_provider = _rooted(rootfs, "/usr/lib64/ossl-modules/legacy.so")
    fipsmodule_config = _rooted(rootfs, "/etc/pki/tls/fipsmodule.cnf")
    legacy_provider.unlink(missing_ok=True)
    fipsmodule_config.unlink(missing_ok=True)
    _require(not legacy_provider.exists(), "legacy OpenSSL provider survived in runtime rootfs")
    _require(not fipsmodule_config.exists(), "fipsmodule.cnf survived in runtime rootfs")


def build(
    rootfs: Path,
    *,
    runtime_lockfile: Path,
    fips_proof: Path,
    fips_openssl: Path,
    fips_lib64: Path,
    target_arch: str,
    provider_nevra: str,
    module_version: str,
) -> None:
    """Run the fail-closed production rootfs build after the install transaction."""
    strip_packages(rootfs)
    _verify_runtime_lock_floor(rootfs, runtime_lockfile)
    _verify_fips(
        rootfs,
        fips_proof=fips_proof,
        target_arch=target_arch,
        provider_nevra=provider_nevra,
        module_version=module_version,
    )
    _trim_filesystem(rootfs, fips_openssl=fips_openssl, fips_lib64=fips_lib64)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    strip_parser = subparsers.add_parser("strip-packages", help="apply only the reusable package strip")
    strip_parser.add_argument("--rootfs", type=Path, required=True)

    build_parser = subparsers.add_parser("build", help="finish the production runtime rootfs")
    build_parser.add_argument("--rootfs", type=Path, required=True)
    build_parser.add_argument("--runtime-lockfile", type=Path, required=True)
    build_parser.add_argument("--fips-proof", type=Path, required=True)
    build_parser.add_argument("--fips-openssl", type=Path, required=True)
    build_parser.add_argument("--fips-lib64", type=Path, required=True)
    build_parser.add_argument("--target-arch", choices=tuple(RPM_ARCH_BY_TARGET), required=True)
    build_parser.add_argument("--provider-nevra", required=True)
    build_parser.add_argument("--module-version", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "strip-packages":
            strip_packages(args.rootfs)
        else:
            build(
                args.rootfs,
                runtime_lockfile=args.runtime_lockfile,
                fips_proof=args.fips_proof,
                fips_openssl=args.fips_openssl,
                fips_lib64=args.fips_lib64,
                target_arch=args.target_arch,
                provider_nevra=args.provider_nevra,
                module_version=args.module_version,
            )
    except (BuildError, OSError, subprocess.CalledProcessError) as exc:
        print(f"runtime rootfs build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
