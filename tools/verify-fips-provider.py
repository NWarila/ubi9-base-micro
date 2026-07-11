#!/usr/bin/env python3
# Purpose: Verify the pinned OpenSSL FIPS provider and emit the discarded-stage proof contract.
# Role: build
# Micro-container candidate: no - runs only in the discarded fips-verify builder stage.
# Build-process: yes - validates installed provider state and emits build-consumed proof files.

"""Verify the OpenSSL FIPS provider and emit its byte-compatible proof."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

RPM_ARCHES = {"amd64": "x86_64", "arm64": "aarch64"}
PROVIDER_HEADER = re.compile(rb"^  ([A-Za-z0-9][A-Za-z0-9_.-]*)$")
PROVIDER_FIELD = re.compile(rb"^    (version|status):[ ](.+)$")
PROOF_FILES = {
    "expected-provider.nevra",
    "fips.so.sha256",
    "libs.nevra",
    "module.version",
    "proof.txt",
    "provider.nevra",
}


class VerificationError(RuntimeError):
    """Raised when installed FIPS provider evidence violates the contract."""


@dataclass(frozen=True)
class ProviderInfo:
    """Parsed fields belonging to one OpenSSL provider block."""

    version: str
    status: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _decoded(value: bytes, name: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{name} is not valid UTF-8") from exc


def parse_providers(transcript: bytes) -> dict[str, ProviderInfo]:
    """Parse provider headers and their own version/status fields without external state."""
    lines = transcript.splitlines()
    _require(bool(lines) and lines[0] == b"Providers:", "OpenSSL provider transcript must start with Providers:")

    providers: dict[str, ProviderInfo] = {}
    current_name: str | None = None
    current_fields: dict[str, str] = {}

    def finish_provider() -> None:
        if current_name is None:
            return
        missing = {"version", "status"} - current_fields.keys()
        _require(not missing, f"OpenSSL provider {current_name!r} missing fields: {sorted(missing)}")
        providers[current_name] = ProviderInfo(
            version=current_fields["version"],
            status=current_fields["status"],
        )

    for line in lines[1:]:
        header = PROVIDER_HEADER.fullmatch(line)
        if header is not None:
            finish_provider()
            name = _decoded(header.group(1), "OpenSSL provider name")
            _require(name not in providers and name != current_name, f"duplicate OpenSSL provider: {name}")
            current_name = name
            current_fields = {}
            continue

        leading_spaces = len(line) - len(line.lstrip(b" "))
        _require(
            not line or leading_spaces == 0 or leading_spaces >= 4,
            f"malformed OpenSSL provider header: {_decoded(line, 'provider transcript line')!r}",
        )
        _require(
            current_name is not None or not line,
            f"unexpected content outside an OpenSSL provider block: {_decoded(line, 'provider transcript line')!r}",
        )
        field = PROVIDER_FIELD.fullmatch(line)
        if field is None:
            continue
        key = _decoded(field.group(1), "OpenSSL provider field")
        value = _decoded(field.group(2), f"OpenSSL provider {key}")
        _require(key not in current_fields, f"duplicate {key} field in OpenSSL provider {current_name!r}")
        current_fields[key] = value

    finish_provider()
    _require(bool(providers), "OpenSSL provider transcript contains no provider blocks")
    return providers


def validate_provider_transcript(transcript: bytes, module_version: str) -> dict[str, ProviderInfo]:
    """Apply the FIPS/base/default and FIPS field assertions to a parsed transcript."""
    providers = parse_providers(transcript)
    _require("fips" in providers, "required OpenSSL fips provider is missing")
    _require("base" in providers, "required OpenSSL base provider is missing")
    _require("default" not in providers, "default OpenSSL provider unexpectedly active")
    fips = providers["fips"]
    _require(
        fips.version == module_version,
        f"unexpected OpenSSL FIPS provider module version: {fips.version}",
    )
    _require(fips.status == "active", f"OpenSSL FIPS provider status is not active: {fips.status}")
    return providers


def raw_provider_slice(transcript: bytes, provider_name: str) -> bytes:
    """Return the provider header plus eight following raw lines, matching grep -A8."""
    lines = transcript.splitlines(keepends=True)
    expected_header = f"  {provider_name}".encode()
    matches = [index for index, line in enumerate(lines) if line.rstrip(b"\r\n") == expected_header]
    _require(len(matches) == 1, f"expected exactly one raw {provider_name} provider header")
    start_index = matches[0]
    return b"".join(lines[start_index : start_index + 9])


def _rpm_nevra(package: str) -> str:
    result = subprocess.run(
        ["rpm", "-q", "--qf", "%{NEVRA}\\n", package],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = _decoded(result.stderr, f"rpm query stderr for {package}").strip()
        raise VerificationError(f"rpm query failed for {package}: {detail or f'exit {result.returncode}'}")
    lines = result.stdout.splitlines()
    _require(len(lines) == 1 and bool(lines[0]), f"rpm query for {package} must yield exactly one non-empty row")
    value = _decoded(lines[0], f"rpm query result for {package}")
    _require(value == value.strip(), f"rpm query for {package} yielded surrounding whitespace")
    return value


def _openssl_env(openssl_cnf: Path, modules_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["OPENSSL_CONF"] = str(openssl_cnf)
    env["OPENSSL_MODULES"] = str(modules_dir)
    return env


def _openssl_combined(
    arguments: Sequence[str],
    *,
    input_bytes: bytes | None,
    openssl_cnf: Path,
    modules_dir: Path,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["openssl", *arguments],
        check=False,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=_openssl_env(openssl_cnf, modules_dir),
    )


def _openssl_split(
    arguments: Sequence[str],
    *,
    input_bytes: bytes,
    openssl_cnf: Path,
    modules_dir: Path,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["openssl", *arguments],
        check=False,
        input=input_bytes,
        capture_output=True,
        env=_openssl_env(openssl_cnf, modules_dir),
    )


def _command_failure(name: str, result: subprocess.CompletedProcess[bytes]) -> VerificationError:
    detail = result.stderr if result.stderr is not None else result.stdout
    rendered = _decoded(detail, f"{name} diagnostic").strip()
    return VerificationError(f"{name} failed: {rendered or f'exit {result.returncode}'}")


def _write_proof(proof_dir: Path, files: Mapping[str, bytes]) -> None:
    _require(set(files) == PROOF_FILES, "internal proof file set does not match the six-file contract")
    proof_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    for name, content in files.items():
        (proof_dir / name).write_bytes(content)

    actual = {entry.name for entry in proof_dir.iterdir()}
    _require(
        actual == PROOF_FILES,
        f"proof directory entries must be exactly {sorted(PROOF_FILES)}; got {sorted(actual)}",
    )
    for name in sorted(PROOF_FILES):
        path = proof_dir / name
        _require(path.is_file() and path.stat().st_size > 0, f"proof file is missing or empty: {path}")


def verify_fips_provider(
    *,
    target_arch: str,
    provider_nevra: str,
    module_version: str,
    expected_fips_so_sha256: str,
    openssl_cnf: Path,
    modules_dir: Path,
    proof_dir: Path,
) -> None:
    """Verify the installed provider, exercise approved mode, and write proof files."""
    rpm_arch = RPM_ARCHES[target_arch]
    expected_provider_nevra = f"{provider_nevra}.{rpm_arch}"
    installed_provider_nevra = _rpm_nevra("openssl-fips-provider-so")
    libs_nevra = _rpm_nevra("openssl-libs")
    _require(
        installed_provider_nevra == expected_provider_nevra,
        f"unexpected openssl-fips-provider-so NEVRA: {installed_provider_nevra}",
    )

    fips_so = modules_dir / "fips.so"
    with fips_so.open("rb") as stream:
        fips_so_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    _require(
        fips_so_sha256 == expected_fips_so_sha256,
        f"unexpected openssl-fips-provider-so fips.so sha256: {fips_so_sha256}",
    )

    provider_list = _openssl_combined(
        ["list", "-providers", "-verbose"],
        input_bytes=None,
        openssl_cnf=openssl_cnf,
        modules_dir=modules_dir,
    )
    if provider_list.returncode != 0:
        raise _command_failure("OpenSSL provider listing", provider_list)
    providers_verbose = provider_list.stdout.rstrip(b"\n") + b"\n"
    providers = validate_provider_transcript(providers_verbose, module_version)

    md5 = _openssl_combined(
        ["dgst", "-md5"],
        input_bytes=b"x",
        openssl_cnf=openssl_cnf,
        modules_dir=modules_dir,
    )
    if md5.returncode == 0:
        raise VerificationError("md5 unexpectedly succeeded under OpenSSL FIPS approved mode")

    sha256 = _openssl_split(
        ["dgst", "-sha256"],
        input_bytes=b"x",
        openssl_cnf=openssl_cnf,
        modules_dir=modules_dir,
    )
    if sha256.returncode != 0:
        raise _command_failure("OpenSSL SHA-256 probe", sha256)

    aes = _openssl_split(
        ["enc", "-aes-256-cbc", "-pbkdf2", "-pass", "pass:test"],
        input_bytes=b"x",
        openssl_cnf=openssl_cnf,
        modules_dir=modules_dir,
    )
    if aes.returncode != 0:
        raise _command_failure("OpenSSL AES-256-CBC probe", aes)
    _require(bool(aes.stdout), "OpenSSL AES-256-CBC probe produced empty ciphertext")

    fips = providers["fips"]
    proof = b"".join(
        [
            f"openssl-fips-provider-so NEVRA={installed_provider_nevra}\n".encode(),
            f"openssl-libs NEVRA={libs_nevra}\n".encode(),
            f"openssl-fips-provider-so fips.so sha256={fips_so_sha256}\n".encode(),
            f"openssl-fips-provider module-version={fips.version}\n".encode(),
            raw_provider_slice(providers_verbose, "fips"),
            raw_provider_slice(providers_verbose, "base"),
            b"md5 failure:\n",
            md5.stdout,
            b"sha256 success:\n",
            sha256.stdout,
            f"aes-256-cbc success bytes={len(aes.stdout)}\n".encode(),
        ]
    )
    _write_proof(
        proof_dir,
        {
            "provider.nevra": f"{installed_provider_nevra}\n".encode(),
            "expected-provider.nevra": f"{expected_provider_nevra}\n".encode(),
            "libs.nevra": f"{libs_nevra}\n".encode(),
            "fips.so.sha256": f"{fips_so_sha256}\n".encode(),
            "module.version": f"{fips.version}\n".encode(),
            "proof.txt": proof,
        },
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-arch", choices=sorted(RPM_ARCHES), required=True)
    parser.add_argument("--provider-nevra", required=True)
    parser.add_argument("--module-version", required=True)
    parser.add_argument("--expected-fips-so-sha256", required=True)
    parser.add_argument("--openssl-cnf", type=Path, required=True)
    parser.add_argument("--modules-dir", type=Path, required=True)
    parser.add_argument("--proof-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        verify_fips_provider(
            target_arch=args.target_arch,
            provider_nevra=args.provider_nevra,
            module_version=args.module_version,
            expected_fips_so_sha256=args.expected_fips_so_sha256,
            openssl_cnf=args.openssl_cnf,
            modules_dir=args.modules_dir,
            proof_dir=args.proof_dir,
        )
    except (OSError, VerificationError) as exc:
        print(f"FIPS provider verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
