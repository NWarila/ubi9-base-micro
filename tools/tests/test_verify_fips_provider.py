# Purpose: Validate strict provider parsing, inverted probes, scoped environments, and byte-exact FIPS proof output.
# Role: test
# Micro-container candidate: gate-adjacent - pytest coverage for discarded-stage FIPS provider verification.
# Build-process: no - test-only recorded transcripts and synthetic external executables.

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import runpy
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/verify-fips-provider.py"
PROVIDER_NEVRA = "openssl-fips-provider-so-3.0.7-8.el9"
PROVIDER_FULL_NEVRA = f"{PROVIDER_NEVRA}.x86_64"
LIBS_NEVRA = "openssl-libs-1:3.2.2-6.el9_5.1.x86_64"
MODULE_VERSION = "3.0.7-395c1a240fbfffd8"

FIPS_BLOCK = b"""  fips
    name: Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider
    version: 3.0.7-395c1a240fbfffd8
    status: active
    build info: 3.0.7-395c1a240fbfffd8
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
"""
BASE_BLOCK = b"""  base
    name: OpenSSL Base Provider
    version: 3.0.7
    status: active
    build info: 3.0.7
    gettable provider parameters:
      name: pointer to a UTF8 encoded string (arbitrary size)
      version: pointer to a UTF8 encoded string (arbitrary size)
      buildinfo: pointer to a UTF8 encoded string (arbitrary size)
      status: integer (arbitrary size)
"""
GOLDEN_TRANSCRIPT = b"Providers:\n" + FIPS_BLOCK + BASE_BLOCK

ToolFunction = Callable[..., dict[str, Any]]
TOOL_NAMESPACE = runpy.run_path(str(TOOL))
parse_providers = cast(ToolFunction, TOOL_NAMESPACE["parse_providers"])
validate_provider_transcript = cast(ToolFunction, TOOL_NAMESPACE["validate_provider_transcript"])
VerificationError = cast(type[Exception], TOOL_NAMESPACE["VerificationError"])


@dataclass(frozen=True)
class ToolFixture:
    state: Path
    openssl_log: Path
    modules_dir: Path
    openssl_cnf: Path
    proof_dir: Path
    env: dict[str, str]
    fips_so_sha256: str


def _write_executable(path: Path, source: str) -> None:
    path.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _fake_rpm_source() -> str:
    return r"""
import json
import os
import sys
from pathlib import Path

state = json.loads(Path(os.environ["FAKE_FIPS_STATE"]).read_text(encoding="utf-8"))
if state["rpm_exit"] != 0:
    print("synthetic rpm failure", file=sys.stderr)
    raise SystemExit(state["rpm_exit"])
package = sys.argv[-1]
sys.stdout.write(state["rpm_outputs"].get(package, ""))
"""


def _fake_openssl_source() -> str:
    return r"""
import base64
import json
import os
import sys
from pathlib import Path

state = json.loads(Path(os.environ["FAKE_FIPS_STATE"]).read_text(encoding="utf-8"))
record = {
    "arguments": sys.argv[1:],
    "OPENSSL_CONF": os.environ.get("OPENSSL_CONF"),
    "OPENSSL_MODULES": os.environ.get("OPENSSL_MODULES"),
}
with Path(os.environ["FAKE_OPENSSL_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(record, sort_keys=True) + "\n")

arguments = sys.argv[1:]
if arguments == ["list", "-providers", "-verbose"]:
    sys.stdout.buffer.write(state["provider_output"].encode())
    raise SystemExit(state["provider_list_exit"])
if arguments == ["dgst", "-md5"]:
    sys.stdin.buffer.read()
    sys.stdout.buffer.write(state["md5_output"].encode())
    raise SystemExit(state["md5_exit"])
if arguments == ["dgst", "-sha256"]:
    sys.stdin.buffer.read()
    sys.stdout.buffer.write(state["sha256_output"].encode())
    if state["sha256_exit"] != 0:
        sys.stderr.write("synthetic sha256 failure")
    raise SystemExit(state["sha256_exit"])
if arguments == ["enc", "-aes-256-cbc", "-pbkdf2", "-pass", "pass:test"]:
    sys.stdin.buffer.read()
    sys.stdout.buffer.write(base64.b64decode(state["aes_output"]))
    if state["aes_exit"] != 0:
        sys.stderr.write("synthetic aes failure")
    raise SystemExit(state["aes_exit"])
raise SystemExit(f"unsupported fake openssl arguments: {arguments}")
"""


def _fixture_state() -> dict[str, Any]:
    return {
        "rpm_exit": 0,
        "rpm_outputs": {
            "openssl-fips-provider-so": f"{PROVIDER_FULL_NEVRA}\n",
            "openssl-libs": f"{LIBS_NEVRA}\n",
        },
        "provider_output": GOLDEN_TRANSCRIPT.decode(),
        "provider_list_exit": 0,
        "md5_output": "Error setting digest\nerror:0308010C:digital envelope routines::unsupported",
        "md5_exit": 1,
        "sha256_output": "SHA2-256(stdin)= 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881\n",
        "sha256_exit": 0,
        "aes_output": base64.b64encode(b"Salted__0123456789abcdef01234567").decode(),
        "aes_exit": 0,
    }


@pytest.fixture
def tool_fixture(tmp_path: Path) -> ToolFixture:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(fake_bin / "rpm", _fake_rpm_source())
    _write_executable(fake_bin / "openssl", _fake_openssl_source())

    state = tmp_path / "state.json"
    state.write_text(json.dumps(_fixture_state()), encoding="utf-8")
    openssl_log = tmp_path / "openssl.jsonl"
    openssl_log.write_text("", encoding="utf-8")
    modules_dir = tmp_path / "ossl-modules"
    modules_dir.mkdir()
    fips_so = modules_dir / "fips.so"
    fips_so.write_bytes(b"recorded fips provider fixture\n")
    openssl_cnf = tmp_path / "openssl-fips.cnf"
    openssl_cnf.write_text("openssl_conf = openssl_init\n", encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "FAKE_FIPS_STATE": str(state),
            "FAKE_OPENSSL_LOG": str(openssl_log),
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
        }
    )
    return ToolFixture(
        state=state,
        openssl_log=openssl_log,
        modules_dir=modules_dir,
        openssl_cnf=openssl_cnf,
        proof_dir=tmp_path / "fips-proof",
        env=env,
        fips_so_sha256=hashlib.sha256(fips_so.read_bytes()).hexdigest(),
    )


def _command(fixture: ToolFixture, *, proof_dir: Path | None = None, expected_sha256: str | None = None) -> list[str]:
    return [
        sys.executable,
        str(TOOL),
        "--target-arch",
        "amd64",
        "--provider-nevra",
        PROVIDER_NEVRA,
        "--module-version",
        MODULE_VERSION,
        "--expected-fips-so-sha256",
        expected_sha256 or fixture.fips_so_sha256,
        "--openssl-cnf",
        str(fixture.openssl_cnf),
        "--modules-dir",
        str(fixture.modules_dir),
        "--proof-dir",
        str(proof_dir or fixture.proof_dir),
    ]


def _run(
    fixture: ToolFixture,
    *,
    proof_dir: Path | None = None,
    expected_sha256: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(fixture, proof_dir=proof_dir, expected_sha256=expected_sha256),
        check=False,
        capture_output=True,
        text=True,
        env=fixture.env,
    )


def _mutate_state(fixture: ToolFixture, **changes: Any) -> None:
    state = cast(dict[str, Any], json.loads(fixture.state.read_text(encoding="utf-8")))
    state.update(changes)
    fixture.state.write_text(json.dumps(state), encoding="utf-8")


def test_parser_accepts_real_verbose_shape_and_ignores_nested_names() -> None:
    providers = parse_providers(GOLDEN_TRANSCRIPT)

    assert set(providers) == {"base", "fips"}
    assert providers["fips"].version == MODULE_VERSION
    assert providers["fips"].status == "active"


@pytest.mark.parametrize(
    ("transcript", "message"),
    [
        (b"Providers:\n" + BASE_BLOCK, "required OpenSSL fips provider is missing"),
        (
            GOLDEN_TRANSCRIPT.replace(MODULE_VERSION.encode(), b"3.0.7-version-skew", 1),
            "unexpected OpenSSL FIPS provider module version",
        ),
        (GOLDEN_TRANSCRIPT.replace(b"    status: active", b"    status: inactive", 1), "status is not active"),
        (
            GOLDEN_TRANSCRIPT
            + b"  default\n    name: OpenSSL Default Provider\n    version: 3.0.7\n    status: active\n",
            "default OpenSSL provider unexpectedly active",
        ),
        (b"Providers:\n" + FIPS_BLOCK, "required OpenSSL base provider is missing"),
        (
            GOLDEN_TRANSCRIPT.replace(
                f"    version: {MODULE_VERSION}".encode(),
                f"      version: {MODULE_VERSION}".encode(),
                1,
            ),
            "missing fields: ['version']",
        ),
    ],
)
def test_provider_semantic_mutations_fail(transcript: bytes, message: str) -> None:
    with pytest.raises(VerificationError, match=re.escape(message)):
        validate_provider_transcript(transcript, MODULE_VERSION)


def test_cross_block_version_and_status_cannot_satisfy_fips() -> None:
    fips_without_fields = b"""  fips
    name: Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider
    build info: fixture
"""

    with pytest.raises(VerificationError, match="missing fields"):
        validate_provider_transcript(b"Providers:\n" + fips_without_fields + BASE_BLOCK, MODULE_VERSION)


@pytest.mark.parametrize(
    ("transcript", "message"),
    [
        (GOLDEN_TRANSCRIPT + FIPS_BLOCK, "duplicate OpenSSL provider"),
        (
            GOLDEN_TRANSCRIPT.replace(
                f"    version: {MODULE_VERSION}\n".encode(),
                f"    version: {MODULE_VERSION}\n    version: duplicate\n".encode(),
                1,
            ),
            "duplicate version field",
        ),
        (
            GOLDEN_TRANSCRIPT.replace(
                b"    status: active\n",
                b"    status: active\n    status: active\n",
                1,
            ),
            "duplicate status field",
        ),
        (GOLDEN_TRANSCRIPT.replace(b"  fips\n", b"   fips\n", 1), "malformed OpenSSL provider header"),
    ],
)
def test_structural_provider_mutations_fail(transcript: bytes, message: str) -> None:
    with pytest.raises(VerificationError, match=re.escape(message)):
        parse_providers(transcript)


def test_success_writes_exact_six_file_byte_contract_and_scopes_every_openssl_call(
    tool_fixture: ToolFixture,
) -> None:
    result = _run(tool_fixture)

    assert result.returncode == 0, result.stderr
    state = _fixture_state()
    golden_lines = GOLDEN_TRANSCRIPT.splitlines(keepends=True)
    fips_slice = b"".join(golden_lines[1:10])
    base_slice = b"".join(golden_lines[11:20])
    expected = {
        "provider.nevra": f"{PROVIDER_FULL_NEVRA}\n".encode(),
        "expected-provider.nevra": f"{PROVIDER_FULL_NEVRA}\n".encode(),
        "libs.nevra": f"{LIBS_NEVRA}\n".encode(),
        "fips.so.sha256": f"{tool_fixture.fips_so_sha256}\n".encode(),
        "module.version": f"{MODULE_VERSION}\n".encode(),
        "proof.txt": b"".join(
            [
                f"openssl-fips-provider-so NEVRA={PROVIDER_FULL_NEVRA}\n".encode(),
                f"openssl-libs NEVRA={LIBS_NEVRA}\n".encode(),
                f"openssl-fips-provider-so fips.so sha256={tool_fixture.fips_so_sha256}\n".encode(),
                f"openssl-fips-provider module-version={MODULE_VERSION}\n".encode(),
                fips_slice,
                base_slice,
                b"md5 failure:\n",
                cast(str, state["md5_output"]).encode(),
                b"sha256 success:\n",
                cast(str, state["sha256_output"]).encode(),
                f"aes-256-cbc success bytes={len(base64.b64decode(cast(str, state['aes_output'])))}\n".encode(),
            ]
        ),
    }
    assert {path.name for path in tool_fixture.proof_dir.iterdir()} == set(expected)
    for name, expected_bytes in expected.items():
        assert (tool_fixture.proof_dir / name).read_bytes() == expected_bytes
    assert b"unsupportedsha256 success" in expected["proof.txt"]

    calls = [json.loads(line) for line in tool_fixture.openssl_log.read_text(encoding="utf-8").splitlines()]
    assert len(calls) == 4
    for call in calls:
        assert call["OPENSSL_CONF"] == str(tool_fixture.openssl_cnf)
        assert call["OPENSSL_MODULES"] == str(tool_fixture.modules_dir)


def test_md5_success_is_the_failure_condition(tool_fixture: ToolFixture) -> None:
    _mutate_state(tool_fixture, md5_exit=0)

    result = _run(tool_fixture)

    assert result.returncode != 0
    assert "md5 unexpectedly succeeded under OpenSSL FIPS approved mode" in result.stderr


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"provider_list_exit": 9}, "OpenSSL provider listing failed"),
        ({"sha256_exit": 9}, "OpenSSL SHA-256 probe failed"),
        ({"aes_exit": 9}, "OpenSSL AES-256-CBC probe failed"),
        ({"aes_output": ""}, "produced empty ciphertext"),
    ],
)
def test_openssl_subprocess_failure_classes_fail(
    tool_fixture: ToolFixture,
    changes: dict[str, Any],
    message: str,
) -> None:
    _mutate_state(tool_fixture, **changes)

    result = _run(tool_fixture)

    assert result.returncode != 0
    assert message in result.stderr


def test_rpm_subprocess_failure_fails(tool_fixture: ToolFixture) -> None:
    _mutate_state(tool_fixture, rpm_exit=7)

    result = _run(tool_fixture)

    assert result.returncode != 0
    assert "rpm query failed for openssl-fips-provider-so" in result.stderr


@pytest.mark.parametrize("provider_output", ["", f"{PROVIDER_FULL_NEVRA}\nsecond-row\n"])
def test_rpm_empty_or_multi_row_output_fails(tool_fixture: ToolFixture, provider_output: str) -> None:
    state = _fixture_state()
    rpm_outputs = cast(dict[str, str], state["rpm_outputs"])
    rpm_outputs["openssl-fips-provider-so"] = provider_output
    _mutate_state(tool_fixture, rpm_outputs=rpm_outputs)

    result = _run(tool_fixture)

    assert result.returncode != 0
    assert "must yield exactly one non-empty row" in result.stderr


def test_provider_nevra_skew_fails(tool_fixture: ToolFixture) -> None:
    state = _fixture_state()
    rpm_outputs = cast(dict[str, str], state["rpm_outputs"])
    rpm_outputs["openssl-fips-provider-so"] = f"{PROVIDER_NEVRA}.aarch64\n"
    _mutate_state(tool_fixture, rpm_outputs=rpm_outputs)

    result = _run(tool_fixture)

    assert result.returncode != 0
    assert "unexpected openssl-fips-provider-so NEVRA" in result.stderr


def test_fips_so_sha256_skew_fails(tool_fixture: ToolFixture) -> None:
    result = _run(tool_fixture, expected_sha256="0" * 64)

    assert result.returncode != 0
    assert "unexpected openssl-fips-provider-so fips.so sha256" in result.stderr


def test_proof_directory_write_failure_fails(tool_fixture: ToolFixture, tmp_path: Path) -> None:
    proof_file = tmp_path / "not-a-directory"
    proof_file.write_text("occupied\n", encoding="utf-8")

    result = _run(tool_fixture, proof_dir=proof_file)

    assert result.returncode != 0
    assert "FIPS provider verification failed" in result.stderr
