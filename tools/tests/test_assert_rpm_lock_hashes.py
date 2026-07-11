# Purpose: Validate the RPM lock hash gate against synthetic lockfiles, installroots, and fake rpm output.
# Role: test
# Micro-container candidate: gate-adjacent - pytest coverage for the RPM supply-chain assertion.
# Build-process: no - test-only fixtures; an exec-enabled temp directory is required for the fake rpm shim.

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from tools import rpmlock

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "tools/assert-rpm-lock-hashes.py"
PACKAGE = "fixture-1-1.x86_64"
SHA256_HEADER = "1" * 64
SIGMD5 = "a" * 32
RPM_BYTES = b"synthetic signed RPM\n"
RPM_SHA256 = hashlib.sha256(RPM_BYTES).hexdigest()
RPM_FILENAME = "fixture-1-1.x86_64.rpm"
RPM_URL = f"https://cdn-ubi.redhat.com/content/public/ubi/fixture/{RPM_FILENAME}"


@dataclass(frozen=True)
class GateFixture:
    lockfile: Path
    direct_dir: Path
    rpm_path: Path
    state: Path
    log: Path
    env: dict[str, str]

    @property
    def direct_line(self) -> str:
        return f"{rpmlock.DIRECT_PREFIX}{PACKAGE}|{RPM_URL}|{RPM_SHA256}"

    @property
    def row(self) -> str:
        return f"{PACKAGE}|yes|fixture|0|1|1|x86_64|{SHA256_HEADER}|{SIGMD5}"

    @property
    def text(self) -> str:
        return f"{self.direct_line}\n{self.row}\n"


def _write_executable(path: Path, source: str) -> None:
    path.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
    path.chmod(0o755)


def _fake_rpm_source() -> str:
    return r"""
import json
import os
import sys
from pathlib import Path

state = json.loads(Path(os.environ["FAKE_RPM_STATE"]).read_text(encoding="utf-8"))
with Path(os.environ["FAKE_RPM_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
arguments = sys.argv[1:]
if arguments and arguments[0] == "-K":
    response = state["signature"]
else:
    package = arguments[-1]
    response = state["queries"].get(package, {"stdout": "", "returncode": 1})
sys.stdout.write(response["stdout"])
raise SystemExit(response["returncode"])
"""


def _state(*, query_stdout: str = f"{SHA256_HEADER}|{SIGMD5}\n") -> dict[str, Any]:
    return {
        "queries": {PACKAGE: {"stdout": query_stdout, "returncode": 0}},
        "signature": {"stdout": f"{RPM_FILENAME}: digests signatures OK\n", "returncode": 0},
    }


@pytest.fixture
def gate_fixture(tmp_path: Path) -> Iterator[GateFixture]:
    # The harness mounts /tmp noexec. Keep only the disposable executable shim
    # under the exec-capable worktree; lockfiles and RPM blobs remain in tmp_path.
    with tempfile.TemporaryDirectory(prefix=".assert-rpm-test-", dir=ROOT) as executable_directory:
        fake_bin = Path(executable_directory)
        _write_executable(fake_bin / "rpm", _fake_rpm_source())
        state = tmp_path / "rpm-state.json"
        state.write_text(json.dumps(_state()), encoding="utf-8")
        log = tmp_path / "rpm-argv.jsonl"
        log.write_text("", encoding="utf-8")
        direct_dir = tmp_path / "rpms"
        direct_dir.mkdir()
        rpm_path = direct_dir / RPM_FILENAME
        rpm_path.write_bytes(RPM_BYTES)
        lockfile = tmp_path / "runtime.txt"
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
        env["FAKE_RPM_STATE"] = str(state)
        env["FAKE_RPM_LOG"] = str(log)
        fixture = GateFixture(lockfile, direct_dir, rpm_path, state, log, env)
        lockfile.write_text(fixture.text, encoding="utf-8")
        yield fixture


def _command(fixture: GateFixture, *, direct: bool = False, lockfile: Path | None = None) -> list[str]:
    command = [
        sys.executable,
        str(GATE),
        "--root",
        "/fake-root",
        "--lockfile",
        str(lockfile or fixture.lockfile),
    ]
    if direct:
        command.extend(["--direct-rpm-dir", str(fixture.direct_dir)])
    return command


def _run(
    fixture: GateFixture, *, direct: bool = False, lockfile: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(fixture, direct=direct, lockfile=lockfile),
        cwd=ROOT,
        env=fixture.env,
        text=True,
        capture_output=True,
        check=False,
    )


def _write_state(fixture: GateFixture, state: dict[str, Any]) -> None:
    fixture.state.write_text(json.dumps(state), encoding="utf-8")


def test_positive_fixture_prints_exact_counts_and_uses_exact_rpm_argv(gate_fixture: GateFixture) -> None:
    result = _run(gate_fixture)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "runtime RPM content hashes verified with %{SHA256HEADER}/%{SIGMD5}: 1 packages",
        "direct RPM source pins verified from lockfile: 1 packages",
    ]
    assert [json.loads(line) for line in gate_fixture.log.read_text(encoding="utf-8").splitlines()] == [
        ["--root=/fake-root", "-q", "--qf", "%{SHA256HEADER}|%{SIGMD5}\n", PACKAGE]
    ]


def test_direct_rpm_directory_uses_real_file_hash_and_signature_check(gate_fixture: GateFixture) -> None:
    result = _run(gate_fixture, direct=True)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"{RPM_FILENAME}: digests signatures OK",
        "runtime RPM content hashes verified with %{SHA256HEADER}/%{SIGMD5}: 1 packages",
        "direct RPM source pins verified from lockfile: 1 packages",
    ]
    assert [json.loads(line) for line in gate_fixture.log.read_text(encoding="utf-8").splitlines()][1] == [
        "-K",
        str(gate_fixture.rpm_path),
    ]


@pytest.mark.parametrize(
    ("lock_bytes", "message"),
    [
        (b"", "RPM lockfile missing or empty"),
        (None, "RPM lockfile missing or empty"),
    ],
)
def test_rejects_empty_or_missing_lockfile(
    gate_fixture: GateFixture,
    tmp_path: Path,
    lock_bytes: bytes | None,
    message: str,
) -> None:
    lockfile = tmp_path / "missing-or-empty.txt"
    if lock_bytes is not None:
        lockfile.write_bytes(lock_bytes)

    result = _run(gate_fixture, lockfile=lockfile)

    assert result.returncode == 1
    assert message in result.stderr


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda fixture: f"{fixture.direct_line}|\n{fixture.row}\n", "invalid direct RPM entry"),
        (
            lambda fixture: fixture.text.replace("https://cdn-ubi.redhat.com/", "https://example.invalid/", 1),
            "direct RPM source must be cdn-ubi.redhat.com",
        ),
        (lambda fixture: fixture.text.replace(RPM_SHA256, "g" * 64, 1), "invalid direct RPM sha256"),
        (
            lambda fixture: f"{fixture.direct_line}\n{fixture.direct_line}\n{fixture.row}\n",
            "duplicate direct RPM entry",
        ),
        (lambda fixture: f"{fixture.direct_line}\n{fixture.row}|\n", "too many columns"),
        (lambda fixture: fixture.text.replace("|yes|", "||", 1), "empty field in row"),
        (lambda fixture: fixture.text.replace(SHA256_HEADER, "1" * 63, 1), "invalid SHA256HEADER"),
        (lambda fixture: fixture.text.replace(SIGMD5, "a" * 31, 1), "invalid SIGMD5"),
        (lambda fixture: f"{fixture.row}\n", f"missing direct RPM source pin for {PACKAGE}"),
        (lambda fixture: f"{fixture.row}\n{fixture.direct_line}\n", "direct RPM source pin must precede package row"),
        (
            lambda fixture: fixture.text.replace(RPM_FILENAME, "wrong-1-1.x86_64.rpm", 1),
            "direct RPM URL filename mismatch",
        ),
        (lambda fixture: fixture.text.removesuffix("\n"), "RPM lockfile must end with a line feed"),
    ],
)
def test_rejects_lock_grammar_and_cross_row_failures(
    gate_fixture: GateFixture,
    mutate: Any,
    message: str,
) -> None:
    gate_fixture.lockfile.write_text(mutate(gate_fixture), encoding="utf-8")

    result = _run(gate_fixture)

    assert result.returncode == 1
    assert message in result.stderr


def test_rejects_lockfile_without_package_rows(gate_fixture: GateFixture) -> None:
    gate_fixture.lockfile.write_text("# comment only\n", encoding="utf-8")

    result = _run(gate_fixture)

    assert result.returncode == 1
    assert "lockfile has no package rows" in result.stderr


def test_rejects_named_orphan_before_aggregate_count(gate_fixture: GateFixture) -> None:
    orphan = (
        f"{rpmlock.DIRECT_PREFIX}orphan-1-1.noarch|"
        "https://cdn-ubi.redhat.com/content/public/ubi/fixture/orphan-1-1.noarch.rpm|"
        f"{'2' * 64}"
    )
    gate_fixture.lockfile.write_text(f"{gate_fixture.direct_line}\n{orphan}\n{gate_fixture.row}\n", encoding="utf-8")

    result = _run(gate_fixture)

    assert result.returncode == 1
    assert "direct RPM entry has no matching package row: orphan-1-1.noarch" in result.stderr
    assert "expected 1 direct RPM pins" not in result.stderr


def test_duplicate_package_row_preserves_legacy_gate_behavior(gate_fixture: GateFixture) -> None:
    gate_fixture.lockfile.write_text(
        f"{gate_fixture.direct_line}\n{gate_fixture.row}\n{gate_fixture.row}\n",
        encoding="utf-8",
    )

    result = _run(gate_fixture)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "runtime RPM content hashes verified with %{SHA256HEADER}/%{SIGMD5}: 2 packages",
        "direct RPM source pins verified from lockfile: 1 packages",
    ]


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ({"stdout": "", "returncode": 1}, "locked RPM missing from installroot after transaction"),
        ({"stdout": f"{SHA256_HEADER}{SIGMD5}\n", "returncode": 0}, "unexpected RPM hash query output"),
        (
            {"stdout": f"{SHA256_HEADER}|{SIGMD5}\nextra\n", "returncode": 0},
            "unexpected RPM hash query output",
        ),
        ({"stdout": f"{'2' * 64}|{SIGMD5}\n", "returncode": 0}, "SHA256HEADER mismatch"),
        ({"stdout": f"{SHA256_HEADER}|{'b' * 32}\n", "returncode": 0}, "SIGMD5 mismatch"),
    ],
)
def test_rejects_installed_rpm_query_failures(
    gate_fixture: GateFixture,
    query: dict[str, Any],
    message: str,
) -> None:
    state = _state()
    state["queries"][PACKAGE] = query
    _write_state(gate_fixture, state)

    result = _run(gate_fixture)

    assert result.returncode == 1
    assert message in result.stderr


def test_query_output_normalization_matches_shell_command_substitution(gate_fixture: GateFixture) -> None:
    _write_state(gate_fixture, _state(query_stdout=f"{SHA256_HEADER}|{SIGMD5}\n\n\n"))

    result = _run(gate_fixture)

    assert result.returncode == 0, result.stderr


def test_rejects_missing_or_empty_direct_rpm_file(gate_fixture: GateFixture) -> None:
    gate_fixture.rpm_path.unlink()
    missing = _run(gate_fixture, direct=True)
    gate_fixture.rpm_path.write_bytes(b"")
    empty = _run(gate_fixture, direct=True)

    assert missing.returncode == 1
    assert empty.returncode == 1
    assert "direct RPM file missing or empty" in missing.stderr
    assert "direct RPM file missing or empty" in empty.stderr


def test_rejects_direct_rpm_sha256_mismatch(gate_fixture: GateFixture) -> None:
    gate_fixture.rpm_path.write_bytes(b"mutated RPM\n")

    result = _run(gate_fixture, direct=True)

    assert result.returncode == 1
    assert f"direct RPM sha256 mismatch for {PACKAGE}" in result.stderr


@pytest.mark.parametrize(
    ("signature", "message"),
    [
        ({"stdout": f"{RPM_FILENAME}: NOT OK\n", "returncode": 0}, "direct RPM GPG verification failed"),
        (
            {"stdout": f"{RPM_FILENAME}: digests signatures OK\n", "returncode": 7},
            "rpm -K exited 7",
        ),
    ],
)
def test_rejects_rpm_signature_failures(
    gate_fixture: GateFixture,
    signature: dict[str, Any],
    message: str,
) -> None:
    state = _state()
    state["signature"] = signature
    _write_state(gate_fixture, state)

    result = _run(gate_fixture, direct=True)

    assert result.returncode == 1
    assert message in result.stderr


def test_self_test_covers_positive_and_installed_hash_mutation() -> None:
    result = subprocess.run(
        [sys.executable, str(GATE), "--self-test"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "RPM lock hash assertion self-test: ok (positive fixture and installed hash mutation)\n"
