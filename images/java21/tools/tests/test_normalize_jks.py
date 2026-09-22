from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import pytest

SCRIPT = Path(__file__).parents[1] / "normalize_jks.py"
SPEC = importlib.util.spec_from_file_location("normalize_jks", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
normalize_jks = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = normalize_jks
SPEC.loader.exec_module(normalize_jks)

MAGIC = 0xFEEDFEED
VERSION = 2
SALT = b"Mighty Aphrodite"
TRAILER_LENGTH = 20
DEFAULT_EPOCH = 1_704_067_200
SEEDED_BYTES = b"pre-existing destination\n"
SEEDED_MTIME_NS = 946_684_800_123_456_789


@dataclass(frozen=True)
class Entry:
    alias: bytes
    timestamp: int
    certificate: bytes
    certificate_type: bytes = b"X.509"
    tag: int = 2


@dataclass(frozen=True)
class ParsedEntry:
    alias: bytes
    timestamp: int
    certificate_type: bytes
    certificate: bytes


@dataclass(frozen=True)
class ParsedStore:
    version: int
    count: int
    entries: tuple[ParsedEntry, ...]


@dataclass(frozen=True)
class Snapshot:
    content: bytes
    mode: int
    mtime_ns: int


def jks_digest(password: str, body: bytes) -> bytes:
    return hashlib.sha1(password.encode("utf-16-be") + SALT + body).digest()


def encode_entry(entry: Entry) -> bytes:
    if entry.tag != 2:
        return struct.pack(">I", entry.tag)
    return b"".join(
        (
            struct.pack(">IH", entry.tag, len(entry.alias)),
            entry.alias,
            struct.pack(">qH", entry.timestamp, len(entry.certificate_type)),
            entry.certificate_type,
            struct.pack(">I", len(entry.certificate)),
            entry.certificate,
        )
    )


def seal_body(body: bytes, password: str = "changeit") -> bytes:
    return body + jks_digest(password, body)


def build_store(
    entries: list[Entry],
    *,
    password: str = "changeit",
    magic: int = MAGIC,
    version: int = VERSION,
    count: int | None = None,
    extra_body: bytes = b"",
) -> bytes:
    declared_count = len(entries) if count is None else count
    body = struct.pack(">III", magic, version, declared_count)
    body += b"".join(encode_entry(entry) for entry in entries)
    body += extra_body
    return seal_body(body, password)


def entries(count: int, *, timestamp: int = 42) -> list[Entry]:
    return [
        Entry(
            alias=f"certificate-{index:06d}".encode(),
            timestamp=timestamp + index,
            certificate=b"opaque-certificate-" + struct.pack(">I", index),
        )
        for index in range(count)
    ]


def snapshot(path: Path) -> Snapshot:
    details = path.stat()
    return Snapshot(path.read_bytes(), stat.S_IMODE(details.st_mode), details.st_mtime_ns)


def seed_destination(path: Path) -> Snapshot:
    path.write_bytes(SEEDED_BYTES)
    path.chmod(0o600)
    os.utime(path, ns=(SEEDED_MTIME_NS, SEEDED_MTIME_NS))
    return snapshot(path)


def parse_store_independently(raw: bytes, password: str) -> ParsedStore:
    """Parse a JKS container without calling any production parsing code."""
    assert len(raw) >= 12 + TRAILER_LENGTH
    body, trailer = raw[:-TRAILER_LENGTH], raw[-TRAILER_LENGTH:]
    assert trailer == jks_digest(password, body)
    magic, version, count = struct.unpack_from(">III", body)
    assert magic == MAGIC
    assert version == VERSION
    offset = 12
    parsed: list[ParsedEntry] = []
    for _ in range(count):
        tag = struct.unpack_from(">I", body, offset)[0]
        assert tag == 2
        offset += 4
        alias_length = struct.unpack_from(">H", body, offset)[0]
        offset += 2
        alias = body[offset : offset + alias_length]
        assert len(alias) == alias_length
        offset += alias_length
        timestamp = struct.unpack_from(">q", body, offset)[0]
        offset += 8
        type_length = struct.unpack_from(">H", body, offset)[0]
        offset += 2
        certificate_type = body[offset : offset + type_length]
        assert len(certificate_type) == type_length
        offset += type_length
        certificate_length = struct.unpack_from(">I", body, offset)[0]
        offset += 4
        certificate = body[offset : offset + certificate_length]
        assert len(certificate) == certificate_length
        offset += certificate_length
        parsed.append(ParsedEntry(alias, timestamp, certificate_type, certificate))
    assert offset == len(body)
    return ParsedStore(version, count, tuple(parsed))


def assert_exact_transform(source: bytes, output: bytes, epoch: int, password: str) -> None:
    source_store = parse_store_independently(source, password)
    output_store = parse_store_independently(output, password)
    assert output_store.version == source_store.version
    assert output_store.count == source_store.count
    assert [entry.alias for entry in output_store.entries] == [entry.alias for entry in source_store.entries]
    assert [entry.certificate_type for entry in output_store.entries] == [
        entry.certificate_type for entry in source_store.entries
    ]
    assert [entry.certificate for entry in output_store.entries] == [
        entry.certificate for entry in source_store.entries
    ]
    assert {entry.timestamp for entry in output_store.entries} == {epoch * 1000}


def invoke(
    tmp_path: Path,
    source: bytes,
    *,
    epoch: str | None = str(DEFAULT_EPOCH),
    min_entries: str | None = "1",
    password: str = "changeit",
    expect_success: bool,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source_path = tmp_path / "source.jks"
    destination = tmp_path / "destination.jks"
    source_path.write_bytes(source)
    before = seed_destination(destination)
    command = [sys.executable, str(SCRIPT), str(source_path), str(destination)]
    if epoch is not None:
        command.extend(("--epoch", epoch))
    if min_entries is not None:
        command.extend(("--min-entries", min_entries))
    if password != "changeit":
        command.extend(("--password", password))
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert "Traceback" not in result.stderr
    if expect_success:
        assert result.returncode == 0, result.stderr
        assert result.stderr == ""
        assert result.stdout.startswith("normalized ")
        assert epoch is not None
        assert_exact_transform(source, destination.read_bytes(), int(epoch), password)
    else:
        assert result.returncode != 0
        assert result.stderr
        assert snapshot(destination) == before
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))
    return result, destination


def malformed_alias_length_store() -> bytes:
    body = struct.pack(">III", MAGIC, VERSION, 1)
    body += struct.pack(">IH", 2, 0xFFFF)
    return seal_body(body)


def malformed_certificate_length_store() -> bytes:
    alias = b"alias"
    body = struct.pack(">III", MAGIC, VERSION, 1)
    body += struct.pack(">IH", 2, len(alias)) + alias
    body += struct.pack(">qH", 10, len(b"X.509")) + b"X.509"
    body += struct.pack(">I", 0xFFFFFFFF)
    return seal_body(body)


@pytest.mark.parametrize(
    ("name", "source", "min_entries", "message"),
    [
        ("empty-valid", build_store([]), "1", "store holds 0 entries"),
        (
            "bad-input-trailer",
            build_store(entries(1))[:-1] + b"\x00",
            "1",
            "input integrity check failed",
        ),
        ("bad-magic", build_store(entries(1), magic=0xDEADBEEF), "1", "not a JKS store"),
        ("bad-version", build_store(entries(1), version=9), "1", "unsupported JKS version 9"),
        (
            "private-key-entry",
            build_store([Entry(b"", 0, b"", tag=1)]),
            "1",
            "private-key entry found",
        ),
        (
            "certificate-type-not-x509",
            build_store([Entry(b"alias", 1, b"certificate", b"PGP")]),
            "1",
            "unexpected certificate type",
        ),
        (
            "alias-length-overflow",
            malformed_alias_length_store(),
            "1",
            "truncated alias or creation date",
        ),
        (
            "certificate-length-overflow",
            malformed_certificate_length_store(),
            "1",
            "truncated certificate body",
        ),
        (
            "count-lower-than-actual",
            build_store(entries(2), count=1),
            "1",
            "trailing bytes after 1 entries",
        ),
        (
            "count-higher-than-actual",
            build_store(entries(1), count=2),
            "1",
            "entry 1: truncated before tag",
        ),
        (
            "one-trailing-byte-after-sealed-store",
            build_store(entries(1)) + b"\x00",
            "1",
            "input integrity check failed",
        ),
        (
            "duplicate-alias",
            build_store(
                [
                    Entry(b"duplicate", 1, b"first"),
                    Entry(b"duplicate", 2, b"second"),
                ]
            ),
            "1",
            "duplicate decoded alias",
        ),
        (
            "non-utf8-alias-bytes",
            build_store([Entry(b"\x80", 1, b"certificate")]),
            "1",
            "invalid modified UTF-8",
        ),
        (
            "entry-count-below-minimum",
            build_store(entries(1)),
            "2",
            "store holds 1 entries",
        ),
        (
            "alias-byte-ff",
            build_store([Entry(b"\xff", 1, b"certificate")]),
            "1",
            "invalid modified UTF-8",
        ),
        (
            "identical-decoded-aliases",
            build_store(
                [
                    Entry(b"\xc0\x80", 1, b"first"),
                    Entry(b"\xc0\x80", 2, b"second"),
                ]
            ),
            "1",
            "duplicate decoded alias",
        ),
        (
            "unknown-entry-tag",
            build_store([Entry(b"", 0, b"", tag=3)]),
            "1",
            "unsupported JKS entry tag 3",
        ),
    ],
    ids=[
        "empty-valid",
        "bad-input-trailer",
        "bad-magic",
        "bad-version",
        "private-key-entry",
        "certificate-type-not-x509",
        "alias-length-overflow",
        "certificate-length-overflow",
        "count-lower-than-actual",
        "count-higher-than-actual",
        "one-trailing-byte-after-sealed-store",
        "duplicate-alias",
        "non-utf8-alias-bytes",
        "entry-count-below-minimum",
        "alias-byte-ff",
        "identical-decoded-aliases",
        "unknown-entry-tag",
    ],
)
def test_rejection_matrix(tmp_path: Path, name: str, source: bytes, min_entries: str, message: str) -> None:
    del name
    result, _ = invoke(tmp_path, source, min_entries=min_entries, expect_success=False)
    assert message in result.stderr


@pytest.mark.parametrize(
    ("name", "source", "expected_count"),
    [
        ("one-entry-valid", build_store(entries(1)), 1),
        ("constructed-146-entry-store", build_store(entries(146)), 146),
        (
            "modified-utf8-nul-alias",
            build_store([Entry(b"\xc0\x80", 9, b"opaque")]),
            1,
        ),
    ],
    ids=["one-entry-valid", "constructed-146-entry-store", "modified-utf8-nul-alias"],
)
def test_acceptance_matrix(tmp_path: Path, name: str, source: bytes, expected_count: int) -> None:
    del name
    result, _ = invoke(tmp_path, source, expect_success=True)
    assert f"normalized {expected_count} entries" in result.stdout


def test_every_proper_prefix_is_rejected_cleanly(tmp_path: Path) -> None:
    valid = build_store(entries(1))
    messages: set[str] = set()
    for length in range(len(valid)):
        result, _ = invoke(tmp_path, valid[:length], expect_success=False)
        messages.add(result.stderr.strip())
    assert messages


@pytest.mark.parametrize(
    "alias",
    [
        b"\x00",
        b"\x80",
        b"\xc0",
        b"\xc0\x81",
        b"\xc2A",
        b"\xe0\x80\x80",
        b"\xe1\x80",
        b"\xe1\x80A",
        b"\xf0\x90\x80\x80",
        b"\xff",
    ],
)
def test_invalid_modified_utf8_aliases_are_rejected(tmp_path: Path, alias: bytes) -> None:
    source = build_store([Entry(alias, 1, b"certificate")])
    result, _ = invoke(tmp_path, source, expect_success=False)
    assert "invalid modified UTF-8" in result.stderr or "overlong modified UTF-8" in result.stderr


def test_locale_case_equivalence_is_not_claimed(tmp_path: Path) -> None:
    source = build_store([Entry(b"Alias", 1, b"first"), Entry(b"alias", 2, b"second")])
    invoke(tmp_path, source, expect_success=True)


@pytest.mark.parametrize(
    ("epoch", "min_entries", "argument", "message"),
    [
        ("-1", "1", "--epoch", "between 0 and 4102444800"),
        ("not-an-integer", "1", "--epoch", "must be an integer"),
        ("4102444801", "1", "--epoch", "between 0 and 4102444800"),
        (str(DEFAULT_EPOCH), "0", "--min-entries", "between 1 and 100000"),
        (str(DEFAULT_EPOCH), "-1", "--min-entries", "between 1 and 100000"),
        (str(DEFAULT_EPOCH), "not-an-integer", "--min-entries", "must be an integer"),
        (str(DEFAULT_EPOCH), "100001", "--min-entries", "between 1 and 100000"),
    ],
)
def test_illegal_numeric_cli_values_are_usage_errors(
    tmp_path: Path,
    epoch: str,
    min_entries: str,
    argument: str,
    message: str,
) -> None:
    result, _ = invoke(
        tmp_path,
        build_store(entries(1)),
        epoch=epoch,
        min_entries=min_entries,
        expect_success=False,
    )
    assert result.returncode == 2
    assert f"argument {argument}" in result.stderr
    assert message in result.stderr


def test_epoch_zero_is_accepted(tmp_path: Path) -> None:
    _, destination = invoke(tmp_path, build_store(entries(1)), epoch="0", expect_success=True)
    assert destination.stat().st_mtime_ns == 0


def test_epoch_upper_bound_is_accepted(tmp_path: Path) -> None:
    _, destination = invoke(
        tmp_path,
        build_store(entries(1)),
        epoch="4102444800",
        expect_success=True,
    )
    assert destination.stat().st_mtime_ns == 4_102_444_800_000_000_000


def test_minimum_entries_upper_bound_is_a_legal_value(tmp_path: Path) -> None:
    result, _ = invoke(
        tmp_path,
        build_store(entries(1)),
        min_entries="100000",
        expect_success=False,
    )
    assert result.returncode == 1
    assert "store holds 1 entries, below the required floor of 100000" in result.stderr


@pytest.mark.parametrize(
    ("epoch", "min_entries", "missing"),
    [
        (None, "1", "--epoch"),
        (str(DEFAULT_EPOCH), None, "--min-entries"),
        (None, None, "--epoch, --min-entries"),
    ],
)
def test_required_numeric_flags_are_enforced(
    tmp_path: Path, epoch: str | None, min_entries: str | None, missing: str
) -> None:
    result, _ = invoke(
        tmp_path,
        build_store(entries(1)),
        epoch=epoch,
        min_entries=min_entries,
        expect_success=False,
    )
    assert result.returncode == 2
    assert f"the following arguments are required: {missing}" in result.stderr


def test_timestamp_only_variance_normalizes_to_identical_bytes(tmp_path: Path) -> None:
    first = build_store(entries(3, timestamp=100))
    second = build_store(entries(3, timestamp=900_000))
    _, first_output = invoke(tmp_path / "first", first, expect_success=True)
    _, second_output = invoke(tmp_path / "second", second, expect_success=True)
    assert first_output.read_bytes() == second_output.read_bytes()


def test_invalid_input_trailer_is_not_resealed(tmp_path: Path) -> None:
    valid = build_store(entries(1))
    corrupt = valid[:-1] + bytes((valid[-1] ^ 0xFF,))
    result, _ = invoke(tmp_path, corrupt, expect_success=False)
    assert "input integrity check failed" in result.stderr


def test_floor_rejects_99_and_accepts_100(tmp_path: Path) -> None:
    rejected, _ = invoke(
        tmp_path / "below",
        build_store(entries(99)),
        min_entries="100",
        expect_success=False,
    )
    assert "store holds 99 entries, below the required floor of 100" in rejected.stderr
    accepted, _ = invoke(
        tmp_path / "at",
        build_store(entries(100)),
        min_entries="100",
        expect_success=True,
    )
    assert "normalized 100 entries" in accepted.stdout


def test_non_default_password_output_has_independent_valid_trailer(tmp_path: Path) -> None:
    password = "different-password"
    source = build_store(entries(2), password=password)
    invoke(tmp_path, source, password=password, expect_success=True)


def test_certificate_bytes_are_copied_as_opaque_data(tmp_path: Path) -> None:
    source = build_store([Entry(b"alias", 1, b"not-DER\x00\xff")])
    invoke(tmp_path, source, expect_success=True)


def test_success_metadata_round_trips_through_fstat(tmp_path: Path) -> None:
    epoch = 1_234_567_890
    _, destination = invoke(tmp_path, build_store(entries(1)), epoch=str(epoch), expect_success=True)
    descriptor = os.open(destination, os.O_RDONLY)
    try:
        details = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    assert stat.S_IMODE(details.st_mode) == 0o644
    assert details.st_mtime_ns == epoch * 1_000_000_000


class FailingStream:
    def __init__(self, stream: BinaryIO, operation: str) -> None:
        self.stream = stream
        self.operation = operation

    def __enter__(self) -> FailingStream:
        return self

    def __exit__(self, *args: object) -> None:
        self.stream.close()

    def write(self, data: bytes) -> int:
        if self.operation == "write":
            raise OSError("injected write failure")
        return self.stream.write(data)

    def flush(self) -> None:
        if self.operation == "flush":
            raise OSError("injected flush failure")
        self.stream.flush()


@pytest.mark.parametrize("operation", ["write", "flush", "chmod", "utime"])
def test_pre_replace_failures_remove_temporary_and_preserve_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    destination = tmp_path / "destination.jks"
    before = seed_destination(destination)
    original_open = Path.open

    def failing_open(path: Path, *args: object, **kwargs: object) -> FailingStream:
        stream = original_open(path, *args, **kwargs)
        return FailingStream(stream, operation)

    def fail(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError(f"injected {operation} failure")

    with monkeypatch.context() as patcher:
        if operation in {"write", "flush"}:
            patcher.setattr(Path, "open", failing_open)
        else:
            patcher.setattr(normalize_jks.os, operation, fail)
        with pytest.raises(OSError, match=f"injected {operation} failure"):
            normalize_jks._atomic_replace(destination, b"replacement", DEFAULT_EPOCH)

    assert snapshot(destination) == before
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


def test_replace_sees_complete_file_and_metadata_before_single_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = build_store(entries(2))
    output, _ = normalize_jks.normalize(source, DEFAULT_EPOCH, "changeit", 1)
    destination = tmp_path / "destination.jks"
    before = seed_destination(destination)
    real_replace = os.replace
    calls: list[tuple[Path, Path]] = []

    def inspecting_replace(source_path: Path, destination_path: Path) -> None:
        assert Path(source_path).read_bytes() == output
        details = Path(source_path).stat()
        assert stat.S_IMODE(details.st_mode) == 0o644
        assert details.st_mtime_ns == DEFAULT_EPOCH * 1_000_000_000
        assert snapshot(destination) == before
        calls.append((Path(source_path), Path(destination_path)))
        real_replace(source_path, destination_path)

    monkeypatch.setattr(normalize_jks.os, "replace", inspecting_replace)
    normalize_jks._atomic_replace(destination, output, DEFAULT_EPOCH)

    assert len(calls) == 1
    assert calls[0][1] == destination
    assert_exact_transform(source, destination.read_bytes(), DEFAULT_EPOCH, "changeit")
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))
