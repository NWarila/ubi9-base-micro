#!/usr/bin/env python3
"""Normalize trusted-certificate creation dates in an integrity-sealed JKS store."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import struct
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

JKS_MAGIC = 0xFEEDFEED
JKS_VERSION = 2
PRIVATE_KEY_TAG = 1
TRUSTED_CERT_TAG = 2
SALT = b"Mighty Aphrodite"
TRAILER_LENGTH = 20
MAX_EPOCH = 4_102_444_800
MAX_MIN_ENTRIES = 100_000


class RejectedError(Exception):
    """The input is not an acceptable trusted-certificate JKS store."""


def _bounded_integer(name: str, minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value, 10)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from exc
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"{name} must be between {minimum} and {maximum} (inclusive)")
        return parsed

    return parse


def _digest(password: str, body: bytes) -> bytes:
    return hashlib.sha1(password.encode("utf-16-be") + SALT + body).digest()


def _decode_modified_utf8(value: bytes, *, field: str) -> tuple[int, ...]:
    """Decode Java modified UTF-8 to its exact sequence of UTF-16 code units."""
    units: list[int] = []
    offset = 0
    while offset < len(value):
        first = value[offset]
        if 0x01 <= first <= 0x7F:
            units.append(first)
            offset += 1
            continue

        if 0xC0 <= first <= 0xDF:
            if offset + 1 >= len(value) or value[offset + 1] & 0xC0 != 0x80:
                raise RejectedError(f"{field}: invalid modified UTF-8 at byte {offset}")
            second = value[offset + 1]
            unit = ((first & 0x1F) << 6) | (second & 0x3F)
            if unit == 0:
                if first != 0xC0 or second != 0x80:
                    raise RejectedError(f"{field}: invalid modified UTF-8 at byte {offset}")
            elif unit < 0x80:
                raise RejectedError(f"{field}: overlong modified UTF-8 at byte {offset}")
            units.append(unit)
            offset += 2
            continue

        if 0xE0 <= first <= 0xEF:
            if offset + 2 >= len(value) or value[offset + 1] & 0xC0 != 0x80 or value[offset + 2] & 0xC0 != 0x80:
                raise RejectedError(f"{field}: invalid modified UTF-8 at byte {offset}")
            unit = ((first & 0x0F) << 12) | ((value[offset + 1] & 0x3F) << 6) | (value[offset + 2] & 0x3F)
            if unit < 0x800:
                raise RejectedError(f"{field}: overlong modified UTF-8 at byte {offset}")
            units.append(unit)
            offset += 3
            continue

        raise RejectedError(f"{field}: invalid modified UTF-8 at byte {offset}")

    return tuple(units)


def _read_u16(body: bytes, offset: int, *, error: str) -> int:
    if offset + 2 > len(body):
        raise RejectedError(error)
    return struct.unpack_from(">H", body, offset)[0]


def _read_u32(body: bytes, offset: int, *, error: str) -> int:
    if offset + 4 > len(body):
        raise RejectedError(error)
    return struct.unpack_from(">I", body, offset)[0]


def normalize(raw: bytes, epoch: int, password: str, min_entries: int) -> tuple[bytes, int]:
    """Validate a JKS store and return an exact transform with normalized dates."""
    if len(raw) < 12 + TRAILER_LENGTH:
        raise RejectedError(f"file too short to be a JKS store: {len(raw)} bytes")

    magic, version, count = struct.unpack_from(">III", raw)
    if magic != JKS_MAGIC:
        raise RejectedError(f"not a JKS store: magic={magic:#x}")
    if version != JKS_VERSION:
        raise RejectedError(f"unsupported JKS version {version}; expected {JKS_VERSION}")

    body = raw[:-TRAILER_LENGTH]
    trailer = raw[-TRAILER_LENGTH:]
    expected_trailer = _digest(password, body)
    if not hmac.compare_digest(trailer, expected_trailer):
        raise RejectedError(
            f"input integrity check failed: trailer {trailer.hex()} != computed {expected_trailer.hex()}"
        )

    # A correctly rooted extraction with no anchor source produces a reproducible,
    # 32-byte, zero-entry store. The floor turns that silent loss of TLS trust into
    # a build stop. It is only a liveness guard, not a provenance guarantee: stores
    # extracted from different roots can normalize identically when their CA inputs match.
    if count < min_entries:
        raise RejectedError(f"store holds {count} entries, below the required floor of {min_entries}")

    output = bytearray(raw[:12])
    offset = 12
    aliases: set[tuple[int, ...]] = set()
    normalized_date = struct.pack(">q", epoch * 1000)

    for index in range(count):
        tag = _read_u32(body, offset, error=f"entry {index}: truncated before tag")
        if tag == PRIVATE_KEY_TAG:
            raise RejectedError(
                f"entry {index}: private-key entry found; this store must contain trusted certificates only"
            )
        if tag != TRUSTED_CERT_TAG:
            raise RejectedError(f"entry {index}: unsupported JKS entry tag {tag}")
        output += body[offset : offset + 4]
        offset += 4

        alias_length = _read_u16(body, offset, error=f"entry {index}: truncated alias length")
        alias_start = offset + 2
        alias_end = alias_start + alias_length
        if alias_end + 8 > len(body):
            raise RejectedError(f"entry {index}: truncated alias or creation date")
        alias_bytes = body[alias_start:alias_end]
        decoded_alias = _decode_modified_utf8(alias_bytes, field=f"entry {index} alias")
        if decoded_alias in aliases:
            raise RejectedError(f"entry {index}: duplicate decoded alias")
        aliases.add(decoded_alias)
        output += body[offset:alias_end]
        offset = alias_end + 8
        output += normalized_date

        type_length = _read_u16(body, offset, error=f"entry {index}: truncated certificate type length")
        type_start = offset + 2
        type_end = type_start + type_length
        if type_end + 4 > len(body):
            raise RejectedError(f"entry {index}: truncated certificate type")
        type_bytes = body[type_start:type_end]
        decoded_type = _decode_modified_utf8(type_bytes, field=f"entry {index} certificate type")
        if decoded_type != tuple(map(ord, "X.509")):
            raise RejectedError(f"entry {index}: unexpected certificate type")
        output += body[offset:type_end]
        offset = type_end

        certificate_length = _read_u32(body, offset, error=f"entry {index}: truncated certificate length")
        certificate_end = offset + 4 + certificate_length
        if certificate_end > len(body):
            raise RejectedError(f"entry {index}: truncated certificate body")
        # Certificate bytes are deliberately opaque here. The target JDK validates DER
        # in the rootfs-dependent stage.
        output += body[offset:certificate_end]
        offset = certificate_end

    if offset != len(body):
        raise RejectedError(f"{len(body) - offset} trailing bytes after {count} entries")

    # Exact decoded duplicates are rejected above. Locale-aware case equivalence is
    # intentionally left to the target JDK in the rootfs-dependent stage.
    output += _digest(password, bytes(output))
    return bytes(output), count


def _atomic_replace(destination: Path, data: bytes, epoch: int) -> None:
    destination_directory = destination.parent
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination_directory, prefix=f".{destination.name}.", suffix=".tmp"
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    replaced = False
    try:
        with temporary.open("wb") as stream:
            written = stream.write(data)
            if written != len(data):
                raise OSError(f"short write: wrote {written} of {len(data)} bytes")
            stream.flush()
        os.chmod(temporary, 0o644)  # noqa: PTH101 -- failure point is tested directly
        os.utime(temporary, (epoch, epoch))
        os.replace(temporary, destination)  # noqa: PTH105 -- atomic operation is spied on in tests
        replaced = True
    finally:
        if not replaced:
            temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("src", type=Path)
    parser.add_argument("dst", type=Path)
    parser.add_argument(
        "--epoch",
        required=True,
        type=_bounded_integer("--epoch", 0, MAX_EPOCH),
        help="SOURCE_DATE_EPOCH in seconds",
    )
    parser.add_argument(
        "--min-entries",
        required=True,
        type=_bounded_integer("--min-entries", 1, MAX_MIN_ENTRIES),
        help="minimum trusted-certificate entry count",
    )
    parser.add_argument("--password", default="changeit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        raw = args.src.read_bytes()
        output, count = normalize(raw, args.epoch, args.password, args.min_entries)
        _atomic_replace(args.dst, output, args.epoch)
    except (OSError, RejectedError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 1
    print(f"normalized {count} entries -> {args.dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
