#!/usr/bin/env python3
# Purpose: Bind verified base-python SLSA provenance to exact Fulcio workflow extensions
# Role: gate
# Micro-container candidate: yes - pure-stdlib verified-envelope and certificate policy with self-test

"""Validate the SLSA certificate that authenticated an exact verified envelope."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

PREDICATE_TYPE = "https://slsa.dev/provenance/v0.2"
CERTIFICATE_ANNOTATION = "dev.sigstore.cosign/certificate"
PREDICATE_ANNOTATION = "predicateType"
ENVELOPE_MEDIA_TYPE = "application/vnd.dsse.envelope.v1+json"
SHA = re.compile(r"^[0-9a-f]{40}$")
REF = re.compile(r"^refs/(?:heads/main|tags/python/v[^\s]+)$")
SIGNER_SHA = "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a"
WORKFLOW = ".github/workflows/publish-python.yaml"
WORKFLOW_URI_PREFIX = "https://github.com/NWarila/ubi9-base-micro/"
EXTENSIONS = {
    "1.3.6.1.4.1.57264.1.10": "build signer digest",
    "1.3.6.1.4.1.57264.1.13": "source repository digest",
    "1.3.6.1.4.1.57264.1.14": "source repository ref",
    "1.3.6.1.4.1.57264.1.18": "build config URI",
    "1.3.6.1.4.1.57264.1.19": "build config digest",
}


class CertificateError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise CertificateError(message)


def content_digest(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        f"{label} must be a sha256 digest",
    )
    return str(value)


def load_records(path: Path) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8").strip()
    require(bool(raw), f"{path} is empty")
    try:
        loaded = json.loads(raw)
        candidates = loaded if isinstance(loaded, list) else [loaded]
    except json.JSONDecodeError:
        candidates = [json.loads(line) for line in raw.splitlines() if line.strip()]
    require(bool(candidates), f"{path} contains no records")
    require(all(isinstance(candidate, dict) for candidate in candidates), f"{path} records must be objects")
    return candidates


def read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    require(offset < len(data), "certificate DER ended before a tag")
    tag = data[offset]
    offset += 1
    require(offset < len(data), "certificate DER ended before a length")
    first_length = data[offset]
    offset += 1
    if first_length & 0x80:
        length_octets = first_length & 0x7F
        require(0 < length_octets <= 4 and offset + length_octets <= len(data), "certificate DER length is invalid")
        length = int.from_bytes(data[offset : offset + length_octets], "big")
        offset += length_octets
    else:
        length = first_length
    end = offset + length
    require(end <= len(data), "certificate DER value exceeds its container")
    return tag, data[offset:end], end


def oid_text(raw: bytes) -> str:
    require(bool(raw), "certificate extension OID is empty")
    first = raw[0]
    components = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for octet in raw[1:]:
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            components.append(value)
            value = 0
    require(value == 0, "certificate extension OID is truncated")
    return ".".join(str(component) for component in components)


def direct_children(content: bytes) -> list[tuple[int, bytes]]:
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(content):
        tag, value, end = read_tlv(content, offset)
        children.append((tag, value))
        offset = end
    require(offset == len(content), "certificate DER child sequence is malformed")
    return children


def extension_values_from_der(der: bytes) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {oid: [] for oid in EXTENSIONS}

    def visit(tag: int, content: bytes) -> None:
        if tag & 0x20:
            children = direct_children(content)
            if len(children) >= 2 and children[0][0] == 0x06:
                oid = oid_text(children[0][1])
                if oid in found:
                    value_node = children[-1]
                    require(value_node[0] == 0x04, f"Fulcio extension {oid} must contain an OCTET STRING")
                    inner_tag, inner_value, inner_end = read_tlv(value_node[1], 0)
                    require(
                        inner_tag == 0x0C and inner_end == len(value_node[1]),
                        f"Fulcio extension {oid} must contain one UTF8String",
                    )
                    try:
                        found[oid].append(inner_value.decode("utf-8"))
                    except UnicodeDecodeError as exc:
                        raise CertificateError(f"Fulcio extension {oid} is not UTF-8") from exc
            for child_tag, child_content in children:
                visit(child_tag, child_content)

    root_tag, root_content, root_end = read_tlv(der, 0)
    require(root_end == len(der), "certificate PEM contains trailing DER data")
    visit(root_tag, root_content)
    return found


def pem_der(pem: str) -> bytes:
    lines = pem.strip().splitlines()
    require(
        len(lines) >= 3 and lines[0] == "-----BEGIN CERTIFICATE-----" and lines[-1] == "-----END CERTIFICATE-----",
        "SLSA layer certificate annotation is not one PEM certificate",
    )
    try:
        return base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError as exc:
        raise CertificateError("SLSA layer certificate PEM body is invalid base64") from exc


def slsa_layers(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    layers = manifest.get("layers")
    require(isinstance(layers, list), "attestation manifest layers must be a list")
    assert isinstance(layers, list)
    selected = []
    for layer in layers:
        if not isinstance(layer, dict):
            continue
        annotations = layer.get("annotations")
        if isinstance(annotations, dict) and annotations.get(PREDICATE_ANNOTATION) == PREDICATE_TYPE:
            selected.append(layer)
    require(
        len(selected) == 1,
        f"attestation manifest must contain exactly one SLSA provenance layer; found {len(selected)}",
    )
    return selected


def expected_extensions(sha: str, ref: str) -> dict[str, str]:
    require(SHA.fullmatch(sha) is not None, "expected publishing SHA must be 40 lowercase hex")
    require(REF.fullmatch(ref) is not None, "expected publishing ref is not a supported Python publish ref")
    return {
        "1.3.6.1.4.1.57264.1.10": SIGNER_SHA,
        "1.3.6.1.4.1.57264.1.13": sha,
        "1.3.6.1.4.1.57264.1.14": ref,
        "1.3.6.1.4.1.57264.1.18": f"{WORKFLOW_URI_PREFIX}{WORKFLOW}@{ref}",
        "1.3.6.1.4.1.57264.1.19": sha,
    }


def validate(
    *,
    verified_records: list[dict[str, Any]],
    manifest: dict[str, Any],
    envelope_raw: bytes,
    sha: str,
    ref: str,
) -> None:
    try:
        envelope = json.loads(envelope_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CertificateError(f"registry SLSA envelope is invalid JSON: {exc}") from exc
    require(isinstance(envelope, dict), "registry SLSA envelope must be a JSON object")
    require(
        sum(record == envelope for record in verified_records) == 1,
        "registry SLSA envelope must exactly match one successfully verified Cosign record",
    )
    layer = slsa_layers(manifest)[0]
    require(layer.get("mediaType") == ENVELOPE_MEDIA_TYPE, "SLSA layer mediaType mismatch")
    observed_layer_digest = "sha256:" + hashlib.sha256(envelope_raw).hexdigest()
    require(
        layer.get("digest") == observed_layer_digest,
        "SLSA layer digest does not match the registry envelope bytes",
    )
    annotations = layer.get("annotations")
    assert isinstance(annotations, dict)
    certificate = annotations.get(CERTIFICATE_ANNOTATION)
    require(isinstance(certificate, str), "SLSA layer is missing its Fulcio certificate annotation")
    assert isinstance(certificate, str)
    observed = extension_values_from_der(pem_der(certificate))
    for oid, expected in expected_extensions(sha, ref).items():
        label = EXTENSIONS[oid]
        values = observed[oid]
        require(len(values) == 1, f"Fulcio {label} extension {oid} must occur exactly once; found {len(values)}")
        require(
            values[0] == expected,
            f"Fulcio {label} extension {oid} mismatch: expected {expected}, observed {values[0]}",
        )


def der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_length(len(value)) + value


def oid_der(oid: str) -> bytes:
    components = [int(component) for component in oid.split(".")]
    encoded = bytearray([components[0] * 40 + components[1]])
    for component in components[2:]:
        remaining = component
        groups = [remaining & 0x7F]
        remaining >>= 7
        while remaining:
            groups.append(0x80 | (remaining & 0x7F))
            remaining >>= 7
        encoded.extend(reversed(groups))
    return bytes(encoded)


def synthetic_der(values: dict[str, list[str]]) -> bytes:
    extensions = []
    for oid, members in values.items():
        for member in members:
            inner = tlv(0x0C, member.encode())
            extensions.append(tlv(0x30, tlv(0x06, oid_der(oid)) + tlv(0x04, inner)))
    return tlv(0x30, b"".join(extensions))


def pem(der: bytes) -> str:
    body = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"


def fixture(values: dict[str, list[str]]) -> tuple[list[dict[str, Any]], dict[str, Any], bytes]:
    envelope = {"payloadType": "application/vnd.in-toto+json", "payload": "e30=", "signatures": [{"sig": "c2ln"}]}
    raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    manifest = {
        "layers": [
            {
                "mediaType": ENVELOPE_MEDIA_TYPE,
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "annotations": {
                    PREDICATE_ANNOTATION: PREDICATE_TYPE,
                    CERTIFICATE_ANNOTATION: pem(synthetic_der(values)),
                },
            }
        ]
    }
    return [copy.deepcopy(envelope)], manifest, raw


def self_test() -> None:
    sha = "a" * 40
    ref = "refs/heads/main"
    baseline_values = {oid: [value] for oid, value in expected_extensions(sha, ref).items()}
    records, manifest, raw = fixture(baseline_values)
    validate(verified_records=records, manifest=manifest, envelope_raw=raw, sha=sha, ref=ref)
    mutations: list[tuple[str, str, dict[str, list[str]]]] = []
    for oid, label in EXTENSIONS.items():
        missing = copy.deepcopy(baseline_values)
        missing[oid] = []
        mutations.append(
            (f"missing {label}", f"Fulcio {label} extension {oid} must occur exactly once; found 0", missing)
        )
        wrong = copy.deepcopy(baseline_values)
        wrong[oid] = ["wrong"]
        mutations.append((f"wrong {label}", f"Fulcio {label} extension {oid} mismatch", wrong))
        duplicate = copy.deepcopy(baseline_values)
        duplicate[oid].append("conflict")
        mutations.append(
            (f"conflicting {label}", f"Fulcio {label} extension {oid} must occur exactly once; found 2", duplicate)
        )
    for label, expected, values in mutations:
        records, manifest, raw = fixture(values)
        try:
            validate(verified_records=records, manifest=manifest, envelope_raw=raw, sha=sha, ref=ref)
        except CertificateError as exc:
            require(str(exc).startswith(expected), f"self-test {label} rejected for the wrong reason: {exc}")
            print(f"python SLSA certificate negative rejected [{label}] reason={exc}")
        else:
            raise CertificateError(f"self-test mutation unexpectedly passed: {label}")
    print(f"python SLSA certificate self-test passed: baseline plus {len(mutations)} extension mutations")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verified", type=Path)
    parser.add_argument("--attestation-manifest", type=Path)
    parser.add_argument("--envelope", type=Path)
    parser.add_argument("--sha")
    parser.add_argument("--ref")
    parser.add_argument("--print-layer-digest", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        require(args.attestation_manifest is not None, "--attestation-manifest is required")
        manifest = json.loads(args.attestation_manifest.read_text(encoding="utf-8"))
        require(isinstance(manifest, dict), "attestation manifest must be a JSON object")
        layer = slsa_layers(manifest)[0]
        if args.print_layer_digest:
            print(content_digest(layer.get("digest"), "SLSA layer digest"))
            return 0
        require(
            args.verified and args.envelope and args.sha and args.ref,
            "verified mode requires --verified, --envelope, --sha, and --ref",
        )
        validate(
            verified_records=load_records(args.verified),
            manifest=manifest,
            envelope_raw=args.envelope.read_bytes(),
            sha=args.sha,
            ref=args.ref,
        )
        print(f"python SLSA certificate policy passed: signer={SIGNER_SHA} source={args.sha}@{args.ref}")
        return 0
    except (CertificateError, json.JSONDecodeError, OSError) as exc:
        print(f"python SLSA certificate policy failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
