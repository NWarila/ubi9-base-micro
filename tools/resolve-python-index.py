#!/usr/bin/env python3
# Purpose: Bind the pushed base-python digest to exact registry index bytes and a closed child matrix
# Role: gate
# Micro-container candidate: yes - pure-stdlib file-in/JSON-out policy

"""Resolve the only publishable base-python OCI index shape.

The push metadata digest and registry-served bytes are independent inputs.  The
bytes must hash to that digest before descriptors are interpreted.  Runnable
children and BuildKit provenance descriptors then form two exact one-per-
architecture sets.  The same digest can also be checked at named consumers and
after checksum-bound artifact transfer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

IMAGE_REPOSITORY = "ghcr.io/nwarila/ubi9-base-python"
OCI_IMAGE_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
ATTESTATION_TYPE_KEY = "vnd.docker.reference.type"
ATTESTATION_DIGEST_KEY = "vnd.docker.reference.digest"
ATTESTATION_TYPE = "attestation-manifest"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([^\x00\r\n]+)$")
CONSUMERS = frozenset({"sign", "attest", "alias"})
INSPECTED_OBJECT_KEYS = {
    "runnable_descriptor": frozenset({"digest", "mediaType", "platform", "size"}),
    "attestation_descriptor": frozenset({"annotations", "digest", "mediaType", "platform", "size"}),
    "runnable_platform": frozenset({"architecture", "os"}),
    "attestation_platform": frozenset({"architecture", "os"}),
}


class PythonIndexError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise PythonIndexError(message)


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def content_digest(value: Any, label: str) -> str:
    require(isinstance(value, str) and DIGEST.fullmatch(value) is not None, f"{label} must be a sha256 digest")
    return cast(str, value)


@dataclass(frozen=True)
class IndexEvidence:
    image: str
    index_digest: str
    children: dict[str, str]
    attestations: dict[str, str]

    def document(self) -> dict[str, Any]:
        return {
            "image": self.image,
            "index_digest": self.index_digest,
            "children": self.children,
            "attestations": self.attestations,
        }


def validate_index(
    raw: bytes,
    *,
    push_digest: str,
    fetch_reference: str,
    repository: str = IMAGE_REPOSITORY,
    consumer_digests: dict[str, str] | None = None,
) -> IndexEvidence:
    content_digest(push_digest, "push metadata digest")
    require(bool(repository) and "@" not in repository and "://" not in repository, "registry repository is invalid")
    expected_reference = f"{repository}@{push_digest}"
    require(
        fetch_reference == expected_reference,
        f"registry index fetch must use the exact digest reference {expected_reference}",
    )
    actual_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    require(
        actual_digest == push_digest,
        "registry index bytes digest mismatch: "
        f"push metadata declares {push_digest}, registry bytes compute to {actual_digest}",
    )
    try:
        document = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PythonIndexError(f"registry index is malformed JSON: {exc}") from exc
    require(isinstance(document, dict), "registry index must be a top-level JSON object")
    require(
        document.get("schemaVersion") == 2 and type(document.get("schemaVersion")) is int,
        "registry index schemaVersion must equal integer 2",
    )
    require(document.get("mediaType") == OCI_IMAGE_INDEX, f"registry index mediaType must be {OCI_IMAGE_INDEX}")
    manifests = document.get("manifests")
    require(isinstance(manifests, list) and manifests, "registry index manifests must be a non-empty list")

    children: dict[str, list[str]] = {"amd64": [], "arm64": []}
    attestations: list[tuple[int, str, dict[str, Any]]] = []
    digest_positions: dict[str, int] = {}
    for position, descriptor in enumerate(manifests):
        label = f"registry index manifests[{position}]"
        require(isinstance(descriptor, dict), f"{label} must be an object")
        require({"mediaType", "digest", "size"} <= set(descriptor), f"{label} is missing a required field")
        media_type = descriptor.get("mediaType")
        require(media_type != OCI_IMAGE_INDEX, f"{label} must not be a nested image index descriptor")
        require(media_type == OCI_IMAGE_MANIFEST, f"{label}.mediaType must be {OCI_IMAGE_MANIFEST}")
        descriptor_digest = content_digest(descriptor.get("digest"), f"{label}.digest")
        size = descriptor.get("size")
        require(
            isinstance(size, int) and not isinstance(size, bool) and size >= 0,
            f"{label}.size must be a non-negative integer",
        )
        require(
            descriptor_digest not in digest_positions,
            f"registry index descriptor digest {descriptor_digest} is repeated at "
            f"manifests[{digest_positions.get(descriptor_digest)}] and manifests[{position}]",
        )
        digest_positions[descriptor_digest] = position
        platform = descriptor.get("platform")
        require(isinstance(platform, dict), f"{label}.platform must be an object")
        operating_system = platform.get("os")
        architecture = platform.get("architecture")
        if operating_system == "linux":
            require(
                set(descriptor) == INSPECTED_OBJECT_KEYS["runnable_descriptor"],
                f"{label} must equal the locked runnable descriptor shape",
            )
            require(
                set(platform) == INSPECTED_OBJECT_KEYS["runnable_platform"],
                f"{label}.platform must equal the locked linux runnable platform",
            )
            require(
                architecture in children,
                f"registry index contains unsupported runnable platform linux/{architecture}",
            )
            children[cast(str, architecture)].append(descriptor_digest)
        elif operating_system == "unknown" and architecture == "unknown":
            require(
                set(descriptor) == INSPECTED_OBJECT_KEYS["attestation_descriptor"],
                f"{label} must equal the locked BuildKit attestation descriptor shape",
            )
            require(
                set(platform) == INSPECTED_OBJECT_KEYS["attestation_platform"],
                f"{label}.platform must equal the locked unknown/unknown attestation platform",
            )
            attestations.append((position, descriptor_digest, descriptor))
        else:
            raise PythonIndexError(
                f"registry index contains unsupported descriptor platform {operating_system}/{architecture}"
            )

    resolved_children: dict[str, str] = {}
    for architecture in ("amd64", "arm64"):
        count = len(children[architecture])
        require(
            count == 1,
            f"registry index must contain exactly one linux/{architecture} runnable descriptor; found {count}",
        )
        resolved_children[architecture] = children[architecture][0]
    require(
        resolved_children["amd64"] != resolved_children["arm64"],
        "registry index linux/amd64 and linux/arm64 child digests must be distinct",
    )

    require(
        len(attestations) == 2,
        f"registry index must contain exactly two BuildKit attestation descriptors; found {len(attestations)}",
    )
    resolved_attestations: dict[str, list[str]] = {"amd64": [], "arm64": []}
    child_architecture = {digest: architecture for architecture, digest in resolved_children.items()}
    locked_annotations = {ATTESTATION_TYPE_KEY, ATTESTATION_DIGEST_KEY}
    for position, descriptor_digest, descriptor in attestations:
        label = f"registry index manifests[{position}]"
        annotations = descriptor.get("annotations")
        require(
            isinstance(annotations, dict) and annotations.get(ATTESTATION_TYPE_KEY) == ATTESTATION_TYPE,
            f"{label} unknown/unknown descriptor must carry {ATTESTATION_TYPE_KEY}={ATTESTATION_TYPE}",
        )
        assert isinstance(annotations, dict)
        require(
            set(annotations) == locked_annotations,
            f"{label}.annotations must equal the locked BuildKit attestation shape",
        )
        reference = content_digest(
            annotations.get(ATTESTATION_DIGEST_KEY),
            f"{label}.annotations[{ATTESTATION_DIGEST_KEY!r}]",
        )
        require(
            reference in child_architecture,
            f"{label} attestation reference digest must name an eligible platform child",
        )
        require(
            descriptor_digest not in child_architecture,
            "registry index attestation descriptor digests must be disjoint from runnable child digests",
        )
        resolved_attestations[child_architecture[reference]].append(descriptor_digest)
    final_attestations: dict[str, str] = {}
    for architecture in ("amd64", "arm64"):
        count = len(resolved_attestations[architecture])
        require(
            count == 1,
            "registry index must contain exactly one BuildKit attestation reference for "
            f"linux/{architecture}; found {count}",
        )
        final_attestations[architecture] = resolved_attestations[architecture][0]

    supplied_consumers = consumer_digests or {}
    require(set(supplied_consumers) <= CONSUMERS, "unknown index-digest consumer name")
    for consumer in sorted(supplied_consumers):
        observed = content_digest(supplied_consumers[consumer], f"{consumer} consumer digest")
        require(
            observed == push_digest,
            f"{consumer} consumer index digest mismatch: expected {push_digest}, observed {observed}",
        )
    return IndexEvidence(repository, push_digest, resolved_children, final_attestations)


def parse_checksum_manifest(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise PythonIndexError("cross-job checksum manifest is not UTF-8") from exc
    require(lines, "cross-job checksum manifest is empty")
    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        match = CHECKSUM_LINE.fullmatch(line)
        require(match is not None, f"cross-job checksum manifest line {line_number} is malformed")
        assert match is not None
        digest, relative = match.groups()
        path = Path(relative)
        require(not path.is_absolute() and ".." not in path.parts, f"cross-job checksum path is unsafe: {relative}")
        require(relative not in entries, f"cross-job checksum path is duplicated: {relative}")
        entries[relative] = digest
    return entries


def verify_bundle(root: Path, manifest: Path, expected_manifest_digest: str, required_files: set[str] | None) -> None:
    content_digest(expected_manifest_digest, "expected cross-job checksum manifest digest")
    try:
        manifest_raw = manifest.read_bytes()
    except FileNotFoundError as exc:
        raise PythonIndexError(f"missing cross-job checksum manifest: {manifest}") from exc
    actual_manifest_digest = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    require(
        actual_manifest_digest == expected_manifest_digest,
        "cross-job checksum manifest digest mismatch: "
        f"expected {expected_manifest_digest}, observed {actual_manifest_digest}",
    )
    entries = parse_checksum_manifest(manifest_raw)
    if required_files is not None:
        require(
            set(entries) == required_files,
            "cross-job checksum manifest file set does not match the required artifact set",
        )
    for relative, expected in sorted(entries.items()):
        path = root / relative
        require(path.is_file(), f"cross-job artifact is missing required file: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        require(
            actual == expected,
            f"cross-job artifact checksum mismatch for {relative}: "
            f"expected sha256:{expected}, observed sha256:{actual}",
        )


def parse_consumers(raw_values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in raw_values:
        name, separator, digest = raw.partition("=")
        require(separator == "=" and name and name not in result, f"invalid or duplicate --consumer value: {raw}")
        result[name] = digest
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-manifest", type=Path)
    parser.add_argument("--push-digest")
    parser.add_argument("--fetch-reference")
    parser.add_argument("--repository", default=IMAGE_REPOSITORY)
    parser.add_argument("--consumer", action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--bundle-root", type=Path)
    parser.add_argument("--bundle-manifest", type=Path)
    parser.add_argument("--bundle-digest")
    parser.add_argument("--require-file", action="append", default=[])
    parser.add_argument("--require-manifest-files", action="store_true")
    args = parser.parse_args()
    try:
        if (
            args.bundle_root
            or args.bundle_manifest
            or args.bundle_digest
            or args.require_file
            or args.require_manifest_files
        ):
            require(
                args.bundle_root
                and args.bundle_manifest
                and args.bundle_digest
                and (args.require_file or args.require_manifest_files)
                and not (args.require_file and args.require_manifest_files),
                "bundle verification requires the bundle inputs and exactly one file-set policy",
            )
            required_files = None if args.require_manifest_files else set(args.require_file)
            verify_bundle(args.bundle_root, args.bundle_manifest, args.bundle_digest, required_files)
            file_policy = "authenticated manifest" if required_files is None else ",".join(sorted(required_files))
            print(f"cross-job artifact integrity passed: files={file_policy}")
            return 0
        require(
            args.index_manifest and args.push_digest and args.fetch_reference,
            "index resolution requires --index-manifest, --push-digest, and --fetch-reference",
        )
        try:
            raw = args.index_manifest.read_bytes()
        except FileNotFoundError as exc:
            raise PythonIndexError(f"missing registry index artifact: {args.index_manifest}") from exc
        evidence = validate_index(
            raw,
            push_digest=args.push_digest,
            fetch_reference=args.fetch_reference,
            repository=args.repository,
            consumer_digests=parse_consumers(args.consumer),
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(evidence.document(), sort_keys=True) + "\n", encoding="utf-8")
        github_output = args.github_output or (
            Path(os.environ["GITHUB_OUTPUT"]) if "GITHUB_OUTPUT" in os.environ else None
        )
        if github_output:
            with github_output.open("a", encoding="utf-8") as output:
                output.write(f"index_digest={evidence.index_digest}\n")
                for architecture in ("amd64", "arm64"):
                    output.write(f"{architecture}_digest={evidence.children[architecture]}\n")
                    output.write(f"{architecture}_attestation_digest={evidence.attestations[architecture]}\n")
        print(
            "registry index resolution passed: "
            f"index={evidence.index_digest} amd64={evidence.children['amd64']} arm64={evidence.children['arm64']}"
        )
        return 0
    except (PythonIndexError, OSError) as exc:
        print(f"python index resolution failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
