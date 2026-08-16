#!/usr/bin/env python3
# Purpose: Bind the pushed base-python digest to exact registry index bytes and a closed child matrix
# Role: gate
# Micro-container candidate: yes - pure-stdlib file-in/JSON-out policy with self-tests

"""Resolve the only publishable base-python OCI index shape.

The push metadata digest and registry-served bytes are independent inputs.  The
bytes must hash to that digest before descriptors are interpreted.  Runnable
children and BuildKit provenance descriptors then form two exact one-per-
architecture sets.  The same digest can also be checked at named consumers and
after checksum-bound artifact transfer.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
CONSUMERS = frozenset({"sign", "attest", "vex", "alias"})


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
                architecture in children,
                f"registry index contains unsupported runnable platform linux/{architecture}",
            )
            children[cast(str, architecture)].append(descriptor_digest)
        elif operating_system == "unknown" and architecture == "unknown":
            require(
                set(platform) == {"os", "architecture"},
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


def image_descriptor(digest_character: str, architecture: str) -> dict[str, Any]:
    return {
        "mediaType": OCI_IMAGE_MANIFEST,
        "digest": "sha256:" + digest_character * 64,
        "size": 1234,
        "platform": {"architecture": architecture, "os": "linux"},
    }


def attestation_descriptor(digest_character: str, reference: str) -> dict[str, Any]:
    return {
        "mediaType": OCI_IMAGE_MANIFEST,
        "digest": "sha256:" + digest_character * 64,
        "size": 567,
        "annotations": {
            ATTESTATION_TYPE_KEY: ATTESTATION_TYPE,
            ATTESTATION_DIGEST_KEY: reference,
        },
        "platform": {"architecture": "unknown", "os": "unknown"},
    }


def production_index() -> dict[str, Any]:
    amd64 = "sha256:" + "1" * 64
    arm64 = "sha256:" + "2" * 64
    return {
        "schemaVersion": 2,
        "mediaType": OCI_IMAGE_INDEX,
        "manifests": [
            image_descriptor("1", "amd64"),
            image_descriptor("2", "arm64"),
            attestation_descriptor("3", amd64),
            attestation_descriptor("4", arm64),
        ],
    }


def serialize(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def reason(callable_value: Any) -> str:
    try:
        callable_value()
    except PythonIndexError as exc:
        return f"REJECT: {exc}"
    return "ACCEPT: closed production index and single-digest dataflow"


def load_assert_vex() -> Any:
    path = Path(__file__).with_name("assert-vex.py")
    spec = importlib.util.spec_from_file_location("python_assert_vex_for_index_agreement", path)
    require(spec is not None and spec.loader is not None, "could not load assert-vex policy for agreement tests")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def scanner_documents(product: str, architecture: str, floor_names: set[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    image_id = "sha256:" + "9" * 64
    packages = sorted(floor_names | {"python3.12", "python3.12-libs"})
    trivy = {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.71.0"},
        "ArtifactName": product,
        "ArtifactType": "container_image",
        "Metadata": {
            "OS": {"Family": "redhat", "Name": "9.8"},
            "ImageID": image_id,
            "ImageConfig": {"architecture": architecture},
            "RepoDigests": [product],
        },
        "Results": [
            {
                "Target": f"{product} (redhat 9.8)",
                "Class": "os-pkgs",
                "Type": "redhat",
                "Packages": [
                    {
                        "Name": package,
                        "Version": "3.12.13-3.el9_8.1" if package.startswith("python3.12") else "1",
                    }
                    for package in packages
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-11940",
                        "PkgName": package,
                        "InstalledVersion": "3.12.13-3.el9_8.1",
                        "Severity": "HIGH",
                    }
                    for package in ("python3.12", "python3.12-libs")
                ],
            }
        ],
    }
    grype = {
        "descriptor": {"name": "grype", "version": "0.115.0"},
        "distro": {"name": "redhat", "version": "9.8"},
        "source": {
            "type": "image",
            "target": {
                "userInput": product,
                "imageID": image_id,
                "architecture": architecture,
                "repoDigests": [product],
            },
        },
        "matches": [
            {
                "vulnerability": {"id": "CVE-2026-11940", "severity": "High"},
                "artifact": {"name": package, "version": "3.12.13-3.el9_8.1"},
            }
            for package in ("python3.12", "python3.12-libs")
        ],
        "ignoredMatches": [],
        "alertsByPackage": {},
    }
    return trivy, grype


def vex_message(
    root: Path,
    *,
    raw_index: bytes,
    product: str,
    architecture: str = "amd64",
    index_reference: str | None = None,
    only_index_reference: bool = False,
    mutate_document: bool = False,
    missing_manifest: bool = False,
) -> str:
    module = load_assert_vex()
    floor = Path("images/python/rpm-lock/micro-floor.json")
    floor_names = set(module.package_floor_names(floor, architecture))
    trivy, grype = scanner_documents(product, architecture, floor_names)
    trivy_path = root / "trivy.json"
    grype_path = root / "grype.json"
    trivy_path.write_text(json.dumps(trivy), encoding="utf-8")
    grype_path.write_text(json.dumps(grype), encoding="utf-8")
    vex_dir = root / "images" / "python" / "vex"
    if vex_dir.exists():
        shutil.rmtree(vex_dir)
    shutil.copytree("images/python/vex", vex_dir)
    if mutate_document:
        canonical = vex_dir / "cve-2026-11940.openvex.json"
        document = json.loads(canonical.read_text(encoding="utf-8"))
        document["statements"][0]["products"][2]["@id"] += "-mutated"
        canonical.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    manifest = root / "index.json"
    if manifest.exists():
        manifest.unlink()
    if not missing_manifest:
        manifest.write_bytes(raw_index)
    raw_digest = "sha256:" + hashlib.sha256(raw_index).hexdigest()
    reference = index_reference or f"{IMAGE_REPOSITORY}@{raw_digest}"
    command = [
        sys.executable,
        "tools/assert-vex.py",
        "--product",
        product,
        "--trivy-json",
        str(trivy_path),
        "--grype-json",
        str(grype_path),
        "--package-floor",
        str(floor),
        "--vex-dir",
        str(vex_dir),
        "--index-reference",
        reference,
    ]
    if not only_index_reference:
        command.extend(["--index-manifest", str(manifest)])
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    output = (result.stdout + result.stderr).strip().splitlines()
    if result.returncode == 0:
        disposition = next((line for line in output if line.startswith("accept-and-track disposition:")), "accepted")
        return f"ACCEPT: {disposition}"
    diagnostic = next(
        (line.removeprefix("assert-vex failed: ") for line in output if line.startswith("assert-vex failed: ")),
        next(
            (line for line in output if line.startswith("accept-and-track rejected for ")),
            next((line for line in reversed(output) if line), "no diagnostic"),
        ),
    )
    return f"REJECT: {diagnostic}"


def agreement_rows(production_raw: bytes | None = None) -> list[tuple[str, str, str]]:
    baseline_raw = production_raw if production_raw is not None else serialize(production_index())
    try:
        baseline = json.loads(baseline_raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PythonIndexError(f"agreement production index is malformed JSON: {exc}") from exc
    require(isinstance(baseline, dict), "agreement production index must be an object")
    baseline_digest = "sha256:" + hashlib.sha256(baseline_raw).hexdigest()
    baseline_evidence = validate_index(
        baseline_raw,
        push_digest=baseline_digest,
        fetch_reference=f"{IMAGE_REPOSITORY}@{baseline_digest}",
    )
    amd64_digest = baseline_evidence.children["amd64"]
    amd64_product = f"{IMAGE_REPOSITORY}@{amd64_digest}"
    attestation_product = f"{IMAGE_REPOSITORY}@{baseline_evidence.attestations['amd64']}"
    index_product = f"{IMAGE_REPOSITORY}@{baseline_digest}"
    other_digest = "sha256:" + "f" * 64
    manifests = baseline.get("manifests")
    assert isinstance(manifests, list)
    attestation_positions = [
        position
        for position, descriptor in enumerate(manifests)
        if isinstance(descriptor, dict) and descriptor.get("platform") == {"architecture": "unknown", "os": "unknown"}
    ]
    require(len(attestation_positions) == 2, "agreement production index attestation inventory changed")

    cases: list[dict[str, Any]] = []

    def add(
        label: str,
        document: dict[str, Any] | None = None,
        *,
        exact_raw: bytes | None = None,
        **values: Any,
    ) -> None:
        raw = exact_raw if exact_raw is not None else serialize(document if document is not None else baseline)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        cases.append(
            {
                "label": label,
                "raw": raw,
                "push_digest": digest,
                "fetch_reference": f"{IMAGE_REPOSITORY}@{digest}",
                "consumer_digests": {},
                "product": amd64_product,
                "architecture": "amd64",
                **values,
            }
        )

    add("production index", exact_raw=baseline_raw)
    extra = copy.deepcopy(baseline)
    extra["manifests"].append(image_descriptor("5", "s390x"))
    add("extra runnable platform", extra)
    duplicate = copy.deepcopy(baseline)
    duplicate["manifests"].append(image_descriptor("5", "amd64"))
    add("duplicate runnable platform", duplicate)
    unannotated = copy.deepcopy(baseline)
    unannotated["manifests"][attestation_positions[0]].pop("annotations")
    add("unannotated unknown descriptor", unannotated)
    wrong_reference = copy.deepcopy(baseline)
    wrong_reference["manifests"][attestation_positions[0]]["annotations"][ATTESTATION_DIGEST_KEY] = "sha256:" + "6" * 64
    add("wrong attestation reference", wrong_reference)
    excess = copy.deepcopy(baseline)
    excess["manifests"].append(attestation_descriptor("5", amd64_digest))
    add("excess attestation", excess)
    duplicate_reference = copy.deepcopy(baseline)
    duplicate_reference["manifests"][attestation_positions[1]]["annotations"][ATTESTATION_DIGEST_KEY] = amd64_digest
    add("duplicate attestation reference", duplicate_reference)
    add(
        "registry bytes differ from push digest",
        push_digest=other_digest,
        fetch_reference=f"{IMAGE_REPOSITORY}@{other_digest}",
    )
    add("tag-resolved fetch", fetch_reference=f"{IMAGE_REPOSITORY}:candidate")
    for consumer in ("sign", "attest", "vex", "alias"):
        add(f"different digest reaches {consumer} consumer", consumer_digests={consumer: other_digest})
    add("index digest submitted as product", product=index_product)
    add("attestation digest submitted as product", product=attestation_product)
    add("amd64 child with arm64 scanner report", architecture="arm64")
    add("one index flag without the other", only_index_reference=True)
    add("mutated canonical reviewed document", mutate_document=True)
    add(
        "index reference names a different repository",
        vex_reference=f"ghcr.io/example/ubi9-base-python@{baseline_digest}",
    )
    add("tampered cross-job artifact", bundle_tamper=True)
    add("missing index artifact", missing_manifest=True)

    rows: list[tuple[str, str, str]] = []
    with tempfile.TemporaryDirectory(prefix="python-index-agreement-") as raw_tmp:
        root = Path(raw_tmp)
        for case in cases:
            if case.get("bundle_tamper"):
                bundle = root / "bundle"
                bundle.mkdir(exist_ok=True)
                index_path = bundle / "index.json"
                index_path.write_bytes(baseline_raw)
                manifest = bundle / "SHA256SUMS"
                manifest.write_text(f"{hashlib.sha256(baseline_raw).hexdigest()}  index.json\n", encoding="utf-8")
                expected_manifest = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
                index_path.write_bytes(baseline_raw + b" ")
                publish = reason(
                    lambda bundle=bundle, manifest=manifest, expected_manifest=expected_manifest: verify_bundle(
                        bundle, manifest, expected_manifest, {"index.json"}
                    )
                )
            elif case.get("missing_manifest"):
                publish = "REJECT: missing registry index artifact"
            else:
                publish = reason(
                    lambda case=case: validate_index(
                        case["raw"],
                        push_digest=case["push_digest"],
                        fetch_reference=case["fetch_reference"],
                        consumer_digests=case["consumer_digests"],
                    )
                )
            vex_reference = case.get("vex_reference")
            if case["label"] == "registry bytes differ from push digest":
                vex_reference = f"{IMAGE_REPOSITORY}@{case['push_digest']}"
            if case["label"] == "different digest reaches vex consumer":
                vex_reference = f"{IMAGE_REPOSITORY}@{other_digest}"
            if case.get("bundle_tamper"):
                vex_reference = f"{IMAGE_REPOSITORY}@{baseline_digest}"
            vex = vex_message(
                root,
                raw_index=case["raw"] + (b" " if case.get("bundle_tamper") else b""),
                product=case["product"],
                architecture=case["architecture"],
                index_reference=vex_reference,
                only_index_reference=bool(case.get("only_index_reference")),
                mutate_document=bool(case.get("mutate_document")),
                missing_manifest=bool(case.get("missing_manifest")),
            )
            rows.append((case["label"], publish, vex))
    return rows


def self_test(production_raw: bytes | None = None) -> None:
    rows = agreement_rows(production_raw)
    expectations = {
        "production index": ("ACCEPT", "ACCEPT"),
        "extra runnable platform": ("REJECT", "REJECT"),
        "duplicate runnable platform": ("REJECT", "REJECT"),
        "unannotated unknown descriptor": ("REJECT", "REJECT"),
        "wrong attestation reference": ("REJECT", "REJECT"),
        "excess attestation": ("REJECT", "ACCEPT"),
        "duplicate attestation reference": ("REJECT", "ACCEPT"),
        "registry bytes differ from push digest": ("REJECT", "REJECT"),
        "tag-resolved fetch": ("REJECT", "ACCEPT"),
        "different digest reaches sign consumer": ("REJECT", "ACCEPT"),
        "different digest reaches attest consumer": ("REJECT", "ACCEPT"),
        "different digest reaches vex consumer": ("REJECT", "REJECT"),
        "different digest reaches alias consumer": ("REJECT", "ACCEPT"),
        "index digest submitted as product": ("ACCEPT", "REJECT"),
        "attestation digest submitted as product": ("ACCEPT", "REJECT"),
        "amd64 child with arm64 scanner report": ("ACCEPT", "REJECT"),
        "one index flag without the other": ("ACCEPT", "REJECT"),
        "mutated canonical reviewed document": ("ACCEPT", "REJECT"),
        "index reference names a different repository": ("ACCEPT", "REJECT"),
        "tampered cross-job artifact": ("REJECT", "REJECT"),
        "missing index artifact": ("REJECT", "REJECT"),
    }
    require({label for label, _, _ in rows} == set(expectations), "agreement table case inventory mismatch")
    for label, publish, vex in rows:
        expected_publish, expected_vex = expectations[label]
        require(publish.startswith(expected_publish + ":"), f"agreement {label} publish result mismatch: {publish}")
        require(vex.startswith(expected_vex + ":"), f"agreement {label} VEX result mismatch: {vex}")
        print(f"AGREEMENT | {label} | publish={publish} | vex={vex}")
    print(f"python index resolver self-test passed: {len(rows)} agreement cases")


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
    parser.add_argument("--agreement-index", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test(args.agreement_index.read_bytes() if args.agreement_index else None)
            return 0
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
