#!/usr/bin/env python3
# Purpose: Default-deny OpenVEX gate over unfixed HIGH/CRITICAL Trivy+Grype findings
# Role: gate
# Micro-container candidate: yes - pure-stdlib, scanner-JSON-in/exit-out, has --self-test

"""Default-deny OpenVEX gate for unfixed HIGH/CRITICAL findings."""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import re
import sys
import tempfile
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

HIGH_CRITICAL = {"HIGH", "CRITICAL"}
SEVERITY_ORDER = {"UNKNOWN": 0, "NEGLIGIBLE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
ACCEPTED_STATUSES = {"fixed", "not_affected"}
OPENVEX_STATUSES = {"affected", "fixed", "not_affected", "under_investigation"}
OPENVEX_NOT_AFFECTED_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
CONTENT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SCANNER_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
IMAGE_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
REGISTRY_COMPONENT = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
REGISTRY = rf"{REGISTRY_COMPONENT}(?:\.{REGISTRY_COMPONENT})*(?::[0-9]+)?"
IMAGE_NAME = rf"(?:(?:{REGISTRY})/)?{IMAGE_NAME_COMPONENT}(?:/{IMAGE_NAME_COMPONENT})*"
IMAGE_REFERENCE = re.compile(rf"{IMAGE_NAME}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{{0,127}}|@sha256:[0-9a-f]{{64}})?\Z")
DIGEST_IMAGE_REFERENCE = re.compile(rf"{IMAGE_NAME}@sha256:[0-9a-f]{{64}}\Z")
RHEL_9_RELEASE = re.compile(r"9(?:\.[0-9]+)*\Z")
SUPPORTED_ARCHITECTURES = {"amd64", "arm64"}
TRIVY_FIX_STATUSES = {
    "affected",
    "end_of_life",
    "fixed",
    "fix_deferred",
    "not_affected",
    "under_investigation",
    "unknown",
    "will_not_fix",
}
GRYPE_FIX_STATES = {"fixed", "not-fixed", "unknown", "wont-fix"}
PUBLISHED_PYTHON_REPOSITORY = "ghcr.io/nwarila/ubi9-base-python"
PUBLISHED_MICRO_REPOSITORY = "ghcr.io/nwarila/ubi9-base-micro"
PUBLISHED_PYTHON_CHILD_POLICY_PRODUCT = (
    "https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-python/published-platform-children"
)
PUBLISHED_MICRO_CHILD_POLICY_PRODUCT = (
    "https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-micro/published-platform-children"
)
OCI_IMAGE_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
BUILDKIT_ATTESTATION_TYPE_ANNOTATION = "vnd.docker.reference.type"
BUILDKIT_ATTESTATION_TYPE = "attestation-manifest"
BUILDKIT_ATTESTATION_DIGEST_ANNOTATION = "vnd.docker.reference.digest"
VULNERABLE_CODE_ABSENCE_ID_PREFIX = (
    "https://github.com/NWarila/ubi9-base-micro/policy/vulnerable-code-not-present?absent-packages="
)
Mutation = Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], Any]

TD9_ACTION_STATEMENT = (
    "This image ships the vulnerable CPython standard-library tarfile module in python3.12-libs "
    "3.12.13-3.el9_8.1. As of 2026-08-13 Red Hat lists RHEL 9 python3.12 as Affected with no fixed RPM "
    "(RHEL 9 python3.9 is fixed via RHSA-2026:54268; the upstream CPython 3.12 branch is fixed). "
    "Consumers must not rely on tarfile.extractall() 'data' or 'tar' filters to contain untrusted archives "
    "until a fixed RPM is absorbed; risk is realized only by a consumer that extracts attacker-supplied "
    "archives relying on those filters. Accepted and tracked as TD-9 in docs/TECH-DEBT.md; review-by "
    "2026-10-01."
)

CVE_2026_14456_PYTHON_ACTION_STATEMENT = (
    "This image ships openssl-libs 1:3.5.5-5.el9_8 (OpenSSL 3.5.x), whose QUIC server implementation "
    "allows denial of service via unbounded memory growth. As of 2026-08-18 Red Hat lists RHEL 9 openssl "
    "as Affected with no fixed RPM; Red Hat Enterprise Linux 9.8 and later ship OpenSSL 3.5.x, and "
    "earlier RHEL versions do not include the QUIC server feature. Risk is realized only by an application "
    "that explicitly enables an OpenSSL QUIC server listener; this image runs no server process by default "
    "and its entrypoint is the Python interpreter. Consumers that enable an OpenSSL QUIC server listener "
    "must mitigate at the application boundary until a fixed RPM is absorbed. Accepted and tracked as "
    "TD-12 in docs/TECH-DEBT.md; review-by 2026-10-01."
)

CVE_2026_14456_MICRO_ACTION_STATEMENT = (
    "This image ships openssl-libs 1:3.5.5-5.el9_8 (OpenSSL 3.5.x), whose QUIC server implementation "
    "allows denial of service via unbounded memory growth. As of 2026-08-18 Red Hat lists RHEL 9 openssl "
    "as Affected with no fixed RPM; Red Hat Enterprise Linux 9.8 and later ship OpenSSL 3.5.x, and "
    "earlier RHEL versions do not include the QUIC server feature. Risk is realized only by an application "
    "that explicitly enables an OpenSSL QUIC server listener; this image ships no default command and "
    "removes runtime executables. Consumers that enable an OpenSSL QUIC server listener must mitigate at "
    "the application boundary until a fixed RPM is absorbed. Accepted and tracked as TD-12 in "
    "docs/TECH-DEBT.md; review-by 2026-10-01."
)


class VexError(Exception):
    pass


def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise VexError(f"duplicate JSON object member {key!r}")
        document[key] = value
    return document


@dataclass
class Finding:
    vulnerability: str
    severity: str
    scanners: set[str] = field(default_factory=set)
    packages: set[str] = field(default_factory=set)
    records: list[FindingRecord] = field(default_factory=list)

    def merge(self, other: Finding) -> None:
        if other.scanners and (not self.scanners or SEVERITY_ORDER[other.severity] > SEVERITY_ORDER[self.severity]):
            self.severity = other.severity
        self.scanners.update(other.scanners)
        self.packages.update(other.packages)
        self.records.extend(other.records)


@dataclass(frozen=True)
class FindingRecord:
    scanner: str
    package: str
    version: str
    has_fix: bool
    identity_rejections: tuple[str, ...]


@dataclass(frozen=True)
class Statement:
    path: Path
    index: int
    vulnerabilities: frozenset[str]
    products: frozenset[str]
    status: str
    justification: str | None
    document: dict[str, Any]
    statement: dict[str, Any]


@dataclass(frozen=True)
class AcceptAndTrackSurface:
    statement_path: str
    document_id: str
    document_timestamp: str
    document_version: int
    local_products: tuple[str, ...]
    published_repository: str
    policy_product: str
    subcomponents: tuple[str, ...]
    action_statement: str
    action_statement_timestamp: str


@dataclass(frozen=True)
class AcceptAndTrackDisposition:
    vulnerability: str
    packages: tuple[tuple[str, str], ...]
    debt_id: str
    review_by: str
    surfaces: tuple[AcceptAndTrackSurface, ...]


@dataclass(frozen=True)
class ExactNotAffectedSurface:
    statement_path: str
    document_id: str
    document_timestamp: str
    document_version: int
    local_products: tuple[str, ...]
    published_repository: str
    policy_product: str
    subcomponents: tuple[str, ...]
    impact_statement: str


@dataclass(frozen=True)
class ExactNotAffectedDisposition:
    vulnerability: str
    packages: tuple[tuple[str, str], ...]
    absent_packages: tuple[str, ...]
    justification: str
    surfaces: tuple[ExactNotAffectedSurface, ...]


ACCEPT_AND_TRACK_DISPOSITIONS = (
    AcceptAndTrackDisposition(
        vulnerability="CVE-2026-11940",
        packages=(
            ("python3.12", "3.12.13-3.el9_8.1"),
            ("python3.12-libs", "3.12.13-3.el9_8.1"),
        ),
        debt_id="TD-9",
        review_by="2026-10-01",
        surfaces=(
            AcceptAndTrackSurface(
                statement_path="images/python/vex/cve-2026-11940.openvex.json",
                document_id=("https://github.com/NWarila/ubi9-base-micro/images/python/vex/cve-2026-11940"),
                document_timestamp="2026-08-14T00:00:00Z",
                document_version=2,
                local_products=(
                    "local/ubi9-base-python:ci-amd64",
                    "local/ubi9-base-python:ci-arm64",
                ),
                published_repository="ghcr.io/nwarila/ubi9-base-python",
                policy_product=(
                    "https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-python/published-platform-children"
                ),
                subcomponents=(
                    "pkg:rpm/redhat/python3.12@3.12.13-3.el9_8.1",
                    "pkg:rpm/redhat/python3.12-libs@3.12.13-3.el9_8.1",
                ),
                action_statement=TD9_ACTION_STATEMENT,
                action_statement_timestamp="2026-08-13T00:00:00Z",
            ),
        ),
    ),
    AcceptAndTrackDisposition(
        vulnerability="CVE-2026-14456",
        packages=(("openssl-libs", "1:3.5.5-5.el9_8"),),
        debt_id="TD-12",
        review_by="2026-10-01",
        surfaces=(
            AcceptAndTrackSurface(
                statement_path="images/python/vex/cve-2026-14456.openvex.json",
                document_id=("https://github.com/NWarila/ubi9-base-micro/images/python/vex/cve-2026-14456"),
                document_timestamp="2026-08-18T00:00:00Z",
                document_version=1,
                local_products=(
                    "local/ubi9-base-python:ci-amd64",
                    "local/ubi9-base-python:ci-arm64",
                ),
                published_repository="ghcr.io/nwarila/ubi9-base-python",
                policy_product=(
                    "https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-python/published-platform-children"
                ),
                subcomponents=("pkg:rpm/redhat/openssl-libs@3.5.5-5.el9_8?epoch=1",),
                action_statement=CVE_2026_14456_PYTHON_ACTION_STATEMENT,
                action_statement_timestamp="2026-08-18T00:00:00Z",
            ),
            AcceptAndTrackSurface(
                statement_path="vex/cve-2026-14456.openvex.json",
                document_id="https://github.com/NWarila/ubi9-base-micro/vex/cve-2026-14456",
                document_timestamp="2026-08-18T00:00:00Z",
                document_version=1,
                local_products=("ghcr.io/nwarila/ubi9-base-micro:base-micro",),
                published_repository="ghcr.io/nwarila/ubi9-base-micro",
                policy_product=(
                    "https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-micro/published-platform-children"
                ),
                subcomponents=("pkg:rpm/redhat/openssl-libs@3.5.5-5.el9_8?epoch=1",),
                action_statement=CVE_2026_14456_MICRO_ACTION_STATEMENT,
                action_statement_timestamp="2026-08-18T00:00:00Z",
            ),
        ),
    ),
)


CVE_2026_53613_IMPACT_STATEMENT = (
    "The installed libuuid package is built from the util-linux source RPM, so Grype maps CVE-2026-53613 "
    "to it. The vulnerable code is mount(8) at /usr/bin/mount, which is shipped by util-linux-core. Neither "
    "util-linux nor util-linux-core is installed in either image architecture; only libuuid "
    "0:2.37.4-25.el9 is installed from that source RPM. Therefore the vulnerable code is not present in "
    "this product."
)

EXACT_NOT_AFFECTED_DISPOSITIONS = (
    ExactNotAffectedDisposition(
        vulnerability="CVE-2026-53613",
        packages=(("libuuid", "2.37.4-25.el9"),),
        absent_packages=("util-linux", "util-linux-core"),
        justification="vulnerable_code_not_present",
        surfaces=(
            ExactNotAffectedSurface(
                statement_path="images/python/vex/cve-2026-53613.openvex.json",
                document_id="https://github.com/NWarila/ubi9-base-micro/images/python/vex/cve-2026-53613",
                document_timestamp="2026-08-23T00:00:00Z",
                document_version=1,
                local_products=(
                    "local/ubi9-base-python:ci-amd64",
                    "local/ubi9-base-python:ci-arm64",
                ),
                published_repository="ghcr.io/nwarila/ubi9-base-python",
                policy_product=PUBLISHED_PYTHON_CHILD_POLICY_PRODUCT,
                subcomponents=("pkg:rpm/redhat/libuuid@2.37.4-25.el9?epoch=0",),
                impact_statement=CVE_2026_53613_IMPACT_STATEMENT,
            ),
        ),
    ),
)


@dataclass(frozen=True)
class TrivyEvidence:
    artifact_name: str
    image_id: str
    architecture: str
    os_version: str
    repo_digests: tuple[str, ...]
    package_names: frozenset[str]


@dataclass(frozen=True)
class GrypeEvidence:
    source_type: str
    user_input: str | None
    image_id: str | None
    architecture: str | None
    distro_version: str
    repo_digests: tuple[str, ...]


def digest_reference_parts(reference: str, label: str) -> tuple[str, str]:
    if DIGEST_IMAGE_REFERENCE.fullmatch(reference) is None:
        raise VexError(f"{label} must be a digest-qualified image reference")
    repository, digest = reference.rsplit("@", 1)
    return repository, digest


def validate_index_child_evidence(
    product: str,
    architecture: str,
    index_reference: str,
    index_manifest: Path,
    pinned_repository: str,
) -> None:
    product_repository, product_digest = digest_reference_parts(product, "published-child --product")
    if product_repository != pinned_repository:
        raise VexError(f"published-child --product repository must be {pinned_repository}")

    index_repository, index_digest = digest_reference_parts(index_reference, "--index-reference")
    if index_repository != pinned_repository:
        raise VexError(f"--index-reference repository must be {pinned_repository}")

    try:
        index_bytes = index_manifest.read_bytes()
    except FileNotFoundError as exc:
        raise VexError(f"missing index manifest: {index_manifest}") from exc
    actual_index_digest = "sha256:" + hashlib.sha256(index_bytes).hexdigest()
    if actual_index_digest != index_digest:
        raise VexError(
            "index manifest digest mismatch: "
            f"--index-reference declares {index_digest}, bytes compute to {actual_index_digest}"
        )

    try:
        document = json.loads(index_bytes, object_pairs_hook=reject_duplicate_members)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VexError(f"index manifest is malformed JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise VexError("index manifest must be a top-level JSON object")
    if "schemaVersion" not in document:
        raise VexError("index manifest is missing schemaVersion")
    schema_version = document["schemaVersion"]
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise VexError("index manifest schemaVersion must be an integer")
    if schema_version != 2:
        raise VexError("index manifest schemaVersion must equal 2")
    if document.get("mediaType") != OCI_IMAGE_INDEX_MEDIA_TYPE:
        raise VexError(f"index manifest mediaType must be {OCI_IMAGE_INDEX_MEDIA_TYPE}")
    manifests = document.get("manifests")
    if not isinstance(manifests, list):
        raise VexError("index manifest manifests must be a list")
    if not manifests:
        raise VexError("index manifest manifests must not be empty")

    children: dict[str, list[str]] = {architecture: [] for architecture in sorted(SUPPORTED_ARCHITECTURES)}
    attestations: list[tuple[int, str, dict[str, Any]]] = []
    descriptor_digest_first_seen: dict[str, int] = {}
    duplicate_descriptor_digest: tuple[str, int, int] | None = None
    for descriptor_index, raw_descriptor in enumerate(manifests):
        label = f"index manifest manifests[{descriptor_index}]"
        if not isinstance(raw_descriptor, dict):
            raise VexError(f"{label} must be an object")
        for required_field in ("mediaType", "digest", "size"):
            if required_field not in raw_descriptor:
                raise VexError(f"{label} is missing {required_field}")
        descriptor_media_type = raw_descriptor["mediaType"]
        if not isinstance(descriptor_media_type, str) or not descriptor_media_type:
            raise VexError(f"{label}.mediaType must be a non-empty string")
        descriptor_digest = content_digest(raw_descriptor["digest"], f"{label}.digest")
        first_descriptor_index = descriptor_digest_first_seen.get(descriptor_digest)
        if first_descriptor_index is None:
            descriptor_digest_first_seen[descriptor_digest] = descriptor_index
        elif duplicate_descriptor_digest is None:
            duplicate_descriptor_digest = (descriptor_digest, first_descriptor_index, descriptor_index)
        descriptor_size = raw_descriptor["size"]
        if not isinstance(descriptor_size, int) or isinstance(descriptor_size, bool) or descriptor_size < 0:
            raise VexError(f"{label}.size must be a non-negative integer")
        if descriptor_media_type == OCI_IMAGE_INDEX_MEDIA_TYPE:
            raise VexError(f"{label} must not be a nested image index descriptor")
        if descriptor_media_type != OCI_IMAGE_MANIFEST_MEDIA_TYPE:
            raise VexError(f"{label}.mediaType must be {OCI_IMAGE_MANIFEST_MEDIA_TYPE}")

        platform = raw_descriptor.get("platform")
        if not isinstance(platform, dict):
            raise VexError(f"{label}.platform must be an object")
        operating_system = platform.get("os")
        platform_architecture = platform.get("architecture")
        if (
            not isinstance(operating_system, str)
            or not operating_system
            or not isinstance(platform_architecture, str)
            or not platform_architecture
        ):
            raise VexError(f"{label}.platform os and architecture must be non-empty strings")
        if operating_system == "linux":
            if platform_architecture not in SUPPORTED_ARCHITECTURES:
                raise VexError(f"index manifest contains unsupported runnable platform linux/{platform_architecture}")
            children[platform_architecture].append(descriptor_digest)
            continue
        if operating_system == "unknown" and platform_architecture == "unknown":
            if set(platform) != {"os", "architecture"}:
                raise VexError(f"{label}.platform must equal the locked unknown/unknown attestation platform")
            attestations.append((descriptor_index, descriptor_digest, raw_descriptor))
            continue
        raise VexError(
            f"index manifest contains unsupported descriptor platform {operating_system}/{platform_architecture}"
        )

    for required_architecture in sorted(SUPPORTED_ARCHITECTURES):
        count = len(children[required_architecture])
        if count != 1:
            raise VexError(
                "index manifest must contain exactly one "
                f"linux/{required_architecture} image manifest descriptor; found {count}"
            )
    child_digests = {required_architecture: values[0] for required_architecture, values in children.items()}
    if child_digests["amd64"] == child_digests["arm64"]:
        raise VexError("index manifest linux/amd64 and linux/arm64 child digests must be distinct")

    eligible_child_digests = frozenset(child_digests.values())
    attestation_digests: set[str] = set()
    locked_annotation_keys = {
        BUILDKIT_ATTESTATION_TYPE_ANNOTATION,
        BUILDKIT_ATTESTATION_DIGEST_ANNOTATION,
    }
    for descriptor_index, descriptor_digest, descriptor in attestations:
        label = f"index manifest manifests[{descriptor_index}]"
        annotations = descriptor.get("annotations")
        if (
            not isinstance(annotations, dict)
            or annotations.get(BUILDKIT_ATTESTATION_TYPE_ANNOTATION) != BUILDKIT_ATTESTATION_TYPE
        ):
            raise VexError(
                f"{label} unknown/unknown descriptor must carry "
                f"{BUILDKIT_ATTESTATION_TYPE_ANNOTATION}={BUILDKIT_ATTESTATION_TYPE}"
            )
        reference_digest = content_digest(
            annotations.get(BUILDKIT_ATTESTATION_DIGEST_ANNOTATION),
            f"{label}.annotations[{BUILDKIT_ATTESTATION_DIGEST_ANNOTATION!r}]",
        )
        if reference_digest not in eligible_child_digests:
            raise VexError(f"{label} attestation reference digest must name an eligible platform child")
        if set(annotations) != locked_annotation_keys:
            raise VexError(f"{label}.annotations must equal the locked BuildKit attestation shape")
        attestation_digests.add(descriptor_digest)

    if not attestation_digests.isdisjoint(eligible_child_digests):
        raise VexError(
            "index manifest attestation descriptor digests must be disjoint from eligible platform child digests"
        )
    if duplicate_descriptor_digest is not None:
        descriptor_digest, first_descriptor_index, duplicate_descriptor_index = duplicate_descriptor_digest
        raise VexError(
            f"index manifest descriptor digest {descriptor_digest} is repeated at "
            f"manifests[{first_descriptor_index}] and manifests[{duplicate_descriptor_index}]; "
            "duplicate or contradictory descriptors are forbidden"
        )
    if product_digest == index_digest:
        raise VexError("the index digest is never eligible as a published-child product")
    expected_child_digest = child_digests[architecture]
    if product_digest == expected_child_digest:
        return
    if product_digest in attestation_digests:
        raise VexError("published-child product digest identifies an attestation descriptor")
    if product_digest in eligible_child_digests:
        raise VexError(
            f"published-child product digest does not match the index child for scanner architecture {architecture}"
        )
    raise VexError("published-child product digest is absent from the verified index")


def accept_and_track_surface_candidates(
    finding: Finding,
    product: str,
    architecture: str,
    index_reference: str | None,
    index_manifest: Path | None,
    dispositions: tuple[AcceptAndTrackDisposition, ...],
) -> list[tuple[AcceptAndTrackDisposition, AcceptAndTrackSurface]]:
    if (index_reference is None) != (index_manifest is None):
        raise VexError("--index-reference and --index-manifest must be supplied together")

    identity_candidates = [
        disposition
        for disposition in dispositions
        if disposition.vulnerability == finding.vulnerability
        and finding_package_versions(finding) == frozenset(disposition.packages)
    ]
    local_candidates = [
        (disposition, surface)
        for disposition in identity_candidates
        for surface in disposition.surfaces
        if product in surface.local_products
    ]
    if local_candidates:
        if index_reference is not None:
            raise VexError("index evidence must not be supplied for a local accept-and-track product")
        return local_candidates
    if not identity_candidates:
        return []
    if index_reference is None or index_manifest is None:
        return []

    product_repository, _product_digest = digest_reference_parts(product, "published-child --product")
    index_repository, _index_digest = digest_reference_parts(index_reference, "--index-reference")
    repositories = sorted(
        {surface.published_repository for disposition in identity_candidates for surface in disposition.surfaces}
    )
    if product_repository not in repositories:
        if len(repositories) == 1:
            raise VexError(f"published-child --product repository must be {repositories[0]}")
        expected = ",".join(repositories) if repositories else "none"
        raise VexError(
            "published-child repository does not match a pinned accept-and-track surface: "
            f"observed={product_repository} expected={expected}"
        )
    if index_repository != product_repository:
        raise VexError(f"--index-reference repository must be {product_repository}")
    published_candidates = [
        (disposition, surface)
        for disposition in identity_candidates
        for surface in disposition.surfaces
        if surface.published_repository == product_repository
    ]
    if not published_candidates:
        expected = ",".join(repositories) if repositories else "none"
        raise VexError(
            "published-child repository does not match a pinned accept-and-track surface: "
            f"observed={product_repository} expected={expected}"
        )
    validate_index_child_evidence(
        product,
        architecture,
        index_reference,
        index_manifest,
        product_repository,
    )
    return published_candidates


def exact_not_affected_surface_candidates(
    finding: Finding,
    product: str,
    architecture: str,
    index_reference: str | None,
    index_manifest: Path | None,
    dispositions: tuple[ExactNotAffectedDisposition, ...],
) -> list[tuple[ExactNotAffectedDisposition, ExactNotAffectedSurface]]:
    if (index_reference is None) != (index_manifest is None):
        raise VexError("--index-reference and --index-manifest must be supplied together")

    identity_candidates = [
        disposition
        for disposition in dispositions
        if disposition.vulnerability == finding.vulnerability
        and finding_package_versions(finding) == frozenset(disposition.packages)
    ]
    local_candidates = [
        (disposition, surface)
        for disposition in identity_candidates
        for surface in disposition.surfaces
        if product in surface.local_products
    ]
    if local_candidates:
        if index_reference is not None:
            raise VexError("index evidence must not be supplied for a local exact not-affected product")
        return local_candidates
    if not identity_candidates:
        return []
    if index_reference is None or index_manifest is None:
        return []

    product_repository, _product_digest = digest_reference_parts(product, "published-child --product")
    index_repository, _index_digest = digest_reference_parts(index_reference, "--index-reference")
    repositories = sorted(
        {surface.published_repository for disposition in identity_candidates for surface in disposition.surfaces}
    )
    if product_repository not in repositories:
        if len(repositories) == 1:
            raise VexError(f"published-child --product repository must be {repositories[0]}")
        expected = ",".join(repositories) if repositories else "none"
        raise VexError(
            "published-child repository does not match a pinned exact not-affected surface: "
            f"observed={product_repository} expected={expected}"
        )
    if index_repository != product_repository:
        raise VexError(f"--index-reference repository must be {product_repository}")
    published_candidates = [
        (disposition, surface)
        for disposition in identity_candidates
        for surface in disposition.surfaces
        if surface.published_repository == product_repository
    ]
    if not published_candidates:
        expected = ",".join(repositories) if repositories else "none"
        raise VexError(
            "published-child repository does not match a pinned exact not-affected surface: "
            f"observed={product_repository} expected={expected}"
        )
    validate_index_child_evidence(
        product,
        architecture,
        index_reference,
        index_manifest,
        product_repository,
    )
    return published_candidates


def accept_and_track_product_eligible(
    product: str,
    architecture: str,
    index_reference: str | None,
    index_manifest: Path | None,
    surface: AcceptAndTrackSurface,
) -> bool:
    """Exercise one explicit surface in the standalone OCI-index self-test matrix."""
    if (index_reference is None) != (index_manifest is None):
        raise VexError("--index-reference and --index-manifest must be supplied together")
    if product in surface.local_products:
        if index_reference is not None:
            raise VexError("index evidence must not be supplied for a local accept-and-track product")
        return True
    if index_reference is None or index_manifest is None:
        return False
    validate_index_child_evidence(
        product,
        architecture,
        index_reference,
        index_manifest,
        surface.published_repository,
    )
    return True


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_members,
        )
    except FileNotFoundError as exc:
        raise VexError(f"missing JSON input: {path}") from exc
    except json.JSONDecodeError as exc:
        raise VexError(f"invalid JSON in {path}: {exc}") from exc


def scanner_document(path: Path, scanner: str) -> dict[str, Any]:
    document = load_json(path)
    if not isinstance(document, dict):
        raise VexError(f"{scanner} report must be a JSON object")
    return document


def non_empty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VexError(f"{label} must be a non-empty string")
    return value.strip()


def content_digest(value: Any, label: str) -> str:
    digest = non_empty_string(value, label)
    if digest != value or CONTENT_DIGEST.fullmatch(digest) is None:
        raise VexError(f"{label} must be a sha256 content digest")
    return digest


def scanner_version(value: Any, label: str) -> str:
    version = non_empty_string(value, label)
    if version != value or SCANNER_VERSION.fullmatch(version) is None:
        raise VexError(f"{label} must be a three-component numeric version")
    return version


def supported_architecture(value: Any, label: str) -> str:
    architecture = non_empty_string(value, label)
    if architecture != value or architecture not in SUPPORTED_ARCHITECTURES:
        raise VexError(f"{label} must be amd64 or arm64")
    return architecture


def finding_severity(value: Any, label: str) -> str:
    normalized = non_empty_string(value, label).upper()
    if normalized not in SEVERITY_ORDER:
        raise VexError(f"{label} has unsupported value {value!r}")
    return normalized


def repository_digest(value: Any, label: str) -> str:
    reference = non_empty_string(value, label)
    if reference != value or DIGEST_IMAGE_REFERENCE.fullmatch(reference) is None:
        raise VexError(f"{label} must be a digest-qualified image reference")
    return reference


def optional_repo_digests(value: dict[str, Any], key: str, label: str) -> tuple[str, ...]:
    if key not in value:
        return ()
    raw_references = value[key]
    if not isinstance(raw_references, list):
        raise VexError(f"{label} must be a list when present")
    return tuple(repository_digest(reference, f"{label}[{index}]") for index, reference in enumerate(raw_references))


def validate_trivy_report(document: dict[str, Any]) -> TrivyEvidence:
    schema_version = document.get("SchemaVersion")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version != 2:
        raise VexError("Trivy SchemaVersion must be 2")

    trivy = document.get("Trivy")
    if not isinstance(trivy, dict):
        raise VexError("Trivy identity must be an object")
    scanner_version(trivy.get("Version"), "Trivy.Version")

    artifact_name = non_empty_string(document.get("ArtifactName"), "Trivy ArtifactName")
    if document.get("ArtifactType") != "container_image":
        raise VexError("Trivy ArtifactType must be container_image")

    metadata = document.get("Metadata")
    if not isinstance(metadata, dict):
        raise VexError("Trivy Metadata must be an object")
    operating_system = metadata.get("OS")
    if not isinstance(operating_system, dict):
        raise VexError("Trivy Metadata.OS must be an object")
    if operating_system.get("Family") != "redhat":
        raise VexError("Trivy Metadata.OS.Family must be redhat")
    os_version = non_empty_string(operating_system.get("Name"), "Trivy Metadata.OS.Name")
    image_id = content_digest(metadata.get("ImageID"), "Trivy Metadata.ImageID")
    image_config = metadata.get("ImageConfig")
    if not isinstance(image_config, dict):
        raise VexError("Trivy Metadata.ImageConfig must be an object")
    architecture = supported_architecture(
        image_config.get("architecture"),
        "Trivy Metadata.ImageConfig.architecture",
    )
    repo_digests = optional_repo_digests(metadata, "RepoDigests", "Trivy Metadata.RepoDigests")

    results = document.get("Results")
    if not isinstance(results, list):
        raise VexError("Trivy Results must be a list")
    package_names: set[str] = set()
    os_result_seen = False
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise VexError(f"Trivy Results[{result_index}] must be an object")
        non_empty_string(result.get("Target"), f"Trivy Results[{result_index}].Target")
        if result.get("Class") != "os-pkgs" or result.get("Type") != "redhat":
            continue
        os_result_seen = True
        packages = result.get("Packages")
        if not isinstance(packages, list):
            raise VexError(f"Trivy Results[{result_index}].Packages must be a list")
        for package_index, package in enumerate(packages):
            if not isinstance(package, dict):
                raise VexError(f"Trivy Results[{result_index}].Packages[{package_index}] must be an object")
            package_names.add(
                non_empty_string(
                    package.get("Name"),
                    f"Trivy Results[{result_index}].Packages[{package_index}].Name",
                )
            )
            non_empty_string(
                package.get("Version"),
                f"Trivy Results[{result_index}].Packages[{package_index}].Version",
            )
    if not os_result_seen:
        raise VexError("Trivy report requires at least one Class=os-pkgs Type=redhat result")
    if not package_names:
        raise VexError("Trivy os-pkgs/redhat inventory must be non-empty")

    return TrivyEvidence(
        artifact_name=artifact_name,
        image_id=image_id,
        architecture=architecture,
        os_version=os_version,
        repo_digests=repo_digests,
        package_names=frozenset(package_names),
    )


def validate_grype_report(document: dict[str, Any]) -> GrypeEvidence:
    descriptor = document.get("descriptor")
    if not isinstance(descriptor, dict) or descriptor.get("name") != "grype":
        raise VexError("Grype report must contain a grype descriptor")
    scanner_version(descriptor.get("version"), "Grype descriptor.version")

    distro = document.get("distro")
    if not isinstance(distro, dict):
        raise VexError("Grype distro must be an object")
    if distro.get("name") != "redhat":
        raise VexError("Grype distro.name must be redhat")
    distro_version = non_empty_string(distro.get("version"), "Grype distro.version")

    source = document.get("source")
    if not isinstance(source, dict):
        raise VexError("Grype source must be an object")
    source_type = source.get("type")
    target = source.get("target")
    if source_type == "image":
        if not isinstance(target, dict):
            raise VexError("Grype image source.target must be an object")
        user_input = non_empty_string(target.get("userInput"), "Grype source.target.userInput")
        image_id = content_digest(target.get("imageID"), "Grype source.target.imageID")
        architecture = supported_architecture(target.get("architecture"), "Grype source.target.architecture")
        repo_digests = optional_repo_digests(target, "repoDigests", "Grype source.target.repoDigests")
    elif source_type == "directory":
        non_empty_string(target, "Grype directory source.target")
        user_input = None
        image_id = None
        architecture = None
        repo_digests = ()
    else:
        raise VexError("Grype source.type must be image or directory")

    matches = document.get("matches")
    if not isinstance(matches, list):
        raise VexError("Grype matches must be a list")

    return GrypeEvidence(
        source_type=source_type,
        user_input=user_input,
        image_id=image_id,
        architecture=architecture,
        distro_version=distro_version,
        repo_digests=repo_digests,
    )


def validate_report_binding(
    product: str,
    trivy: TrivyEvidence,
    grype: GrypeEvidence,
) -> None:
    expected_product = non_empty_string(product, "--product")
    if expected_product != product:
        raise VexError("--product must not contain surrounding whitespace")
    if IMAGE_REFERENCE.fullmatch(expected_product) is None:
        raise VexError("--product must be a well-formed image reference")
    if grype.source_type != "image":
        raise VexError("report binding requires a Grype image source")
    if trivy.artifact_name != expected_product:
        raise VexError("Trivy ArtifactName does not match --product")
    if grype.user_input != expected_product:
        raise VexError("Grype source.target.userInput does not match --product")
    if trivy.image_id != grype.image_id:
        raise VexError("Trivy and Grype imageID values do not match")
    if trivy.architecture != grype.architecture:
        raise VexError("Trivy and Grype architecture values do not match")
    if trivy.os_version != grype.distro_version:
        raise VexError("Trivy OS and Grype distro versions do not match")
    if RHEL_9_RELEASE.fullmatch(trivy.os_version) is None:
        raise VexError("Trivy OS and Grype distro versions must identify RHEL 9")
    digest_addressed = DIGEST_IMAGE_REFERENCE.fullmatch(expected_product) is not None
    if digest_addressed and not trivy.repo_digests:
        raise VexError("Trivy Metadata.RepoDigests is required for a digest-addressed --product")
    if digest_addressed and not grype.repo_digests:
        raise VexError("Grype source.target.repoDigests is required for a digest-addressed --product")
    if digest_addressed and expected_product not in trivy.repo_digests:
        raise VexError("Trivy Metadata.RepoDigests does not contain --product")
    if digest_addressed and expected_product not in grype.repo_digests:
        raise VexError("Grype source.target.repoDigests does not contain --product")
    if frozenset(trivy.repo_digests) != frozenset(grype.repo_digests):
        raise VexError("Trivy and Grype repository digest evidence does not match")


def package_floor_names(path: Path, architecture: str) -> frozenset[str]:
    document = load_json(path)
    if not isinstance(document, dict):
        raise VexError(f"package floor contract must be a JSON object: {path}")

    runtime = document.get("runtime")
    raw_floor: Any
    nevra_floor = False
    if isinstance(runtime, dict) and "package_floor" in runtime:
        raw_floor = runtime["package_floor"]
    else:
        parent = document.get("parent")
        floor = parent.get("floor") if isinstance(parent, dict) else None
        if not isinstance(floor, dict) or architecture not in floor:
            raise VexError(f"{path}: missing package floor for architecture {architecture}")
        raw_floor = floor[architecture]
        nevra_floor = True

    if not isinstance(raw_floor, list) or not raw_floor:
        raise VexError(f"{path}: package floor must be a non-empty list")

    names: set[str] = set()
    for index, raw_package in enumerate(raw_floor):
        package = non_empty_string(raw_package, f"{path}: package floor[{index}]")
        if nevra_floor:
            parts = package.rsplit("-", 2)
            if len(parts) != 3 or not parts[0]:
                raise VexError(f"{path}: package floor[{index}] must be an RPM NEVRA")
            package = parts[0]
        names.add(package)
    return frozenset(names)


def validate_contract_floor(path: Path, architecture: str, inventory: frozenset[str]) -> None:
    expected = package_floor_names(path, architecture)
    missing = sorted(expected - inventory)
    if missing:
        raise VexError("Trivy inventory missing contract package floor: " + ", ".join(missing))


def trivy_has_fix(vulnerability: dict[str, Any]) -> bool:
    fixed_version = ""
    if "FixedVersion" in vulnerability:
        raw_fixed_version = vulnerability["FixedVersion"]
        if not isinstance(raw_fixed_version, str):
            return False
        fixed_version = raw_fixed_version.strip()
    status: str | None = None
    if "Status" in vulnerability:
        raw_status = vulnerability["Status"]
        if not isinstance(raw_status, str) or raw_status not in TRIVY_FIX_STATUSES:
            return False
        status = raw_status
    return bool(fixed_version) or status == "fixed"


def parse_trivy(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    results = data.get("Results")
    if not isinstance(results, list):
        raise VexError("Trivy Results must be a list")
    for result_index, result in enumerate(results):
        raw_vulnerabilities = result.get("Vulnerabilities")
        if raw_vulnerabilities is None:
            continue
        if not isinstance(raw_vulnerabilities, list):
            raise VexError(f"Trivy Results[{result_index}].Vulnerabilities must be a list or null")
        for finding_index, vulnerability in enumerate(raw_vulnerabilities):
            label = f"Trivy Results[{result_index}].Vulnerabilities[{finding_index}]"
            if not isinstance(vulnerability, dict):
                raise VexError(f"{label} must be an object")
            raw_vuln_id = vulnerability.get("VulnerabilityID")
            vuln_id = non_empty_string(raw_vuln_id, f"{label}.VulnerabilityID")
            sev = finding_severity(vulnerability.get("Severity"), f"{label}.Severity")
            raw_package = vulnerability.get("PkgName")
            package = non_empty_string(raw_package, f"{label}.PkgName")
            if sev not in HIGH_CRITICAL:
                continue
            raw_version = vulnerability.get("InstalledVersion")
            version = raw_version.strip() if isinstance(raw_version, str) else ""
            identity_rejections = tuple(
                f"{field_label} must not contain surrounding whitespace"
                for raw_value, normalized, field_label in (
                    (raw_vuln_id, vuln_id, f"{label}.VulnerabilityID"),
                    (raw_package, package, f"{label}.PkgName"),
                    (raw_version, version, f"{label}.InstalledVersion"),
                )
                if isinstance(raw_value, str) and raw_value != normalized
            )
            has_fix = trivy_has_fix(vulnerability)
            findings.append(
                Finding(
                    vulnerability=vuln_id,
                    severity=sev,
                    scanners=set() if has_fix else {"trivy"},
                    packages=set() if has_fix else {package},
                    records=[FindingRecord("trivy", package, version, has_fix, identity_rejections)],
                )
            )
    return findings


def grype_has_fix(vulnerability: dict[str, Any]) -> bool:
    raw_fix = vulnerability.get("fix")
    if raw_fix is None:
        return False
    if not isinstance(raw_fix, dict):
        return False
    # `available` is deliberately unread and descriptive here. Any future fixability
    # decision that consults it must validate it in the same change.
    raw_versions = raw_fix.get("versions")
    versions_valid = isinstance(raw_versions, list) and all(
        isinstance(version, str) and bool(version.strip()) for version in raw_versions
    )
    if not versions_valid:
        return False
    versions = raw_versions
    raw_state = raw_fix.get("state")
    state_valid = isinstance(raw_state, str) and raw_state in GRYPE_FIX_STATES
    if not state_valid:
        return False
    state = raw_state
    return bool(versions) or state == "fixed"


def parse_grype(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    matches = data.get("matches")
    if not isinstance(matches, list):
        raise VexError("Grype matches must be a list")
    for match_index, match in enumerate(matches):
        label = f"Grype matches[{match_index}]"
        if not isinstance(match, dict):
            raise VexError(f"{label} must be an object")
        vulnerability = match.get("vulnerability")
        if not isinstance(vulnerability, dict):
            raise VexError(f"{label}.vulnerability must be an object")
        artifact = match.get("artifact")
        if not isinstance(artifact, dict):
            raise VexError(f"{label}.artifact must be an object")
        raw_vuln_id = vulnerability.get("id")
        vuln_id = non_empty_string(raw_vuln_id, f"{label}.vulnerability.id")
        sev = finding_severity(vulnerability.get("severity"), f"{label}.vulnerability.severity")
        raw_package = artifact.get("name")
        package = non_empty_string(raw_package, f"{label}.artifact.name")
        if sev not in HIGH_CRITICAL:
            continue
        raw_version = artifact.get("version")
        version = raw_version.strip() if isinstance(raw_version, str) else ""
        identity_rejections = tuple(
            f"{field_label} must not contain surrounding whitespace"
            for raw_value, normalized, field_label in (
                (raw_vuln_id, vuln_id, f"{label}.vulnerability.id"),
                (raw_package, package, f"{label}.artifact.name"),
                (raw_version, version, f"{label}.artifact.version"),
            )
            if isinstance(raw_value, str) and raw_value != normalized
        )
        has_fix = grype_has_fix(vulnerability)
        findings.append(
            Finding(
                vulnerability=vuln_id,
                severity=sev,
                scanners=set() if has_fix else {"grype"},
                packages=set() if has_fix else {package},
                records=[FindingRecord("grype", package, version, has_fix, identity_rejections)],
            )
        )
    return findings


def union_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.vulnerability)
        if existing is None:
            merged[finding.vulnerability] = finding
        else:
            existing.merge(finding)
    return [merged[key] for key in sorted(merged) if merged[key].scanners]


def extract_vulnerability_ids(value: Any) -> frozenset[str]:
    ids: set[str] = set()
    if isinstance(value, str):
        ids.add(value.strip())
    elif isinstance(value, dict):
        for key in ("name", "id", "@id"):
            candidate = value.get(key)
            if candidate:
                ids.add(str(candidate).strip())
        aliases = value.get("aliases")
        if isinstance(aliases, list):
            ids.update(str(alias).strip() for alias in aliases if str(alias).strip())
    return frozenset(vuln for vuln in ids if vuln)


def extract_product_ids(product: Any) -> set[str]:
    ids: set[str] = set()
    if isinstance(product, str):
        if product.strip():
            ids.add(product.strip())
        return ids

    if not isinstance(product, dict):
        return ids

    for key in ("@id", "id", "name"):
        candidate = product.get(key)
        if candidate:
            ids.add(str(candidate).strip())

    identifiers = product.get("identifiers")
    if isinstance(identifiers, dict):
        ids.update(str(value).strip() for value in identifiers.values() if str(value).strip())
    elif isinstance(identifiers, list):
        for item in identifiers:
            if isinstance(item, str) and item.strip():
                ids.add(item.strip())
            elif isinstance(item, dict):
                ids.update(str(value).strip() for value in item.values() if str(value).strip())

    return ids


def load_vex_statements(vex_dir: Path) -> list[Statement]:
    if not vex_dir.is_dir():
        raise VexError(f"missing VEX directory: {vex_dir}")

    statements: list[Statement] = []
    for path in sorted(vex_dir.glob("*.json")):
        document = load_json(path)
        if "@context" not in document:
            raise VexError(f"{path}: missing @context")
        raw_statements = document.get("statements")
        if not isinstance(raw_statements, list):
            raise VexError(f"{path}: statements must be a list")

        for index, raw in enumerate(raw_statements):
            if not isinstance(raw, dict):
                raise VexError(f"{path}: statement {index} must be an object")
            vulnerabilities = extract_vulnerability_ids(raw.get("vulnerability"))
            if not vulnerabilities:
                raise VexError(f"{path}: statement {index} missing vulnerability id")

            status = str(raw.get("status") or "").strip()
            if status not in OPENVEX_STATUSES:
                raise VexError(f"{path}: statement {index} has invalid status {status!r}")

            justification = raw.get("justification")
            justification_text = str(justification).strip() if justification is not None else None
            if status == "not_affected":
                if not justification_text:
                    raise VexError(f"{path}: statement {index} not_affected requires justification")
                if justification_text not in OPENVEX_NOT_AFFECTED_JUSTIFICATIONS:
                    raise VexError(f"{path}: statement {index} has unsupported justification {justification_text!r}")

            raw_products = raw.get("products")
            if not isinstance(raw_products, list) or not raw_products:
                raise VexError(f"{path}: statement {index} requires non-empty products")
            products: set[str] = set()
            for product in raw_products:
                products.update(extract_product_ids(product))
            if not products:
                raise VexError(f"{path}: statement {index} has no product identifiers")

            statements.append(
                Statement(
                    path=path,
                    index=index,
                    vulnerabilities=vulnerabilities,
                    products=frozenset(products),
                    status=status,
                    justification=justification_text,
                    document=document,
                    statement=raw,
                )
            )
    return statements


def product_candidates(product: str) -> set[str]:
    return {product, f"pkg:oci/{product}"}


def vulnerable_code_absence_rejection(statement: Statement, package_names: frozenset[str]) -> str | None:
    if statement.justification != "vulnerable_code_not_present":
        return None
    statement_id = statement.statement.get("@id")
    if not isinstance(statement_id, str) or not statement_id.startswith(VULNERABLE_CODE_ABSENCE_ID_PREFIX):
        return "vulnerable_code_not_present requires a statement @id declaring absent packages"
    absent_packages = statement_id.removeprefix(VULNERABLE_CODE_ABSENCE_ID_PREFIX).split(",")
    if not absent_packages or any(not name or name.strip() != name for name in absent_packages):
        return "vulnerable_code_not_present statement @id has an invalid absent-packages set"
    contradictions = sorted(set(absent_packages) & package_names)
    if contradictions:
        return (
            "vulnerable_code_not_present contradiction: scanned Trivy inventory contains "
            f"declared-absent package(s): {','.join(contradictions)}"
        )
    return None


def accepted_statement(
    finding: Finding,
    product: str,
    statements: list[Statement],
    package_names: frozenset[str],
) -> Statement | None:
    candidates = product_candidates(product)
    for statement in statements:
        if finding.vulnerability not in statement.vulnerabilities:
            continue
        if statement.status not in ACCEPTED_STATUSES:
            continue
        if statement.status == "not_affected" and not statement.justification:
            continue
        if statement.products.isdisjoint(candidates):
            continue
        rejection = vulnerable_code_absence_rejection(statement, package_names)
        if rejection is not None:
            raise VexError(rejection)
        return statement
    return None


def expected_accept_and_track_document(
    disposition: AcceptAndTrackDisposition,
    surface: AcceptAndTrackSurface,
) -> dict[str, Any]:
    products = [
        {
            "@id": product,
            "subcomponents": [{"@id": subcomponent} for subcomponent in surface.subcomponents],
        }
        for product in (*surface.local_products, surface.policy_product)
    ]
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": surface.document_id,
        "author": "NWarila",
        "timestamp": surface.document_timestamp,
        "version": surface.document_version,
        "statements": [
            {
                "vulnerability": {"name": disposition.vulnerability},
                "products": products,
                "status": "affected",
                "action_statement": surface.action_statement,
                "action_statement_timestamp": surface.action_statement_timestamp,
            }
        ],
    }


def expected_exact_not_affected_document(
    disposition: ExactNotAffectedDisposition,
    surface: ExactNotAffectedSurface,
) -> dict[str, Any]:
    products = [
        {
            "@id": product,
            "subcomponents": [{"@id": subcomponent} for subcomponent in surface.subcomponents],
        }
        for product in (*surface.local_products, surface.policy_product)
    ]
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": surface.document_id,
        "author": "NWarila",
        "timestamp": surface.document_timestamp,
        "version": surface.document_version,
        "statements": [
            {
                "@id": VULNERABLE_CODE_ABSENCE_ID_PREFIX + ",".join(disposition.absent_packages),
                "vulnerability": {"name": disposition.vulnerability},
                "products": products,
                "status": "not_affected",
                "justification": disposition.justification,
                "impact_statement": surface.impact_statement,
            }
        ],
    }


def finding_package_versions(finding: Finding) -> frozenset[tuple[str, str]]:
    return frozenset((record.package, record.version) for record in finding.records if not record.has_fix)


def statement_path_matches(path: Path, expected: str) -> bool:
    canonical_paths = {
        surface.statement_path for disposition in ACCEPT_AND_TRACK_DISPOSITIONS for surface in disposition.surfaces
    }
    canonical_paths.update(
        surface.statement_path for disposition in EXACT_NOT_AFFECTED_DISPOSITIONS for surface in disposition.surfaces
    )
    matching_paths = [
        candidate
        for candidate in canonical_paths
        if len(path.parts) >= len(Path(candidate).parts)
        and path.parts[-len(Path(candidate).parts) :] == Path(candidate).parts
    ]
    if not matching_paths:
        return False
    longest_match = max(matching_paths, key=lambda candidate: len(Path(candidate).parts))
    return expected == longest_match


def accept_and_track_statement_rejection(
    statement: Statement,
    disposition: AcceptAndTrackDisposition,
    surface: AcceptAndTrackSurface,
) -> str | None:
    if not statement_path_matches(statement.path, surface.statement_path):
        return f"statement source must be {surface.statement_path}"

    document = statement.document
    expected = expected_accept_and_track_document(disposition, surface)
    top_keys = {"@context", "@id", "author", "timestamp", "version", "statements"}
    if set(document) != top_keys:
        return "statement document has unexpected or missing top-level fields"
    for key in ("@context", "@id", "author", "timestamp", "version"):
        if document.get(key) != expected[key]:
            return f"statement document field {key} does not match the canonical value"

    raw_statements = document.get("statements")
    if not isinstance(raw_statements, list) or len(raw_statements) != 1:
        return "statement document must contain exactly one statement"
    raw = statement.statement
    statement_keys = {
        "vulnerability",
        "products",
        "status",
        "action_statement",
        "action_statement_timestamp",
    }
    if set(raw) != statement_keys:
        return "accept-and-track statement has unexpected or missing fields"
    vulnerability = raw.get("vulnerability")
    if not isinstance(vulnerability, dict) or set(vulnerability) != {"name"}:
        return "accept-and-track vulnerability must contain only its name"
    if vulnerability.get("name") != disposition.vulnerability:
        return f"accept-and-track vulnerability must be {disposition.vulnerability}"

    expected_statement = expected["statements"][0]
    if raw.get("products") != expected_statement["products"]:
        return "accept-and-track products and subcomponents must match the canonical ordered set"
    if raw.get("status") != "affected":
        return "accept-and-track status must be affected"

    action_statement = raw.get("action_statement")
    if not isinstance(action_statement, str):
        return "accept-and-track action_statement must be a string"
    review_markers = re.findall(r"review-by [0-9]{4}-[0-9]{2}-[0-9]{2}", action_statement)
    if len(review_markers) != 1:
        return "accept-and-track action_statement must contain exactly one review-by marker"
    expected_review_marker = f"review-by {disposition.review_by}"
    if review_markers[0] != expected_review_marker:
        return f"accept-and-track action_statement must contain {expected_review_marker}"
    if disposition.debt_id not in action_statement:
        return f"accept-and-track action_statement must name {disposition.debt_id}"
    if action_statement != surface.action_statement:
        return "accept-and-track action_statement does not match the canonical text"
    if raw.get("action_statement_timestamp") != expected_statement["action_statement_timestamp"]:
        return "accept-and-track action_statement_timestamp does not match the canonical value"
    if document != expected:
        return "accept-and-track statement does not match the canonical document"
    return None


def exact_not_affected_statement_rejection(
    statement: Statement,
    disposition: ExactNotAffectedDisposition,
    surface: ExactNotAffectedSurface,
) -> str | None:
    if not statement_path_matches(statement.path, surface.statement_path):
        return f"statement source must be {surface.statement_path}"

    document = statement.document
    expected = expected_exact_not_affected_document(disposition, surface)
    top_keys = {"@context", "@id", "author", "timestamp", "version", "statements"}
    if set(document) != top_keys:
        return "exact not-affected document has unexpected or missing top-level fields"
    for key in ("@context", "@id", "author", "timestamp", "version"):
        if document.get(key) != expected[key]:
            return f"exact not-affected document field {key} does not match the canonical value"

    raw_statements = document.get("statements")
    if not isinstance(raw_statements, list) or len(raw_statements) != 1:
        return "exact not-affected document must contain exactly one statement"
    raw = statement.statement
    statement_keys = {
        "@id",
        "vulnerability",
        "products",
        "status",
        "justification",
        "impact_statement",
    }
    if set(raw) != statement_keys:
        return "exact not-affected statement has unexpected or missing fields"
    vulnerability = raw.get("vulnerability")
    if not isinstance(vulnerability, dict) or set(vulnerability) != {"name"}:
        return "exact not-affected vulnerability must contain only its name"
    if vulnerability.get("name") != disposition.vulnerability:
        return f"exact not-affected vulnerability must be {disposition.vulnerability}"

    expected_statement = expected["statements"][0]
    if raw.get("products") != expected_statement["products"]:
        return "exact not-affected products and subcomponents must match the canonical ordered set"
    if raw.get("status") != "not_affected":
        return "exact not-affected status must be not_affected"
    if raw.get("justification") != disposition.justification:
        return f"exact not-affected justification must be {disposition.justification}"
    if raw.get("impact_statement") != surface.impact_statement:
        return "exact not-affected impact_statement does not match the canonical text"
    if document != expected:
        return "exact not-affected statement does not match the canonical document"
    return None


def accepted_accept_and_track_statement(
    finding: Finding,
    product: str,
    statements: list[Statement],
    dispositions: tuple[AcceptAndTrackDisposition, ...],
    today: date,
    architecture: str,
    index_reference: str | None,
    index_manifest: Path | None,
) -> tuple[Statement | None, AcceptAndTrackDisposition | None, AcceptAndTrackSurface | None, str | None]:
    identity_rejections = sorted({rejection for record in finding.records for rejection in record.identity_rejections})
    if identity_rejections:
        return (
            None,
            None,
            None,
            "malformed accept-and-track scanner identity evidence: " + "; ".join(identity_rejections),
        )
    candidates = accept_and_track_surface_candidates(
        finding,
        product,
        architecture,
        index_reference,
        index_manifest,
        dispositions,
    )
    if not candidates:
        return None, None, None, "no exact in-tool accept-and-track allowlist entry"
    if len(candidates) > 1:
        return (
            None,
            None,
            None,
            f"multiple exact in-tool accept-and-track authorization matches: {len(candidates)}",
        )
    disposition, surface = candidates[0]
    canonical_pairs = [
        (canonical_disposition, canonical_surface)
        for canonical_disposition in ACCEPT_AND_TRACK_DISPOSITIONS
        for canonical_surface in canonical_disposition.surfaces
    ]
    if (disposition, surface) not in canonical_pairs:
        return None, None, None, "in-tool accept-and-track allowlist entry does not match the canonical authorization"

    review_by = date.fromisoformat(disposition.review_by)
    if today > review_by:
        packages = ",".join(f"{name}@{version}" for name, version in disposition.packages)
        raise VexError(
            "expired accept-and-track entry: "
            f"{disposition.vulnerability} product={product} packages={packages} "
            f"debt={disposition.debt_id} review-by={disposition.review_by}"
        )

    fixed_records = sorted(
        {
            (record.scanner, record.package, record.version)
            for record in finding.records
            if record.has_fix and (record.package, record.version) in disposition.packages
        }
    )
    if fixed_records:
        evidence = ",".join(f"{scanner}:{package}@{version}" for scanner, package, version in fixed_records)
        return None, None, None, f"valid fix evidence refuses accept-and-track disposition: {evidence}"

    target_statements = [
        statement for statement in statements if disposition.vulnerability in statement.vulnerabilities
    ]
    if len(target_statements) > 1:
        locations = ",".join(f"{statement.path}#{statement.index}" for statement in target_statements)
        raise VexError(f"duplicate accept-and-track statements for {disposition.vulnerability}: {locations}")
    if not target_statements:
        return None, None, None, f"no reviewed OpenVEX statement for {disposition.vulnerability}"
    statement = target_statements[0]
    rejection = accept_and_track_statement_rejection(statement, disposition, surface)
    if rejection is not None:
        return None, None, None, rejection
    return statement, disposition, surface, None


def accepted_exact_not_affected_statement(
    finding: Finding,
    product: str,
    statements: list[Statement],
    dispositions: tuple[ExactNotAffectedDisposition, ...],
    architecture: str,
    index_reference: str | None,
    index_manifest: Path | None,
    package_names: frozenset[str],
) -> tuple[Statement | None, ExactNotAffectedDisposition | None, ExactNotAffectedSurface | None, str | None]:
    identity_rejections = sorted({rejection for record in finding.records for rejection in record.identity_rejections})
    if identity_rejections:
        return (
            None,
            None,
            None,
            "malformed exact not-affected scanner identity evidence: " + "; ".join(identity_rejections),
        )
    candidates = exact_not_affected_surface_candidates(
        finding,
        product,
        architecture,
        index_reference,
        index_manifest,
        dispositions,
    )
    if not candidates:
        return None, None, None, "no exact in-tool not-affected disposition entry"
    if len(candidates) > 1:
        return None, None, None, f"multiple exact in-tool not-affected disposition matches: {len(candidates)}"
    disposition, surface = candidates[0]
    canonical_pairs = [
        (canonical_disposition, canonical_surface)
        for canonical_disposition in EXACT_NOT_AFFECTED_DISPOSITIONS
        for canonical_surface in canonical_disposition.surfaces
    ]
    if (disposition, surface) not in canonical_pairs:
        return None, None, None, "in-tool not-affected entry does not match the canonical authorization"

    target_statements = [
        statement for statement in statements if disposition.vulnerability in statement.vulnerabilities
    ]
    if len(target_statements) > 1:
        locations = ",".join(f"{statement.path}#{statement.index}" for statement in target_statements)
        raise VexError(f"duplicate exact not-affected statements for {disposition.vulnerability}: {locations}")
    if not target_statements:
        return None, None, None, f"no reviewed OpenVEX statement for {disposition.vulnerability}"
    statement = target_statements[0]
    rejection = exact_not_affected_statement_rejection(statement, disposition, surface)
    if rejection is not None:
        return None, None, None, rejection
    rejection = vulnerable_code_absence_rejection(statement, package_names)
    if rejection is not None:
        return None, None, None, rejection
    return statement, disposition, surface, None


def assert_vex(
    product: str,
    trivy_json: Path,
    grype_json: Path,
    package_floor: Path,
    vex_dir: Path,
    emit: bool = True,
    *,
    accept_and_track: tuple[AcceptAndTrackDisposition, ...] = ACCEPT_AND_TRACK_DISPOSITIONS,
    exact_not_affected: tuple[ExactNotAffectedDisposition, ...] = EXACT_NOT_AFFECTED_DISPOSITIONS,
    today: date | None = None,
    index_reference: str | None = None,
    index_manifest: Path | None = None,
) -> int:
    trivy_document = scanner_document(trivy_json, "Trivy")
    grype_document = scanner_document(grype_json, "Grype")
    trivy_evidence = validate_trivy_report(trivy_document)
    grype_evidence = validate_grype_report(grype_document)
    validate_report_binding(product, trivy_evidence, grype_evidence)
    validate_contract_floor(package_floor, trivy_evidence.architecture, trivy_evidence.package_names)
    if (index_reference is None) != (index_manifest is None):
        raise VexError("--index-reference and --index-manifest must be supplied together")

    findings = union_findings(parse_trivy(trivy_document) + parse_grype(grype_document))
    statements = load_vex_statements(vex_dir)

    if emit:
        print(f"unfixed HIGH/CRITICAL findings requiring VEX: {len(findings)}")

    evaluation_date = date.today() if today is None else today
    missing: list[Finding] = []
    rejection_reasons: list[tuple[Finding, str]] = []
    exact_not_affected_rejection_reasons: list[tuple[Finding, str]] = []
    matched: list[tuple[Finding, Statement]] = []
    tracked: list[tuple[Finding, Statement, AcceptAndTrackDisposition, AcceptAndTrackSurface]] = []
    accept_and_track_vulnerabilities = {disposition.vulnerability for disposition in ACCEPT_AND_TRACK_DISPOSITIONS}
    exact_not_affected_vulnerabilities = {disposition.vulnerability for disposition in EXACT_NOT_AFFECTED_DISPOSITIONS}
    for finding in findings:
        if finding.vulnerability in accept_and_track_vulnerabilities:
            statement, disposition, surface, rejection = accepted_accept_and_track_statement(
                finding,
                product,
                statements,
                accept_and_track,
                evaluation_date,
                trivy_evidence.architecture,
                index_reference,
                index_manifest,
            )
            if statement is not None and disposition is not None and surface is not None:
                tracked.append((finding, statement, disposition, surface))
            else:
                missing.append(finding)
                if rejection is not None:
                    rejection_reasons.append((finding, rejection))
            continue
        if finding.vulnerability in exact_not_affected_vulnerabilities:
            exact_statement, exact_disposition_match, exact_surface_match, rejection = (
                accepted_exact_not_affected_statement(
                    finding,
                    product,
                    statements,
                    exact_not_affected,
                    trivy_evidence.architecture,
                    index_reference,
                    index_manifest,
                    trivy_evidence.package_names,
                )
            )
            if exact_statement is not None and exact_disposition_match is not None and exact_surface_match is not None:
                matched.append((finding, exact_statement))
            else:
                missing.append(finding)
                if rejection is not None:
                    exact_not_affected_rejection_reasons.append((finding, rejection))
            continue
        statement = accepted_statement(finding, product, statements, trivy_evidence.package_names)
        if statement is None:
            missing.append(finding)
        else:
            matched.append((finding, statement))

    for finding, statement in matched:
        if emit:
            print(
                "accepted VEX: "
                f"{finding.vulnerability} status={statement.status} "
                f"product={product} source={statement.path}"
            )

    for _finding, statement, disposition, _surface in tracked:
        if emit:
            packages = ",".join(f"{name}@{version}" for name, version in disposition.packages)
            print(
                "accept-and-track disposition: "
                f"{disposition.vulnerability} packages={packages} debt={disposition.debt_id} "
                f"review-by={disposition.review_by} product={product} source={statement.path}"
            )

    if tracked and emit:
        print(f"undispositioned unfixed HIGH/CRITICAL findings: {len(missing)}")

    if missing:
        if emit:
            for finding, reason in rejection_reasons:
                print(f"accept-and-track rejected for {finding.vulnerability}: {reason}", file=sys.stderr)
            for finding, reason in exact_not_affected_rejection_reasons:
                print(f"exact not-affected rejected for {finding.vulnerability}: {reason}", file=sys.stderr)
            print("un-vexed unfixed HIGH/CRITICAL findings:", file=sys.stderr)
            for finding in missing:
                scanners = ",".join(sorted(finding.scanners))
                packages = ",".join(sorted(finding.packages))
                print(
                    f"- {finding.vulnerability} severity={finding.severity} scanners={scanners} packages={packages}",
                    file=sys.stderr,
                )
        return 1

    return 0


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="assert-vex-") as raw_tmp:
        tmp = Path(raw_tmp)
        product = "example.invalid/base-micro@sha256:" + ("a" * 64)
        image_id = "sha256:" + ("b" * 64)
        trivy_json = tmp / "trivy.json"
        grype_json = tmp / "grype.json"
        package_floor = tmp / "package-floor.json"
        vex_dir = tmp / "vex"
        vex_dir.mkdir()

        clean_trivy: dict[str, Any] = {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.71.0"},
            "ArtifactName": product,
            "ArtifactType": "container_image",
            "Metadata": {
                "OS": {"Family": "redhat", "Name": "9.8"},
                "ImageID": image_id,
                "ImageConfig": {"architecture": "amd64"},
                "RepoDigests": [product],
            },
            "Results": [
                {
                    "Target": f"{product} (redhat 9.8)",
                    "Class": "os-pkgs",
                    "Type": "redhat",
                    "Packages": [{"Name": "glibc", "Version": "2.34"}],
                    "Vulnerabilities": [],
                },
                {
                    "Target": "Python",
                    "Class": "lang-pkgs",
                    "Type": "python-pkg",
                },
            ],
        }
        clean_grype: dict[str, Any] = {
            "descriptor": {"name": "grype", "version": "0.115.0"},
            "distro": {"name": "redhat", "version": "9.8"},
            "source": {
                "type": "image",
                "target": {
                    "userInput": product,
                    "imageID": image_id,
                    "architecture": "amd64",
                    "repoDigests": [product],
                },
            },
            "matches": [],
            "ignoredMatches": [],
            "alertsByPackage": {},
        }
        clean_floor: dict[str, Any] = {"runtime": {"package_floor": ["glibc"]}}

        def run_fixture(
            trivy: Any,
            grype: Any,
            floor: Any,
            *,
            emit: bool = False,
            expected_product: str = product,
        ) -> int:
            write_json(trivy_json, trivy)
            write_json(grype_json, grype)
            write_json(package_floor, floor)
            return assert_vex(
                expected_product,
                trivy_json,
                grype_json,
                package_floor,
                vex_dir,
                emit=emit,
            )

        def run_fixture_with_output(
            trivy: Any,
            grype: Any,
            floor: Any,
        ) -> tuple[int, str]:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = run_fixture(trivy, grype, floor, emit=True)
            return result, stdout.getvalue() + stderr.getvalue()

        def expect_vex_rejection(label: str, action: Callable[[], Any], expected_reason: str) -> None:
            try:
                action()
            except VexError as exc:
                if expected_reason not in str(exc):
                    print(f"self-test failed: {label} rejected for wrong reason: {exc}", file=sys.stderr)
                    raise SystemExit(1) from exc
            except Exception as exc:
                print(
                    f"self-test failed: {label} rejected for wrong reason: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                raise SystemExit(1) from exc
            else:
                print(f"self-test failed: {label} unexpectedly passed", file=sys.stderr)
                raise SystemExit(1)
            print(f"assert-vex self-test: {label} rejected at its expected discriminator")

        if run_fixture(clean_trivy, clean_grype, clean_floor) != 0:
            print("self-test failed: correctly bound zero-finding reports did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: correctly bound zero-finding reports passed")

        local_trivy = copy.deepcopy(clean_trivy)
        local_grype = copy.deepcopy(clean_grype)
        local_product = "example.invalid/base-micro:self-test"
        local_trivy["ArtifactName"] = local_product
        local_grype["source"]["target"]["userInput"] = local_product
        local_trivy["Metadata"].pop("RepoDigests")
        local_grype["source"]["target"]["repoDigests"] = []
        if run_fixture(local_trivy, local_grype, clean_floor, expected_product=local_product) != 0:
            print("self-test failed: local-mode empty/absent repo digests did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: local-mode empty/absent repo digests passed")

        tag_trivy = copy.deepcopy(clean_trivy)
        tag_grype = copy.deepcopy(clean_grype)
        tag_product = "example.invalid/base-micro:self-test"
        tag_trivy["ArtifactName"] = tag_product
        tag_grype["source"]["target"]["userInput"] = tag_product
        if run_fixture(tag_trivy, tag_grype, clean_floor, expected_product=tag_product) != 0:
            print("self-test failed: tag-mode digest repository evidence did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: tag-mode digest repository evidence passed")

        inherited_floor = {
            "parent": {
                "floor": {
                    "amd64": ["glibc-2.34-1.el9.x86_64"],
                }
            }
        }
        if run_fixture(clean_trivy, clean_grype, inherited_floor) != 0:
            print("self-test failed: inherited architecture floor did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: inherited architecture floor passed")

        directory_grype = copy.deepcopy(clean_grype)
        directory_grype["source"] = {"type": "directory", "target": "/rootfs"}
        directory_evidence = validate_grype_report(directory_grype)
        if directory_evidence.source_type != "directory":
            print("self-test failed: directory/string source pair was not accepted", file=sys.stderr)
            return 1
        print("assert-vex self-test: exact directory/string source pair accepted")

        missing_json = tmp / "missing-input.json"
        invalid_json = tmp / "invalid-input.json"
        invalid_json.write_text("{", encoding="utf-8")

        loader_document: dict[str, Any] = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2099-0003"},
                    "products": [{"@id": product}],
                    "status": "fixed",
                }
            ],
        }

        def loader_fixture(label: str, document: dict[str, Any]) -> Callable[[], list[Statement]]:
            directory = tmp / f"loader-{label}"
            directory.mkdir()
            write_json(directory / "fixture.json", document)
            return lambda: load_vex_statements(directory)

        singleton_probes: list[tuple[str, Callable[[], Any], str]] = [
            (
                "missing JSON input",
                lambda: load_json(missing_json),
                f"missing JSON input: {missing_json}",
            ),
            (
                "invalid JSON input",
                lambda: load_json(invalid_json),
                f"invalid JSON in {invalid_json}:",
            ),
            (
                "missing VEX directory",
                lambda: load_vex_statements(tmp / "missing-vex"),
                f"missing VEX directory: {tmp / 'missing-vex'}",
            ),
            (
                "OpenVEX context",
                loader_fixture(
                    "context",
                    {key: value for key, value in loader_document.items() if key != "@context"},
                ),
                ": missing @context",
            ),
            (
                "OpenVEX statements container",
                loader_fixture("statements-container", {**loader_document, "statements": {}}),
                ": statements must be a list",
            ),
            (
                "OpenVEX statement object",
                loader_fixture("statement-object", {**loader_document, "statements": [[]]}),
                ": statement 0 must be an object",
            ),
            (
                "OpenVEX vulnerability identifier",
                loader_fixture(
                    "vulnerability-id",
                    {
                        **loader_document,
                        "statements": [
                            {
                                **loader_document["statements"][0],
                                "vulnerability": {},
                            }
                        ],
                    },
                ),
                ": statement 0 missing vulnerability id",
            ),
            (
                "OpenVEX status",
                loader_fixture(
                    "status",
                    {
                        **loader_document,
                        "statements": [{**loader_document["statements"][0], "status": "invalid"}],
                    },
                ),
                ": statement 0 has invalid status 'invalid'",
            ),
            (
                "OpenVEX not-affected justification",
                loader_fixture(
                    "missing-justification",
                    {
                        **loader_document,
                        "statements": [{**loader_document["statements"][0], "status": "not_affected"}],
                    },
                ),
                ": statement 0 not_affected requires justification",
            ),
            (
                "OpenVEX justification vocabulary",
                loader_fixture(
                    "unsupported-justification",
                    {
                        **loader_document,
                        "statements": [
                            {
                                **loader_document["statements"][0],
                                "status": "not_affected",
                                "justification": "unsupported",
                            }
                        ],
                    },
                ),
                ": statement 0 has unsupported justification 'unsupported'",
            ),
            (
                "OpenVEX products container",
                loader_fixture(
                    "products-container",
                    {
                        **loader_document,
                        "statements": [
                            {key: value for key, value in loader_document["statements"][0].items() if key != "products"}
                        ],
                    },
                ),
                ": statement 0 requires non-empty products",
            ),
            (
                "OpenVEX product identifiers",
                loader_fixture(
                    "product-identifiers",
                    {
                        **loader_document,
                        "statements": [{**loader_document["statements"][0], "products": [{}]}],
                    },
                ),
                ": statement 0 has no product identifiers",
            ),
        ]
        for label, action, expected_reason in singleton_probes:
            expect_vex_rejection(label, action, expected_reason)

        probes: list[tuple[str, str, Any, Any, Any, str]] = []

        def add_probe(
            label: str,
            expected_reason: str,
            mutate: Mutation,
            *,
            expected_product: str = product,
        ) -> None:
            trivy = copy.deepcopy(clean_trivy)
            grype = copy.deepcopy(clean_grype)
            floor = copy.deepcopy(clean_floor)
            mutate(trivy, grype, floor)
            probes.append((label, expected_reason, trivy, grype, floor, expected_product))

        def replace_with_malformed_inherited_floor(
            _trivy: dict[str, Any],
            _grype: dict[str, Any],
            floor: dict[str, Any],
        ) -> None:
            floor.clear()
            floor.update({"parent": {"floor": {"amd64": ["glibc"]}}})

        def replace_with_invalid_product(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            _floor: dict[str, Any],
        ) -> None:
            trivy["ArtifactName"] = "not an image"
            grype["source"]["target"]["userInput"] = "not an image"

        def replace_with_invalid_trivy_tag_digest(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            _floor: dict[str, Any],
        ) -> None:
            trivy["ArtifactName"] = tag_product
            grype["source"]["target"]["userInput"] = tag_product
            trivy["Metadata"]["RepoDigests"] = [malformed_digest_reference]

        def replace_with_invalid_grype_tag_digest(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            _floor: dict[str, Any],
        ) -> None:
            trivy["ArtifactName"] = tag_product
            grype["source"]["target"]["userInput"] = tag_product
            grype["source"]["target"]["repoDigests"] = [malformed_digest_reference]

        probes.append(
            (
                "Trivy non-object document",
                "Trivy report must be a JSON object",
                [],
                copy.deepcopy(clean_grype),
                copy.deepcopy(clean_floor),
                product,
            )
        )
        probes.append(
            (
                "Trivy hollow document",
                "Trivy SchemaVersion must be 2",
                {},
                copy.deepcopy(clean_grype),
                copy.deepcopy(clean_floor),
                product,
            )
        )
        add_probe(
            "Trivy schema version",
            "Trivy SchemaVersion must be 2",
            lambda trivy, _grype, _floor: trivy.__setitem__("SchemaVersion", 1),
        )
        add_probe(
            "Trivy identity object",
            "Trivy identity must be an object",
            lambda trivy, _grype, _floor: trivy.__setitem__("Trivy", "0.71.0"),
        )
        add_probe(
            "Trivy identity version",
            "Trivy.Version must be a non-empty string",
            lambda trivy, _grype, _floor: trivy.__setitem__("Trivy", {}),
        )
        add_probe(
            "Trivy identity version shape",
            "Trivy.Version must be a three-component numeric version",
            lambda trivy, _grype, _floor: trivy["Trivy"].__setitem__("Version", "opaque"),
        )
        add_probe(
            "Trivy artifact identity",
            "Trivy ArtifactName must be a non-empty string",
            lambda trivy, _grype, _floor: trivy.__setitem__("ArtifactName", ""),
        )
        add_probe(
            "Trivy artifact type",
            "Trivy ArtifactType must be container_image",
            lambda trivy, _grype, _floor: trivy.__setitem__("ArtifactType", "filesystem"),
        )
        add_probe(
            "Trivy metadata object",
            "Trivy Metadata must be an object",
            lambda trivy, _grype, _floor: trivy.__setitem__("Metadata", []),
        )
        add_probe(
            "Trivy OS object",
            "Trivy Metadata.OS must be an object",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("OS", []),
        )
        add_probe(
            "Trivy Red Hat family",
            "Trivy Metadata.OS.Family must be redhat",
            lambda trivy, _grype, _floor: trivy["Metadata"]["OS"].__setitem__("Family", "alpine"),
        )
        add_probe(
            "Trivy OS release",
            "Trivy Metadata.OS.Name must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Metadata"]["OS"].__setitem__("Name", ""),
        )
        add_probe(
            "Trivy image ID",
            "Trivy Metadata.ImageID must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("ImageID", ""),
        )
        add_probe(
            "Trivy image ID content digest",
            "Trivy Metadata.ImageID must be a sha256 content digest",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("ImageID", "opaque"),
        )
        add_probe(
            "Padded image IDs",
            "Trivy Metadata.ImageID must be a sha256 content digest",
            lambda trivy, grype, _floor: (
                trivy["Metadata"].__setitem__("ImageID", f" {image_id}"),
                grype["source"]["target"].__setitem__("imageID", f" {image_id}"),
            ),
        )
        add_probe(
            "Trivy image config object",
            "Trivy Metadata.ImageConfig must be an object",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("ImageConfig", []),
        )
        add_probe(
            "Trivy architecture",
            "Trivy Metadata.ImageConfig.architecture must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Metadata"]["ImageConfig"].__setitem__("architecture", ""),
        )
        add_probe(
            "Trivy architecture domain",
            "Trivy Metadata.ImageConfig.architecture must be amd64 or arm64",
            lambda trivy, _grype, _floor: trivy["Metadata"]["ImageConfig"].__setitem__(
                "architecture",
                "opaque",
            ),
        )
        add_probe(
            "Trivy repo digest container",
            "Trivy Metadata.RepoDigests must be a list when present",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("RepoDigests", product),
        )
        add_probe(
            "Trivy repo digest entry",
            "Trivy Metadata.RepoDigests[0] must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("RepoDigests", [""]),
        )
        add_probe(
            "Trivy repo digest shape",
            "Trivy Metadata.RepoDigests[0] must be a digest-qualified image reference",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__("RepoDigests", ["opaque"]),
        )
        add_probe(
            "Trivy results container",
            "Trivy Results must be a list",
            lambda trivy, _grype, _floor: trivy.__setitem__("Results", {}),
        )
        add_probe(
            "Trivy result object",
            "Trivy Results[1] must be an object",
            lambda trivy, _grype, _floor: trivy.__setitem__("Results", [trivy["Results"][0], []]),
        )
        add_probe(
            "Trivy result target",
            "Trivy Results[0].Target must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0].pop("Target"),
        )
        add_probe(
            "Trivy OS result class",
            "Trivy report requires at least one Class=os-pkgs Type=redhat result",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Class", "lang-pkgs"),
        )
        add_probe(
            "Trivy OS result type",
            "Trivy report requires at least one Class=os-pkgs Type=redhat result",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Type", "debian"),
        )
        add_probe(
            "Trivy packages container",
            "Trivy Results[0].Packages must be a list",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Packages", {}),
        )
        add_probe(
            "Trivy package object",
            "Trivy Results[0].Packages[0] must be an object",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Packages", ["glibc"]),
        )
        add_probe(
            "Trivy package name",
            "Trivy Results[0].Packages[0].Name must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0]["Packages"][0].__setitem__("Name", ""),
        )
        add_probe(
            "Trivy package version",
            "Trivy Results[0].Packages[0].Version must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0]["Packages"][0].__setitem__("Version", ""),
        )
        add_probe(
            "Trivy empty inventory",
            "Trivy os-pkgs/redhat inventory must be non-empty",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Packages", []),
        )
        add_probe(
            "Trivy vulnerabilities container",
            "Trivy Results[0].Vulnerabilities must be a list or null",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Vulnerabilities", {}),
        )
        add_probe(
            "Trivy finding object",
            "Trivy Results[0].Vulnerabilities[0] must be an object",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__("Vulnerabilities", [[]]),
        )
        valid_trivy_finding = {
            "VulnerabilityID": "CVE-2099-0001",
            "PkgName": "glibc",
            "Severity": "HIGH",
        }
        add_probe(
            "Trivy finding ID",
            "Trivy Results[0].Vulnerabilities[0].VulnerabilityID must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__(
                "Vulnerabilities",
                [{key: value for key, value in valid_trivy_finding.items() if key != "VulnerabilityID"}],
            ),
        )
        add_probe(
            "Trivy finding severity",
            "Trivy Results[0].Vulnerabilities[0].Severity must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__(
                "Vulnerabilities",
                [{key: value for key, value in valid_trivy_finding.items() if key != "Severity"}],
            ),
        )
        add_probe(
            "Trivy unsupported finding severity",
            "Trivy Results[0].Vulnerabilities[0].Severity has unsupported value",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__(
                "Vulnerabilities",
                [{**valid_trivy_finding, "Severity": "UNSUPPORTED"}],
            ),
        )
        add_probe(
            "Trivy finding package",
            "Trivy Results[0].Vulnerabilities[0].PkgName must be a non-empty string",
            lambda trivy, _grype, _floor: trivy["Results"][0].__setitem__(
                "Vulnerabilities",
                [{key: value for key, value in valid_trivy_finding.items() if key != "PkgName"}],
            ),
        )
        probes.append(
            (
                "Grype non-object document",
                "Grype report must be a JSON object",
                copy.deepcopy(clean_trivy),
                [],
                copy.deepcopy(clean_floor),
                product,
            )
        )
        probes.append(
            (
                "Grype hollow document",
                "Grype report must contain a grype descriptor",
                copy.deepcopy(clean_trivy),
                {},
                copy.deepcopy(clean_floor),
                product,
            )
        )
        add_probe(
            "Grype descriptor object",
            "Grype report must contain a grype descriptor",
            lambda _trivy, grype, _floor: grype.__setitem__("descriptor", []),
        )
        add_probe(
            "Grype descriptor name",
            "Grype report must contain a grype descriptor",
            lambda _trivy, grype, _floor: grype["descriptor"].__setitem__("name", "other"),
        )
        add_probe(
            "Grype descriptor version",
            "Grype descriptor.version must be a non-empty string",
            lambda _trivy, grype, _floor: grype["descriptor"].__setitem__("version", ""),
        )
        add_probe(
            "Grype descriptor version shape",
            "Grype descriptor.version must be a three-component numeric version",
            lambda _trivy, grype, _floor: grype["descriptor"].__setitem__("version", "opaque"),
        )
        add_probe(
            "Grype distro object",
            "Grype distro must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__("distro", []),
        )
        add_probe(
            "Grype Red Hat distro",
            "Grype distro.name must be redhat",
            lambda _trivy, grype, _floor: grype["distro"].__setitem__("name", "ubuntu"),
        )
        add_probe(
            "Grype distro version",
            "Grype distro.version must be a non-empty string",
            lambda _trivy, grype, _floor: grype["distro"].__setitem__("version", ""),
        )
        add_probe(
            "Grype source object",
            "Grype source must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__("source", []),
        )
        add_probe(
            "Grype image target pair",
            "Grype image source.target must be an object",
            lambda _trivy, grype, _floor: grype["source"].__setitem__("target", product),
        )
        add_probe(
            "Grype image user input",
            "Grype source.target.userInput must be a non-empty string",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("userInput", ""),
        )
        add_probe(
            "Grype image ID",
            "Grype source.target.imageID must be a non-empty string",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("imageID", ""),
        )
        add_probe(
            "Grype image ID content digest",
            "Grype source.target.imageID must be a sha256 content digest",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("imageID", "opaque"),
        )
        add_probe(
            "Grype architecture",
            "Grype source.target.architecture must be a non-empty string",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("architecture", ""),
        )
        add_probe(
            "Grype architecture domain",
            "Grype source.target.architecture must be amd64 or arm64",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("architecture", "opaque"),
        )
        add_probe(
            "Shared opaque architecture",
            "Trivy Metadata.ImageConfig.architecture must be amd64 or arm64",
            lambda trivy, grype, _floor: (
                trivy["Metadata"]["ImageConfig"].__setitem__("architecture", "opaque"),
                grype["source"]["target"].__setitem__("architecture", "opaque"),
            ),
        )
        add_probe(
            "Grype repo digest container",
            "Grype source.target.repoDigests must be a list when present",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("repoDigests", product),
        )
        add_probe(
            "Grype repo digest entry",
            "Grype source.target.repoDigests[0] must be a non-empty string",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("repoDigests", [""]),
        )
        add_probe(
            "Grype repo digest shape",
            "Grype source.target.repoDigests[0] must be a digest-qualified image reference",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("repoDigests", ["opaque"]),
        )
        add_probe(
            "Grype directory target pair",
            "Grype directory source.target must be a non-empty string",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "directory", "target": {"path": "/rootfs"}},
            ),
        )
        add_probe(
            "Grype SBOM source mode",
            "Grype source.type must be image or directory",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "sbom", "target": "/tmp/image.cdx.json"},
            ),
        )
        add_probe(
            "Grype file source mode",
            "Grype source.type must be image or directory",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "file", "target": "/tmp/rootfs.tar"},
            ),
        )
        add_probe(
            "Grype unknown source mode",
            "Grype source.type must be image or directory",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "unknown", "target": "/tmp/unknown"},
            ),
        )
        add_probe(
            "Grype matches container",
            "Grype matches must be a list",
            lambda _trivy, grype, _floor: grype.__setitem__("matches", {}),
        )
        valid_grype_match = {
            "vulnerability": {"id": "CVE-2099-0002", "severity": "HIGH"},
            "artifact": {"name": "glibc"},
        }
        add_probe(
            "Grype match object",
            "Grype matches[0] must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__("matches", [[]]),
        )
        add_probe(
            "Grype vulnerability object",
            "Grype matches[0].vulnerability must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "vulnerability": []}],
            ),
        )
        add_probe(
            "Grype finding ID",
            "Grype matches[0].vulnerability.id must be a non-empty string",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "vulnerability": {"severity": "HIGH"}}],
            ),
        )
        add_probe(
            "Grype finding severity",
            "Grype matches[0].vulnerability.severity must be a non-empty string",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "vulnerability": {"id": "CVE-2099-0002"}}],
            ),
        )
        add_probe(
            "Grype artifact object",
            "Grype matches[0].artifact must be an object",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "artifact": []}],
            ),
        )
        add_probe(
            "Grype finding package",
            "Grype matches[0].artifact.name must be a non-empty string",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "matches",
                [{**valid_grype_match, "artifact": {}}],
            ),
        )
        add_probe(
            "Directory evidence cannot bypass image binding",
            "report binding requires a Grype image source",
            lambda _trivy, grype, _floor: grype.__setitem__(
                "source",
                {"type": "directory", "target": "/rootfs"},
            ),
        )
        add_probe(
            "Product image reference shape",
            "--product must be a well-formed image reference",
            replace_with_invalid_product,
            expected_product="not an image",
        )
        add_probe(
            "Trivy stale product",
            "Trivy ArtifactName does not match --product",
            lambda trivy, _grype, _floor: trivy.__setitem__("ArtifactName", "example.invalid/stale:old"),
        )
        add_probe(
            "Grype wrong product",
            "Grype source.target.userInput does not match --product",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__(
                "userInput",
                "example.invalid/wrong:target",
            ),
        )
        add_probe(
            "Cross-scanner image ID",
            "Trivy and Grype imageID values do not match",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__(
                "imageID",
                "sha256:" + ("c" * 64),
            ),
        )
        add_probe(
            "Cross-scanner architecture",
            "Trivy and Grype architecture values do not match",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("architecture", "arm64"),
        )
        add_probe(
            "Cross-scanner OS release",
            "Trivy OS and Grype distro versions do not match",
            lambda trivy, grype, _floor: (
                trivy["Metadata"]["OS"].__setitem__("Name", "8.10"),
                grype["distro"].__setitem__("version", "7.9"),
            ),
        )
        add_probe(
            "Consumer RHEL major release",
            "Trivy OS and Grype distro versions must identify RHEL 9",
            lambda trivy, grype, _floor: (
                trivy["Metadata"]["OS"].__setitem__("Name", "8.10"),
                grype["distro"].__setitem__("version", "8.10"),
            ),
        )
        add_probe(
            "Trivy required digest repository evidence",
            "Trivy Metadata.RepoDigests is required for a digest-addressed --product",
            lambda trivy, _grype, _floor: trivy["Metadata"].pop("RepoDigests"),
        )
        add_probe(
            "Grype required digest repository evidence",
            "Grype source.target.repoDigests is required for a digest-addressed --product",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__("repoDigests", []),
        )
        add_probe(
            "Trivy populated repo digest binding",
            "Trivy Metadata.RepoDigests does not contain --product",
            lambda trivy, _grype, _floor: trivy["Metadata"].__setitem__(
                "RepoDigests",
                ["example.invalid/wrong@sha256:" + ("d" * 64)],
            ),
        )
        add_probe(
            "Grype populated repo digest binding",
            "Grype source.target.repoDigests does not contain --product",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__(
                "repoDigests",
                ["example.invalid/wrong@sha256:" + ("d" * 64)],
            ),
        )
        additional_digest = "example.invalid/base-micro@sha256:" + ("d" * 64)
        add_probe(
            "Cross-scanner repo digest evidence",
            "Trivy and Grype repository digest evidence does not match",
            lambda _trivy, grype, _floor: grype["source"]["target"].__setitem__(
                "repoDigests",
                [product, additional_digest],
            ),
        )
        malformed_digest_reference = "!@sha256:" + ("d" * 64)
        add_probe(
            "Trivy tag-mode repository digest shape",
            "Trivy Metadata.RepoDigests[0] must be a digest-qualified image reference",
            replace_with_invalid_trivy_tag_digest,
            expected_product=tag_product,
        )
        add_probe(
            "Grype tag-mode repository digest shape",
            "Grype source.target.repoDigests[0] must be a digest-qualified image reference",
            replace_with_invalid_grype_tag_digest,
            expected_product=tag_product,
        )
        probes.append(
            (
                "Package floor non-object",
                "package floor contract must be a JSON object",
                copy.deepcopy(clean_trivy),
                copy.deepcopy(clean_grype),
                [],
                product,
            )
        )
        add_probe(
            "Package floor schema",
            "missing package floor for architecture amd64",
            lambda _trivy, _grype, floor: floor.clear(),
        )
        add_probe(
            "Package floor non-empty",
            "package floor must be a non-empty list",
            lambda _trivy, _grype, floor: floor["runtime"].__setitem__("package_floor", []),
        )
        add_probe(
            "Package floor entry",
            "package floor[0] must be a non-empty string",
            lambda _trivy, _grype, floor: floor["runtime"].__setitem__("package_floor", [""]),
        )
        add_probe(
            "Package floor inventory binding",
            "Trivy inventory missing contract package floor: zlib",
            lambda _trivy, _grype, floor: floor["runtime"].__setitem__("package_floor", ["glibc", "zlib"]),
        )
        add_probe(
            "Inherited floor NEVRA",
            "package floor[0] must be an RPM NEVRA",
            replace_with_malformed_inherited_floor,
        )

        rejected = 0
        for label, expected_reason, trivy, grype, floor, expected_product in probes:
            try:
                run_fixture(trivy, grype, floor, expected_product=expected_product)
            except VexError as exc:
                if expected_reason not in str(exc):
                    print(
                        f"self-test failed: {label} rejected for wrong reason: {exc}",
                        file=sys.stderr,
                    )
                    return 1
                rejected += 1
            else:
                print(f"self-test failed: {label} unexpectedly passed", file=sys.stderr)
                return 1
        print(f"assert-vex self-test: {rejected}/{len(probes)} mutations rejected at their expected discriminator")

        try:
            run_fixture(clean_trivy, clean_grype, clean_floor, expected_product=f" {product}")
        except VexError as exc:
            expected_reason = "--product must not contain surrounding whitespace"
            if expected_reason not in str(exc):
                print(
                    f"self-test failed: product whitespace rejected for wrong reason: {exc}",
                    file=sys.stderr,
                )
                return 1
        else:
            print("self-test failed: product whitespace unexpectedly passed", file=sys.stderr)
            return 1
        print("assert-vex self-test: product whitespace rejected at its expected discriminator")

        parser_probes: list[tuple[str, Callable[[dict[str, Any]], list[Finding]], dict[str, Any], str]] = [
            ("Trivy parser missing Results", parse_trivy, {}, "Trivy Results must be a list"),
            ("Grype parser missing matches", parse_grype, {}, "Grype matches must be a list"),
        ]
        for label, parser, document, expected_reason in parser_probes:
            try:
                parser(document)
            except VexError as exc:
                if expected_reason not in str(exc):
                    print(f"self-test failed: {label} rejected for wrong reason: {exc}", file=sys.stderr)
                    return 1
            else:
                print(f"self-test failed: {label} unexpectedly passed", file=sys.stderr)
                return 1
            print(f"assert-vex self-test: {label} rejected at its expected discriminator")

        duplicate_documents = [
            (
                "duplicate fix keys malicious-last order",
                '{"fix":{"versions":[{}],"versions":["1.2.3"],"state":[],"state":"fixed"}}',
            ),
            (
                "duplicate fix keys malformed-last order",
                '{"fix":{"versions":["1.2.3"],"versions":[{}],"state":"fixed","state":[]}}',
            ),
        ]
        for label, raw_document in duplicate_documents:
            duplicate_json = tmp / f"{label.replace(' ', '-')}.json"
            duplicate_json.write_text(raw_document, encoding="utf-8")
            try:
                load_json(duplicate_json)
            except VexError as exc:
                if "duplicate JSON object member" not in str(exc):
                    print(f"self-test failed: {label} rejected for wrong reason: {exc}", file=sys.stderr)
                    return 1
            else:
                print(f"self-test failed: {label} unexpectedly passed", file=sys.stderr)
                return 1
            print(f"assert-vex self-test: {label} rejected at its expected discriminator")

        def trivy_fix_fixture(fix: Any) -> dict[str, Any]:
            trivy = copy.deepcopy(clean_trivy)
            trivy["Results"][0]["Vulnerabilities"] = [{**valid_trivy_finding, **fix}]
            return trivy

        def grype_fix_fixture(fix: Any) -> dict[str, Any]:
            grype = copy.deepcopy(clean_grype)
            grype["matches"] = [
                {
                    **valid_grype_match,
                    "vulnerability": {
                        **valid_grype_match["vulnerability"],
                        "fix": fix,
                    },
                }
            ]
            return grype

        no_fix_probes = [
            (
                "Trivy null FixedVersion with fixed Status",
                trivy_fix_fixture({"FixedVersion": None, "Status": "fixed"}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy malformed FixedVersion type",
                trivy_fix_fixture({"FixedVersion": [], "Status": "fixed"}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy non-canonical Status case",
                trivy_fix_fixture({"Status": "FiXeD"}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy padded Status",
                trivy_fix_fixture({"Status": " fixed "}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy fixed version with malformed Status type",
                trivy_fix_fixture({"FixedVersion": "1.2.3", "Status": []}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Trivy fixed version with unrecognised Status",
                trivy_fix_fixture({"FixedVersion": "1.2.3", "Status": "surprising"}),
                clean_grype,
                "CVE-2099-0001 severity=HIGH scanners=trivy",
            ),
            (
                "Grype malformed fix object",
                clean_trivy,
                grype_fix_fixture([]),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype malformed versions container",
                clean_trivy,
                grype_fix_fixture({"versions": {}, "state": "fixed"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype malformed versions entry",
                clean_trivy,
                grype_fix_fixture({"versions": [{}], "state": "not-fixed"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype empty versions entry",
                clean_trivy,
                grype_fix_fixture({"versions": [""], "state": "not-fixed"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype version with malformed state type",
                clean_trivy,
                grype_fix_fixture({"versions": ["1.2.3"], "state": []}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype version with missing state",
                clean_trivy,
                grype_fix_fixture({"versions": ["1.2.3"]}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype version with unrecognised state",
                clean_trivy,
                grype_fix_fixture({"versions": ["1.2.3"], "state": "surprising"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype non-canonical state case",
                clean_trivy,
                grype_fix_fixture({"versions": [], "state": "FiXeD"}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
            (
                "Grype padded state",
                clean_trivy,
                grype_fix_fixture({"versions": [], "state": " fixed "}),
                "CVE-2099-0002 severity=HIGH scanners=grype",
            ),
        ]
        no_fix_rejected = 0
        for label, trivy, grype, expected_reason in no_fix_probes:
            result, output = run_fixture_with_output(trivy, grype, clean_floor)
            if result != 1 or expected_reason not in output:
                print(
                    f"self-test failed: {label} was not treated as an unfixed finding: {output}",
                    file=sys.stderr,
                )
                return 1
            print(f"assert-vex self-test: {label} treated as no fix")
            no_fix_rejected += 1
        print(
            "assert-vex self-test: "
            f"{no_fix_rejected}/{len(no_fix_probes)} malformed fix records retained their findings"
        )

        valid_fixed_trivy = trivy_fix_fixture({"FixedVersion": "1.2.3", "Status": "fixed"})
        if run_fixture(valid_fixed_trivy, clean_grype, clean_floor) != 0:
            print("self-test failed: complete Trivy fix evidence was not honoured", file=sys.stderr)
            return 1
        valid_fixed_trivy_without_status = trivy_fix_fixture({"FixedVersion": "1.2.3"})
        if run_fixture(valid_fixed_trivy_without_status, clean_grype, clean_floor) != 0:
            print("self-test failed: Trivy FixedVersion without Status was not honoured", file=sys.stderr)
            return 1
        valid_fixed_trivy_status_only = trivy_fix_fixture({"Status": "fixed"})
        if run_fixture(valid_fixed_trivy_status_only, clean_grype, clean_floor) != 0:
            print("self-test failed: Trivy fixed Status without FixedVersion was not honoured", file=sys.stderr)
            return 1
        valid_deferred_trivy = trivy_fix_fixture({"FixedVersion": "1.2.3", "Status": "fix_deferred"})
        if run_fixture(valid_deferred_trivy, clean_grype, clean_floor) != 0:
            print("self-test failed: Trivy fix_deferred status was not honoured", file=sys.stderr)
            return 1
        valid_fixed_grype = grype_fix_fixture({"versions": ["1.2.3"], "state": "fixed"})
        if run_fixture(clean_trivy, valid_fixed_grype, clean_floor) != 0:
            print("self-test failed: complete Grype fix evidence was not honoured", file=sys.stderr)
            return 1
        print("assert-vex self-test: complete Trivy and Grype fix evidence honoured")
        print("assert-vex self-test: Trivy FixedVersion without Status honoured")
        print("assert-vex self-test: Trivy fixed Status without FixedVersion honoured")
        print("assert-vex self-test: Trivy fix_deferred status honoured")

        accept_product = "local/ubi9-base-python:ci-amd64"
        accept_vex_dir = tmp / "images" / "python" / "vex"
        accept_vex_dir.mkdir(parents=True)
        canonical_vex_name = "cve-2026-11940.openvex.json"
        td9_disposition = next(
            disposition
            for disposition in ACCEPT_AND_TRACK_DISPOSITIONS
            if disposition.vulnerability == "CVE-2026-11940"
        )
        td9_surface = next(
            surface
            for surface in td9_disposition.surfaces
            if surface.statement_path == "images/python/vex/cve-2026-11940.openvex.json"
        )
        canonical_vex = expected_accept_and_track_document(td9_disposition, td9_surface)

        accept_trivy = copy.deepcopy(clean_trivy)
        accept_trivy["ArtifactName"] = accept_product
        accept_trivy["Metadata"]["ImageConfig"]["architecture"] = "amd64"
        accept_trivy["Metadata"].pop("RepoDigests")
        accept_trivy["Results"][0]["Packages"] = [
            {"Name": "glibc", "Version": "2.34"},
            {"Name": "python3.12", "Version": "3.12.13-3.el9_8.1"},
            {"Name": "python3.12-libs", "Version": "3.12.13-3.el9_8.1"},
        ]
        accept_trivy["Results"][0]["Vulnerabilities"] = []

        accept_grype = copy.deepcopy(clean_grype)
        accept_grype["source"]["target"]["userInput"] = accept_product
        accept_grype["source"]["target"]["architecture"] = "amd64"
        accept_grype["source"]["target"]["repoDigests"] = []

        def target_trivy_records(*, fixed: bool) -> list[dict[str, Any]]:
            records: list[dict[str, Any]] = []
            for package in ("python3.12", "python3.12-libs"):
                record: dict[str, Any] = {
                    "VulnerabilityID": "CVE-2026-11940",
                    "PkgName": package,
                    "InstalledVersion": "3.12.13-3.el9_8.1",
                    "Severity": "HIGH",
                }
                if fixed:
                    record.update({"FixedVersion": "3.12.13-4.el9_8", "Status": "fixed"})
                records.append(record)
            return records

        def target_grype_records(*, fixed: bool) -> list[dict[str, Any]]:
            records: list[dict[str, Any]] = []
            for package in ("python3.12", "python3.12-libs"):
                vulnerability: dict[str, Any] = {
                    "id": "CVE-2026-11940",
                    "severity": "High",
                }
                if fixed:
                    vulnerability["fix"] = {"versions": ["3.12.13-4.el9_8"], "state": "fixed"}
                records.append(
                    {
                        "vulnerability": vulnerability,
                        "artifact": {"name": package, "version": "3.12.13-3.el9_8.1"},
                    }
                )
            return records

        accept_grype["matches"] = target_grype_records(fixed=False)

        def bind_accept_reports(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            fixture_product: str,
            architecture: str = "amd64",
        ) -> None:
            trivy["ArtifactName"] = fixture_product
            trivy["Metadata"]["ImageConfig"]["architecture"] = architecture
            grype["source"]["target"]["userInput"] = fixture_product
            grype["source"]["target"]["architecture"] = architecture
            if DIGEST_IMAGE_REFERENCE.fullmatch(fixture_product) is None:
                trivy["Metadata"].pop("RepoDigests", None)
                grype["source"]["target"]["repoDigests"] = []
            else:
                trivy["Metadata"]["RepoDigests"] = [fixture_product]
                grype["source"]["target"]["repoDigests"] = [fixture_product]

        def run_accept_fixture(
            trivy: dict[str, Any],
            grype: dict[str, Any],
            *,
            fixture_product: str = accept_product,
            document: dict[str, Any] | None = canonical_vex,
            filename: str = canonical_vex_name,
            extra_documents: tuple[tuple[str, dict[str, Any]], ...] = (),
            dispositions: tuple[AcceptAndTrackDisposition, ...] = ACCEPT_AND_TRACK_DISPOSITIONS,
            evaluation_date: date = date(2026, 8, 13),
            fixture_index_reference: str | None = None,
            fixture_index_manifest: Path | None = None,
        ) -> tuple[int | None, str, VexError | None]:
            for old_document in accept_vex_dir.glob("*.json"):
                old_document.unlink()
            if document is not None:
                write_json(accept_vex_dir / filename, document)
            for extra_name, extra_document in extra_documents:
                write_json(accept_vex_dir / extra_name, extra_document)
            write_json(trivy_json, trivy)
            write_json(grype_json, grype)
            write_json(package_floor, clean_floor)
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = assert_vex(
                        fixture_product,
                        trivy_json,
                        grype_json,
                        package_floor,
                        accept_vex_dir,
                        emit=True,
                        accept_and_track=dispositions,
                        today=evaluation_date,
                        index_reference=fixture_index_reference,
                        index_manifest=fixture_index_manifest,
                    )
            except VexError as exc:
                return None, stdout.getvalue() + stderr.getvalue(), exc
            return result, stdout.getvalue() + stderr.getvalue(), None

        def expect_accept_rejection(
            label: str,
            *,
            expected_reason: str,
            trivy: dict[str, Any] = accept_trivy,
            grype: dict[str, Any] = accept_grype,
            fixture_product: str = accept_product,
            document: dict[str, Any] | None = canonical_vex,
            filename: str = canonical_vex_name,
            dispositions: tuple[AcceptAndTrackDisposition, ...] = ACCEPT_AND_TRACK_DISPOSITIONS,
            fixture_index_reference: str | None = None,
            fixture_index_manifest: Path | None = None,
        ) -> None:
            result, output, error = run_accept_fixture(
                copy.deepcopy(trivy),
                copy.deepcopy(grype),
                fixture_product=fixture_product,
                document=copy.deepcopy(document),
                filename=filename,
                dispositions=dispositions,
                fixture_index_reference=fixture_index_reference,
                fixture_index_manifest=fixture_index_manifest,
            )
            if error is not None or result != 1 or expected_reason not in output:
                print(
                    f"self-test failed: {label} rejected for wrong reason: "
                    f"result={result} error={error} output={output}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if any(line.startswith("accept-and-track disposition:") for line in output.splitlines()):
                print(f"self-test failed: {label} emitted a disposition: {output}", file=sys.stderr)
                raise SystemExit(1)
            print(f"assert-vex self-test: {label} rejected: {expected_reason}")

        baseline_result, baseline_output, baseline_error = run_accept_fixture(accept_trivy, accept_grype)
        baseline_markers = [
            "accept-and-track disposition: CVE-2026-11940",
            "python3.12@3.12.13-3.el9_8.1",
            "python3.12-libs@3.12.13-3.el9_8.1",
            "debt=TD-9",
            "review-by=2026-10-01",
            "undispositioned unfixed HIGH/CRITICAL findings: 0",
        ]
        if (
            baseline_error is not None
            or baseline_result != 0
            or any(marker not in baseline_output for marker in baseline_markers)
        ):
            print(
                "self-test failed: canonical accept-and-track fixture did not pass with complete output: "
                f"result={baseline_result} error={baseline_error} output={baseline_output}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: canonical accept-and-track disposition passed with zero undispositioned findings")

        amd64_child_digest = "sha256:" + ("1" * 64)
        arm64_child_digest = "sha256:" + ("2" * 64)
        attestation_digest = "sha256:" + ("3" * 64)

        def image_descriptor(digest: str, architecture: str) -> dict[str, Any]:
            return {
                "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                "digest": digest,
                "size": 1234,
                "platform": {"architecture": architecture, "os": "linux"},
            }

        def attestation_descriptor(digest: str, child_digest: str) -> dict[str, Any]:
            return {
                "mediaType": OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                "digest": digest,
                "size": 567,
                "annotations": {
                    BUILDKIT_ATTESTATION_TYPE_ANNOTATION: BUILDKIT_ATTESTATION_TYPE,
                    BUILDKIT_ATTESTATION_DIGEST_ANNOTATION: child_digest,
                },
                "platform": {"architecture": "unknown", "os": "unknown"},
            }

        valid_index: dict[str, Any] = {
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [
                image_descriptor(amd64_child_digest, "amd64"),
                image_descriptor(arm64_child_digest, "arm64"),
                attestation_descriptor(attestation_digest, amd64_child_digest),
            ],
        }
        index_manifest_path = tmp / "python-index.json"

        def serialize_index(document: Any) -> bytes:
            return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

        def reference_for_index(
            raw_index: bytes,
            repository: str = PUBLISHED_PYTHON_REPOSITORY,
        ) -> str:
            return f"{repository}@sha256:{hashlib.sha256(raw_index).hexdigest()}"

        valid_index_bytes = serialize_index(valid_index)
        valid_index_reference = reference_for_index(valid_index_bytes)
        published_product = f"{PUBLISHED_PYTHON_REPOSITORY}@{amd64_child_digest}"

        def mutated_index(apply: Callable[[dict[str, Any]], Any]) -> bytes:
            mutant = copy.deepcopy(valid_index)
            apply(mutant)
            return serialize_index(mutant)

        def expect_index_rejection(
            label: str,
            expected_reason: str,
            *,
            fixture_product: str = published_product,
            raw_index: bytes = valid_index_bytes,
            fixture_index_reference: str | None = None,
            architecture: str = "amd64",
            index_manifest_supplied: bool = True,
        ) -> None:
            index_manifest_path.write_bytes(raw_index)
            supplied_reference = (
                reference_for_index(raw_index) if fixture_index_reference is None else fixture_index_reference
            )
            supplied_manifest = index_manifest_path if index_manifest_supplied else None
            try:
                accept_and_track_product_eligible(
                    fixture_product,
                    architecture,
                    supplied_reference,
                    supplied_manifest,
                    td9_surface,
                )
            except VexError as exc:
                if str(exc) != expected_reason:
                    print(
                        f"self-test failed: {label} rejected for wrong reason: {exc}",
                        file=sys.stderr,
                    )
                    raise SystemExit(1) from exc
            except Exception as exc:
                print(
                    f"self-test failed: {label} rejected for wrong reason: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                raise SystemExit(1) from exc
            else:
                print(f"self-test failed: {label} unexpectedly passed", file=sys.stderr)
                raise SystemExit(1)
            print(f"assert-vex self-test: {label} rejected: {expected_reason}")

        wrong_digest_reference = f"{PUBLISHED_PYTHON_REPOSITORY}@sha256:{'0' * 64}"
        actual_valid_digest = "sha256:" + hashlib.sha256(valid_index_bytes).hexdigest()
        expect_index_rejection(
            "index evidence declared digest mismatch",
            "index manifest digest mismatch: "
            f"--index-reference declares sha256:{'0' * 64}, bytes compute to {actual_valid_digest}",
            fixture_index_reference=wrong_digest_reference,
        )
        reformatted_index = json.dumps(valid_index, indent=2, sort_keys=True).encode("utf-8")
        reformatted_digest = "sha256:" + hashlib.sha256(reformatted_index).hexdigest()
        expect_index_rejection(
            "index evidence reformatted bytes",
            "index manifest digest mismatch: "
            f"--index-reference declares {actual_valid_digest}, bytes compute to {reformatted_digest}",
            raw_index=reformatted_index,
            fixture_index_reference=valid_index_reference,
        )
        for wrong_repository in (
            "ghcr.io/nwarila/ubi9-base-micro",
            "ghcr.io/nwarila/ubi9-base-python-x",
        ):
            expect_index_rejection(
                f"index evidence wrong repository {wrong_repository}",
                f"--index-reference repository must be {PUBLISHED_PYTHON_REPOSITORY}",
                fixture_index_reference=reference_for_index(valid_index_bytes, wrong_repository),
            )
        non_index_bytes = mutated_index(lambda value: value.update(mediaType=OCI_IMAGE_MANIFEST_MEDIA_TYPE))
        expect_index_rejection(
            "index evidence non-index media type",
            f"index manifest mediaType must be {OCI_IMAGE_INDEX_MEDIA_TYPE}",
            raw_index=non_index_bytes,
        )
        malformed_index = b"{"
        expect_index_rejection(
            "index evidence malformed JSON",
            "index manifest is malformed JSON: Expecting property name enclosed in double quotes: "
            "line 1 column 2 (char 1)",
            raw_index=malformed_index,
        )
        empty_index_bytes = mutated_index(lambda value: value.update(manifests=[]))
        expect_index_rejection(
            "index evidence empty manifests",
            "index manifest manifests must not be empty",
            raw_index=empty_index_bytes,
        )

        missing_schema_bytes = mutated_index(lambda value: value.pop("schemaVersion"))
        expect_index_rejection(
            "OCI index missing schemaVersion",
            "index manifest is missing schemaVersion",
            raw_index=missing_schema_bytes,
        )
        wrong_schema_bytes = mutated_index(lambda value: value.update(schemaVersion=3))
        expect_index_rejection(
            "OCI index schemaVersion other than 2",
            "index manifest schemaVersion must equal 2",
            raw_index=wrong_schema_bytes,
        )
        boolean_schema_bytes = mutated_index(lambda value: value.update(schemaVersion=True))
        expect_index_rejection(
            "OCI index boolean schemaVersion",
            "index manifest schemaVersion must be an integer",
            raw_index=boolean_schema_bytes,
        )
        non_object_index = serialize_index([])
        expect_index_rejection(
            "OCI index non-object top level",
            "index manifest must be a top-level JSON object",
            raw_index=non_object_index,
        )
        non_list_manifests = mutated_index(lambda value: value.update(manifests={}))
        expect_index_rejection(
            "OCI index non-list manifests",
            "index manifest manifests must be a list",
            raw_index=non_list_manifests,
        )

        def index_without_descriptor_field(field: str) -> bytes:
            mutant = copy.deepcopy(valid_index)
            mutant["manifests"][0].pop(field)
            return serialize_index(mutant)

        for missing_field in ("mediaType", "digest", "size"):
            missing_field_bytes = index_without_descriptor_field(missing_field)
            expect_index_rejection(
                f"OCI descriptor missing {missing_field}",
                f"index manifest manifests[0] is missing {missing_field}",
                raw_index=missing_field_bytes,
            )
        uppercase_digest_bytes = mutated_index(
            lambda value: value["manifests"][0].update(digest="sha256:" + ("A" * 64))
        )
        expect_index_rejection(
            "OCI descriptor non-lowercase digest",
            "index manifest manifests[0].digest must be a sha256 content digest",
            raw_index=uppercase_digest_bytes,
        )
        malformed_digest_bytes = mutated_index(lambda value: value["manifests"][0].update(digest="sha256:short"))
        expect_index_rejection(
            "OCI descriptor malformed digest",
            "index manifest manifests[0].digest must be a sha256 content digest",
            raw_index=malformed_digest_bytes,
        )
        non_integer_size_bytes = mutated_index(lambda value: value["manifests"][0].update(size="1234"))
        expect_index_rejection(
            "OCI descriptor non-integer size",
            "index manifest manifests[0].size must be a non-negative integer",
            raw_index=non_integer_size_bytes,
        )

        expect_index_rejection(
            "index digest submitted as product",
            "the index digest is never eligible as a published-child product",
            fixture_product=valid_index_reference,
        )
        same_child_bytes = mutated_index(lambda value: value["manifests"][1].update(digest=amd64_child_digest))
        expect_index_rejection(
            "two platform descriptors carry the same digest",
            "index manifest linux/amd64 and linux/arm64 child digests must be distinct",
            raw_index=same_child_bytes,
        )
        third_platform_bytes = mutated_index(
            lambda value: value["manifests"].append(image_descriptor("sha256:" + ("4" * 64), "s390x"))
        )
        expect_index_rejection(
            "third runnable platform",
            "index manifest contains unsupported runnable platform linux/s390x",
            raw_index=third_platform_bytes,
        )
        duplicate_platform_bytes = mutated_index(
            lambda value: value["manifests"].append(image_descriptor("sha256:" + ("4" * 64), "amd64"))
        )
        expect_index_rejection(
            "duplicate linux/amd64 descriptor",
            "index manifest must contain exactly one linux/amd64 image manifest descriptor; found 2",
            raw_index=duplicate_platform_bytes,
        )
        missing_architecture_bytes = mutated_index(lambda value: value["manifests"].pop(1))
        expect_index_rejection(
            "missing linux/arm64 descriptor",
            "index manifest must contain exactly one linux/arm64 image manifest descriptor; found 0",
            raw_index=missing_architecture_bytes,
        )
        nested_index_bytes = mutated_index(
            lambda value: value["manifests"].append(
                {
                    "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
                    "digest": "sha256:" + ("4" * 64),
                    "size": 42,
                    "platform": {"architecture": "s390x", "os": "linux"},
                }
            )
        )
        expect_index_rejection(
            "nested image-index descriptor",
            "index manifest manifests[3] must not be a nested image index descriptor",
            fixture_product=f"{PUBLISHED_PYTHON_REPOSITORY}@sha256:{'4' * 64}",
            raw_index=nested_index_bytes,
        )
        missing_attestation_type_bytes = mutated_index(
            lambda value: value["manifests"][2]["annotations"].pop(BUILDKIT_ATTESTATION_TYPE_ANNOTATION)
        )
        expect_index_rejection(
            "unknown/unknown descriptor missing reference-type annotation",
            "index manifest manifests[2] unknown/unknown descriptor must carry "
            f"{BUILDKIT_ATTESTATION_TYPE_ANNOTATION}={BUILDKIT_ATTESTATION_TYPE}",
            raw_index=missing_attestation_type_bytes,
        )
        unrelated_reference_digest = "sha256:" + ("5" * 64)
        wrong_attestation_reference_bytes = mutated_index(
            lambda value: value["manifests"][2]["annotations"].update(
                {BUILDKIT_ATTESTATION_DIGEST_ANNOTATION: unrelated_reference_digest}
            )
        )
        expect_index_rejection(
            "unknown/unknown descriptor references neither eligible child",
            "index manifest manifests[2] attestation reference digest must name an eligible platform child",
            raw_index=wrong_attestation_reference_bytes,
        )
        expect_index_rejection(
            "unknown/unknown attestation descriptor submitted as product",
            "published-child product digest identifies an attestation descriptor",
            fixture_product=f"{PUBLISHED_PYTHON_REPOSITORY}@{attestation_digest}",
        )
        swapped_mapping_bytes = mutated_index(
            lambda value: (
                value["manifests"][0]["platform"].update(architecture="arm64"),
                value["manifests"][1]["platform"].update(architecture="amd64"),
            )
        )
        expect_index_rejection(
            "swapped amd64 and arm64 mapping",
            "published-child product digest does not match the index child for scanner architecture amd64",
            raw_index=swapped_mapping_bytes,
        )
        expect_index_rejection(
            "product digest absent from index",
            "published-child product digest is absent from the verified index",
            fixture_product=f"{PUBLISHED_PYTHON_REPOSITORY}@sha256:{'6' * 64}",
        )
        expect_index_rejection(
            "tag-addressed published-child product",
            "published-child --product must be a digest-qualified image reference",
            fixture_product=f"{PUBLISHED_PYTHON_REPOSITORY}:latest",
        )
        expect_index_rejection(
            "wrong repository in published-child product",
            f"published-child --product repository must be {PUBLISHED_PYTHON_REPOSITORY}",
            fixture_product=f"ghcr.io/nwarila/ubi9-base-python-x@{amd64_child_digest}",
        )
        expect_index_rejection(
            "index evidence supplied for local CI product",
            "index evidence must not be supplied for a local accept-and-track product",
            fixture_product=accept_product,
        )
        expect_index_rejection(
            "unpaired index evidence",
            "--index-reference and --index-manifest must be supplied together",
            index_manifest_supplied=False,
        )

        published_trivy = copy.deepcopy(accept_trivy)
        published_grype = copy.deepcopy(accept_grype)
        bind_accept_reports(published_trivy, published_grype, published_product, "amd64")

        def run_cli_fixture(
            fixture_product: str,
            raw_index: bytes | None,
        ) -> tuple[int, str]:
            fixture_trivy = copy.deepcopy(accept_trivy)
            fixture_grype = copy.deepcopy(accept_grype)
            bind_accept_reports(fixture_trivy, fixture_grype, fixture_product, "amd64")
            for old_document in accept_vex_dir.glob("*.json"):
                old_document.unlink()
            write_json(accept_vex_dir / canonical_vex_name, canonical_vex)
            write_json(trivy_json, fixture_trivy)
            write_json(grype_json, fixture_grype)
            write_json(package_floor, clean_floor)
            arguments = [
                "--product",
                fixture_product,
                "--trivy-json",
                str(trivy_json),
                "--grype-json",
                str(grype_json),
                "--package-floor",
                str(package_floor),
                "--vex-dir",
                str(accept_vex_dir),
            ]
            if raw_index is not None:
                index_manifest_path.write_bytes(raw_index)
                arguments.extend(
                    [
                        "--index-reference",
                        reference_for_index(raw_index),
                        "--index-manifest",
                        str(index_manifest_path),
                    ]
                )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = main(arguments)
            return result, stdout.getvalue() + stderr.getvalue()

        def expect_cli_rejection(
            label: str,
            expected_reason: str,
            *,
            fixture_product: str = published_product,
            raw_index: bytes = valid_index_bytes,
        ) -> None:
            result, output = run_cli_fixture(fixture_product, raw_index)
            if result != 1 or f"assert-vex failed: {expected_reason}" not in output:
                print(
                    f"self-test failed: full CLI {label} rejected for wrong reason: result={result} output={output}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            print(f"assert-vex self-test: full CLI {label} rejected: {expected_reason}")

        duplicate_descriptor_reason = (
            f"index manifest descriptor digest {attestation_digest} is repeated at manifests[2] and manifests[3]; "
            "duplicate or contradictory descriptors are forbidden"
        )
        identical_duplicate_attestation_bytes = mutated_index(
            lambda value: value["manifests"].append(copy.deepcopy(value["manifests"][2]))
        )
        contradictory_attestation_bytes = mutated_index(
            lambda value: value["manifests"].append(attestation_descriptor(attestation_digest, arm64_child_digest))
        )
        duplicate_probe_failed = False
        for label, raw_index in (
            ("identical duplicate attestation descriptor", identical_duplicate_attestation_bytes),
            ("same attestation digest with contradictory child annotations", contradictory_attestation_bytes),
        ):
            result, output = run_cli_fixture(published_product, raw_index)
            if result != 1 or f"assert-vex failed: {duplicate_descriptor_reason}" not in output:
                print(
                    f"self-test failed: full CLI {label} rejected for wrong reason: result={result} output={output}",
                    file=sys.stderr,
                )
                duplicate_probe_failed = True
            else:
                print(f"assert-vex self-test: full CLI {label} rejected: {duplicate_descriptor_reason}")
        if duplicate_probe_failed:
            return 1

        missing_attestation_reference_bytes = mutated_index(
            lambda value: value["manifests"][2]["annotations"].pop(BUILDKIT_ATTESTATION_DIGEST_ANNOTATION)
        )
        expect_cli_rejection(
            "attestation descriptor missing reference-digest annotation",
            "index manifest manifests[2].annotations['vnd.docker.reference.digest'] must be a non-empty string",
            raw_index=missing_attestation_reference_bytes,
        )
        extra_attestation_annotation_bytes = mutated_index(
            lambda value: value["manifests"][2]["annotations"].update({"org.example.extra": "forbidden"})
        )
        expect_cli_rejection(
            "attestation descriptor with an extra annotation key",
            "index manifest manifests[2].annotations must equal the locked BuildKit attestation shape",
            raw_index=extra_attestation_annotation_bytes,
        )

        def attestation_without_descriptor_field(field: str) -> bytes:
            return mutated_index(lambda value: value["manifests"][2].pop(field))

        def index_with_descriptor_field(
            descriptor_index: int,
            field: str,
            value: Any,
        ) -> bytes:
            def apply(document: dict[str, Any]) -> None:
                document["manifests"][descriptor_index][field] = value

            return mutated_index(apply)

        def index_with_schema_version(value: Any) -> bytes:
            def apply(document: dict[str, Any]) -> None:
                document["schemaVersion"] = value

            return mutated_index(apply)

        for missing_field in ("mediaType", "digest", "size"):
            expect_cli_rejection(
                f"attestation descriptor missing {missing_field}",
                f"index manifest manifests[2] is missing {missing_field}",
                raw_index=attestation_without_descriptor_field(missing_field),
            )
        attestation_type_failures: tuple[tuple[str, str, Any, str], ...] = (
            (
                "mediaType",
                "integer",
                17,
                "index manifest manifests[2].mediaType must be a non-empty string",
            ),
            (
                "digest",
                "integer",
                17,
                "index manifest manifests[2].digest must be a non-empty string",
            ),
            (
                "size",
                "string",
                "567",
                "index manifest manifests[2].size must be a non-negative integer",
            ),
        )
        for field, invalid_type, invalid_value, expected_reason in attestation_type_failures:
            type_failure_bytes = index_with_descriptor_field(2, field, invalid_value)
            expect_cli_rejection(
                f"attestation descriptor {field} with {invalid_type} type",
                expected_reason,
                raw_index=type_failure_bytes,
            )

        size_failures: tuple[tuple[str, Any], ...] = (
            ("boolean", True),
            ("float", 1234.5),
            ("negative", -1),
        )
        for invalid_type, invalid_value in size_failures:
            size_failure_bytes = index_with_descriptor_field(0, "size", invalid_value)
            expect_cli_rejection(
                f"descriptor size that is {invalid_type}",
                "index manifest manifests[0].size must be a non-negative integer",
                raw_index=size_failure_bytes,
            )

        for invalid_type, invalid_value in (("string", "2"), ("null", None)):
            schema_failure_bytes = index_with_schema_version(invalid_value)
            expect_cli_rejection(
                f"schemaVersion with {invalid_type} type",
                "index manifest schemaVersion must be an integer",
                raw_index=schema_failure_bytes,
            )

        for repository_label, repository in (
            ("unexpected", "ghcr.io/example/ubi9-base-python"),
            ("look-alike", "ghcr.io/nwarila/ubi9-base-python-x"),
        ):
            expect_cli_rejection(
                f"published-child product in {repository_label} repository",
                f"published-child --product repository must be {PUBLISHED_PYTHON_REPOSITORY}",
                fixture_product=f"{repository}@{amd64_child_digest}",
            )

        windows_platform_bytes = mutated_index(lambda value: value["manifests"][0]["platform"].update(os="windows"))
        expect_cli_rejection(
            "descriptor platform windows/amd64",
            "index manifest contains unsupported descriptor platform windows/amd64",
            raw_index=windows_platform_bytes,
        )

        distinct_attestation_product = f"{PUBLISHED_PYTHON_REPOSITORY}@{attestation_digest}"
        distinct_result, distinct_output = run_cli_fixture(
            distinct_attestation_product,
            valid_index_bytes,
        )
        distinct_reason = "published-child product digest identifies an attestation descriptor"
        if distinct_result != 1 or f"assert-vex failed: {distinct_reason}" not in distinct_output:
            print(
                "self-test failed: full CLI distinct attestation digest rejected for wrong reason: "
                f"result={distinct_result} output={distinct_output}",
                file=sys.stderr,
            )
            return 1
        print(f"assert-vex self-test: full CLI distinct attestation digest rejected: {distinct_reason}")

        legitimate_result, legitimate_output = run_cli_fixture(
            published_product,
            valid_index_bytes,
        )
        legitimate_disposition = next(
            (line for line in legitimate_output.splitlines() if line.startswith("accept-and-track disposition:")),
            None,
        )
        if legitimate_result != 0 or legitimate_disposition is None:
            print(
                "self-test failed: full CLI legitimate child did not pass: "
                f"result={legitimate_result} output={legitimate_output}",
                file=sys.stderr,
            )
            return 1
        print(f"assert-vex self-test: full CLI legitimate child accepted: {legitimate_disposition}")

        second_attestation_digest = "sha256:" + ("4" * 64)
        two_attestations_bytes = mutated_index(
            lambda value: value["manifests"].append(
                attestation_descriptor(second_attestation_digest, arm64_child_digest)
            )
        )
        two_attestations_result, two_attestations_output = run_cli_fixture(
            published_product,
            two_attestations_bytes,
        )
        if two_attestations_result != 0 or not any(
            line.startswith("accept-and-track disposition:") for line in two_attestations_output.splitlines()
        ):
            print(
                "self-test failed: full CLI two distinct well-formed attestation descriptors did not pass: "
                f"result={two_attestations_result} output={two_attestations_output}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: full CLI two distinct well-formed attestation descriptors accepted")

        legacy_result, legacy_output = run_cli_fixture(accept_product, None)
        if legacy_result != 0 or not any(
            line.startswith("accept-and-track disposition:") for line in legacy_output.splitlines()
        ):
            print(
                "self-test failed: full CLI legacy local-product path did not pass: "
                f"result={legacy_result} output={legacy_output}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: full CLI legacy local-product path accepted")

        aliased_attestation_bytes = mutated_index(lambda value: value["manifests"][2].update(digest=amd64_child_digest))
        alias_result, alias_output = run_cli_fixture(
            published_product,
            aliased_attestation_bytes,
        )
        alias_reason = (
            "index manifest attestation descriptor digests must be disjoint from eligible platform child digests"
        )
        if alias_result != 1 or f"assert-vex failed: {alias_reason}" not in alias_output:
            print(
                "self-test failed: full CLI aliased attestation digest rejected for wrong reason: "
                f"result={alias_result} output={alias_output}",
                file=sys.stderr,
            )
            return 1
        print(f"assert-vex self-test: full CLI aliased attestation digest rejected: {alias_reason}")

        index_manifest_path.write_bytes(valid_index_bytes)
        published_result, published_output, published_error = run_accept_fixture(
            published_trivy,
            published_grype,
            fixture_product=published_product,
            fixture_index_reference=valid_index_reference,
            fixture_index_manifest=index_manifest_path,
        )
        if (
            published_error is not None
            or published_result != 0
            or any(marker not in published_output for marker in baseline_markers)
        ):
            print(
                "self-test failed: verified published-child production-shape fixture did not pass: "
                f"result={published_result} error={published_error} output={published_output}",
                file=sys.stderr,
            )
            return 1
        print(
            "assert-vex self-test: verified published-child production shape accepted: "
            + next(line for line in published_output.splitlines() if line.startswith("accept-and-track disposition:"))
        )
        expect_accept_rejection(
            "published-child unavailable without index evidence",
            expected_reason="un-vexed unfixed HIGH/CRITICAL findings",
            trivy=published_trivy,
            grype=published_grype,
            fixture_product=published_product,
        )

        published_altered_vex = copy.deepcopy(canonical_vex)
        published_altered_vex["statements"][0]["products"][2]["@id"] += "-altered"
        expect_accept_rejection(
            "published-child altered canonical document",
            expected_reason="accept-and-track products and subcomponents must match the canonical ordered set",
            trivy=published_trivy,
            grype=published_grype,
            fixture_product=published_product,
            document=published_altered_vex,
            fixture_index_reference=valid_index_reference,
            fixture_index_manifest=index_manifest_path,
        )
        expect_accept_rejection(
            "published-child canonical statement without in-tool authorization",
            expected_reason="no exact in-tool accept-and-track allowlist entry",
            trivy=published_trivy,
            grype=published_grype,
            fixture_product=published_product,
            dispositions=(),
            fixture_index_reference=valid_index_reference,
            fixture_index_manifest=index_manifest_path,
        )
        published_padded_grype = copy.deepcopy(published_grype)
        published_padded_grype["matches"][0]["artifact"]["name"] = " python3.12 "
        expect_accept_rejection(
            "published-child byte-noncanonical scanner identity",
            expected_reason=(
                "malformed accept-and-track scanner identity evidence: "
                "Grype matches[0].artifact.name must not contain surrounding whitespace"
            ),
            trivy=published_trivy,
            grype=published_padded_grype,
            fixture_product=published_product,
            fixture_index_reference=valid_index_reference,
            fixture_index_manifest=index_manifest_path,
        )
        published_wrong_package_grype = copy.deepcopy(published_grype)
        published_wrong_package_grype["matches"][0]["artifact"]["version"] = "3.12.13-3.el9_8.2"
        expect_accept_rejection(
            "published-child exact package-version pair",
            expected_reason="no exact in-tool accept-and-track allowlist entry",
            trivy=published_trivy,
            grype=published_wrong_package_grype,
            fixture_product=published_product,
            fixture_index_reference=valid_index_reference,
            fixture_index_manifest=index_manifest_path,
        )
        published_fixed_trivy = copy.deepcopy(published_trivy)
        published_fixed_trivy["Results"][0]["Vulnerabilities"] = target_trivy_records(fixed=True)
        expect_accept_rejection(
            "published-child valid cross-scanner fix evidence",
            expected_reason=(
                "valid fix evidence refuses accept-and-track disposition: "
                "trivy:python3.12@3.12.13-3.el9_8.1,trivy:python3.12-libs@3.12.13-3.el9_8.1"
            ),
            trivy=published_fixed_trivy,
            grype=published_grype,
            fixture_product=published_product,
            fixture_index_reference=valid_index_reference,
            fixture_index_manifest=index_manifest_path,
        )
        published_expired_result, _, published_expired_error = run_accept_fixture(
            published_trivy,
            published_grype,
            fixture_product=published_product,
            evaluation_date=date(2026, 10, 2),
            fixture_index_reference=valid_index_reference,
            fixture_index_manifest=index_manifest_path,
        )
        expected_published_expiry = (
            "expired accept-and-track entry: CVE-2026-11940 "
            f"product={published_product} "
            "packages=python3.12@3.12.13-3.el9_8.1,python3.12-libs@3.12.13-3.el9_8.1 "
            "debt=TD-9 review-by=2026-10-01"
        )
        if (
            published_expired_result is not None
            or published_expired_error is None
            or str(published_expired_error) != expected_published_expiry
        ):
            print(
                f"self-test failed: published-child elapsed entry rejected for wrong reason: {published_expired_error}",
                file=sys.stderr,
            )
            return 1
        print(f"assert-vex self-test: published-child elapsed entry rejected: {expected_published_expiry}")

        padded_identity_probes: list[tuple[str, Callable[[dict[str, Any]], Any], str]] = [
            (
                "accept-and-track padded scanner vulnerability id",
                lambda match: match["vulnerability"].__setitem__("id", " CVE-2026-11940 "),
                "malformed accept-and-track scanner identity evidence: "
                "Grype matches[0].vulnerability.id must not contain surrounding whitespace",
            ),
            (
                "accept-and-track padded scanner package name",
                lambda match: match["artifact"].__setitem__("name", " python3.12 "),
                "malformed accept-and-track scanner identity evidence: "
                "Grype matches[0].artifact.name must not contain surrounding whitespace",
            ),
            (
                "accept-and-track padded scanner version",
                lambda match: match["artifact"].__setitem__("version", " 3.12.13-3.el9_8.1 "),
                "malformed accept-and-track scanner identity evidence: "
                "Grype matches[0].artifact.version must not contain surrounding whitespace",
            ),
        ]
        for label, mutate_match, expected_reason in padded_identity_probes:
            padded_grype = copy.deepcopy(accept_grype)
            mutate_match(padded_grype["matches"][0])
            expect_accept_rejection(
                label,
                expected_reason=expected_reason,
                grype=padded_grype,
            )
        print("assert-vex self-test: 3/3 padded scanner identity bound-pair probes emitted no disposition")

        def mutate_vex(apply: Callable[[dict[str, Any]], Any]) -> dict[str, Any]:
            mutated = copy.deepcopy(canonical_vex)
            apply(mutated)
            return mutated

        statement_mutations: list[tuple[str, dict[str, Any], str]] = [
            (
                "accept-and-track statement wrong CVE",
                mutate_vex(lambda value: value["statements"][0]["vulnerability"].update(name="CVE-2099-0000")),
                "no reviewed OpenVEX statement for CVE-2026-11940",
            ),
            (
                "accept-and-track statement first package altered",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"][0].update(
                        {"@id": "pkg:rpm/redhat/python3.12-extra@3.12.13-3.el9_8.1"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement first package missing",
                mutate_vex(lambda value: value["statements"][0]["products"][0]["subcomponents"].pop(0)),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement second package altered",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"][1].update(
                        {"@id": "pkg:rpm/redhat/python3.12-libs-extra@3.12.13-3.el9_8.1"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement second package missing",
                mutate_vex(lambda value: value["statements"][0]["products"][0]["subcomponents"].pop(1)),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement extra package",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"].append(
                        {"@id": "pkg:rpm/redhat/extra@1"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement first version altered",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"][0].update(
                        {"@id": "pkg:rpm/redhat/python3.12@3.12.13-3.el9_8.2"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement second version altered",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0]["subcomponents"][1].update(
                        {"@id": "pkg:rpm/redhat/python3.12-libs@3.12.13-3.el9_8.2"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement wrong product",
                mutate_vex(
                    lambda value: value["statements"][0]["products"][0].update(
                        {"@id": "local/ubi9-base-python:ci-other"}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "accept-and-track statement status other than affected",
                mutate_vex(lambda value: value["statements"][0].update(status="fixed")),
                "accept-and-track status must be affected",
            ),
            (
                "accept-and-track statement zero review markers",
                mutate_vex(
                    lambda value: value["statements"][0].update(
                        action_statement=TD9_ACTION_STATEMENT.replace("review-by", "review by")
                    )
                ),
                "accept-and-track action_statement must contain exactly one review-by marker",
            ),
            (
                "accept-and-track statement two review markers",
                mutate_vex(
                    lambda value: value["statements"][0].update(
                        action_statement=TD9_ACTION_STATEMENT + " review-by 2026-10-01"
                    )
                ),
                "accept-and-track action_statement must contain exactly one review-by marker",
            ),
            (
                "accept-and-track statement wrong review date",
                mutate_vex(
                    lambda value: value["statements"][0].update(
                        action_statement=TD9_ACTION_STATEMENT.replace("2026-10-01", "2026-10-02")
                    )
                ),
                "accept-and-track action_statement must contain review-by 2026-10-01",
            ),
            (
                "accept-and-track statement wrong debt id",
                mutate_vex(
                    lambda value: value["statements"][0].update(
                        action_statement=TD9_ACTION_STATEMENT.replace("TD-9", "TD-10")
                    )
                ),
                "accept-and-track action_statement must name TD-9",
            ),
            (
                "accept-and-track statement added alias",
                mutate_vex(lambda value: value["statements"][0]["vulnerability"].update(aliases=[])),
                "accept-and-track vulnerability must contain only its name",
            ),
            (
                "accept-and-track statement added product",
                mutate_vex(
                    lambda value: value["statements"][0]["products"].append(
                        {"@id": "local/ubi9-base-python:ci-extra", "subcomponents": []}
                    )
                ),
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
        ]
        for label, mutated_document, expected_reason in statement_mutations:
            expect_accept_rejection(label, expected_reason=expected_reason, document=mutated_document)

        expect_accept_rejection(
            "accept-and-track allowlist present but statement absent",
            expected_reason="no reviewed OpenVEX statement for CVE-2026-11940",
            document=None,
        )
        expect_accept_rejection(
            "accept-and-track statement present but allowlist absent",
            expected_reason="no exact in-tool accept-and-track allowlist entry",
            dispositions=(),
        )
        expect_accept_rejection(
            "accept-and-track canonical statement under wrong file name",
            expected_reason="statement source must be images/python/vex/cve-2026-11940.openvex.json",
            filename="wrong.openvex.json",
        )

        canonical_disposition = td9_disposition
        allowlist_mutations: list[tuple[str, AcceptAndTrackDisposition, str]] = [
            (
                "accept-and-track allowlist wrong CVE",
                replace(canonical_disposition, vulnerability="CVE-2099-0000"),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist wrong product",
                replace(
                    canonical_disposition,
                    surfaces=(
                        replace(
                            canonical_disposition.surfaces[0],
                            local_products=("local/ubi9-base-python:ci-other",),
                        ),
                    ),
                ),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist missing first package",
                replace(canonical_disposition, packages=canonical_disposition.packages[1:]),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist missing second package",
                replace(canonical_disposition, packages=canonical_disposition.packages[:1]),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist extra package",
                replace(canonical_disposition, packages=(*canonical_disposition.packages, ("extra", "1"))),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist first version altered",
                replace(
                    canonical_disposition,
                    packages=(("python3.12", "3.12.13-3.el9_8.2"), canonical_disposition.packages[1]),
                ),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist second version altered",
                replace(
                    canonical_disposition,
                    packages=(canonical_disposition.packages[0], ("python3.12-libs", "3.12.13-3.el9_8.2")),
                ),
                "no exact in-tool accept-and-track allowlist entry",
            ),
            (
                "accept-and-track allowlist wrong debt id",
                replace(canonical_disposition, debt_id="TD-10"),
                "in-tool accept-and-track allowlist entry does not match the canonical authorization",
            ),
            (
                "accept-and-track allowlist wrong review date",
                replace(canonical_disposition, review_by="2026-10-02"),
                "in-tool accept-and-track allowlist entry does not match the canonical authorization",
            ),
            (
                "accept-and-track allowlist wrong statement path",
                replace(
                    canonical_disposition,
                    surfaces=(
                        replace(
                            canonical_disposition.surfaces[0],
                            statement_path="images/python/vex/other.openvex.json",
                        ),
                    ),
                ),
                "in-tool accept-and-track allowlist entry does not match the canonical authorization",
            ),
        ]
        for label, mutated_disposition, expected_reason in allowlist_mutations:
            expect_accept_rejection(
                label,
                expected_reason=expected_reason,
                dispositions=(mutated_disposition,),
            )

        unintended_trivy = copy.deepcopy(accept_trivy)
        unintended_grype = copy.deepcopy(accept_grype)
        unintended_product = "local/ubi9-base-python:ci-amd64-extra"
        bind_accept_reports(unintended_trivy, unintended_grype, unintended_product)
        expect_accept_rejection(
            "accept-and-track unintended base-python tag",
            expected_reason="un-vexed unfixed HIGH/CRITICAL findings",
            trivy=unintended_trivy,
            grype=unintended_grype,
            fixture_product=unintended_product,
        )

        duplicate_file_result, _, duplicate_file_error = run_accept_fixture(
            accept_trivy,
            accept_grype,
            extra_documents=(("duplicate.openvex.json", canonical_vex),),
        )
        if (
            duplicate_file_result is not None
            or duplicate_file_error is None
            or "duplicate accept-and-track statements for CVE-2026-11940" not in str(duplicate_file_error)
        ):
            print(
                f"self-test failed: duplicate accept-and-track file rejected for wrong reason: {duplicate_file_error}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: duplicate accept-and-track file rejected at its expected discriminator")

        duplicate_statement = copy.deepcopy(canonical_vex)
        duplicate_statement["statements"].append(copy.deepcopy(duplicate_statement["statements"][0]))
        duplicate_statement_result, _, duplicate_statement_error = run_accept_fixture(
            accept_trivy,
            accept_grype,
            document=duplicate_statement,
        )
        if (
            duplicate_statement_result is not None
            or duplicate_statement_error is None
            or "duplicate accept-and-track statements for CVE-2026-11940" not in str(duplicate_statement_error)
        ):
            print(
                "self-test failed: duplicate accept-and-track statement rejected for wrong reason: "
                f"{duplicate_statement_error}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: duplicate accept-and-track statement rejected at its expected discriminator")

        expired_result, _, expired_error = run_accept_fixture(
            accept_trivy,
            accept_grype,
            evaluation_date=date(2026, 10, 2),
        )
        expected_expiry = (
            "expired accept-and-track entry: CVE-2026-11940 product=local/ubi9-base-python:ci-amd64 "
            "packages=python3.12@3.12.13-3.el9_8.1,python3.12-libs@3.12.13-3.el9_8.1 "
            "debt=TD-9 review-by=2026-10-01"
        )
        if expired_result is not None or expired_error is None or str(expired_error) != expected_expiry:
            print(
                f"self-test failed: elapsed accept-and-track entry rejected for wrong reason: {expired_error}",
                file=sys.stderr,
            )
            return 1
        print(f"assert-vex self-test: elapsed candidate-scoped entry rejected: {expected_expiry}")

        micro_product = "ghcr.io/nwarila/ubi9-base-micro:base-micro"
        micro_trivy = copy.deepcopy(accept_trivy)
        micro_grype = copy.deepcopy(accept_grype)
        bind_accept_reports(micro_trivy, micro_grype, micro_product)
        micro_before = run_accept_fixture(
            micro_trivy,
            micro_grype,
            fixture_product=micro_product,
            evaluation_date=date(2026, 10, 1),
        )
        micro_after = run_accept_fixture(
            micro_trivy,
            micro_grype,
            fixture_product=micro_product,
            evaluation_date=date(2026, 10, 2),
        )
        if (
            micro_before[:2] != micro_after[:2]
            or micro_before[0] != 1
            or "un-vexed unfixed HIGH/CRITICAL findings" not in micro_before[1]
            or any(line.startswith("accept-and-track disposition:") for line in micro_before[1].splitlines())
            or micro_before[2] is not None
            or micro_after[2] is not None
        ):
            print("self-test failed: micro product output changed after the review date", file=sys.stderr)
            return 1
        print("assert-vex self-test: micro product evaluation remained byte-identical after review date")

        dormant_trivy = copy.deepcopy(accept_trivy)
        dormant_grype = copy.deepcopy(clean_grype)
        bind_accept_reports(dormant_trivy, dormant_grype, accept_product)
        dormant_before = run_accept_fixture(
            dormant_trivy,
            dormant_grype,
            evaluation_date=date(2026, 10, 1),
        )
        dormant_after = run_accept_fixture(
            dormant_trivy,
            dormant_grype,
            evaluation_date=date(2026, 10, 2),
        )
        if (
            dormant_before[:2] != dormant_after[:2]
            or dormant_before[0] != 0
            or "unfixed HIGH/CRITICAL findings requiring VEX: 0" not in dormant_before[1]
            or dormant_before[2] is not None
            or dormant_after[2] is not None
        ):
            print("self-test failed: dormant base-python entry output changed after the review date", file=sys.stderr)
            return 1
        print("assert-vex self-test: dormant base-python entry evaluation remained byte-identical after review date")

        trivy_fixed = copy.deepcopy(accept_trivy)
        trivy_fixed["Results"][0]["Vulnerabilities"] = target_trivy_records(fixed=True)
        grype_unfixed = copy.deepcopy(accept_grype)
        expect_accept_rejection(
            "accept-and-track Trivy-fixed Grype-unfixed contradiction",
            expected_reason=(
                "valid fix evidence refuses accept-and-track disposition: "
                "trivy:python3.12@3.12.13-3.el9_8.1,trivy:python3.12-libs@3.12.13-3.el9_8.1"
            ),
            trivy=trivy_fixed,
            grype=grype_unfixed,
        )

        trivy_unfixed = copy.deepcopy(accept_trivy)
        trivy_unfixed["Results"][0]["Vulnerabilities"] = target_trivy_records(fixed=False)
        grype_fixed = copy.deepcopy(accept_grype)
        grype_fixed["matches"] = target_grype_records(fixed=True)
        expect_accept_rejection(
            "accept-and-track Grype-fixed Trivy-unfixed contradiction",
            expected_reason=(
                "valid fix evidence refuses accept-and-track disposition: "
                "grype:python3.12@3.12.13-3.el9_8.1,grype:python3.12-libs@3.12.13-3.el9_8.1"
            ),
            trivy=trivy_unfixed,
            grype=grype_fixed,
        )

        all_fixed_result, all_fixed_output, all_fixed_error = run_accept_fixture(trivy_fixed, grype_fixed)
        if (
            all_fixed_error is not None
            or all_fixed_result != 0
            or "unfixed HIGH/CRITICAL findings requiring VEX: 0" not in all_fixed_output
            or "accept-and-track disposition:" in all_fixed_output
        ):
            print(
                "self-test failed: all-fixed target pair did not take the trivial pass: "
                f"result={all_fixed_result} error={all_fixed_error} output={all_fixed_output}",
                file=sys.stderr,
            )
            return 1
        print("assert-vex self-test: all-fixed target pair passed without an accept-and-track disposition")

        surface_pairs = tuple(
            (disposition, surface) for disposition in ACCEPT_AND_TRACK_DISPOSITIONS for surface in disposition.surfaces
        )

        def surface_reports(
            disposition: AcceptAndTrackDisposition,
            fixture_product: str,
            *,
            architecture: str = "amd64",
            trivy_fixed_state: bool = False,
            grype_fixed_state: bool = False,
            trivy_finding: bool = True,
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            trivy = copy.deepcopy(clean_trivy)
            grype = copy.deepcopy(clean_grype)
            bind_accept_reports(trivy, grype, fixture_product, architecture)
            trivy["Results"][0]["Packages"] = [
                {"Name": "glibc", "Version": "2.34"},
                *[{"Name": package, "Version": version} for package, version in disposition.packages],
            ]
            trivy["Results"][0]["Vulnerabilities"] = []
            if trivy_finding:
                for package, version in disposition.packages:
                    trivy_record: dict[str, Any] = {
                        "VulnerabilityID": disposition.vulnerability,
                        "PkgName": package,
                        "InstalledVersion": version,
                        "Severity": "HIGH",
                    }
                    if trivy_fixed_state:
                        trivy_record.update({"FixedVersion": version + ".fixed", "Status": "fixed"})
                    trivy["Results"][0]["Vulnerabilities"].append(trivy_record)
            grype["matches"] = []
            for package, version in disposition.packages:
                vulnerability: dict[str, Any] = {
                    "id": disposition.vulnerability,
                    "severity": "High",
                }
                if grype_fixed_state:
                    vulnerability["fix"] = {"versions": [version + ".fixed"], "state": "fixed"}
                grype["matches"].append(
                    {
                        "vulnerability": vulnerability,
                        "artifact": {"name": package, "version": version},
                    }
                )
            return trivy, grype

        def run_surface_fixture(
            disposition: AcceptAndTrackDisposition,
            surface: AcceptAndTrackSurface,
            fixture_product: str,
            *,
            trivy: dict[str, Any] | None = None,
            grype: dict[str, Any] | None = None,
            document: dict[str, Any] | None = None,
            omit_statement: bool = False,
            statement_surface: AcceptAndTrackSurface | None = None,
            filename: str | None = None,
            dispositions: tuple[AcceptAndTrackDisposition, ...] = ACCEPT_AND_TRACK_DISPOSITIONS,
            evaluation_date: date = date(2026, 8, 18),
            fixture_index_reference: str | None = None,
            fixture_index_manifest: Path | None = None,
            duplicate_document: bool = False,
        ) -> tuple[int | None, str, VexError | None]:
            fixture_trivy, fixture_grype = surface_reports(disposition, fixture_product)
            if trivy is not None:
                fixture_trivy = copy.deepcopy(trivy)
            if grype is not None:
                fixture_grype = copy.deepcopy(grype)
            selected_statement_surface = surface if statement_surface is None else statement_surface
            fixture_vex_dir = tmp / Path(selected_statement_surface.statement_path).parent
            fixture_vex_dir.mkdir(parents=True, exist_ok=True)
            for old_document in fixture_vex_dir.glob("*.json"):
                old_document.unlink()
            selected_document = (
                expected_accept_and_track_document(disposition, surface)
                if document is None
                else copy.deepcopy(document)
            )
            if not omit_statement:
                fixture_name = filename or Path(selected_statement_surface.statement_path).name
                write_json(fixture_vex_dir / fixture_name, selected_document)
                if duplicate_document:
                    write_json(fixture_vex_dir / "duplicate.openvex.json", selected_document)
            write_json(trivy_json, fixture_trivy)
            write_json(grype_json, fixture_grype)
            write_json(package_floor, clean_floor)
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = assert_vex(
                        fixture_product,
                        trivy_json,
                        grype_json,
                        package_floor,
                        fixture_vex_dir,
                        emit=True,
                        accept_and_track=dispositions,
                        today=evaluation_date,
                        index_reference=fixture_index_reference,
                        index_manifest=fixture_index_manifest,
                    )
            except VexError as exc:
                return None, stdout.getvalue() + stderr.getvalue(), exc
            return result, stdout.getvalue() + stderr.getvalue(), None

        def require_surface_result(
            label: str,
            result: tuple[int | None, str, VexError | None],
            *,
            accepted: bool,
            reason: str = "",
        ) -> None:
            status, output, error = result
            if accepted:
                if error is not None or status != 0 or "accept-and-track disposition:" not in output:
                    print(
                        f"self-test failed: {label} did not accept: status={status} error={error} output={output}",
                        file=sys.stderr,
                    )
                    raise SystemExit(1)
                print(f"assert-vex self-test: {label} accepted")
                return
            combined = output + (str(error) if error is not None else "")
            if (error is None and status != 1) or reason not in combined:
                print(
                    f"self-test failed: {label} rejected for wrong reason: "
                    f"status={status} error={error} output={output}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if any(line.startswith("accept-and-track disposition:") for line in output.splitlines()):
                print(f"self-test failed: {label} emitted a disposition: {output}", file=sys.stderr)
                raise SystemExit(1)
            print(f"assert-vex self-test: {label} rejected: {reason}")

        def action_statement_mutation(replacement: str) -> Callable[[dict[str, Any]], None]:
            def mutate(document: dict[str, Any]) -> None:
                document["statements"][0].update(action_statement=replacement)

            return mutate

        for disposition, surface in surface_pairs:
            surface_label = f"{disposition.vulnerability} {surface.statement_path}"
            canonical_document = expected_accept_and_track_document(disposition, surface)
            for local_product in surface.local_products:
                local_label = f"{surface_label} local {local_product}"
                require_surface_result(
                    local_label + " two-key path",
                    run_surface_fixture(disposition, surface, local_product),
                    accepted=True,
                )
                require_surface_result(
                    local_label + " missing entry",
                    run_surface_fixture(disposition, surface, local_product, dispositions=()),
                    accepted=False,
                    reason="no exact in-tool accept-and-track allowlist entry",
                )
                require_surface_result(
                    local_label + " missing statement",
                    run_surface_fixture(disposition, surface, local_product, omit_statement=True),
                    accepted=False,
                    reason=f"no reviewed OpenVEX statement for {disposition.vulnerability}",
                )
                require_surface_result(
                    local_label + " index authority forbidden",
                    run_surface_fixture(
                        disposition,
                        surface,
                        local_product,
                        fixture_index_reference=f"{surface.published_repository}@sha256:{'0' * 64}",
                        fixture_index_manifest=index_manifest_path,
                    ),
                    accepted=False,
                    reason="index evidence must not be supplied for a local accept-and-track product",
                )

            surface_statement_mutations: tuple[tuple[str, Callable[[dict[str, Any]], Any], str], ...] = (
                ("top-level field", lambda value: value.update(extra=True), "unexpected or missing top-level"),
                ("context", lambda value: value.update({"@context": "https://example.invalid"}), "field @context"),
                ("document id", lambda value: value.update({"@id": "https://example.invalid/wrong"}), "field @id"),
                ("author", lambda value: value.update(author="Other"), "field author"),
                ("timestamp", lambda value: value.update(timestamp="2026-08-19T00:00:00Z"), "field timestamp"),
                ("version", lambda value: value.update(version=99), "field version"),
                (
                    "statement field",
                    lambda value: value["statements"][0].update(extra=True),
                    "unexpected or missing fields",
                ),
                (
                    "CVE",
                    lambda value: value["statements"][0]["vulnerability"].update(name="CVE-2099-0000"),
                    "no reviewed OpenVEX statement",
                ),
                (
                    "CVE alias",
                    lambda value: value["statements"][0]["vulnerability"].update(aliases=[]),
                    "vulnerability must contain only its name",
                ),
                (
                    "product",
                    lambda value: value["statements"][0]["products"][0].update({"@id": "wrong"}),
                    "products and subcomponents",
                ),
                (
                    "missing product",
                    lambda value: value["statements"][0]["products"].pop(),
                    "products and subcomponents",
                ),
                (
                    "extra product",
                    lambda value: value["statements"][0]["products"].append({"@id": "wrong", "subcomponents": []}),
                    "products and subcomponents",
                ),
                (
                    "product key",
                    lambda value: value["statements"][0]["products"][0].update(identifiers={}),
                    "products and subcomponents",
                ),
                (
                    "policy IRI",
                    lambda value: value["statements"][0]["products"][-1].update(
                        {"@id": "https://example.invalid/policy"}
                    ),
                    "products and subcomponents",
                ),
                (
                    "subcomponent",
                    lambda value: value["statements"][0]["products"][0]["subcomponents"][0].update({"@id": "wrong"}),
                    "products and subcomponents",
                ),
                (
                    "missing subcomponent",
                    lambda value: value["statements"][0]["products"][0]["subcomponents"].pop(),
                    "products and subcomponents",
                ),
                (
                    "extra subcomponent",
                    lambda value: value["statements"][0]["products"][0]["subcomponents"].append(
                        {"@id": "pkg:rpm/redhat/extra@1"}
                    ),
                    "products and subcomponents",
                ),
                ("status", lambda value: value["statements"][0].update(status="fixed"), "status must be affected"),
                ("action", lambda value: value["statements"][0].update(action_statement="wrong"), "review-by marker"),
                (
                    "zero review markers",
                    action_statement_mutation(surface.action_statement.replace("review-by", "review by")),
                    "exactly one review-by marker",
                ),
                (
                    "two review markers",
                    action_statement_mutation(surface.action_statement + " review-by 2026-10-01"),
                    "exactly one review-by marker",
                ),
                (
                    "wrong review date",
                    action_statement_mutation(surface.action_statement.replace("2026-10-01", "2026-10-02")),
                    "must contain review-by 2026-10-01",
                ),
                (
                    "wrong debt id",
                    action_statement_mutation(surface.action_statement.replace(disposition.debt_id, "TD-wrong")),
                    f"must name {disposition.debt_id}",
                ),
                (
                    "action timestamp",
                    lambda value: value["statements"][0].update(action_statement_timestamp="wrong"),
                    "action_statement_timestamp",
                ),
            )
            local_product = surface.local_products[0]
            for mutation_label, mutate, reason in surface_statement_mutations:
                mutant = copy.deepcopy(canonical_document)
                mutate(mutant)
                require_surface_result(
                    f"{surface_label} canonical-document mutation {mutation_label}",
                    run_surface_fixture(disposition, surface, local_product, document=mutant),
                    accepted=False,
                    reason=reason,
                )
            require_surface_result(
                f"{surface_label} duplicate statement files",
                run_surface_fixture(disposition, surface, local_product, duplicate_document=True),
                accepted=False,
                reason=f"duplicate accept-and-track statements for {disposition.vulnerability}",
            )
            require_surface_result(
                f"{surface_label} wrong statement path",
                run_surface_fixture(disposition, surface, local_product, filename="wrong.openvex.json"),
                accepted=False,
                reason=f"statement source must be {surface.statement_path}",
            )

            base_trivy, base_grype = surface_reports(disposition, local_product)
            for field_label, field_name in (
                ("vulnerability", "id"),
                ("package", "name"),
                ("version", "version"),
            ):
                padded_grype = copy.deepcopy(base_grype)
                target = padded_grype["matches"][0]["vulnerability" if field_name == "id" else "artifact"]
                target[field_name] = f" {target[field_name]} "
                require_surface_result(
                    f"{surface_label} scanner identity {field_label}",
                    run_surface_fixture(disposition, surface, local_product, trivy=base_trivy, grype=padded_grype),
                    accepted=False,
                    reason="malformed accept-and-track scanner identity evidence",
                )

            for scanner_name, trivy_fixed_state, grype_fixed_state in (
                ("Trivy", True, False),
                ("Grype", False, True),
            ):
                fixed_trivy, fixed_grype = surface_reports(
                    disposition,
                    local_product,
                    trivy_fixed_state=trivy_fixed_state,
                    grype_fixed_state=grype_fixed_state,
                )
                require_surface_result(
                    f"{surface_label} valid {scanner_name} fix evidence",
                    run_surface_fixture(disposition, surface, local_product, trivy=fixed_trivy, grype=fixed_grype),
                    accepted=False,
                    reason="valid fix evidence refuses accept-and-track disposition",
                )

            wrong_package_trivy, wrong_package_grype = surface_reports(disposition, local_product)
            wrong_package_grype["matches"][0]["artifact"]["name"] += "-wrong"
            require_surface_result(
                f"{surface_label} wrong package",
                run_surface_fixture(
                    disposition,
                    surface,
                    local_product,
                    trivy=wrong_package_trivy,
                    grype=wrong_package_grype,
                ),
                accepted=False,
                reason="no exact in-tool accept-and-track allowlist entry",
            )
            wrong_version_trivy, wrong_version_grype = surface_reports(disposition, local_product)
            wrong_version_grype["matches"][0]["artifact"]["version"] += ".wrong"
            require_surface_result(
                f"{surface_label} wrong version",
                run_surface_fixture(
                    disposition,
                    surface,
                    local_product,
                    trivy=wrong_version_trivy,
                    grype=wrong_version_grype,
                ),
                accepted=False,
                reason="no exact in-tool accept-and-track allowlist entry",
            )
            require_surface_result(
                f"{surface_label} active expiry",
                run_surface_fixture(
                    disposition,
                    surface,
                    local_product,
                    evaluation_date=date(2026, 10, 2),
                ),
                accepted=False,
                reason=f"expired accept-and-track entry: {disposition.vulnerability}",
            )

            overlapping = (disposition, disposition)
            require_surface_result(
                f"{surface_label} overlapping authorization candidates",
                run_surface_fixture(disposition, surface, local_product, dispositions=overlapping),
                accepted=False,
                reason="multiple exact in-tool accept-and-track authorization matches: 2",
            )

            surface_allowlist_mutations: tuple[tuple[str, AcceptAndTrackDisposition, str], ...] = (
                (
                    "CVE",
                    replace(disposition, vulnerability="CVE-2099-0000"),
                    "no exact in-tool accept-and-track allowlist entry",
                ),
                (
                    "packages",
                    replace(disposition, packages=((disposition.packages[0][0], "wrong"),)),
                    "no exact in-tool accept-and-track allowlist entry",
                ),
                (
                    "missing package",
                    replace(disposition, packages=disposition.packages[1:]),
                    "no exact in-tool accept-and-track allowlist entry",
                ),
                (
                    "extra package",
                    replace(disposition, packages=(*disposition.packages, ("extra", "1"))),
                    "no exact in-tool accept-and-track allowlist entry",
                ),
                (
                    "package name",
                    replace(
                        disposition,
                        packages=(("wrong", disposition.packages[0][1]), *disposition.packages[1:]),
                    ),
                    "no exact in-tool accept-and-track allowlist entry",
                ),
                (
                    "debt id",
                    replace(disposition, debt_id="TD-wrong"),
                    "does not match the canonical authorization",
                ),
                (
                    "review date",
                    replace(disposition, review_by="2026-10-02"),
                    "does not match the canonical authorization",
                ),
                (
                    "statement path",
                    replace(
                        disposition,
                        surfaces=(replace(surface, statement_path="vex/wrong.openvex.json"),),
                    ),
                    "does not match the canonical authorization",
                ),
                (
                    "local products",
                    replace(
                        disposition,
                        surfaces=(replace(surface, local_products=("local/wrong:tag",)),),
                    ),
                    "no exact in-tool accept-and-track allowlist entry",
                ),
                (
                    "published repository",
                    replace(
                        disposition,
                        surfaces=(replace(surface, published_repository="ghcr.io/example/wrong"),),
                    ),
                    "does not match the canonical authorization",
                ),
                (
                    "policy IRI",
                    replace(
                        disposition,
                        surfaces=(replace(surface, policy_product="https://example.invalid/wrong"),),
                    ),
                    "does not match the canonical authorization",
                ),
                (
                    "action text",
                    replace(
                        disposition,
                        surfaces=(replace(surface, action_statement="wrong"),),
                    ),
                    "does not match the canonical authorization",
                ),
            )
            for mutation_label, mutated_disposition, reason in surface_allowlist_mutations:
                require_surface_result(
                    f"{surface_label} allowlist mutation {mutation_label}",
                    run_surface_fixture(
                        disposition,
                        surface,
                        local_product,
                        dispositions=(mutated_disposition,),
                    ),
                    accepted=False,
                    reason=reason,
                )

            wrong_tag = local_product + "-look-alike"
            wrong_tag_trivy, wrong_tag_grype = surface_reports(disposition, wrong_tag)
            require_surface_result(
                f"{surface_label} wrong-tag local product",
                run_surface_fixture(
                    disposition,
                    surface,
                    wrong_tag,
                    trivy=wrong_tag_trivy,
                    grype=wrong_tag_grype,
                ),
                accepted=False,
                reason="no exact in-tool accept-and-track allowlist entry",
            )

        print(
            "assert-vex self-test: parameterized local/canonical/allowlist/scanner/fix/duplicate/expiry "
            f"matrices covered {len(surface_pairs)} disposition surfaces"
        )

        for disposition, surface in surface_pairs:
            surface_label = f"{disposition.vulnerability} {surface.statement_path}"
            published_product = f"{surface.published_repository}@{amd64_child_digest}"
            index_manifest_path.write_bytes(valid_index_bytes)
            published_reference = reference_for_index(valid_index_bytes, surface.published_repository)
            published_trivy, published_grype = surface_reports(disposition, published_product)

            def published_fixture(
                fixture_disposition: AcceptAndTrackDisposition = disposition,
                fixture_surface: AcceptAndTrackSurface = surface,
                fixture_product: str = published_product,
                fixture_trivy: dict[str, Any] = published_trivy,
                fixture_grype: dict[str, Any] = published_grype,
                fixture_reference: str = published_reference,
                **kwargs: Any,
            ) -> tuple[int | None, str, VexError | None]:
                return run_surface_fixture(
                    fixture_disposition,
                    fixture_surface,
                    fixture_product,
                    trivy=fixture_trivy,
                    grype=fixture_grype,
                    fixture_index_reference=fixture_reference,
                    fixture_index_manifest=index_manifest_path,
                    **kwargs,
                )

            require_surface_result(
                f"{surface_label} published three-key path",
                published_fixture(),
                accepted=True,
            )
            require_surface_result(
                f"{surface_label} published missing entry",
                published_fixture(dispositions=()),
                accepted=False,
                reason="no exact in-tool accept-and-track allowlist entry",
            )
            require_surface_result(
                f"{surface_label} published missing statement",
                published_fixture(omit_statement=True),
                accepted=False,
                reason=f"no reviewed OpenVEX statement for {disposition.vulnerability}",
            )
            require_surface_result(
                f"{surface_label} published missing index evidence",
                run_surface_fixture(
                    disposition,
                    surface,
                    published_product,
                    trivy=published_trivy,
                    grype=published_grype,
                ),
                accepted=False,
                reason="no exact in-tool accept-and-track allowlist entry",
            )
            altered_statement = expected_accept_and_track_document(disposition, surface)
            altered_statement["statements"][0]["products"][-1]["@id"] += "-wrong"
            require_surface_result(
                f"{surface_label} published altered statement",
                published_fixture(document=altered_statement),
                accepted=False,
                reason="products and subcomponents must match the canonical ordered set",
            )
            require_surface_result(
                f"{surface_label} published altered index digest",
                run_surface_fixture(
                    disposition,
                    surface,
                    published_product,
                    trivy=published_trivy,
                    grype=published_grype,
                    fixture_index_reference=f"{surface.published_repository}@sha256:{'0' * 64}",
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason="index manifest digest mismatch",
            )
            reformatted_index = json.dumps(valid_index, indent=2, sort_keys=True).encode("utf-8")
            index_manifest_path.write_bytes(reformatted_index)
            require_surface_result(
                f"{surface_label} published reformatted index bytes",
                published_fixture(),
                accepted=False,
                reason="index manifest digest mismatch",
            )
            index_manifest_path.write_bytes(valid_index_bytes)
            require_surface_result(
                f"{surface_label} published active expiry",
                published_fixture(evaluation_date=date(2026, 10, 2)),
                accepted=False,
                reason=f"expired accept-and-track entry: {disposition.vulnerability}",
            )
            for scanner_name, trivy_fixed_state, grype_fixed_state in (
                ("Trivy", True, False),
                ("Grype", False, True),
            ):
                fixed_trivy, fixed_grype = surface_reports(
                    disposition,
                    published_product,
                    trivy_fixed_state=trivy_fixed_state,
                    grype_fixed_state=grype_fixed_state,
                )
                require_surface_result(
                    f"{surface_label} published valid {scanner_name} fix evidence",
                    run_surface_fixture(
                        disposition,
                        surface,
                        published_product,
                        trivy=fixed_trivy,
                        grype=fixed_grype,
                        fixture_index_reference=published_reference,
                        fixture_index_manifest=index_manifest_path,
                    ),
                    accepted=False,
                    reason="valid fix evidence refuses accept-and-track disposition",
                )

            index_mutations: tuple[tuple[str, bytes, str], ...] = (
                (
                    "non-index media type",
                    mutated_index(lambda value: value.update(mediaType=OCI_IMAGE_MANIFEST_MEDIA_TYPE)),
                    f"index manifest mediaType must be {OCI_IMAGE_INDEX_MEDIA_TYPE}",
                ),
                ("malformed JSON", b"{", "index manifest is malformed JSON"),
                ("non-object top level", serialize_index([]), "index manifest must be a top-level JSON object"),
                (
                    "empty manifests",
                    mutated_index(lambda value: value.update(manifests=[])),
                    "manifests must not be empty",
                ),
                (
                    "missing schemaVersion",
                    mutated_index(lambda value: value.pop("schemaVersion")),
                    "missing schemaVersion",
                ),
                (
                    "wrong schemaVersion",
                    mutated_index(lambda value: value.update(schemaVersion=3)),
                    "schemaVersion must equal 2",
                ),
                (
                    "boolean schemaVersion",
                    mutated_index(lambda value: value.update(schemaVersion=True)),
                    "schemaVersion must be an integer",
                ),
                (
                    "string schemaVersion",
                    mutated_index(lambda value: value.update(schemaVersion="2")),
                    "schemaVersion must be an integer",
                ),
                (
                    "null schemaVersion",
                    mutated_index(lambda value: value.update(schemaVersion=None)),
                    "schemaVersion must be an integer",
                ),
                (
                    "non-list manifests",
                    mutated_index(lambda value: value.update(manifests={})),
                    "manifests must be a list",
                ),
                (
                    "missing descriptor mediaType",
                    mutated_index(lambda value: value["manifests"][0].pop("mediaType")),
                    "manifests[0] is missing mediaType",
                ),
                (
                    "missing descriptor digest",
                    mutated_index(lambda value: value["manifests"][0].pop("digest")),
                    "manifests[0] is missing digest",
                ),
                (
                    "missing descriptor size",
                    mutated_index(lambda value: value["manifests"][0].pop("size")),
                    "manifests[0] is missing size",
                ),
                (
                    "uppercase descriptor digest",
                    mutated_index(lambda value: value["manifests"][0].update(digest="sha256:" + "A" * 64)),
                    "must be a sha256 content digest",
                ),
                (
                    "malformed descriptor digest",
                    mutated_index(lambda value: value["manifests"][0].update(digest="sha256:short")),
                    "must be a sha256 content digest",
                ),
                (
                    "non-integer descriptor size",
                    mutated_index(lambda value: value["manifests"][0].update(size="1234")),
                    "size must be a non-negative integer",
                ),
                (
                    "boolean descriptor size",
                    mutated_index(lambda value: value["manifests"][0].update(size=True)),
                    "size must be a non-negative integer",
                ),
                (
                    "float descriptor size",
                    mutated_index(lambda value: value["manifests"][0].update(size=1234.5)),
                    "size must be a non-negative integer",
                ),
                (
                    "negative descriptor size",
                    mutated_index(lambda value: value["manifests"][0].update(size=-1)),
                    "size must be a non-negative integer",
                ),
                (
                    "same platform child digest",
                    mutated_index(lambda value: value["manifests"][1].update(digest=amd64_child_digest)),
                    "child digests must be distinct",
                ),
                (
                    "unsupported platform",
                    mutated_index(
                        lambda value: value["manifests"].append(image_descriptor("sha256:" + "4" * 64, "s390x"))
                    ),
                    "unsupported runnable platform linux/s390x",
                ),
                (
                    "duplicate amd64",
                    mutated_index(
                        lambda value: value["manifests"].append(image_descriptor("sha256:" + "4" * 64, "amd64"))
                    ),
                    "exactly one linux/amd64",
                ),
                ("missing arm64", mutated_index(lambda value: value["manifests"].pop(1)), "exactly one linux/arm64"),
                (
                    "nested index descriptor",
                    mutated_index(
                        lambda value: value["manifests"].append(
                            {
                                "mediaType": OCI_IMAGE_INDEX_MEDIA_TYPE,
                                "digest": "sha256:" + "4" * 64,
                                "size": 42,
                                "platform": {"architecture": "s390x", "os": "linux"},
                            }
                        )
                    ),
                    "must not be a nested image index descriptor",
                ),
                (
                    "missing attestation type",
                    mutated_index(
                        lambda value: value["manifests"][2]["annotations"].pop(BUILDKIT_ATTESTATION_TYPE_ANNOTATION)
                    ),
                    "unknown/unknown descriptor must carry",
                ),
                (
                    "wrong attestation child",
                    mutated_index(
                        lambda value: value["manifests"][2]["annotations"].update(
                            {BUILDKIT_ATTESTATION_DIGEST_ANNOTATION: "sha256:" + "5" * 64}
                        )
                    ),
                    "attestation reference digest must name an eligible platform child",
                ),
                (
                    "missing attestation reference digest",
                    mutated_index(
                        lambda value: value["manifests"][2]["annotations"].pop(BUILDKIT_ATTESTATION_DIGEST_ANNOTATION)
                    ),
                    "must be a non-empty string",
                ),
                (
                    "missing attestation mediaType",
                    mutated_index(lambda value: value["manifests"][2].pop("mediaType")),
                    "manifests[2] is missing mediaType",
                ),
                (
                    "missing attestation digest",
                    mutated_index(lambda value: value["manifests"][2].pop("digest")),
                    "manifests[2] is missing digest",
                ),
                (
                    "missing attestation size",
                    mutated_index(lambda value: value["manifests"][2].pop("size")),
                    "manifests[2] is missing size",
                ),
                (
                    "non-string attestation mediaType",
                    mutated_index(lambda value: value["manifests"][2].update(mediaType=17)),
                    "mediaType must be a non-empty string",
                ),
                (
                    "non-string attestation digest",
                    mutated_index(lambda value: value["manifests"][2].update(digest=17)),
                    "digest must be a non-empty string",
                ),
                (
                    "non-integer attestation size",
                    mutated_index(lambda value: value["manifests"][2].update(size="567")),
                    "size must be a non-negative integer",
                ),
                (
                    "extra attestation annotation",
                    mutated_index(lambda value: value["manifests"][2]["annotations"].update(extra="wrong")),
                    "annotations must equal the locked BuildKit attestation shape",
                ),
                (
                    "aliased attestation digest",
                    mutated_index(lambda value: value["manifests"][2].update(digest=amd64_child_digest)),
                    "attestation descriptor digests must be disjoint",
                ),
                (
                    "architecture swap",
                    mutated_index(
                        lambda value: (
                            value["manifests"][0]["platform"].update(architecture="arm64"),
                            value["manifests"][1]["platform"].update(architecture="amd64"),
                        )
                    ),
                    "does not match the index child for scanner architecture amd64",
                ),
                (
                    "windows descriptor",
                    mutated_index(lambda value: value["manifests"][0]["platform"].update(os="windows")),
                    "unsupported descriptor platform windows/amd64",
                ),
                (
                    "duplicate descriptor",
                    mutated_index(lambda value: value["manifests"].append(copy.deepcopy(value["manifests"][2]))),
                    "duplicate or contradictory descriptors are forbidden",
                ),
                (
                    "contradictory duplicate descriptor",
                    mutated_index(
                        lambda value: value["manifests"].append(
                            attestation_descriptor(attestation_digest, arm64_child_digest)
                        )
                    ),
                    "duplicate or contradictory descriptors are forbidden",
                ),
            )
            for mutation_label, raw_index, reason in index_mutations:
                index_manifest_path.write_bytes(raw_index)
                mutated_reference = reference_for_index(raw_index, surface.published_repository)
                require_surface_result(
                    f"{surface_label} OCI-index mutation {mutation_label}",
                    run_surface_fixture(
                        disposition,
                        surface,
                        published_product,
                        trivy=published_trivy,
                        grype=published_grype,
                        fixture_index_reference=mutated_reference,
                        fixture_index_manifest=index_manifest_path,
                    ),
                    accepted=False,
                    reason=reason,
                )
            index_manifest_path.write_bytes(valid_index_bytes)
            require_surface_result(
                f"{surface_label} index digest submitted as product",
                run_surface_fixture(
                    disposition,
                    surface,
                    published_reference,
                    trivy=surface_reports(disposition, published_reference)[0],
                    grype=surface_reports(disposition, published_reference)[1],
                    fixture_index_reference=published_reference,
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason="the index digest is never eligible as a published-child product",
            )
            attestation_product = f"{surface.published_repository}@{attestation_digest}"
            attestation_trivy, attestation_grype = surface_reports(disposition, attestation_product)
            require_surface_result(
                f"{surface_label} attestation descriptor submitted as product",
                run_surface_fixture(
                    disposition,
                    surface,
                    attestation_product,
                    trivy=attestation_trivy,
                    grype=attestation_grype,
                    fixture_index_reference=published_reference,
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason="published-child product digest identifies an attestation descriptor",
            )
            tagged_product = f"{surface.published_repository}:latest"
            tagged_trivy, tagged_grype = surface_reports(disposition, tagged_product)
            require_surface_result(
                f"{surface_label} tag-addressed published product",
                run_surface_fixture(
                    disposition,
                    surface,
                    tagged_product,
                    trivy=tagged_trivy,
                    grype=tagged_grype,
                    fixture_index_reference=published_reference,
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason="published-child --product must be a digest-qualified image reference",
            )
            wrong_repository = surface.published_repository + "-look-alike"
            wrong_repository_product = f"{wrong_repository}@{amd64_child_digest}"
            wrong_repo_trivy, wrong_repo_grype = surface_reports(disposition, wrong_repository_product)
            require_surface_result(
                f"{surface_label} wrong published repository",
                run_surface_fixture(
                    disposition,
                    surface,
                    wrong_repository_product,
                    trivy=wrong_repo_trivy,
                    grype=wrong_repo_grype,
                    fixture_index_reference=reference_for_index(valid_index_bytes, wrong_repository),
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason="published-child",
            )
            require_surface_result(
                f"{surface_label} absent child digest",
                run_surface_fixture(
                    disposition,
                    surface,
                    f"{surface.published_repository}@sha256:{'6' * 64}",
                    trivy=surface_reports(
                        disposition,
                        f"{surface.published_repository}@sha256:{'6' * 64}",
                    )[0],
                    grype=surface_reports(
                        disposition,
                        f"{surface.published_repository}@sha256:{'6' * 64}",
                    )[1],
                    fixture_index_reference=published_reference,
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason="published-child product digest is absent from the verified index",
            )
            require_surface_result(
                f"{surface_label} architecture-swapped child",
                run_surface_fixture(
                    disposition,
                    surface,
                    published_product,
                    trivy=surface_reports(disposition, published_product, architecture="arm64")[0],
                    grype=surface_reports(disposition, published_product, architecture="arm64")[1],
                    fixture_index_reference=published_reference,
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason="does not match the index child for scanner architecture arm64",
            )
            two_attestations = mutated_index(
                lambda value: value["manifests"].append(
                    attestation_descriptor("sha256:" + "4" * 64, arm64_child_digest)
                )
            )
            index_manifest_path.write_bytes(two_attestations)
            require_surface_result(
                f"{surface_label} two distinct attestations",
                run_surface_fixture(
                    disposition,
                    surface,
                    published_product,
                    trivy=published_trivy,
                    grype=published_grype,
                    fixture_index_reference=reference_for_index(
                        two_attestations,
                        surface.published_repository,
                    ),
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=True,
            )

        print(
            "assert-vex self-test: parameterized three-key and OCI-index matrices covered "
            f"{len(surface_pairs)} published disposition surfaces"
        )

        td9_disposition, td9_surface = surface_pairs[0]
        openssl_disposition = ACCEPT_AND_TRACK_DISPOSITIONS[1]
        openssl_python_surface, openssl_micro_surface = openssl_disposition.surfaces
        python_policy_in_micro_document = expected_accept_and_track_document(
            openssl_disposition,
            openssl_micro_surface,
        )
        python_policy_in_micro_document["statements"][0]["products"][-1]["@id"] = (
            "https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-python/published-platform-children"
        )
        micro_policy_in_python_document = expected_accept_and_track_document(
            openssl_disposition,
            openssl_python_surface,
        )
        micro_policy_in_python_document["statements"][0]["products"][-1]["@id"] = (
            "https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-micro/published-platform-children"
        )
        cross_authority_probes = (
            (
                "Python policy IRI substituted into micro document",
                openssl_micro_surface,
                openssl_micro_surface.local_products[0],
                openssl_micro_surface,
                python_policy_in_micro_document,
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "micro policy IRI substituted into Python document",
                openssl_python_surface,
                openssl_python_surface.local_products[0],
                openssl_python_surface,
                micro_policy_in_python_document,
                "accept-and-track products and subcomponents must match the canonical ordered set",
            ),
            (
                "Python statement under micro authority",
                openssl_micro_surface,
                openssl_micro_surface.local_products[0],
                openssl_python_surface,
                expected_accept_and_track_document(openssl_disposition, openssl_python_surface),
                f"statement source must be {openssl_micro_surface.statement_path}",
            ),
            (
                "micro statement under Python authority",
                openssl_python_surface,
                openssl_python_surface.local_products[0],
                openssl_micro_surface,
                expected_accept_and_track_document(openssl_disposition, openssl_micro_surface),
                f"statement source must be {openssl_python_surface.statement_path}",
            ),
            (
                "TD-9 statement offered for CVE-2026-14456",
                openssl_python_surface,
                openssl_python_surface.local_products[0],
                td9_surface,
                expected_accept_and_track_document(td9_disposition, td9_surface),
                "no reviewed OpenVEX statement for CVE-2026-14456",
            ),
            (
                "CVE-2026-14456 statement offered for TD-9",
                td9_surface,
                td9_surface.local_products[0],
                openssl_python_surface,
                expected_accept_and_track_document(openssl_disposition, openssl_python_surface),
                "no reviewed OpenVEX statement for CVE-2026-11940",
            ),
        )
        for (
            label,
            authority_surface,
            authority_product,
            statement_surface,
            offered_document,
            reason,
        ) in cross_authority_probes:
            authority_disposition = td9_disposition if authority_surface is td9_surface else openssl_disposition
            require_surface_result(
                label,
                run_surface_fixture(
                    authority_disposition,
                    authority_surface,
                    authority_product,
                    document=offered_document,
                    statement_surface=statement_surface,
                ),
                accepted=False,
                reason=reason,
            )

        for product_surface, index_surface, label in (
            (openssl_python_surface, openssl_micro_surface, "Python product with micro index/reference"),
            (openssl_micro_surface, openssl_python_surface, "micro product with Python index/reference"),
        ):
            cross_product = f"{product_surface.published_repository}@{amd64_child_digest}"
            cross_trivy, cross_grype = surface_reports(openssl_disposition, cross_product)
            index_manifest_path.write_bytes(valid_index_bytes)
            require_surface_result(
                label,
                run_surface_fixture(
                    openssl_disposition,
                    product_surface,
                    cross_product,
                    trivy=cross_trivy,
                    grype=cross_grype,
                    fixture_index_reference=reference_for_index(
                        valid_index_bytes,
                        index_surface.published_repository,
                    ),
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason=f"--index-reference repository must be {product_surface.published_repository}",
            )

        for surface in (openssl_python_surface, openssl_micro_surface):
            wrong_repository = surface.published_repository + "-look-alike"
            wrong_product = f"{wrong_repository}@{amd64_child_digest}"
            wrong_trivy, wrong_grype = surface_reports(openssl_disposition, wrong_product)
            index_manifest_path.write_bytes(valid_index_bytes)
            require_surface_result(
                f"{surface.statement_path} correct child under look-alike repository",
                run_surface_fixture(
                    openssl_disposition,
                    surface,
                    wrong_product,
                    trivy=wrong_trivy,
                    grype=wrong_grype,
                    fixture_index_reference=reference_for_index(valid_index_bytes, wrong_repository),
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason="published-child repository does not match a pinned accept-and-track surface",
            )
            published_product = f"{surface.published_repository}@{amd64_child_digest}"
            published_trivy, published_grype = surface_reports(openssl_disposition, published_product)
            require_surface_result(
                f"{surface.statement_path} unpaired index reference",
                run_surface_fixture(
                    openssl_disposition,
                    surface,
                    published_product,
                    trivy=published_trivy,
                    grype=published_grype,
                    fixture_index_reference=reference_for_index(
                        valid_index_bytes,
                        surface.published_repository,
                    ),
                ),
                accepted=False,
                reason="--index-reference and --index-manifest must be supplied together",
            )
            require_surface_result(
                f"{surface.statement_path} unpaired index manifest",
                run_surface_fixture(
                    openssl_disposition,
                    surface,
                    published_product,
                    trivy=published_trivy,
                    grype=published_grype,
                    fixture_index_manifest=index_manifest_path,
                ),
                accepted=False,
                reason="--index-reference and --index-manifest must be supplied together",
            )

        print(
            "assert-vex self-test: cross-authority statement/repository/policy/CVE/package/version/"
            "paired-input probes rejected; synthetic Trivy CVE-2026-14456 exact-version path accepted"
        )

        exact_disposition = EXACT_NOT_AFFECTED_DISPOSITIONS[0]
        exact_surface = exact_disposition.surfaces[0]
        exact_document = expected_exact_not_affected_document(exact_disposition, exact_surface)

        def exact_reports(
            fixture_product: str,
            *,
            architecture: str = "amd64",
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            package, version = exact_disposition.packages[0]
            trivy = copy.deepcopy(clean_trivy)
            grype = copy.deepcopy(clean_grype)
            bind_accept_reports(trivy, grype, fixture_product, architecture)
            trivy["Results"][0]["Packages"] = [
                {"Name": "glibc", "Version": "2.34"},
                {"Name": package, "Version": version},
            ]
            trivy["Results"][0]["Vulnerabilities"] = []
            grype["matches"] = [
                {
                    "vulnerability": {
                        "id": exact_disposition.vulnerability,
                        "severity": "High",
                        "fix": {"versions": [], "state": "not-fixed"},
                    },
                    "artifact": {"name": package, "version": version},
                }
            ]
            return trivy, grype

        def run_exact_fixture(
            fixture_product: str,
            *,
            architecture: str = "amd64",
            fixture_index_reference: str | None = None,
            fixture_index_manifest: Path | None = None,
            injected_inventory_package: str | None = None,
        ) -> tuple[int | None, str, VexError | None]:
            fixture_trivy, fixture_grype = exact_reports(
                fixture_product,
                architecture=architecture,
            )
            if injected_inventory_package is not None:
                fixture_trivy["Results"][0]["Packages"].append(
                    {"Name": injected_inventory_package, "Version": "2.37.4-25.el9"}
                )
            fixture_vex_dir = tmp / Path(exact_surface.statement_path).parent
            fixture_vex_dir.mkdir(parents=True, exist_ok=True)
            for old_document in fixture_vex_dir.glob("*.json"):
                old_document.unlink()
            write_json(fixture_vex_dir / Path(exact_surface.statement_path).name, exact_document)
            write_json(trivy_json, fixture_trivy)
            write_json(grype_json, fixture_grype)
            write_json(package_floor, clean_floor)
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = assert_vex(
                        fixture_product,
                        trivy_json,
                        grype_json,
                        package_floor,
                        fixture_vex_dir,
                        emit=True,
                        exact_not_affected=EXACT_NOT_AFFECTED_DISPOSITIONS,
                        index_reference=fixture_index_reference,
                        index_manifest=fixture_index_manifest,
                    )
            except VexError as exc:
                return None, stdout.getvalue() + stderr.getvalue(), exc
            return result, stdout.getvalue() + stderr.getvalue(), None

        def require_exact_result(
            label: str,
            result: tuple[int | None, str, VexError | None],
            *,
            accepted: bool,
            reason: str = "",
        ) -> None:
            status, output, error = result
            combined = output + (str(error) if error is not None else "")
            disposition_line = f"accepted VEX: {exact_disposition.vulnerability} status=not_affected"
            if accepted:
                if error is not None or status != 0 or disposition_line not in output:
                    print(
                        f"self-test failed: {label} did not accept: status={status} error={error} output={output}",
                        file=sys.stderr,
                    )
                    raise SystemExit(1)
                print(f"assert-vex self-test: {label} accepted")
                return
            if (error is None and status != 1) or reason not in combined:
                print(
                    f"self-test failed: {label} rejected for wrong reason: "
                    f"status={status} error={error} output={output}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if disposition_line in output:
                print(f"self-test failed: {label} emitted a disposition: {output}", file=sys.stderr)
                raise SystemExit(1)
            print(f"assert-vex self-test: {label} rejected: {reason}")

        positive_exact_probes = (
            (
                "exact not-affected local amd64 production shape",
                run_exact_fixture("local/ubi9-base-python:ci-amd64"),
            ),
            (
                "exact not-affected local arm64 production shape",
                run_exact_fixture("local/ubi9-base-python:ci-arm64", architecture="arm64"),
            ),
        )
        for label, probe_result in positive_exact_probes:
            require_exact_result(label, probe_result, accepted=True)

        exact_published_product = f"{exact_surface.published_repository}@{amd64_child_digest}"
        index_manifest_path.write_bytes(valid_index_bytes)
        require_exact_result(
            "exact not-affected published child production shape",
            run_exact_fixture(
                exact_published_product,
                fixture_index_reference=reference_for_index(
                    valid_index_bytes,
                    exact_surface.published_repository,
                ),
                fixture_index_manifest=index_manifest_path,
            ),
            accepted=True,
        )

        absence_contradiction = (
            "vulnerable_code_not_present contradiction: scanned Trivy inventory contains "
            "declared-absent package(s): util-linux-core"
        )
        require_exact_result(
            "exact not-affected amd64 inventory absence contradiction",
            run_exact_fixture(
                "local/ubi9-base-python:ci-amd64",
                injected_inventory_package="util-linux-core",
            ),
            accepted=False,
            reason=absence_contradiction,
        )

        print(
            "assert-vex self-test: exact not-affected accepted 3/3 local/published production shapes "
            "and rejected the required absent-package contradiction"
        )

        critical_trivy = copy.deepcopy(clean_trivy)
        critical_trivy["Results"][0]["Vulnerabilities"] = [
            {
                "VulnerabilityID": "CVE-2099-0001",
                "PkgName": "openssl-libs",
                "InstalledVersion": "0",
                "Severity": "CRITICAL",
            }
        ]
        if run_fixture(critical_trivy, clean_grype, clean_floor) == 0:
            print("self-test failed: synthetic-unvexed-critical unexpectedly passed", file=sys.stderr)
            return 1
        print("assert-vex self-test: synthetic-unvexed-critical failed as expected")

        write_json(
            vex_dir / "synthetic.openvex.json",
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": "https://github.com/NWarila/ubi9-base-micro/vex/synthetic",
                "author": "NWarila",
                "timestamp": "2026-01-01T00:00:00Z",
                "version": 1,
                "statements": [
                    {
                        "@id": VULNERABLE_CODE_ABSENCE_ID_PREFIX + "synthetic-vulnerable-code",
                        "vulnerability": {"name": "CVE-2099-0001"},
                        "products": [{"@id": product}],
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present",
                    }
                ],
            },
        )

        if run_fixture(critical_trivy, clean_grype, clean_floor) != 0:
            print("self-test failed: synthetic-vexed-critical did not pass", file=sys.stderr)
            return 1
        print("assert-vex self-test: synthetic-vexed-critical passed")

    print("assert-vex self-test: ok")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", help="exact image reference scanned")
    parser.add_argument("--trivy-json", type=Path, help="Trivy JSON report without --ignore-unfixed")
    parser.add_argument("--grype-json", type=Path, help="Grype JSON report without --only-fixed")
    parser.add_argument("--package-floor", type=Path, help="contract containing the applicable package floor")
    parser.add_argument("--vex-dir", type=Path, default=Path("vex"), help="directory containing OpenVEX JSON")
    parser.add_argument("--index-reference", help="digest-qualified reference for exact registry index bytes")
    parser.add_argument("--index-manifest", type=Path, help="path to exact registry-served OCI index bytes")
    parser.add_argument("--self-test", action="store_true", help="prove default-deny behavior with synthetic data")
    args = parser.parse_args(argv)

    if args.self_test:
        return args
    missing = [name for name in ("product", "trivy_json", "grype_json", "package_floor") if getattr(args, name) is None]
    if missing:
        parser.error("missing required argument(s): " + ", ".join("--" + item.replace("_", "-") for item in missing))
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.self_test:
            return self_test()
        return assert_vex(
            args.product,
            args.trivy_json,
            args.grype_json,
            args.package_floor,
            args.vex_dir,
            index_reference=args.index_reference,
            index_manifest=args.index_manifest,
        )
    except VexError as exc:
        print(f"assert-vex failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
