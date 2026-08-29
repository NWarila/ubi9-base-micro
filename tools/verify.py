#!/usr/bin/env python3
# Purpose: Repository contract checks (pinned SHAs/tags, FIPS RPM digests, required files/ADRs) for ubi9-base-micro
# Role: governance
# Micro-container candidate: no - repo-tree-coupled contract verifier (run via `make verify`), validates the repo, not
# an image

"""Repository contract checks for ubi9-base-micro."""

from __future__ import annotations

import ast
import copy
import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_USES = re.compile(r"uses:\s+([^@\s]+)@([^\s#]+)")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
VERSION_LITERAL = re.compile(r"^v?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$")
HADOLINT_IMAGE = re.compile(r"^ghcr\.io/hadolint/hadolint@sha256:[0-9a-f]{64}$")
EXTERNAL_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
SLSA_GENERATOR_SHA = "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a"
HARDEN_RUNNER = "step-security/harden-runner"
COSIGN_INSTALLER_ACTION = "sigstore/cosign-installer"
COSIGN_RELEASE = "v2.5.2"
LINT_CONFIG_FILES = [
    ".hadolint.yaml",
    ".markdownlint-cli2.jsonc",
    ".pre-commit-config.yaml",
    ".shellcheckrc",
    ".yamllint",
    "pyproject.toml",
    ".github/workflows/lint.yaml",
]
SUPPLY_CHAIN_WORKFLOWS = [
    ".github/workflows/codeql.yml",
    ".github/workflows/dependency-review.yml",
    ".github/workflows/lint.yaml",
    ".github/workflows/scorecard.yml",
    ".github/workflows/zizmor.yml",
]
UBI_FULL_REFERENCE = re.compile(
    r"registry\.access\.redhat\.com/ubi9/ubi-(?P<image>minimal|micro)@sha256:(?P<digest>[0-9a-f]{64})"
)
UBI_REFERENCE_PATTERNS = {
    image: rf"registry\.access\.redhat\.com/ubi9/ubi-{image}@sha256:(?P<digest>[0-9a-f]{{64}})"
    for image in ["minimal", "micro"]
}
UBI_DIGEST_SITES = {
    "minimal": {
        "containers/Dockerfile": re.compile(
            rf"^ARG UBI_MINIMAL_IMAGE={UBI_REFERENCE_PATTERNS['minimal']}[ \t]*$", re.MULTILINE
        ),
        ".github/workflows/publish-image.yaml": re.compile(
            rf"^[ \t]+UBI_MINIMAL_IMAGE: {UBI_REFERENCE_PATTERNS['minimal']}[ \t]*$", re.MULTILINE
        ),
        "images/python/Dockerfile": re.compile(
            rf"^ARG UBI_MINIMAL_IMAGE={UBI_REFERENCE_PATTERNS['minimal']}[ \t]*$", re.MULTILINE
        ),
        "tools/build.sh": re.compile(
            rf'^ubi_minimal_image="\$\{{UBI_MINIMAL_IMAGE:-{UBI_REFERENCE_PATTERNS["minimal"]}\}}"[ \t]*$',
            re.MULTILINE,
        ),
    },
    "micro": {
        "containers/Dockerfile": re.compile(
            rf"^ARG UBI_MICRO_IMAGE={UBI_REFERENCE_PATTERNS['micro']}[ \t]*$", re.MULTILINE
        ),
        ".github/workflows/build.yaml": re.compile(
            rf"^[ \t]+UBI_MICRO_IMAGE: {UBI_REFERENCE_PATTERNS['micro']}[ \t]*$", re.MULTILINE
        ),
        ".github/workflows/nightly.yaml": re.compile(
            rf"^[ \t]+UBI_MICRO_IMAGE: {UBI_REFERENCE_PATTERNS['micro']}[ \t]*$", re.MULTILINE
        ),
        ".github/workflows/publish-image.yaml": re.compile(
            rf"^[ \t]+UBI_MICRO_IMAGE: {UBI_REFERENCE_PATTERNS['micro']}[ \t]*$", re.MULTILINE
        ),
        "tools/run-test-gates.sh": re.compile(
            rf'^ubi_micro_image="\$\{{UBI_MICRO_IMAGE:-{UBI_REFERENCE_PATTERNS["micro"]}\}}"[ \t]*$',
            re.MULTILINE,
        ),
        "tools/build.sh": re.compile(
            rf'^ubi_micro_image="\$\{{UBI_MICRO_IMAGE:-{UBI_REFERENCE_PATTERNS["micro"]}\}}"[ \t]*$',
            re.MULTILINE,
        ),
    },
}
BINFMT_IMAGE = "docker.io/tonistiigi/binfmt"
BINFMT_ACTION = "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8"
BINFMT_FULL_REFERENCE = re.compile(rf"{re.escape(BINFMT_IMAGE)}@sha256:(?P<digest>[0-9a-f]{{64}})")
BINFMT_ACTION_REFERENCE = re.compile(r"^[ \t]+uses: docker/setup-qemu-action@[^\s#]+", re.MULTILINE)
BINFMT_SITE = re.compile(
    rf"^(?P<indent>[ \t]+)uses: {re.escape(BINFMT_ACTION)}[ \t]+# v4\.2\.0[ \t]*\n"
    rf"(?P=indent)with:[ \t]*\n"
    rf"(?P=indent)  platforms: amd64,arm64[ \t]*\n"
    rf"(?P=indent)  image: {re.escape(BINFMT_IMAGE)}@sha256:(?P<digest>[0-9a-f]{{64}})[ \t]*$",
    re.MULTILINE,
)
BINFMT_DIGEST_SITES = {
    ".github/workflows/build.yaml": 2,
    ".github/workflows/nightly.yaml": 2,
    ".github/workflows/publish-image.yaml": 1,
    ".github/workflows/publish-python.yaml": 3,
    ".github/workflows/python-ci.yaml": 2,
    ".github/workflows/rpm-lock-refresh.yaml": 2,
}
PYTHON_BAKE_FILE = "images/python/docker-bake.json"
PYTHON_BAKE_VARIABLES = {
    "BUILDX_VERSION",
    "BUILDX_COMMIT",
    "BUILDX_ASSET_SHA256",
    "BUILDKIT_IMAGE",
    "REPRO_DEST",
    "RELEASE_REF",
    "OCI_REVISION",
    "OCI_SOURCE",
    "OCI_VERSION",
    "UBI_MINIMAL_IMAGE",
    "BASE_MICRO_IMAGE",
}
PYTHON_BAKE_TARGETS = {"base", "ci", "release", "repro"}
PYTHON_BAKE_PROTECTED_FIELDS = {"context", "dockerfile", "target", "platforms"}
PYTHON_BAKE_PROTECTED_ARGS = {"SOURCE_DATE_EPOCH", "OCI_CREATED"}
PYTHON_BUILDKIT_REFERENCE = re.compile(
    r"^docker\.io/moby/buildkit:(?P<version>v\d+\.\d+\.\d+)@sha256:(?P<digest>[0-9a-f]{64})$"
)
OPENSSL_FIPS_PROVIDER_RPM_BASE_URL = "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9"
OPENSSL_FIPS_PROVIDER_RPM_SHA256_AMD64 = "bbf25303def8e1270675531c47bdad432f6ad8ef4c327556ae65bd6abaf8edb5"
OPENSSL_FIPS_PROVIDER_RPM_SHA256_ARM64 = "0cfe7b281ae2ca3cb0ceaa1a0b84f8c087c4ac16662ebb9c19b5681cf39f99a9"
OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AMD64 = "ab48d98504fae6f8636de027a1ee06d21d5e9c27b7beb247017a6fe55567c5e9"
OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_ARM64 = "18c77b9b37e7abf0e8cf1dac4b3de770efe895547bdcab8aea8d8d8592954947"
COMMUNITY_PROFILE_FILES = [
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "SUPPORT.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/pull_request_template.md",
]
DOCKERFILE_FORBIDDEN_MARKERS = [
    "rm -rf /rootfs/var/lib/rpm",
    "rm -rf /var/lib/rpm",
    "ghcr.io/nwarila-" + "platform",
    "fips" + "install",
    "OPENSSL_FIPS_PROVIDER_NEVRA=openssl-fips-provider-so-3.0.7-8.el9.x86_64",
    "OPENSSL_FIPS_MODULE_VERSION_AMD64",
    "OPENSSL_FIPS_PROVIDER_NEVRA_AMD64",
    "OPENSSL_FIPS_MODULE_VERSION_ARM64",
    "OPENSSL_FIPS_PROVIDER_NEVRA_ARM64",
    "openssl-fips-provider-so-3.0.7-11.el9_8",
    "3.0.7-cda111b5812c30d4",
]
REPO_ADRS = [
    (
        "docs/decision-records/repo/0001-byte-for-byte-rootfs-reproducibility.md",
        "Enforce Byte-For-Byte Rootfs Reproducibility",
    ),
    (
        "docs/decision-records/repo/0002-rhel-openssl-fips-approved-mode.md",
        "Use The RHEL OpenSSL FIPS Provider Approved-Mode Config",
    ),
    (
        "docs/decision-records/repo/0003-per-architecture-fips-scope.md",
        "Publish Multi-Arch Images With Per-Architecture FIPS Scope",
    ),
    (
        "docs/decision-records/repo/0004-slsa-generator-tag-pin-exception.md",
        "Keep The SLSA Generator Tag-Pinned With An Integrity Guard",
    ),
    (
        "docs/decision-records/repo/0005-strip-runtime-with-phantom-package-guard.md",
        "Strip Runtime Payload Only Behind Rpmdb And Ownership Guards",
    ),
    (
        "docs/decision-records/repo/0006-rpm-lock-cve-absorption-loop.md",
        "Absorb Patched RPMs Through A Gated Lockfile Refresh Loop",
    ),
    (
        "docs/decision-records/repo/0007-dual-scanner-openvex-default-deny.md",
        "Use Dual Scanners And Default-Deny OpenVEX",
    ),
    (
        "docs/decision-records/repo/0008-tailored-stig-arf-gate.md",
        "Gate The Image With A Tailored RHEL 9 STIG ARF",
    ),
    (
        "docs/decision-records/repo/0009-nist-800-190-image-evidence.md",
        "Emit NIST SP 800-190 Image-Control Evidence",
    ),
    (
        "docs/decision-records/repo/0010-single-repo-base-image-family.md",
        "Keep The Base-Image Family In One Repository With Per-Image Publish Workflows",
    ),
    (
        "docs/decision-records/repo/0011-pin-github-hosted-runner-labels.md",
        "Pin GitHub-Hosted Runner Labels",
    ),
    (
        "docs/decision-records/repo/0012-source-runtime-rpms-from-direct-cdn.md",
        "Source Runtime RPMs From Pinned Direct CDN Blobs",
    ),
    (
        "docs/decision-records/repo/0013-externalize-image-contract-manifest.md",
        "Externalize The Image Contract Manifest",
    ),
    (
        "docs/decision-records/repo/0014-pin-builder-python-closure.md",
        "Pin The Builder Python Closure",
    ),
    (
        "docs/decision-records/repo/0015-separate-python-policy-logic-from-shell-orchestration.md",
        "Separate Python Policy Logic From Shell Orchestration",
    ),
    (
        "docs/decision-records/repo/0016-remove-vulnerable-components-outside-supported-surfaces.md",
        "Remove Vulnerable Components Only Outside Declared Supported Surfaces",
    ),
]


class VerifyError(Exception):
    pass


def require(condition: object, message: str) -> None:
    if not condition:
        raise VerifyError(message)


def read(relative_path: str) -> str:
    path = ROOT / relative_path
    require(path.is_file(), f"missing required file: {relative_path}")
    return path.read_text(encoding="utf-8")


def ubi_digest_sources() -> dict[str, str]:
    paths = {path for sites in UBI_DIGEST_SITES.values() for path in sites}
    return {path: read(path) for path in sorted(paths)}


def require_ubi_digest_equality(sources: Mapping[str, str]) -> None:
    expected_paths = {path for sites in UBI_DIGEST_SITES.values() for path in sites}
    actual_paths = set(sources)
    source_errors = []
    missing_paths = sorted(expected_paths - actual_paths)
    unexpected_paths = sorted(actual_paths - expected_paths)
    if missing_paths:
        source_errors.append("missing " + ", ".join(missing_paths))
    if unexpected_paths:
        source_errors.append("unexpected " + ", ".join(unexpected_paths))
    require(not source_errors, "UBI digest source set mismatch: " + "; ".join(source_errors))

    site_digests: dict[str, list[tuple[str, str]]] = {}
    for image, sites in UBI_DIGEST_SITES.items():
        site_digests[image] = []
        for relative_path, site_pattern in sites.items():
            matches = list(site_pattern.finditer(sources[relative_path]))
            require(
                len(matches) == 1,
                f"UBI digest site mismatch for ubi-{image}: {relative_path} "
                f"expected 1 assignment, found {len(matches)}",
            )
            site_digests[image].append((relative_path, matches[0].group("digest")))

        for relative_path, text in sources.items():
            live_matches = [
                match
                for line in text.splitlines()
                if not line.lstrip().startswith("#")
                for match in UBI_FULL_REFERENCE.finditer(line)
                if match.group("image") == image
            ]
            expected_count = int(relative_path in sites)
            require(
                len(live_matches) == expected_count,
                f"UBI digest site mismatch for ubi-{image}: {relative_path} "
                f"expected {expected_count} live full reference(s), found {len(live_matches)}",
            )

        digests = {digest for _, digest in site_digests[image]}
        require(
            len(digests) == 1,
            f"UBI digest mismatch for ubi-{image}: "
            + ", ".join(f"{path}=sha256:{digest}" for path, digest in site_digests[image]),
        )


def check_ubi_digest_equality() -> None:
    require_ubi_digest_equality(ubi_digest_sources())


def check_ubi_digest_equality_self_test() -> None:
    sources = ubi_digest_sources()
    require_ubi_digest_equality(sources)

    def site_match(image: str, path: str) -> re.Match[str]:
        match = UBI_DIGEST_SITES[image][path].search(sources[path])
        if match is None:
            raise VerifyError(f"UBI digest self-test requires the {path} ubi-{image} assignment")
        return match

    micro_path = "tools/build.sh"
    micro_match = site_match("micro", micro_path)
    current_digest = micro_match.group("digest")
    alternate_digest = ("0" if current_digest != "0" * 64 else "1") * 64
    divergent = dict(sources)
    divergent[micro_path] = sources[micro_path].replace(current_digest, alternate_digest, 1)
    expected_divergence = "UBI digest mismatch for ubi-micro: " + ", ".join(
        f"{path}=sha256:{alternate_digest if path == micro_path else site_match('micro', path).group('digest')}"
        for path in UBI_DIGEST_SITES["micro"]
    )

    gate_path = "tools/run-test-gates.sh"
    gate_match = site_match("micro", gate_path)
    gate_reference = gate_match.group(0).split(":-", 1)[1].removesuffix('}"')
    expected_missing = "UBI digest site mismatch for ubi-micro: tools/run-test-gates.sh expected 1 assignment, found 0"
    missing = dict(sources)
    missing[gate_path] = sources[gate_path].replace(gate_reference, "", 1)
    comment_spoof = dict(missing)
    comment_spoof[gate_path] += f"\n# {gate_reference}\n"
    wrong_context = dict(missing)
    wrong_context[gate_path] += f'\nprintf "%s\\n" "{gate_reference}"\n'

    rejected = 0
    for label, mutated, expected_message in [
        ("one-site divergence", divergent, expected_divergence),
        ("deleted site", missing, expected_missing),
        ("comment spoof", comment_spoof, expected_missing),
        ("wrong-context spoof", wrong_context, expected_missing),
    ]:
        try:
            require_ubi_digest_equality(mutated)
        except VerifyError as exc:
            require(str(exc) == expected_message, f"UBI digest {label} mutation returned unexpected diagnostic: {exc}")
            rejected += 1
        else:
            raise VerifyError(f"UBI digest {label} mutation unexpectedly passed")

    replacement_digest = "2" * 64
    consistent = {
        path: UBI_FULL_REFERENCE.sub(
            lambda match: match.group(0).removesuffix(match.group("digest")) + replacement_digest,
            text,
        )
        for path, text in sources.items()
    }
    require_ubi_digest_equality(consistent)
    print(f"UBI digest mutation probes: unchanged and consistent replacements accepted; {rejected}/4 rejected")


def binfmt_sources() -> dict[str, str]:
    sources = {path: read(path) for path in BINFMT_DIGEST_SITES}
    workflow_paths = sorted({*ROOT.glob(".github/workflows/*.yaml"), *ROOT.glob(".github/workflows/*.yml")})
    for path in workflow_paths:
        relative_path = str(path.relative_to(ROOT))
        if relative_path in sources:
            continue
        text = path.read_text(encoding="utf-8")
        if BINFMT_ACTION_REFERENCE.search(text) or BINFMT_FULL_REFERENCE.search(text):
            sources[relative_path] = text
    return sources


def require_binfmt_digest_equality(sources: Mapping[str, str]) -> None:
    expected_paths = set(BINFMT_DIGEST_SITES)
    actual_paths = set(sources)
    source_errors = []
    missing_paths = sorted(expected_paths - actual_paths)
    unexpected_paths = sorted(actual_paths - expected_paths)
    if missing_paths:
        source_errors.append("missing " + ", ".join(missing_paths))
    if unexpected_paths:
        source_errors.append("unexpected " + ", ".join(unexpected_paths))
    require(not source_errors, "binfmt digest source set mismatch: " + "; ".join(source_errors))

    site_digests: list[tuple[str, str]] = []
    for relative_path, expected_count in BINFMT_DIGEST_SITES.items():
        text = sources[relative_path]
        matches = list(BINFMT_SITE.finditer(text))
        require(
            len(matches) == expected_count,
            f"binfmt digest site mismatch: {relative_path} expected {expected_count} pinned site(s), "
            f"found {len(matches)}",
        )

        action_matches = list(BINFMT_ACTION_REFERENCE.finditer(text))
        require(
            len(action_matches) == expected_count,
            f"binfmt action site mismatch: {relative_path} expected {expected_count} setup-qemu-action site(s), "
            f"found {len(action_matches)}",
        )

        live_references = [
            match
            for line in text.splitlines()
            if not line.lstrip().startswith("#")
            for match in BINFMT_FULL_REFERENCE.finditer(line)
        ]
        require(
            len(live_references) == expected_count,
            f"binfmt digest site mismatch: {relative_path} expected {expected_count} live full reference(s), "
            f"found {len(live_references)}",
        )
        site_digests.extend(
            (f"{relative_path}#{index}", match.group("digest")) for index, match in enumerate(matches, start=1)
        )

    digests = {digest for _, digest in site_digests}
    require(
        len(site_digests) == sum(BINFMT_DIGEST_SITES.values()) and len(digests) == 1,
        "binfmt digest mismatch: " + ", ".join(f"{site}=sha256:{digest}" for site, digest in site_digests),
    )


def check_binfmt_digest_equality() -> None:
    require_binfmt_digest_equality(binfmt_sources())


def check_binfmt_digest_equality_self_test() -> None:
    sources = binfmt_sources()
    require_binfmt_digest_equality(sources)

    target_path = ".github/workflows/build.yaml"
    target_match = BINFMT_SITE.search(sources[target_path])
    if target_match is None:
        raise VerifyError(f"binfmt digest self-test requires the {target_path} pinned site")

    expected_missing = f"binfmt digest site mismatch: {target_path} expected 2 pinned site(s), found 1"
    unpinned = dict(sources)
    reference_start, reference_end = target_match.span("digest")
    reference_prefix = sources[target_path][:reference_start].removesuffix("@sha256:")
    unpinned[target_path] = reference_prefix + ":latest" + sources[target_path][reference_end:]

    current_digest = target_match.group("digest")
    alternate_digest = ("0" if current_digest != "0" * 64 else "1") * 64
    divergent = dict(sources)
    divergent[target_path] = (
        sources[target_path][:reference_start] + alternate_digest + sources[target_path][reference_end:]
    )
    expected_divergence = "binfmt digest mismatch: " + ", ".join(
        f"{relative_path}#{index}=sha256:"
        f"{alternate_digest if relative_path == target_path and index == 1 else match.group('digest')}"
        for relative_path in BINFMT_DIGEST_SITES
        for index, match in enumerate(BINFMT_SITE.finditer(sources[relative_path]), start=1)
    )

    missing = dict(sources)
    missing[target_path] = sources[target_path].replace(target_match.group(0), "", 1)

    rejected = 0
    for label, mutated, expected_message in [
        ("unpinned site", unpinned, expected_missing),
        ("divergent digit", divergent, expected_divergence),
        ("missing site", missing, expected_missing),
    ]:
        try:
            require_binfmt_digest_equality(mutated)
        except VerifyError as exc:
            require(
                str(exc) == expected_message,
                f"binfmt digest {label} mutation returned unexpected diagnostic: {exc}",
            )
            rejected += 1
        else:
            raise VerifyError(f"binfmt digest {label} mutation unexpectedly passed")

    replacement_digest = "2" * 64
    consistent = {
        path: BINFMT_FULL_REFERENCE.sub(
            lambda match: match.group(0).removesuffix(match.group("digest")) + replacement_digest,
            text,
        )
        for path, text in sources.items()
    }
    require_binfmt_digest_equality(consistent)
    print(
        f"binfmt digest mutation probes: unchanged and all-{sum(BINFMT_DIGEST_SITES.values())}-pinned-equal "
        "replacements accepted; "
        f"{rejected}/3 rejected (unpinned site, divergent digit, missing site)"
    )


def check_gitattributes_archive_visibility() -> None:
    tracked_result = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--name-only", "HEAD", "--", ".github/"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    require(
        tracked_result.returncode == 0,
        "git ls-tree failed: " + tracked_result.stderr.decode(errors="replace").strip(),
    )
    tracked_paths = {
        field.decode("utf-8", errors="surrogateescape") for field in tracked_result.stdout.split(b"\0") if field
    }
    require(tracked_paths, "HEAD must contain tracked .github/ files")

    archive_result = subprocess.run(
        ["git", "archive", "--format=tar", "--worktree-attributes", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    require(
        archive_result.returncode == 0,
        "git archive failed: " + archive_result.stderr.decode(errors="replace").strip(),
    )
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_result.stdout), mode="r:") as archive:
            archived_paths = {member.name for member in archive.getmembers()}
    except (OSError, tarfile.TarError) as exc:
        raise VerifyError(f"git archive returned an unreadable tar stream: {exc}") from exc

    hidden_paths = sorted(tracked_paths - archived_paths)
    require(
        not hidden_paths,
        ".gitattributes must keep every tracked .github/ file archive-visible:\n  " + "\n  ".join(hidden_paths),
    )


def reject_stale_fixable_cve_claims(sources: dict[str, str]) -> None:
    stale_patterns = [
        r"fixable\s+HIGH\s+and\s+CRITICAL",
        r"fixable\s+HIGH\s+or\s+CRITICAL",
        r"fixable\s+HIGH/CRITICAL",
        r"--fail-on\s+high\b",
        r"--severity\s+HIGH,CRITICAL\s+--ignore-unfixed",
    ]
    for source, source_text in sources.items():
        for pattern in stale_patterns:
            require(
                re.search(pattern, source_text, flags=re.IGNORECASE) is None,
                f"{source} retains stale fixable-CVE policy form matching: {pattern}",
            )


def check_stale_fixable_cve_claims_self_test() -> None:
    stale_mutations = [
        ("fixable HIGH and CRITICAL", "fixable   HIGH\tand\nCRITICAL"),
        ("fixable HIGH or CRITICAL", "fixable\tHIGH\nor   CRITICAL"),
        ("fixable HIGH/CRITICAL", "fixable\nHIGH/CRITICAL"),
        ("--fail-on high", "--fail-on\nhigh"),
        ("--severity HIGH,CRITICAL --ignore-unfixed", "--severity\tHIGH,CRITICAL\n--ignore-unfixed"),
    ]
    rejected = 0
    for label, fixture in stale_mutations:
        try:
            reject_stale_fixable_cve_claims({f"self-test stale mutation ({label})": fixture})
        except VerifyError:
            rejected += 1
        else:
            raise VerifyError(f"stale fixable-CVE whitespace mutation unexpectedly passed: {label}")

    reject_stale_fixable_cve_claims(
        {
            "self-test clean and near-miss fixtures": (
                "fixable MEDIUM, HIGH, and CRITICAL\n"
                "fixable MEDIUM/HIGH/CRITICAL\n"
                "--fail-on medium\n"
                "--severity MEDIUM,HIGH,CRITICAL --ignore-unfixed\n"
            )
        }
    )
    print(
        f"Stale fixable-CVE whitespace mutation probes: {rejected}/{len(stale_mutations)} rejected; "
        "clean and near-miss fixtures accepted"
    )


def load_json_object(relative_path: str) -> dict[str, Any]:
    try:
        loaded = json.loads(read(relative_path))
    except json.JSONDecodeError as exc:
        raise VerifyError(f"{relative_path} is not valid JSON: {exc}") from exc
    require(isinstance(loaded, dict), f"{relative_path} must contain a JSON object")
    return cast(dict[str, Any], loaded)


def json_type_matches(value: Any, schema_type: str) -> bool:
    if schema_type == "object":
        return isinstance(value, dict)
    if schema_type == "array":
        return isinstance(value, list)
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "boolean":
        return isinstance(value, bool)
    return False


def validate_json_schema(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    schema_type = schema.get("type")
    if schema_type is not None:
        require(isinstance(schema_type, str), f"{path}: schema type must be a string")
        require(json_type_matches(instance, schema_type), f"{path} must be JSON type {schema_type}")

    if "const" in schema:
        require(instance == schema["const"], f"{path} must equal schema const")

    enum_values = schema.get("enum")
    if enum_values is not None:
        require(isinstance(enum_values, list), f"{path}: schema enum must be an array")
        require(instance in enum_values, f"{path} must be one of {enum_values}")

    pattern = schema.get("pattern")
    if pattern is not None:
        require(isinstance(pattern, str), f"{path}: schema pattern must be a string")
        require(isinstance(instance, str), f"{path} must be a string for pattern validation")
        require(re.fullmatch(pattern, instance) is not None, f"{path} does not match pattern {pattern}")

    minimum = schema.get("minimum")
    if minimum is not None:
        require(isinstance(minimum, int) and not isinstance(minimum, bool), f"{path}: schema minimum must be integer")
        require(isinstance(instance, int) and not isinstance(instance, bool), f"{path} must be integer for minimum")
        require(instance >= minimum, f"{path} must be >= {minimum}")

    if isinstance(instance, list):
        min_items = schema.get("minItems")
        if min_items is not None:
            require(isinstance(min_items, int) and not isinstance(min_items, bool), f"{path}: minItems must be integer")
            require(len(instance) >= min_items, f"{path} must contain at least {min_items} item(s)")
        if schema.get("uniqueItems") is True:
            seen: set[str] = set()
            for item in instance:
                marker = json.dumps(item, sort_keys=True, separators=(",", ":"))
                require(marker not in seen, f"{path} must contain unique items")
                seen.add(marker)
        items_schema = schema.get("items")
        if items_schema is not None:
            require(isinstance(items_schema, dict), f"{path}: items schema must be an object")
            for index, item in enumerate(instance):
                validate_json_schema(item, cast(dict[str, Any], items_schema), f"{path}[{index}]")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        require(
            isinstance(required, list) and all(isinstance(item, str) for item in required),
            f"{path}: required must be an array of strings",
        )
        for key in required:
            require(key in instance, f"{path} missing required property {key}")

        properties = schema.get("properties", {})
        require(isinstance(properties, dict), f"{path}: schema properties must be an object")
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            child_path = f"{path}.{key}"
            if key in properties:
                child_schema = properties[key]
                require(isinstance(child_schema, dict), f"{child_path}: property schema must be an object")
                validate_json_schema(value, cast(dict[str, Any], child_schema), child_path)
            elif additional is False:
                raise VerifyError(f"{child_path} is not allowed by schema")
            elif isinstance(additional, dict):
                validate_json_schema(value, cast(dict[str, Any], additional), child_path)
            else:
                require(additional is True, f"{path}: additionalProperties must be boolean or schema")


def value_at(root: dict[str, Any], keys: tuple[str, ...]) -> Any:
    value: Any = root
    path = "$"
    for key in keys:
        require(isinstance(value, dict), f"{path} must be an object")
        require(key in value, f"{path} missing required property {key}")
        value = value[key]
        path = f"{path}.{key}"
    return value


def object_at(root: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    value = value_at(root, keys)
    require(isinstance(value, dict), f"$.{'.'.join(keys)} must be an object")
    return cast(dict[str, Any], value)


def string_at(root: dict[str, Any], keys: tuple[str, ...]) -> str:
    value = value_at(root, keys)
    require(isinstance(value, str), f"$.{'.'.join(keys)} must be a string")
    return cast(str, value)


def int_at(root: dict[str, Any], keys: tuple[str, ...]) -> int:
    value = value_at(root, keys)
    require(isinstance(value, int) and not isinstance(value, bool), f"$.{'.'.join(keys)} must be an integer")
    return cast(int, value)


def bool_at(root: dict[str, Any], keys: tuple[str, ...]) -> bool:
    value = value_at(root, keys)
    require(isinstance(value, bool), f"$.{'.'.join(keys)} must be a boolean")
    return cast(bool, value)


def string_list_at(root: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    value = value_at(root, keys)
    require(
        isinstance(value, list) and all(isinstance(item, str) for item in value),
        f"$.{'.'.join(keys)} must be an array of strings",
    )
    return cast(list[str], value)


def validate_image_contract_invariants(manifest: dict[str, Any]) -> None:
    architectures = string_list_at(manifest, ("architectures",))
    require(len(architectures) == len(set(architectures)), "image contract architectures must be unique")
    fips_arches = object_at(manifest, ("fips", "architectures"))
    require(set(fips_arches) == set(architectures), "image contract FIPS architectures must match architectures")
    repro = object_at(manifest, ("reproducibility",))
    rootfs_digests = object_at(repro, ("canonical_rootfs_digest",))
    rpmdb_digests = object_at(repro, ("rpmdb_sha256",))
    require(
        set(rootfs_digests) == set(architectures),
        "image contract canonical rootfs digest architectures must match architectures",
    )
    require(
        set(rpmdb_digests) == set(architectures),
        "image contract rpmdb digest architectures must match architectures",
    )
    require(
        string_at(manifest, ("fips", "provider_nevra")).startswith("openssl-fips-provider-so-"),
        "image contract FIPS provider must name openssl-fips-provider-so",
    )
    for arch in architectures:
        arch_contract = object_at(manifest, ("fips", "architectures", arch))
        require(
            re.fullmatch(r"[0-9a-f]{64}", string_at(arch_contract, ("fips_so_sha256",))) is not None,
            f"image contract fips.so sha256 for {arch} must be 64 hex characters",
        )
        for digest_name, digest_value in [
            ("canonical rootfs", string_at(rootfs_digests, (arch,))),
            ("rpmdb", string_at(rpmdb_digests, (arch,))),
        ]:
            require(
                re.fullmatch(r"[0-9a-f]{64}", digest_value) is not None,
                f"image contract {digest_name} sha256 for {arch} must be 64 hex characters",
            )
    require(string_list_at(manifest, ("runtime", "package_floor")), "runtime package floor must not be empty")
    require(int_at(manifest, ("runtime", "footprint_limit_bytes")) > 0, "footprint limit must be positive")
    require(
        "<ref>" in string_at(manifest, ("provenance", "cosign", "certificate_identity")),
        "cosign identity must carry <ref>",
    )
    builder_id = string_at(manifest, ("provenance", "slsa", "builder_id"))
    require(
        builder_id.startswith("https://github.com/") and "@refs/tags/" in builder_id,
        "SLSA builder ID must be an exact GitHub workflow tag identity",
    )


def load_image_contract() -> dict[str, Any]:
    schema = load_json_object("contracts/image-manifest.schema.json")
    manifest = load_json_object("contracts/image-manifest.json")
    validate_json_schema(manifest, schema)
    validate_image_contract_invariants(manifest)
    return manifest


IMAGE_CONTRACT = load_image_contract()


def image_architectures() -> list[str]:
    return string_list_at(IMAGE_CONTRACT, ("architectures",))


def fips_module_version() -> str:
    return string_at(IMAGE_CONTRACT, ("fips", "module_version"))


def fips_provider_nevra() -> str:
    return string_at(IMAGE_CONTRACT, ("fips", "provider_nevra"))


def fips_cmvp() -> str:
    return string_at(IMAGE_CONTRACT, ("fips", "cmvp"))


def fips_arch_contract(arch: str) -> dict[str, Any]:
    return object_at(IMAGE_CONTRACT, ("fips", "architectures", arch))


def fips_rpm_arch(arch: str) -> str:
    return string_at(fips_arch_contract(arch), ("rpm_arch",))


def fips_so_sha256(arch: str) -> str:
    return string_at(fips_arch_contract(arch), ("fips_so_sha256",))


def fips_oe_validated(arch: str) -> bool:
    return bool_at(fips_arch_contract(arch), ("oe_validated",))


def fips_disclaimer(arch: str) -> str:
    return string_at(fips_arch_contract(arch), ("disclaimer",))


def fips_provider_nevra_for_arch(arch: str) -> str:
    return f"{fips_provider_nevra()}.{fips_rpm_arch(arch)}"


def fips_expected_status(arch: str) -> dict[str, object]:
    return {
        "arch": arch,
        "module": fips_module_version(),
        "provider_nvr": fips_provider_nevra(),
        "provider_nevra": fips_provider_nevra_for_arch(arch),
        "cmvp": f"#{fips_cmvp()}",
        "oe_validated": fips_oe_validated(arch),
        "disclaimer": fips_disclaimer(arch),
    }


def runtime_package_floor() -> set[str]:
    return set(string_list_at(IMAGE_CONTRACT, ("runtime", "package_floor")))


def footprint_limit_bytes() -> int:
    return int_at(IMAGE_CONTRACT, ("runtime", "footprint_limit_bytes"))


def cosign_certificate_identity() -> str:
    return string_at(IMAGE_CONTRACT, ("provenance", "cosign", "certificate_identity"))


def cosign_workflow_certificate_identity() -> str:
    identity = cosign_certificate_identity()
    github_prefix = "https://github.com/"
    require("/.github/" in identity, "Cosign certificate identity must contain a /.github/ workflow path")
    workflow_index = identity.index("/.github/")
    return github_prefix + "${{ github.repository }}" + identity[workflow_index:].replace("<ref>", "${{ github.ref }}")


def cosign_oidc_issuer() -> str:
    return string_at(IMAGE_CONTRACT, ("provenance", "cosign", "oidc_issuer"))


def slsa_builder_id() -> str:
    return string_at(IMAGE_CONTRACT, ("provenance", "slsa", "builder_id"))


def slsa_attestation_type() -> str:
    return string_at(IMAGE_CONTRACT, ("provenance", "slsa", "attestation_type"))


def slsa_generator_action() -> str:
    builder = slsa_builder_id()
    prefix = "https://github.com/"
    action, _ = builder.removeprefix(prefix).split("@refs/tags/", 1)
    return action


def slsa_generator_tag() -> str:
    _, tag = slsa_builder_id().split("@refs/tags/", 1)
    return tag


def predicate_type(name: str) -> str:
    return string_at(IMAGE_CONTRACT, ("provenance", "attestation_predicate_types", name))


def check_uses_pinned(text: str, source: str) -> None:
    uses = WORKFLOW_USES.findall(text)
    require(uses, f"{source} should pin external actions explicitly")
    bad_refs: list[str] = []
    for action, ref in uses:
        if not EXTERNAL_ACTION.fullmatch(action):
            continue
        if action == slsa_generator_action() and ref == slsa_generator_tag():
            continue
        if not SHA40.fullmatch(ref):
            bad_refs.append(f"{action}@{ref}")
    require(not bad_refs, f"{source} uses entries must be pinned to 40-char SHA: " + ", ".join(bad_refs))


def require_action_sha_pin(text: str, source: str, action: str, *, count: int | None = None) -> None:
    refs = [ref for candidate, ref in WORKFLOW_USES.findall(text) if candidate == action]
    require(refs, f"{source} must use {action}")
    if count is not None:
        require(len(refs) == count, f"{source} must use {action} exactly {count} time(s)")
    require(
        all(SHA40.fullmatch(ref) for ref in refs),
        f"{source} must pin every {action} use to a lowercase 40-character SHA",
    )


def require_version_literal(value: str, source: str) -> None:
    require(
        SHA40.fullmatch(value) is not None or VERSION_LITERAL.fullmatch(value) is not None,
        f"{source} must use a literal version-shaped value or lowercase 40-character SHA",
    )


def precommit_repo_block(text: str, repository: str) -> str:
    marker = f"  - repo: {repository}\n"
    require(text.count(marker) == 1, f".pre-commit-config.yaml must contain exactly one {repository} block")
    return text.split(marker, 1)[1].split("\n  - repo: ", 1)[0]


def require_precommit_hook_pin(text: str, repository: str) -> None:
    block = precommit_repo_block(text, repository)
    match = re.search(r"^    rev:\s+([^\s#]+)\s*$", block, flags=re.MULTILINE)
    if match is None:
        raise VerifyError(f"{repository} pre-commit hook must declare a literal rev")
    require_version_literal(match.group(1), f"{repository} pre-commit hook rev")


def require_hadolint_image_digest(text: str) -> None:
    block = precommit_repo_block(text, "https://github.com/hadolint/hadolint")
    match = re.search(r"^        entry:\s+([^\s]+)\s+hadolint\s*$", block, flags=re.MULTILINE)
    if match is None:
        raise VerifyError("Hadolint hook must invoke the ghcr.io/hadolint/hadolint image")
    require(
        HADOLINT_IMAGE.fullmatch(match.group(1)) is not None,
        "Hadolint hook image must be ghcr.io/hadolint/hadolint@sha256:<64 lowercase hex>",
    )


def check_workflow_uses_present(text: str, source: str) -> None:
    uses = WORKFLOW_USES.findall(text)
    require(uses, f"{source} should pin external actions explicitly")


def check_no_continue_on_error(text: str, source: str) -> None:
    require("continue-on-" + "error" not in text, f"{source} must not use continue-on-error")


def check_harden_runner_audit_steps(text: str, source: str) -> None:
    require("egress-policy: block" not in text, f"{source} must keep harden-runner in audit mode")
    require("allowed-endpoints:" not in text, f"{source} must not configure harden-runner block-mode allowlists")
    lines = text.splitlines()
    step_blocks = 0
    for index, line in enumerate(lines):
        if line == "    steps:":
            step_blocks += 1
            next_index = index + 1
            while next_index < len(lines) and not lines[next_index].strip():
                next_index += 1
            require(next_index < len(lines), f"{source} has an empty steps block")
            require(
                lines[next_index].strip() == "- name: Harden runner",
                f"{source} steps block must start with harden-runner audit step",
            )
            block = "\n".join(lines[next_index : next_index + 5])
            require(
                any(action == HARDEN_RUNNER and SHA40.fullmatch(ref) for action, ref in WORKFLOW_USES.findall(block)),
                f"{source} first harden-runner step must use a lowercase 40-character SHA",
            )
            require("egress-policy: audit" in block, f"{source} harden-runner must use audit egress policy")
    require(step_blocks > 0, f"{source} must contain at least one job steps block")
    require_action_sha_pin(text, source, HARDEN_RUNNER)
    require(
        len([action for action, _ in WORKFLOW_USES.findall(text) if action == HARDEN_RUNNER])
        == text.count("egress-policy: audit"),
        f"{source} harden-runner entries must all use egress-policy: audit",
    )


def cosign_installer_steps(text: str) -> list[str]:
    return re.findall(
        r"      - name: Install Cosign\n"
        rf"        uses: {re.escape(COSIGN_INSTALLER_ACTION)}@([^\s#]+)(?:\s+#[^\n]+)?\n"
        r"        with:\n"
        rf"          cosign-release: {re.escape(COSIGN_RELEASE)}",
        text,
    )


def check_cosign_before_test_gates(text: str, source: str) -> None:
    require_action_sha_pin(text, source, COSIGN_INSTALLER_ACTION, count=1)
    refs = cosign_installer_steps(text)
    require(len(refs) == 1, f"{source} must contain exactly one pinned Cosign v2.5.2 installer step")
    require(SHA40.fullmatch(refs[0]) is not None, f"{source} Cosign installer must use a lowercase 40-character SHA")
    step_pattern = re.compile(
        r"      - name: Install Cosign\n"
        rf"        uses: {re.escape(COSIGN_INSTALLER_ACTION)}@{re.escape(refs[0])}(?:\s+#[^\n]+)?\n"
        r"        with:\n"
        rf"          cosign-release: {re.escape(COSIGN_RELEASE)}"
    )
    match = step_pattern.search(text)
    if match is None:
        raise VerifyError(f"{source} must keep the Cosign v2.5.2 installer step identifiable")
    if source == "nightly workflow":
        gate = (
            "      - name: Run full test-only gate set\n"
            "        id: hardening-gate\n"
            "        env:\n"
            "          ARCH: ${{ matrix.arch }}\n"
            "        run: |\n"
            "          set -euo pipefail\n"
            "          mkdir -p dist/failure-logs\n"
            '          bash tools/run-test-gates.sh 2>&1 | tee "dist/failure-logs/hardening.${ARCH}.log"'
        )
    else:
        gate = "      - name: Run full test-only gate set\n        run: bash tools/run-test-gates.sh"
    require(
        f"{match.group(0)}\n\n{gate}" in text,
        f"{source} must install pinned Cosign v2.5.2 immediately before run-test-gates.sh",
    )


def check_publish_slsa_pins(text: str) -> None:
    tag = slsa_generator_tag()
    action = slsa_generator_action()
    for marker in [
        f'SLSA_GENERATOR_TAG: "{tag}"',
        f'SLSA_GENERATOR_TAG_SHA: "{SLSA_GENERATOR_SHA}"',
        'gh api "repos/slsa-framework/slsa-github-generator/git/ref/tags/${SLSA_GENERATOR_TAG}"',
        'if [[ "${actual}" != "${SLSA_GENERATOR_TAG_SHA}" ]]; then',
    ]:
        require(marker in text, f"publish workflow SLSA tag-integrity guard missing exact marker: {marker}")
    generator_uses = [
        (candidate, ref) for candidate, ref in WORKFLOW_USES.findall(text) if candidate == slsa_generator_action()
    ]
    require(
        generator_uses == [(action, tag)],
        "publish workflow must use exactly one SLSA generator @v2.1.0 tag pin",
    )


def check_pin_invariant_self_test() -> None:
    alternate_sha = "a" * 40
    relaxed_actions = [
        HARDEN_RUNNER,
        "actions/checkout",
        "ossf/scorecard-action",
        "github/codeql-action/init",
        "github/codeql-action/analyze",
        "github/codeql-action/upload-sarif",
        "actions/dependency-review-action",
        "zizmorcore/zizmor-action",
        "reviewdog/action-actionlint",
        COSIGN_INSTALLER_ACTION,
    ]
    for action in relaxed_actions:
        fixture = f"uses: {action}@{alternate_sha}\n"
        require_action_sha_pin(fixture, f"self-test alternate SHA for {action}", action, count=1)
        check_uses_pinned(fixture, f"self-test alternate SHA for {action}")

    invalid_refs = [
        ("tag", "v4"),
        ("branch", "main"),
        ("short SHA", "a" * 12),
        ("uppercase SHA", "A" * 40),
        ("41 hex", "a" * 41),
        ("trailing junk", f"{alternate_sha}-junk"),
    ]
    rejected = 0
    for label, ref in invalid_refs:
        try:
            check_uses_pinned(f"uses: actions/checkout@{ref}\n", f"self-test invalid {label}")
        except VerifyError:
            rejected += 1
        else:
            raise VerifyError(f"action pin invariant self-test unexpectedly accepted {label}: {ref}")

    publish = read(".github/workflows/publish-image.yaml")
    check_publish_slsa_pins(publish)
    slsa_mutations = [
        (
            "reusable tag",
            publish.replace(
                f"{slsa_generator_action()}@{slsa_generator_tag()}",
                f"{slsa_generator_action()}@v2.1.1",
                1,
            ),
        ),
        (
            "tag-integrity SHA",
            publish.replace(
                f'SLSA_GENERATOR_TAG_SHA: "{SLSA_GENERATOR_SHA}"',
                f'SLSA_GENERATOR_TAG_SHA: "{alternate_sha}"',
                1,
            ),
        ),
    ]
    for label, mutated in slsa_mutations:
        require(mutated != publish, f"SLSA {label} mutation fixture did not change")
        try:
            check_publish_slsa_pins(mutated)
        except VerifyError:
            pass
        else:
            raise VerifyError(f"SLSA {label} mutation unexpectedly passed")

    precommit = read(".pre-commit-config.yaml")
    hadolint_block = precommit_repo_block(precommit, "https://github.com/hadolint/hadolint")
    digest_match = re.search(r"ghcr\.io/hadolint/hadolint@sha256:[0-9a-f]{64}", hadolint_block)
    if digest_match is None:
        raise VerifyError("Hadolint digest mutation fixture is missing")
    invalid_hadolint = precommit.replace(digest_match.group(0), "ghcr.io/hadolint/hadolint:latest", 1)
    try:
        require_hadolint_image_digest(invalid_hadolint)
    except VerifyError:
        pass
    else:
        raise VerifyError("Hadolint non-digest image mutation unexpectedly passed")

    print(
        f"Action pin mutation probes: {len(relaxed_actions)}/{len(relaxed_actions)} alternate SHAs accepted; "
        f"{rejected}/{len(invalid_refs)} invalid refs rejected; 2/2 SLSA exact-pin mutations rejected; "
        "1/1 Hadolint digest mutation rejected"
    )


def require_unique_required_files(relative_paths: list[str]) -> None:
    duplicates = sorted(path for path, count in Counter(relative_paths).items() if count > 1)
    require(
        not duplicates,
        "required file list contains duplicate entries: " + ", ".join(duplicates),
    )


def check_required_files() -> None:
    required_files = [
        ".dockerignore",
        ".editorconfig",
        ".gitattributes",
        ".hadolint.yaml",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        ".github/CODEOWNERS",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/pull_request_template.md",
        ".github/renovate.json",
        ".github/zizmor.yml",
        ".github/workflows/build.yaml",
        ".github/workflows/codeql.yml",
        ".github/workflows/dependency-review.yml",
        ".github/workflows/lint.yaml",
        ".github/workflows/nightly.yaml",
        ".github/workflows/publish-image.yaml",
        ".github/workflows/rpm-lock-refresh.yaml",
        ".github/workflows/scorecard.yml",
        ".github/workflows/zizmor.yml",
        ".gitignore",
        ".markdownlint-cli2.jsonc",
        ".pre-commit-config.yaml",
        ".shellcheckrc",
        ".yamllint",
        "LICENSE",
        "Makefile",
        "pyproject.toml",
        "README.md",
        "SECURITY.md",
        "SUPPORT.md",
        "VERSION",
        "containers/Dockerfile",
        "containers/fips/openssl.cnf",
        "contracts/image-manifest.schema.json",
        "contracts/image-manifest.json",
        "contracts/examples/README.md",
        "contracts/examples/fips-status.amd64.json",
        "contracts/examples/fips-status.arm64.json",
        "rpm-lock/runtime.amd64.txt",
        "rpm-lock/runtime.arm64.txt",
        "rpm-lock/builder.amd64.txt",
        "rpm-lock/builder.arm64.txt",
        "rpm-lock/fips-verify.amd64.txt",
        "rpm-lock/fips-verify.arm64.txt",
        "security/cve-ignore.trivyignore.yaml",
        "security/cve-ignore.grype.yaml",
        "docs/README.md",
        "docs/TECH-DEBT.md",
        "docs/compliance/README.md",
        "docs/compliance/acceptance.md",
        "docs/compliance/fips.md",
        "docs/compliance/nist-800-190.md",
        "docs/compliance/stig.md",
        "docs/compliance/vex.md",
        "docs/decision-records/README.md",
        "docs/explanation/footprint.md",
        "images/README.md",
        "images/python/Dockerfile",
        "images/python/.dockerignore",
        "images/python/README.md",
        "images/python/VERSION",
        "images/python/docker-bake.json",
        "images/python/contracts/image-manifest.json",
        "images/python/contracts/image-manifest.schema.json",
        "images/python/rpm-lock/builder.amd64.txt",
        "images/python/rpm-lock/builder.arm64.txt",
        "images/python/rpm-lock/python.amd64.txt",
        "images/python/rpm-lock/python.arm64.txt",
        "images/python/rpm-lock/micro-floor.json",
        "images/python/rpm-lock/requires-exceptions.json",
        "images/python/rpm-lock/retained-payload-trim.json",
        "images/python/rpm-lock/scriptlet-classification.md",
        "images/python/rpm-lock/scriptlets.amd64.txt",
        "images/python/rpm-lock/scriptlets.arm64.txt",
        "images/python/tools/assert-builder-toolchain-floor.sh",
        "images/python/tools/assert-parent-subset.py",
        "images/python/tools/assert-no-rootfs-secrets.py",
        "images/python/tools/assert-sbom-rpms.py",
        "images/python/tools/assert-raw-scanners-no-sqlite.py",
        "images/python/tools/generate-nist-800-190-predicate.py",
        "images/python/tools/assert-reproducible.py",
        "images/python/tools/build-python-rootfs.py",
        "images/python/tools/fetch-builder-rpms.sh",
        "images/python/tools/fetch-python-rpms.sh",
        "images/python/tools/generate-python-lock.sh",
        "images/python/tools/rpmlock.py",
        "images/python/tools/retained_payload_trim.py",
        "images/python/tools/run-stig-arf.sh",
        "images/python/stig/rhel9-base-python-tailoring.xml",
        "images/python/stig/tailoring-justifications.json",
        "images/python/vex/README.md",
        "images/python/vex/cve-2026-53613.openvex.json",
        "images/python/vex/sqlite-component-not-present.openvex.json",
        "images/python/tools/run-python-gates.sh",
        ".github/workflows/python-ci.yaml",
        "docs/explanation/fips-mechanism.md",
        "docs/explanation/reproducibility.md",
        "docs/how-to/consume-base-micro-as-from-base.md",
        "docs/how-to/refresh-the-rpm-lock.md",
        "docs/how-to/reproduce-a-build-byte-for-byte.md",
        "docs/how-to/run-a-gate-locally.md",
        "docs/how-to/verify-a-published-image.md",
        "docs/reference/gates.md",
        "docs/reference/verification-contract.md",
        "docs/reference/verify.md",
        "docs/tutorials/getting-started-build-and-verify.md",
        "tests/fips.sh",
        "tests/hardening.sh",
        "tools/build.sh",
        "tools/run-test-gates.sh",
        "tools/assert-footprint.py",
        "tools/assert-builder-toolchain-floor.sh",
        "tools/build-runtime-rootfs.py",
        "tools/assert-no-phantom-packages.py",
        "tools/assert-reproducible.py",
        "tools/assert-rpm-lock-hashes.py",
        "tools/fetch-runtime-rpms.sh",
        "tools/fetch-builder-rpms.sh",
        "tools/decide-publish-scope.py",
        "tools/decide-python-publish-scope.py",
        "tools/assert-python-alias-policy.py",
        "tools/assert-python-attestation.py",
        "tools/assert-python-provenance.py",
        "tools/assert-python-slsa-certificate.py",
        "tools/python-trust-contract.py",
        "tools/generate-runtime-lock.py",
        "tools/rpmlock.py",
        "tools/verify-fips-provider.py",
        "tools/write-fips-status.py",
        "tools/tests/test_build_runtime_rootfs.py",
        "tools/tests/test_generate_runtime_lock.py",
        "tools/tests/test_assert_rpm_lock_hashes.py",
        "tools/tests/test_rpmlock.py",
        "tools/tests/test_verify_fips_provider.py",
        "tools/tests/test_write_fips_status.py",
        "tools/tests/test_summarize_gates.py",
        "tools/tests/test_render_pr_decision.py",
        "tools/tests/test_render_drift_issue.py",
        "tools/generate-rpm-lock.sh",
        "tools/install-syft.sh",
        "tools/install-trivy.sh",
        "tools/install-grype.sh",
        "tools/install-crane.sh",
        "tools/assert-scanner-db-freshness.py",
        "tools/assert-scanner-canary.py",
        "tools/assert-sbom-rpms.py",
        "tools/assert-no-rootfs-secrets.py",
        "tools/generate-nist-800-190-predicate.py",
        "tools/assert-cosign-rekor.py",
        "tools/assert-slsa-builder-id.py",
        "tools/assert-stig-tailoring.py",
        "tools/assert-rootfs-identity.py",
        "tools/assert-stig-arf.py",
        "tools/generate-stig-arf-predicate.py",
        "tools/summarize-gates.py",
        "tools/render-pr-decision.py",
        "tools/render-drift-issue.py",
        "tools/install-openscap.sh",
        "tools/build-stig-datastream.sh",
        "tools/run-stig-arf.sh",
        "tools/verify.py",
        "stig/rhel9-base-micro-tailoring.xml",
        "stig/tailoring-justifications.json",
        "tests/fixtures/scanner-canary/log4shell.cdx.json",
    ]
    require_unique_required_files(required_files)
    for relative_path in required_files:
        require((ROOT / relative_path).is_file(), f"missing required file: {relative_path}")

    duplicate_fixture = [required_files[0], required_files[0]]
    try:
        require_unique_required_files(duplicate_fixture)
    except VerifyError as exc:
        require(
            str(exc) == f"required file list contains duplicate entries: {required_files[0]}",
            f"required-file uniqueness fixture rejected for the wrong reason: {exc}",
        )
    else:
        raise VerifyError("required-file uniqueness fixture unexpectedly passed")
    print(f"Required-file uniqueness: {len(required_files)}/{len(set(required_files))}; duplicate fixture rejected")
    dockerignore = read(".dockerignore")
    expected_dockerignore_negations = {
        "!containers/",
        "!containers/Dockerfile",
        "!containers/fips/",
        "!containers/fips/openssl.cnf",
        "!contracts/image-manifest.json",
        "!rpm-lock/",
        "!rpm-lock/*.txt",
        "!tools/assert-builder-toolchain-floor.sh",
        "!tools/assert-rpm-lock-hashes.py",
        "!tools/build-runtime-rootfs.py",
        "!tools/fetch-builder-rpms.sh",
        "!tools/fetch-openssl-fips-provider-rpms.sh",
        "!tools/fetch-runtime-rpms.sh",
        "!tools/rpmlock.py",
        "!tools/verify-fips-provider.py",
        "!tools/write-fips-status.py",
    }
    raw_negations = [line for line in dockerignore.splitlines() if line.strip().startswith("!")]
    for raw_line in raw_negations:
        require(
            raw_line == raw_line.strip(),
            f".dockerignore negation lines must not carry leading or trailing whitespace: {raw_line!r}",
        )
    require(
        set(raw_negations) == expected_dockerignore_negations,
        ".dockerignore negation lines must exactly equal the reviewed build-context allowlist",
    )
    for relative_path, _ in REPO_ADRS:
        require((ROOT / relative_path).is_file(), f"missing required ADR: {relative_path}")


def check_image_contract_files() -> None:
    gitignore = read(".gitignore")
    for relative_path in [
        "contracts/",
        "contracts/*.json",
        "contracts/examples/",
        "contracts/examples/*.json",
        "contracts/examples/*.md",
    ]:
        require(f"!/{relative_path}" in gitignore, f".gitignore must allowlist contract path: {relative_path}")

    footprint = read("tools/assert-footprint.py")
    mib = footprint_limit_bytes() // (1024 * 1024)
    require(
        footprint_limit_bytes() == mib * 1024 * 1024 and f"DEFAULT_LIMIT_BYTES = {mib} * 1024 * 1024" in footprint,
        "footprint helper default limit must match the image manifest",
    )

    for arch in image_architectures():
        example = load_json_object(f"contracts/examples/fips-status.{arch}.json")
        require(example == fips_expected_status(arch), f"contract FIPS status example for {arch} must match manifest")


PYTHON_PUBLICATION_POINTERS = {
    "README.md": (
        "## Image Family",
        "[canonical publication evidence contract]"
        "(docs/reference/verification-contract.md#image-family-publication-evidence-contract)",
    ),
    "images/README.md": (
        "# Image Family Trees",
        "[canonical publication evidence contract]"
        "(../docs/reference/verification-contract.md#image-family-publication-evidence-contract)",
    ),
    "SUPPORT.md": (
        "## Not supported here",
        "[canonical publication evidence contract]"
        "(docs/reference/verification-contract.md#image-family-publication-evidence-contract)",
    ),
}


def markdown_section_intro(text: str, heading: str) -> str | None:
    match = re.search(rf"^{re.escape(heading)}[ \t]*$", text, re.MULTILINE)
    if match is None:
        return None
    following_heading = re.search(r"^#{1,6} ", text[match.end() :], re.MULTILINE)
    end = len(text) if following_heading is None else match.end() + following_heading.start()
    return text[match.start() : end]


def markdown_peer_section(text: str, heading: str) -> str | None:
    match = re.search(rf"^(?P<marks>#+) {re.escape(heading.lstrip('# '))}[ \t]*$", text, re.MULTILINE)
    if match is None or heading != match.group(0).rstrip():
        return None
    level = len(match.group("marks"))
    following_peer = re.search(rf"^#{{{level}}}(?!#) ", text[match.end() :], re.MULTILINE)
    end = len(text) if following_peer is None else match.end() + following_peer.start()
    return text[match.start() : end]


def community_profile_support_errors(support: str) -> list[str]:
    heading, pointer = PYTHON_PUBLICATION_POINTERS["SUPPORT.md"]
    section = markdown_section_intro(support, heading)
    if section is None:
        return [f"SUPPORT.md missing community-profile section: {heading}"]
    if pointer not in section:
        return [f"SUPPORT.md missing canonical publication pointer in {heading}"]
    return []


def check_community_profile() -> None:
    gitignore = read(".gitignore")
    for relative_path in COMMUNITY_PROFILE_FILES:
        require((ROOT / relative_path).is_file(), f"missing community profile file: {relative_path}")
        require(f"!/{relative_path}" in gitignore, f".gitignore must allowlist community profile file: {relative_path}")

    version = read("VERSION").strip()
    require(re.fullmatch(r"\d+\.\d+\.\d+", version) is not None, "VERSION must contain a non-empty SemVer version")

    contributing = read("CONTRIBUTING.md")
    for marker in [
        "make build",
        "make test",
        "make verify",
        "make clean",
        "tools/run-test-gates.sh",
        "tools/assert-reproducible.py",
        "--platform linux/amd64",
        "--platform linux/arm64",
        "Sign every commit",
        "deny-all `.gitignore`",
    ]:
        require(marker in contributing, f"CONTRIBUTING.md missing marker: {marker}")

    security = read("SECURITY.md")
    for marker in [
        "https://github.com/NWarila/ubi9-base-micro/security/advisories/new",
        "Supported versions",
        "docs/reference/verify.md",
        "cosign verify",
        "cosign verify-attestation",
        "slsa-verifier verify-image",
        "GitHub Actions OIDC issuer",
        "Do not substitute `gh attestation verify`",
    ]:
        require(marker in security, f"SECURITY.md missing marker: {marker}")
    require(
        re.search(rf"^\|\s*`?{re.escape(version)}`?\b", security, re.M) is not None,
        f"SECURITY.md must list VERSION {version} in the supported-versions table",
    )
    require("mailto:" not in security.lower(), "SECURITY.md must not publish a personal email contact")

    conduct = read("CODE_OF_CONDUCT.md")
    for marker in [
        "Contributor Covenant Code of Conduct",
        "version 2.1",
        "https://github.com/NWarila",
        "Community Impact Guidelines",
    ]:
        require(marker in conduct, f"CODE_OF_CONDUCT.md missing marker: {marker}")

    support = read("SUPPORT.md")
    for marker in [
        "GitHub Discussions are not enabled",
        "tools/run-test-gates.sh",
        "docs/reference/verify.md",
        "`base-node` and `base-java` remain planned",
    ]:
        require(marker in support, f"SUPPORT.md missing marker: {marker}")
    support_errors = community_profile_support_errors(support)
    require(not support_errors, support_errors[0] if support_errors else "SUPPORT.md community profile failed")
    support_pointer = PYTHON_PUBLICATION_POINTERS["SUPPORT.md"][1]
    mutated_support = support.replace(support_pointer, "Publication evidence unavailable", 1)
    require(mutated_support != support, "SUPPORT.md community-profile mutation fixture did not change")
    expected_support_error = "SUPPORT.md missing canonical publication pointer in ## Not supported here"
    require(
        expected_support_error in community_profile_support_errors(mutated_support),
        "SUPPORT.md community-profile publication-pointer mutation unexpectedly passed",
    )
    print(f"Community profile mutation rejected [support publication pointer] diagnostic={expected_support_error}")

    changelog = read("CHANGELOG.md")
    for marker in [
        "Keep a Changelog",
        "Semantic Versioning",
        "## [Unreleased]",
        "Community health files",
    ]:
        require(marker in changelog, f"CHANGELOG.md missing marker: {marker}")
    require(
        re.search(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.M) is not None,
        f"CHANGELOG.md must contain a dated release heading for VERSION {version}",
    )

    bug_form = read(".github/ISSUE_TEMPLATE/bug_report.yml")
    for marker in [
        "name: Bug Report",
        "description: Report a reproducible problem in this repository",
        "This is not a vulnerability report.",
        "Reproducibility",
        "Published digest verification",
        "render: shell",
    ]:
        require(marker in bug_form, f"bug_report.yml missing marker: {marker}")

    feature_form = read(".github/ISSUE_TEMPLATE/feature_request.yml")
    for marker in [
        "name: Feature Request",
        "description: Propose a repository-contract, documentation, or image-build improvement",
        "Would this affect image bytes or release evidence?",
        "both-arch reproducibility gates",
    ]:
        require(marker in feature_form, f"feature_request.yml missing marker: {marker}")

    issue_config = read(".github/ISSUE_TEMPLATE/config.yml")
    for marker in [
        "blank_issues_enabled: false",
        "https://github.com/NWarila/ubi9-base-micro/security/policy",
        "SUPPORT.md",
    ]:
        require(marker in issue_config, f"issue template config missing marker: {marker}")

    pr_template = read(".github/pull_request_template.md")
    for marker in [
        "Commits are signed.",
        "`python tools/verify.py` passes.",
        "deny-all `.gitignore`",
        "fresh amd64 and arm64 byte-for-byte reproducibility proof",
        "`bash tools/run-test-gates.sh` passes",
        "FIPS, STIG, footprint, SBOM, VEX, Trivy, Grype, NIST SP 800-190, SLSA, and Rekor",
        "docs/reference/verify.md",
    ]:
        require(marker in pr_template, f"pull request template missing marker: {marker}")


def python_publication_docs_errors(readme: str, images_readme: str, support: str) -> list[str]:
    errors: list[str] = []
    required = {
        "README.md": readme,
        "images/README.md": images_readme,
        "SUPPORT.md": support,
    }
    for path, text in required.items():
        heading, pointer = PYTHON_PUBLICATION_POINTERS[path]
        section = markdown_section_intro(text, heading)
        if section is None:
            errors.append(f"{path} missing Python publication section: {heading}")
        elif pointer not in section:
            errors.append(f"{path} missing canonical publication pointer in {heading}")
    stale = {
        "README.md": "Only `ubi9-base-micro` exists in this repository today",
        "images/README.md": "Planned base-image variants will live here",
        "SUPPORT.md": "Support for planned `base-python`, `base-node`, or `base-java` images",
    }
    for path, marker in stale.items():
        text = required[path]
        if marker in text:
            errors.append(f"{path} retains stale Python planned-status marker: {marker}")
    return errors


def check_python_publication_docs_self_test() -> None:
    baseline = (read("README.md"), read("images/README.md"), read("SUPPORT.md"))
    require(not python_publication_docs_errors(*baseline), "Python publication docs baseline failed")
    fixtures = [
        (
            "README replacement removed",
            (
                baseline[0].replace(PYTHON_PUBLICATION_POINTERS["README.md"][1], "Publication evidence unavailable", 1),
                *baseline[1:],
            ),
            "README.md missing canonical publication pointer in ## Image Family",
        ),
        (
            "images replacement removed",
            (
                baseline[0],
                baseline[1].replace(
                    PYTHON_PUBLICATION_POINTERS["images/README.md"][1], "Publication evidence unavailable", 1
                ),
                baseline[2],
            ),
            "images/README.md missing canonical publication pointer in # Image Family Trees",
        ),
        (
            "support replacement removed",
            (
                baseline[0],
                baseline[1],
                baseline[2].replace(
                    PYTHON_PUBLICATION_POINTERS["SUPPORT.md"][1], "Publication evidence unavailable", 1
                ),
            ),
            "SUPPORT.md missing canonical publication pointer in ## Not supported here",
        ),
        (
            "README stale claim restored",
            (baseline[0] + "\nOnly `ubi9-base-micro` exists in this repository today\n", *baseline[1:]),
            "README.md retains stale Python planned-status marker: "
            "Only `ubi9-base-micro` exists in this repository today",
        ),
        (
            "images stale claim restored",
            (baseline[0], baseline[1] + "\nPlanned base-image variants will live here\n", baseline[2]),
            "images/README.md retains stale Python planned-status marker: Planned base-image variants will live here",
        ),
        (
            "support stale claim restored",
            (
                baseline[0],
                baseline[1],
                baseline[2] + "\nSupport for planned `base-python`, `base-node`, or `base-java` images\n",
            ),
            "SUPPORT.md retains stale Python planned-status marker: "
            "Support for planned `base-python`, `base-node`, or `base-java` images",
        ),
    ]
    for label, documents, expected in fixtures:
        errors = python_publication_docs_errors(*documents)
        require(expected in errors, f"Python publication docs mutation unexpectedly passed: {label}")
        print(f"Python publication docs mutation rejected [{label}] diagnostic={expected}")
    print(f"Python publication docs mutation probes: {len(fixtures)}/{len(fixtures)} rejected")


def python_bake_contract_error(contract: Any) -> str | None:
    if not isinstance(contract, dict):
        return "python Bake contract must be a JSON object"
    if set(contract) != {"variable", "target"}:
        return "python Bake contract top-level keys must be exactly variable and target"

    variables = contract.get("variable")
    if not isinstance(variables, dict) or set(variables) != PYTHON_BAKE_VARIABLES:
        return "python Bake variable key set mismatch"
    for name, entry in variables.items():
        if not isinstance(entry, dict) or set(entry) != {"default"}:
            return f"python Bake variable {name} must contain only a formal default"

    buildx_version = variables["BUILDX_VERSION"]["default"]
    if not isinstance(buildx_version, str) or VERSION_LITERAL.fullmatch(buildx_version) is None:
        return "Buildx version variable is not a semantic version"
    buildx_commit = variables["BUILDX_COMMIT"]["default"]
    if not isinstance(buildx_commit, str) or SHA40.fullmatch(buildx_commit) is None:
        return "Buildx commit variable is not a 40-character commit"
    buildx_asset = variables["BUILDX_ASSET_SHA256"]["default"]
    if not isinstance(buildx_asset, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", buildx_asset) is None:
        return "Buildx Linux-amd64 asset SHA-256 variable is not digest-shaped"
    buildkit_image = variables["BUILDKIT_IMAGE"]["default"]
    if not isinstance(buildkit_image, str) or PYTHON_BUILDKIT_REFERENCE.fullmatch(buildkit_image) is None:
        return "BuildKit driver image is not digest-pinned"
    repro_dest = variables["REPRO_DEST"]["default"]
    if not isinstance(repro_dest, str) or not repro_dest:
        return "repro destination variable must have a non-empty default"
    if variables["RELEASE_REF"]["default"] != "RELEASE_REF must be set":
        return "release destination variable must have the invalid sentinel default"
    for name in ("OCI_REVISION", "OCI_SOURCE", "OCI_VERSION"):
        if variables[name]["default"] is not None:
            return f"python Bake variable {name} must be nullable"
    for name in ("UBI_MINIMAL_IMAGE", "BASE_MICRO_IMAGE"):
        if variables[name]["default"] is not None:
            return f"python Bake variable {name} must be nullable"

    targets = contract.get("target")
    if not isinstance(targets, dict) or set(targets) != PYTHON_BAKE_TARGETS:
        return "python Bake target key set must be exactly base, ci, release, and repro"
    base = targets.get("base")
    if not isinstance(base, dict) or set(base) != {
        "context",
        "dockerfile",
        "target",
        "platforms",
        "args",
    }:
        return "python Bake base target key set mismatch"
    if base.get("context") != "images/python":
        return "python Bake base context mismatch"
    if base.get("dockerfile") != "Dockerfile":
        return "python Bake base dockerfile mismatch"
    if base.get("target") != "runtime":
        return "python Bake base build target mismatch"
    if base.get("platforms") != ["linux/amd64", "linux/arm64"]:
        return "python Bake base platforms mismatch"
    if base.get("args") != {
        "SOURCE_DATE_EPOCH": "1704067200",
        "OCI_CREATED": "2024-01-01T00:00:00Z",
    }:
        return "python Bake base fixed build args mismatch"

    for name in sorted(set(targets) - {"base"}):
        target = targets[name]
        if not isinstance(target, dict):
            return f"python Bake target {name} must be an object"
        protected_fields = sorted(set(target) & PYTHON_BAKE_PROTECTED_FIELDS)
        if protected_fields:
            return f"python Bake target {name} must not redeclare protected field: {protected_fields[0]}"
        args = target.get("args")
        if isinstance(args, dict):
            protected_args = sorted(set(args) & PYTHON_BAKE_PROTECTED_ARGS)
            if protected_args:
                return f"python Bake target {name} must not redeclare protected field: {protected_args[0]}"
        if target.get("inherits") != ["base"]:
            return f"python Bake target {name} must inherit only base"

    ci = targets["ci"]
    if set(ci) != {"inherits", "output"}:
        return "python Bake ci target key set mismatch"
    if ci.get("output") != ["type=docker"]:
        return "python Bake ci output policy mismatch: expected type=docker"

    release = targets["release"]
    if set(release) != {"inherits", "args", "tags", "attest", "output"}:
        return "python Bake release target key set mismatch"
    if release.get("args") != {
        "OCI_REVISION": "${OCI_REVISION}",
        "OCI_SOURCE": "${OCI_SOURCE}",
        "OCI_VERSION": "${OCI_VERSION}",
    }:
        return "python Bake release protected OCI arguments mismatch"
    if release.get("tags") != ["${RELEASE_REF}"]:
        return "python Bake release tags must resolve only from RELEASE_REF"
    if release.get("attest") != ["type=provenance,mode=max", "type=sbom,disabled=true"]:
        return "python Bake release attestation policy mismatch"
    if release.get("output") != ["type=registry,rewrite-timestamp=true,push-by-digest=true,name-canonical=true"]:
        return "python Bake release output policy mismatch"

    repro = targets["repro"]
    if set(repro) != {"inherits", "args", "no-cache", "attest", "output"}:
        return "python Bake repro target key set mismatch"
    if repro.get("args") != {
        "OCI_REVISION": "reproducibility-harness",
        "OCI_VERSION": "dev",
        "UBI_MINIMAL_IMAGE": "${UBI_MINIMAL_IMAGE}",
        "BASE_MICRO_IMAGE": "${BASE_MICRO_IMAGE}",
    }:
        return "python Bake repro build args mismatch"
    if repro.get("no-cache") is not True:
        return "python Bake repro cache policy mismatch: no-cache must be true"
    if repro.get("attest") != ["type=provenance,disabled=true", "type=sbom,disabled=true"]:
        return "python Bake repro attestation policy mismatch"
    output = repro.get("output")
    if output == ["type=docker,dest=${REPRO_DEST},rewrite-timestamp=false"]:
        return "python Bake repro output policy mismatch: rewrite-timestamp must be true"
    if output != ["type=docker,dest=${REPRO_DEST},rewrite-timestamp=true"]:
        return "python Bake repro output policy mismatch"
    return None


def python_release_bake_errors(contract: Mapping[str, Any]) -> list[str]:
    """Lock the release graph committed in the reviewed Bake baseline."""
    errors: list[str] = []

    def reject(condition: object, message: str) -> None:
        if condition:
            errors.append(message)

    variables = contract.get("variable")
    targets = contract.get("target")
    variable_set_invalid = not isinstance(variables, dict) or set(variables) != PYTHON_BAKE_VARIABLES
    target_set_invalid = not isinstance(targets, dict) or set(targets) != PYTHON_BAKE_TARGETS
    release_ref_default_invalid = (
        not isinstance(variables, dict)
        or not isinstance(variables.get("RELEASE_REF"), dict)
        or variables["RELEASE_REF"].get("default", object()) != "RELEASE_REF must be set"
    )
    release_input_defaults_invalid = not isinstance(variables, dict) or any(
        not isinstance(variables.get(name), dict) or variables[name].get("default", object()) is not None
        for name in ("OCI_REVISION", "OCI_SOURCE", "OCI_VERSION")
    )
    release = targets.get("release") if isinstance(targets, dict) else None
    release_key_set_invalid = not isinstance(release, dict) or set(release) != {
        "inherits",
        "args",
        "tags",
        "attest",
        "output",
    }
    release_inheritance_invalid = not isinstance(release, dict) or release.get("inherits") != ["base"]
    release_args_invalid = not isinstance(release, dict) or release.get("args") != {
        "OCI_REVISION": "${OCI_REVISION}",
        "OCI_SOURCE": "${OCI_SOURCE}",
        "OCI_VERSION": "${OCI_VERSION}",
    }
    release_tags_invalid = not isinstance(release, dict) or release.get("tags") != ["${RELEASE_REF}"]
    release_attest_invalid = not isinstance(release, dict) or release.get("attest") != [
        "type=provenance,mode=max",
        "type=sbom,disabled=true",
    ]
    release_output_invalid = not isinstance(release, dict) or release.get("output") != [
        "type=registry,rewrite-timestamp=true,push-by-digest=true,name-canonical=true"
    ]

    # CHECK: python-release-bake-variable-set
    reject(variable_set_invalid, "python release Bake variable set mismatch")
    # CHECK: python-release-bake-target-set
    reject(target_set_invalid, "python release Bake target set mismatch")
    # CHECK: python-release-bake-ref-default
    reject(release_ref_default_invalid, "python release Bake RELEASE_REF default must be the invalid sentinel")
    # CHECK: python-release-bake-input-defaults
    reject(release_input_defaults_invalid, "python release Bake protected OCI input defaults must be null")
    # CHECK: python-release-bake-key-set
    reject(release_key_set_invalid, "python release Bake target key set mismatch")
    # CHECK: python-release-bake-inheritance
    reject(release_inheritance_invalid, "python release Bake target must inherit only base")
    # CHECK: python-release-bake-args
    reject(release_args_invalid, "python release Bake protected OCI arguments mismatch")
    # CHECK: python-release-bake-tags
    reject(release_tags_invalid, "python release Bake tags must be exactly RELEASE_REF")
    # CHECK: python-release-bake-attest
    reject(release_attest_invalid, "python release Bake attest exporters mismatch")
    # CHECK: python-release-bake-output
    reject(release_output_invalid, "python release Bake registry output mismatch")
    return errors


def _python_release_bake_fixtures(contract: Mapping[str, Any]) -> list[tuple[str, dict[str, Any], str]]:
    fixtures: list[tuple[str, dict[str, Any], str]] = []

    def mutation(
        label: str,
        path: tuple[str, ...],
        value: Any,
        reason: str,
        *,
        delete: bool = False,
    ) -> None:
        changed = copy.deepcopy(dict(contract))
        parent: dict[str, Any] = changed
        for component in path[:-1]:
            parent = cast(dict[str, Any], parent[component])
        if delete:
            del parent[path[-1]]
        else:
            parent[path[-1]] = value
        fixtures.append((label, changed, reason))

    unexpected_variable = copy.deepcopy(contract["variable"])
    unexpected_variable["UNEXPECTED"] = {"default": None}
    mutation(
        "variable-set",
        ("variable",),
        unexpected_variable,
        "python release Bake variable set mismatch",
    )
    unexpected_target = copy.deepcopy(contract["target"])
    unexpected_target["fork"] = {"inherits": ["base"]}
    mutation(
        "target-set",
        ("target",),
        unexpected_target,
        "python release Bake target set mismatch",
    )
    mutation(
        "release-ref-default",
        ("variable", "RELEASE_REF", "default"),
        "ghcr.io/example/release:latest",
        "python release Bake RELEASE_REF default must be the invalid sentinel",
    )
    mutation(
        "release-input-defaults",
        ("variable", "OCI_REVISION", "default"),
        "override",
        "python release Bake protected OCI input defaults must be null",
    )
    open_release = copy.deepcopy(contract["target"]["release"])
    open_release.update(
        {
            "network": "host",
            "entitlements": ["network.host"],
            "secret": ["id=token,src=token"],
            "ssh": ["default"],
        }
    )
    mutation(
        "release-open-key-set",
        ("target", "release"),
        open_release,
        "python release Bake target key set mismatch",
    )
    for label, key, value in (("release-cache-to", "cache-to", ["type=registry,ref=example.invalid/cache"]),):
        changed_release = copy.deepcopy(contract["target"]["release"])
        changed_release[key] = value
        mutation(
            label,
            ("target", "release"),
            changed_release,
            "python release Bake target key set mismatch",
        )
    mutation(
        "release-inheritance",
        ("target", "release", "inherits"),
        ["base", "ci"],
        "python release Bake target must inherit only base",
    )
    mutation(
        "release-args",
        ("target", "release", "args", "OCI_VERSION"),
        "dev",
        "python release Bake protected OCI arguments mismatch",
    )
    mutation(
        "release-tags",
        ("target", "release", "tags"),
        ["ghcr.io/example/release:latest"],
        "python release Bake tags must be exactly RELEASE_REF",
    )
    mutation(
        "release-attest",
        ("target", "release", "attest"),
        ["type=provenance,mode=min", "type=sbom,disabled=true"],
        "python release Bake attest exporters mismatch",
    )
    mutation(
        "release-output",
        ("target", "release", "output"),
        ["type=registry,rewrite-timestamp=false"],
        "python release Bake registry output mismatch",
    )
    return fixtures


def check_python_release_bake_self_test(only_label: str | None = None) -> None:
    contract = cast(dict[str, Any], json.loads(read(PYTHON_BAKE_FILE)))
    require(not python_release_bake_errors(contract), "python release Bake lock baseline failed")
    selected = 0
    fixtures = _python_release_bake_fixtures(contract)
    for label, mutated, expected in fixtures:
        if only_label is not None and label != only_label:
            continue
        selected += 1
        errors = python_release_bake_errors(mutated)
        if expected not in errors:
            raise VerifyError(f"python release Bake mutation unexpectedly passed: {label}")
        print(f"python release Bake mutation rejected [{label}] diagnostic={expected}")
    if only_label is None:
        require(selected == len(fixtures), "python release Bake fixture inventory mismatch")
        print(f"python release Bake mutation probes: {selected}/{len(fixtures)} rejected")
    else:
        require(selected == 1, f"unknown python release Bake fixture: {only_label}")


def check_python_release_bake_checker_mutation_self_test() -> None:
    source = read("tools/verify.py")
    checker_start = source.index("def python_release_bake_errors(")
    checker_end = source.index("\ndef _python_release_bake_fixtures(", checker_start)
    checker_source = source[checker_start:checker_end]
    guards = [
        ("python-release-bake-variable-set", "variable_set_invalid", "variable-set"),
        ("python-release-bake-target-set", "target_set_invalid", "target-set"),
        ("python-release-bake-ref-default", "release_ref_default_invalid", "release-ref-default"),
        ("python-release-bake-input-defaults", "release_input_defaults_invalid", "release-input-defaults"),
        ("python-release-bake-key-set", "release_key_set_invalid", "release-open-key-set"),
        ("python-release-bake-inheritance", "release_inheritance_invalid", "release-inheritance"),
        ("python-release-bake-args", "release_args_invalid", "release-args"),
        ("python-release-bake-tags", "release_tags_invalid", "release-tags"),
        ("python-release-bake-attest", "release_attest_invalid", "release-attest"),
        ("python-release-bake-output", "release_output_invalid", "release-output"),
    ]
    markers = re.findall(r"^    # CHECK: (python-release-bake-[a-z-]+)$", checker_source, re.MULTILINE)
    require(
        Counter(markers) == Counter(guard for guard, _, _ in guards) and len(markers) == len(guards),
        "python release Bake checker mutation list must cover every rejection guard exactly once",
    )
    for guard, condition, fixture in guards:
        anchor = f"reject({condition},"
        require(checker_source.count(anchor) == 1, f"python release Bake checker anchor changed: {guard}")
        mutated_checker = checker_source.replace(anchor, "reject(False,", 1)
        mutated = source[:checker_start] + mutated_checker + source[checker_end:]
        try:
            ast.parse(mutated, filename="tools/verify.py")
        except SyntaxError as exc:
            raise VerifyError(f"python release Bake checker mutation did not parse [{guard}]: {exc}") from exc
        result = _run_mutated_python_verifier(
            mutated,
            ["--check-python-release-bake-fixture", fixture],
        )
        expected = f"verify failed: python release Bake mutation unexpectedly passed: {fixture}"
        require(result.returncode == 1, f"python release Bake checker mutation {guard} returned {result.returncode}")
        require(
            result.stderr.strip() == expected,
            f"python release Bake checker mutation {guard} returned unexpected diagnostic: {result.stderr.strip()!r}",
        )
        location = source[: source.index(f"# CHECK: {guard}")].count("\n") + 1
        print(
            f"python release Bake checker mutation rejected [guard={guard} location=tools/verify.py:{location} "
            f"fixture={fixture} diagnostic={expected}]"
        )
    print(f"python release Bake checker mutation probes: {len(guards)}/{len(guards)} rejected")


def python_buildkit_version(contract: Mapping[str, Any]) -> str:
    reference = contract["variable"]["BUILDKIT_IMAGE"]["default"]
    match = PYTHON_BUILDKIT_REFERENCE.fullmatch(reference)
    if match is None:
        raise VerifyError("BuildKit version cannot be derived from the driver reference")
    return match.group("version")


def python_builder_workflow_error(contract: Mapping[str, Any], workflow: str) -> str | None:
    changes = _workflow_job_block(workflow, "changes")
    if not changes:
        return "python workflow is missing the changes job"
    outputs = {
        "buildx_version": "BUILDX_VERSION",
        "buildx_commit": "BUILDX_COMMIT",
        "buildx_asset_sha256": "BUILDX_ASSET_SHA256",
        "buildkit_image": "BUILDKIT_IMAGE",
        "buildkit_version": None,
    }
    for output in outputs:
        marker = f"      {output}: ${{{{ steps.build-inputs.outputs.{output} }}}}"
        if changes.count(marker) != 1:
            return f"python changes job must expose contract-derived output: {output}"
    if changes.count('json.loads(Path("images/python/docker-bake.json").read_text(encoding="utf-8"))') != 1:
        return "python changes job must parse the Bake contract exactly once"
    if 'variables = json.loads(Path("images/python/docker-bake.json")' not in changes:
        return "python changes job must read raw Bake variable defaults"

    pin_values = {
        "BUILDX_VERSION": contract["variable"]["BUILDX_VERSION"]["default"],
        "BUILDX_COMMIT": contract["variable"]["BUILDX_COMMIT"]["default"],
        "BUILDX_ASSET_SHA256": contract["variable"]["BUILDX_ASSET_SHA256"]["default"],
        "BUILDKIT_IMAGE": contract["variable"]["BUILDKIT_IMAGE"]["default"],
        "BUILDKIT_VERSION": python_buildkit_version(contract),
    }
    for job_name, build_step_name in (
        ("build", "Build the python image"),
        ("reproducibility", "Double-build byte-identical reproducibility gate"),
    ):
        job = _workflow_job_block(workflow, job_name)
        if not job:
            return f"python workflow is missing the {job_name} job"
        for name, value in pin_values.items():
            if value in job:
                return f"python builder job {job_name} hard-codes {name}"
        setup = _workflow_named_step(job, "Set up Docker Buildx")
        if not setup:
            return f"python builder job {job_name} must contain one Buildx setup step"
        for marker in (
            "        id: buildx",
            "          version: ${{ needs.changes.outputs.buildx_version }}",
            "          driver-opts: image=${{ needs.changes.outputs.buildkit_image }}",
        ):
            if marker not in setup:
                return f"python Buildx setup in {job_name} is not contract-derived: {marker.strip()}"
        identity = _workflow_named_step(job, "Assert python builder identity")
        if not identity:
            return f"python builder job {job_name} must contain one identity step"
        if re.search(r"^        continue-on-error\s*:", identity, re.MULTILINE) is not None:
            return f"python identity step in {job_name} must not set continue-on-error"
        step_configuration = [
            line
            for line in identity.splitlines()[1:]
            if line.startswith("        ") and not line.startswith("          ")
        ]
        if step_configuration != ["        env:", "        run: |"]:
            return f"python identity step in {job_name} must contain only env and run configuration"
        run_marker = "        run: |\n"
        if identity.count(run_marker) != 1:
            return f"python identity step in {job_name} must contain one multiline run body"
        run_lines = identity.split(run_marker, 1)[1].splitlines()
        while run_lines and not run_lines[-1].strip():
            run_lines.pop()
        if not run_lines or run_lines[0] != "          set -euo pipefail":
            return f"python identity step in {job_name} must start under set -euo pipefail"
        if any(re.search(r"\bset\s+\+", line.split("#", 1)[0]) is not None for line in run_lines[1:]):
            return f"python identity step in {job_name} must keep set -euo pipefail enabled"
        identity_assertion = "          python3 tools/verify.py --check-python-builder-identity"
        if run_lines[-1] != identity_assertion:
            return f"python identity assertion in {job_name} must be the final unwrapped command"
        identity_outputs = {
            "EXPECTED_BUILDX_VERSION": "buildx_version",
            "EXPECTED_BUILDX_COMMIT": "buildx_commit",
            "EXPECTED_BUILDX_ASSET_SHA256": "buildx_asset_sha256",
            "EXPECTED_BUILDKIT_IMAGE": "buildkit_image",
            "EXPECTED_BUILDKIT_VERSION": "buildkit_version",
        }
        for environment_name, output in identity_outputs.items():
            marker = f"          {environment_name}: ${{{{ needs.changes.outputs.{output} }}}}"
            if marker not in identity:
                return f"python identity step in {job_name} is not contract-derived: {environment_name}"
        for marker in (
            "${DOCKER_CONFIG:-${HOME}/.docker}/cli-plugins/docker-buildx",
            'sha256sum "${buildx_plugin}"',
            "docker buildx version",
            "docker inspect --format '{{.Config.Image}}'",
            "${{ steps.buildx.outputs.nodes }}",
            "python3 tools/verify.py --check-python-builder-identity",
        ):
            if marker not in identity:
                return f"python identity step in {job_name} is missing observation: {marker}"
        build_step = _workflow_named_step(job, build_step_name)
        if not build_step:
            return f"python builder job {job_name} is missing step: {build_step_name}"
        if not (job.index(setup) < job.index(identity) < job.index(build_step)):
            return f"python builder identity in {job_name} must run after setup and before the build"
    return None


def python_builder_identity_errors(expected: Mapping[str, str], observed: Mapping[str, str]) -> list[str]:
    version_output = observed.get("buildx_version_output", "")
    version_match = re.search(r"\b(v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b", version_output)
    commit_match = re.search(r"\b([0-9a-f]{40})\b", version_output)
    actual_version = version_match.group(1) if version_match is not None else "<unparseable>"
    actual_commit = commit_match.group(1) if commit_match is not None else "<unparseable>"

    try:
        nodes = json.loads(observed.get("buildx_nodes", ""))
    except json.JSONDecodeError:
        nodes = None
    if isinstance(nodes, list) and nodes and all(isinstance(node, dict) for node in nodes):
        node_versions = [node.get("buildkit") for node in nodes]
        if all(isinstance(version, str) for version in node_versions) and len(set(node_versions)) == 1:
            actual_buildkit_version = cast("str", node_versions[0])
        else:
            actual_buildkit_version = json.dumps(node_versions, sort_keys=True)
    else:
        actual_buildkit_version = "<unparseable>"

    comparisons = [
        ("Buildx version", expected.get("buildx_version", ""), actual_version),
        ("Buildx commit", expected.get("buildx_commit", ""), actual_commit),
        (
            "Buildx asset SHA-256",
            expected.get("buildx_asset_sha256", ""),
            observed.get("buildx_asset_sha256", ""),
        ),
        (
            "BuildKit driver Config.Image",
            expected.get("buildkit_image", ""),
            observed.get("buildkit_image", ""),
        ),
        ("BuildKit node version", expected.get("buildkit_version", ""), actual_buildkit_version),
    ]
    return [
        f"{name} mismatch: expected {wanted}, observed {actual}"
        for name, wanted, actual in comparisons
        if wanted != actual
    ]


def check_python_builder_identity_environment() -> int:
    expected = {
        "buildx_version": os.environ.get("EXPECTED_BUILDX_VERSION", ""),
        "buildx_commit": os.environ.get("EXPECTED_BUILDX_COMMIT", ""),
        "buildx_asset_sha256": os.environ.get("EXPECTED_BUILDX_ASSET_SHA256", ""),
        "buildkit_image": os.environ.get("EXPECTED_BUILDKIT_IMAGE", ""),
        "buildkit_version": os.environ.get("EXPECTED_BUILDKIT_VERSION", ""),
    }
    observed = {
        "buildx_version_output": os.environ.get("ACTUAL_BUILDX_VERSION_OUTPUT", ""),
        "buildx_asset_sha256": os.environ.get("ACTUAL_BUILDX_ASSET_SHA256", ""),
        "buildkit_image": os.environ.get("ACTUAL_BUILDKIT_IMAGE", ""),
        "buildx_nodes": os.environ.get("BUILDX_NODES", ""),
    }
    errors = python_builder_identity_errors(expected, observed)
    if errors:
        for error in errors:
            print(f"python builder identity failed: {error}", file=sys.stderr)
        return 1
    version_output = observed["buildx_version_output"]
    version = re.search(r"\b(v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b", version_output)
    commit = re.search(r"\b([0-9a-f]{40})\b", version_output)
    if version is None or commit is None:
        print("python builder identity failed: accepted output could not be parsed", file=sys.stderr)
        return 1
    nodes = json.loads(observed["buildx_nodes"])
    print(f"Buildx version identity: expected={expected['buildx_version']} observed={version.group(1)}")
    print(f"Buildx commit identity: expected={expected['buildx_commit']} observed={commit.group(1)}")
    print(
        "Buildx asset SHA-256 identity: "
        f"expected={expected['buildx_asset_sha256']} observed={observed['buildx_asset_sha256']}"
    )
    print(
        "BuildKit driver Config.Image identity: "
        f"expected={expected['buildkit_image']} observed={observed['buildkit_image']}"
    )
    print(
        "BuildKit node version identity: "
        f"expected={expected['buildkit_version']} observed={nodes[0]['buildkit']} nodes={len(nodes)}"
    )
    return 0


def python_pin_renovate_error(config: Any) -> str | None:
    if not isinstance(config, dict):
        return "Renovate config must be an object"
    description = config.get("description")
    if not isinstance(description, str) or "Python builder pins" not in description:
        return "Renovate description must mention Python builder pins"
    managers = config.get("customManagers")
    if not isinstance(managers, list):
        return "Renovate config must declare customManagers"

    buildx_description = (
        "Track the Python Buildx release version; the paired Linux-amd64 asset checksum requires independent "
        "verification."
    )
    buildx_manager = {
        "customType": "regex",
        "description": buildx_description,
        "managerFilePatterns": [r"/^images/python/docker-bake\.json$/"],
        "matchStrings": [
            r'(?<linePrefix>"BUILDX_VERSION": \{\n[ \t]+"default": ")'
            r'(?<currentValue>v[0-9]+\.[0-9]+\.[0-9]+)(?<lineSuffix>"\n[ \t]+\})'
        ],
        "datasourceTemplate": "github-releases",
        "packageNameTemplate": "docker/buildx",
        "versioningTemplate": "semver",
        "autoReplaceStringTemplate": "{{{linePrefix}}}{{{newValue}}}{{{lineSuffix}}}",
    }
    buildx_matches = [manager for manager in managers if manager.get("description") == buildx_description]
    if len(buildx_matches) != 1 or buildx_matches[0] != buildx_manager:
        return "Renovate config must keep one complete Python Buildx github-releases manager"

    buildkit_description = "Track the version-plus-digest Python BuildKit driver image reference."
    buildkit_manager = {
        "customType": "regex",
        "description": buildkit_description,
        "managerFilePatterns": [r"/^images/python/docker-bake\.json$/"],
        "matchStrings": [
            r'(?<linePrefix>"BUILDKIT_IMAGE": \{\n[ \t]+"default": ")'
            r"(?<depName>docker\.io/moby/buildkit):(?<currentValue>v[0-9]+\.[0-9]+\.[0-9]+)@"
            r'(?<currentDigest>sha256:[a-f0-9]{64})(?<lineSuffix>"\n[ \t]+\})'
        ],
        "datasourceTemplate": "docker",
        "packageNameTemplate": "{{{depName}}}",
        "versioningTemplate": "docker",
        "autoReplaceStringTemplate": "{{{linePrefix}}}{{{depName}}}:{{{newValue}}}@{{{newDigest}}}{{{lineSuffix}}}",
    }
    buildkit_matches = [manager for manager in managers if manager.get("description") == buildkit_description]
    if len(buildkit_matches) != 1 or buildkit_matches[0] != buildkit_manager:
        return "Renovate config must keep one complete Python BuildKit docker manager"

    rules = config.get("packageRules")
    if not isinstance(rules, list):
        return "Renovate config must declare packageRules"
    rule_contracts = {
        "Buildx": {
            "description": "Keep Python Buildx release updates gated for independent asset-checksum review.",
            "matchDatasources": ["github-releases"],
            "matchPackageNames": ["docker/buildx"],
            "semanticCommitType": "build",
            "semanticCommitScope": "python-buildx",
        },
        "BuildKit": {
            "description": "Keep Python BuildKit driver image updates gated for both-architecture byte review.",
            "matchDatasources": ["docker"],
            "matchPackageNames": ["docker.io/moby/buildkit"],
            "semanticCommitType": "build",
            "semanticCommitScope": "python-buildkit",
        },
    }
    for name, contract in rule_contracts.items():
        matching = [rule for rule in rules if rule.get("description") == contract["description"]]
        if len(matching) != 1:
            return f"Renovate config must keep one Python {name} matching rule"
        rule = matching[0]
        for key, value in contract.items():
            if rule.get(key) != value:
                return f"Python {name} Renovate rule mismatch: {key}"
        if rule.get("automerge") is not False:
            return f"Python {name} Renovate rule must set automerge: false"
        if set(rule) != {*contract, "automerge"}:
            return f"Python {name} Renovate rule key set mismatch"
    return None


def check_python_build_input_contract() -> None:
    try:
        contract = json.loads(read(PYTHON_BAKE_FILE))
    except json.JSONDecodeError as exc:
        raise VerifyError(f"{PYTHON_BAKE_FILE} is not valid JSON: {exc}") from exc
    contract_error = python_bake_contract_error(contract)
    require(contract_error is None, contract_error or "python Bake contract failed")
    release_errors = python_release_bake_errors(contract)
    require(not release_errors, "python release Bake contract failed: " + "; ".join(release_errors))
    workflow = read(".github/workflows/python-ci.yaml")
    workflow_error = python_builder_workflow_error(contract, workflow)
    require(workflow_error is None, workflow_error or "python builder workflow contract failed")
    require(f"!/{PYTHON_BAKE_FILE}" in read(".gitignore"), ".gitignore must allowlist the Python Bake contract")
    require(
        PYTHON_BAKE_FILE not in read("images/python/.dockerignore"),
        "python .dockerignore must keep the Bake control file out of the build context",
    )


def check_python_build_input_contract_self_test() -> None:
    contract = json.loads(read(PYTHON_BAKE_FILE))
    workflow = read(".github/workflows/python-ci.yaml")
    renovate = json.loads(read(".github/renovate.json"))

    require(python_bake_contract_error(contract) is None, "python Bake contract positive control failed")
    print("python build input positive control [a,b,d]: Bake contract accepted")
    require(
        python_builder_workflow_error(contract, workflow) is None,
        "python builder workflow positive control failed",
    )
    print("python build input positive control [c]: workflow pins and identity steps are contract-derived")

    identity_expected = {
        "buildx_version": "v1.2.3",
        "buildx_commit": "b" * 40,
        "buildx_asset_sha256": "sha256:" + "c" * 64,
        "buildkit_image": "docker.io/moby/buildkit:v4.5.6@sha256:" + "d" * 64,
        "buildkit_version": "v4.5.6",
    }
    identity_observed = {
        "buildx_version_output": f"github.com/docker/buildx v1.2.3 {'b' * 40}",
        "buildx_asset_sha256": "sha256:" + "c" * 64,
        "buildkit_image": "docker.io/moby/buildkit:v4.5.6@sha256:" + "d" * 64,
        "buildx_nodes": json.dumps([{"buildkit": "v4.5.6"}]),
    }
    require(
        not python_builder_identity_errors(identity_expected, identity_observed),
        "python builder identity positive control failed",
    )
    print("python build input positive control [f]: all five identity observations accepted")
    require(python_pin_renovate_error(renovate) is None, "python pin Renovate positive control failed")
    print("python build input positive control [g]: both managers and non-automerge rules accepted")

    harness_positive = subprocess.run(
        [sys.executable, str(ROOT / "images/python/tools/assert-reproducible.py"), "--self-test"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    require(harness_positive.returncode == 0, "python harness CLI positive control failed")
    print("python build input positive control [h]: default self-test invocation accepted")

    rejected = 0

    def reject(label: str, changed: bool, actual: str | None, expected: str) -> None:
        nonlocal rejected
        require(changed, f"python build input mutation is a no-op: {label}")
        require(actual == expected, f"python build input mutation {label} returned unexpected diagnostic: {actual!r}")
        rejected += 1
        print(f"python build input mutation rejected [{label}] changed=true reason={actual}")

    def reject_bake_path(
        label: str,
        path: tuple[str, ...],
        replacement: Any,
        expected: str,
        *,
        delete: bool = False,
    ) -> None:
        mutated = copy.deepcopy(contract)
        parent = mutated
        for component in path[:-1]:
            parent = parent[component]
        if delete:
            del parent[path[-1]]
        else:
            parent[path[-1]] = replacement
        reject(label, mutated != contract, python_bake_contract_error(mutated), expected)

    def mutate_named_workflow_step(
        source: str,
        job_name: str,
        step_name: str,
        old: str,
        new: str,
    ) -> str:
        job = _workflow_job_block(source, job_name)
        step = _workflow_named_step(job, step_name)
        mutated_step = step.replace(old, new, 1)
        return source.replace(step, mutated_step, 1)

    non_object_contract: Any = []
    reject(
        "a/contract-object",
        non_object_contract != contract,
        python_bake_contract_error(non_object_contract),
        "python Bake contract must be a JSON object",
    )
    reject_bake_path(
        "a/top-level-key-set",
        ("unexpected",),
        {},
        "python Bake contract top-level keys must be exactly variable and target",
    )
    reject_bake_path(
        "a/variable-key-set",
        ("variable", "REPRO_DEST"),
        None,
        "python Bake variable key set mismatch",
        delete=True,
    )
    reject_bake_path(
        "a/variable-entry-shape",
        ("variable", "BUILDX_VERSION", "unexpected"),
        True,
        "python Bake variable BUILDX_VERSION must contain only a formal default",
    )
    reject_bake_path(
        "a/buildx-version-shape",
        ("variable", "BUILDX_VERSION", "default"),
        "latest",
        "Buildx version variable is not a semantic version",
    )
    reject_bake_path(
        "a/buildx-commit-shape",
        ("variable", "BUILDX_COMMIT", "default"),
        "deadbeef",
        "Buildx commit variable is not a 40-character commit",
    )
    reject_bake_path(
        "a/buildx-asset-shape",
        ("variable", "BUILDX_ASSET_SHA256", "default"),
        "f" * 64,
        "Buildx Linux-amd64 asset SHA-256 variable is not digest-shaped",
    )
    reject_bake_path(
        "a/repro-destination",
        ("variable", "REPRO_DEST", "default"),
        "",
        "repro destination variable must have a non-empty default",
    )
    reject_bake_path(
        "a/release-destination-sentinel",
        ("variable", "RELEASE_REF", "default"),
        "localhost:5000/example/candidate",
        "release destination variable must have the invalid sentinel default",
    )
    reject_bake_path(
        "a/protected-oci-input-null",
        ("variable", "OCI_REVISION", "default"),
        "override",
        "python Bake variable OCI_REVISION must be nullable",
    )
    reject_bake_path(
        "a/nullable-parent-input",
        ("variable", "UBI_MINIMAL_IMAGE", "default"),
        "override",
        "python Bake variable UBI_MINIMAL_IMAGE must be nullable",
    )
    reject_bake_path(
        "d/base-key-set",
        ("target", "base", "unexpected"),
        True,
        "python Bake base target key set mismatch",
    )
    reject_bake_path(
        "d/base-context",
        ("target", "base", "context"),
        ".",
        "python Bake base context mismatch",
    )
    reject_bake_path(
        "d/base-dockerfile",
        ("target", "base", "dockerfile"),
        "Containerfile",
        "python Bake base dockerfile mismatch",
    )
    reject_bake_path(
        "d/base-build-target",
        ("target", "base", "target"),
        "build",
        "python Bake base build target mismatch",
    )
    reject_bake_path(
        "d/base-platforms",
        ("target", "base", "platforms"),
        ["linux/amd64"],
        "python Bake base platforms mismatch",
    )
    reject_bake_path(
        "d/base-fixed-args",
        ("target", "base", "args", "SOURCE_DATE_EPOCH"),
        "1704067201",
        "python Bake base fixed build args mismatch",
    )
    reject_bake_path(
        "d/non-base-object",
        ("target", "ci"),
        [],
        "python Bake target ci must be an object",
    )
    reject_bake_path(
        "d/protected-arg",
        ("target", "ci", "args"),
        {"SOURCE_DATE_EPOCH": "1704067200"},
        "python Bake target ci must not redeclare protected field: SOURCE_DATE_EPOCH",
    )
    reject_bake_path(
        "d/base-only-inheritance",
        ("target", "ci", "inherits"),
        ["base", "other"],
        "python Bake target ci must inherit only base",
    )
    reject_bake_path(
        "d/ci-key-set",
        ("target", "ci", "tags"),
        ["local/test"],
        "python Bake ci target key set mismatch",
    )
    reject_bake_path(
        "d/ci-output",
        ("target", "ci", "output"),
        ["type=oci"],
        "python Bake ci output policy mismatch: expected type=docker",
    )
    reject_bake_path(
        "d/release-inheritance",
        ("target", "release", "inherits"),
        ["base", "ci"],
        "python Bake target release must inherit only base",
    )
    release_open_fields = copy.deepcopy(contract["target"]["release"])
    release_open_fields.update(
        {
            "network": "host",
            "entitlements": ["network.host"],
            "secret": ["id=token,src=token"],
            "ssh": ["default"],
        }
    )
    reject_bake_path(
        "d/release-key-set-open-fields",
        ("target", "release"),
        release_open_fields,
        "python Bake release target key set mismatch",
    )
    release_cache_export = copy.deepcopy(contract["target"]["release"])
    release_cache_export["cache-to"] = ["type=registry,ref=example.invalid/cache"]
    reject_bake_path(
        "d/release-cache-export",
        ("target", "release"),
        release_cache_export,
        "python Bake release target key set mismatch",
    )
    reject_bake_path(
        "d/release-tags",
        ("target", "release", "tags"),
        ["ghcr.io/example/release:latest"],
        "python Bake release tags must resolve only from RELEASE_REF",
    )
    reject_bake_path(
        "d/release-attest",
        ("target", "release", "attest"),
        ["type=provenance,mode=min", "type=sbom,disabled=true"],
        "python Bake release attestation policy mismatch",
    )
    reject_bake_path(
        "d/release-output",
        ("target", "release", "output"),
        ["type=registry,rewrite-timestamp=false"],
        "python Bake release output policy mismatch",
    )
    reject_bake_path(
        "d/repro-key-set",
        ("target", "repro", "tags"),
        ["local/test"],
        "python Bake repro target key set mismatch",
    )
    reject_bake_path(
        "d/repro-args",
        ("target", "repro", "args", "OCI_VERSION"),
        "release",
        "python Bake repro build args mismatch",
    )
    reject_bake_path(
        "d/repro-no-cache",
        ("target", "repro", "no-cache"),
        False,
        "python Bake repro cache policy mismatch: no-cache must be true",
    )
    reject_bake_path(
        "d/repro-attest",
        ("target", "repro", "attest"),
        ["type=provenance,disabled=false", "type=sbom,disabled=true"],
        "python Bake repro attestation policy mismatch",
    )
    reject_bake_path(
        "b/repro-output",
        ("target", "repro", "output"),
        ["type=oci"],
        "python Bake repro output policy mismatch",
    )

    invalid_buildkit_version = copy.deepcopy(contract)
    invalid_buildkit_version["variable"]["BUILDKIT_IMAGE"]["default"] = "not-a-buildkit-reference"
    buildkit_version_reason: str | None = None
    try:
        python_buildkit_version(invalid_buildkit_version)
    except VerifyError as exc:
        buildkit_version_reason = str(exc)
    reject(
        "a/buildkit-version-derivation",
        invalid_buildkit_version != contract,
        buildkit_version_reason,
        "BuildKit version cannot be derived from the driver reference",
    )

    unpinned = copy.deepcopy(contract)
    original_buildkit = unpinned["variable"]["BUILDKIT_IMAGE"]["default"]
    unpinned["variable"]["BUILDKIT_IMAGE"]["default"] = original_buildkit.split("@", 1)[0]
    reject(
        "a/buildkit-digest",
        unpinned != contract,
        python_bake_contract_error(unpinned),
        "BuildKit driver image is not digest-pinned",
    )

    timestamp = copy.deepcopy(contract)
    timestamp["target"]["repro"]["output"][0] = timestamp["target"]["repro"]["output"][0].replace(
        "rewrite-timestamp=true", "rewrite-timestamp=false"
    )
    reject(
        "b/rewrite-timestamp",
        timestamp != contract,
        python_bake_contract_error(timestamp),
        "python Bake repro output policy mismatch: rewrite-timestamp must be true",
    )

    literal_workflow = workflow.replace(
        "          version: ${{ needs.changes.outputs.buildx_version }}",
        "          version: v0.35.0",
        1,
    )
    reject(
        "c/hard-coded-builder-pin",
        literal_workflow != workflow,
        python_builder_workflow_error(contract, literal_workflow),
        "python builder job build hard-codes BUILDX_VERSION",
    )

    missing_changes_job = workflow.replace("  changes:\n", "  changes-missing:\n", 1)
    reject(
        "c/missing-changes-job",
        missing_changes_job != workflow,
        python_builder_workflow_error(contract, missing_changes_job),
        "python workflow is missing the changes job",
    )

    missing_changes_output = workflow.replace(
        "      buildx_commit: ${{ steps.build-inputs.outputs.buildx_commit }}",
        "      buildx_commit_missing: ${{ steps.build-inputs.outputs.buildx_commit }}",
        1,
    )
    reject(
        "c/changes-output",
        missing_changes_output != workflow,
        python_builder_workflow_error(contract, missing_changes_output),
        "python changes job must expose contract-derived output: buildx_commit",
    )

    duplicate_contract_parse = workflow.replace(
        'json.loads(Path("images/python/docker-bake.json").read_text(encoding="utf-8"))',
        'json.loads(Path("images/python/docker-bake.json").read_text())',
        1,
    )
    reject(
        "c/contract-parse-count",
        duplicate_contract_parse != workflow,
        python_builder_workflow_error(contract, duplicate_contract_parse),
        "python changes job must parse the Bake contract exactly once",
    )

    indirect_variable_defaults = workflow.replace(
        'variables = json.loads(Path("images/python/docker-bake.json")',
        'parsed = json.loads(Path("images/python/docker-bake.json")',
        1,
    )
    reject(
        "c/raw-variable-defaults",
        indirect_variable_defaults != workflow,
        python_builder_workflow_error(contract, indirect_variable_defaults),
        "python changes job must read raw Bake variable defaults",
    )

    missing_builder_job = workflow.replace("  reproducibility:\n", "  reproducibility-missing:\n", 1)
    reject(
        "c/missing-builder-job",
        missing_builder_job != workflow,
        python_builder_workflow_error(contract, missing_builder_job),
        "python workflow is missing the reproducibility job",
    )

    missing_setup = mutate_named_workflow_step(
        workflow,
        "build",
        "Set up Docker Buildx",
        "      - name: Set up Docker Buildx\n",
        "      - name: Set up Docker Buildx missing\n",
    )
    reject(
        "c/buildx-setup-step",
        missing_setup != workflow,
        python_builder_workflow_error(contract, missing_setup),
        "python builder job build must contain one Buildx setup step",
    )

    duplicate_setup = workflow.replace(
        "      - name: Set up Docker Buildx\n",
        "      - name: Set up Docker Buildx\n      - name: Set up Docker Buildx\n",
        1,
    )
    reject(
        "c/buildx-setup-step-count",
        duplicate_setup != workflow,
        python_builder_workflow_error(contract, duplicate_setup),
        "python builder job build must contain one Buildx setup step",
    )

    setup_without_id = mutate_named_workflow_step(
        workflow,
        "build",
        "Set up Docker Buildx",
        "        id: buildx",
        "        id: missing",
    )
    reject(
        "c/buildx-setup-input",
        setup_without_id != workflow,
        python_builder_workflow_error(contract, setup_without_id),
        "python Buildx setup in build is not contract-derived: id: buildx",
    )

    missing_identity = mutate_named_workflow_step(
        workflow,
        "build",
        "Assert python builder identity",
        "      - name: Assert python builder identity\n",
        "      - name: Assert python builder identity missing\n",
    )
    reject(
        "c/identity-step",
        missing_identity != workflow,
        python_builder_workflow_error(contract, missing_identity),
        "python builder job build must contain one identity step",
    )

    identity_continue_on_error = mutate_named_workflow_step(
        workflow,
        "build",
        "Assert python builder identity",
        "      - name: Assert python builder identity\n",
        "      - name: Assert python builder identity\n        continue-on-error: true\n",
    )
    reject(
        "c/identity-continue-on-error",
        identity_continue_on_error != workflow,
        python_builder_workflow_error(contract, identity_continue_on_error),
        "python identity step in build must not set continue-on-error",
    )

    identity_extra_configuration = mutate_named_workflow_step(
        workflow,
        "build",
        "Assert python builder identity",
        "      - name: Assert python builder identity\n",
        "      - name: Assert python builder identity\n        timeout-minutes: 5\n",
    )
    reject(
        "c/identity-step-configuration",
        identity_extra_configuration != workflow,
        python_builder_workflow_error(contract, identity_extra_configuration),
        "python identity step in build must contain only env and run configuration",
    )

    identity_duplicate_run = mutate_named_workflow_step(
        workflow,
        "build",
        "Assert python builder identity",
        "        env:\n",
        "        env:\n          run: |\n",
    )
    reject(
        "c/identity-run-body-count",
        identity_duplicate_run != workflow,
        python_builder_workflow_error(contract, identity_duplicate_run),
        "python identity step in build must contain one multiline run body",
    )

    identity_without_strict_start = mutate_named_workflow_step(
        workflow,
        "build",
        "Assert python builder identity",
        "          set -euo pipefail",
        "          set -eu",
    )
    reject(
        "c/identity-strict-start",
        identity_without_strict_start != workflow,
        python_builder_workflow_error(contract, identity_without_strict_start),
        "python identity step in build must start under set -euo pipefail",
    )

    identity_disables_strict_mode = mutate_named_workflow_step(
        workflow,
        "build",
        "Assert python builder identity",
        "          set -euo pipefail\n",
        "          set -euo pipefail\n          set +e\n",
    )
    reject(
        "c/identity-strict-mode-disabled",
        identity_disables_strict_mode != workflow,
        python_builder_workflow_error(contract, identity_disables_strict_mode),
        "python identity step in build must keep set -euo pipefail enabled",
    )

    identity_wrapped_assertion = mutate_named_workflow_step(
        workflow,
        "build",
        "Assert python builder identity",
        "          python3 tools/verify.py --check-python-builder-identity\n",
        "          python3 tools/verify.py --check-python-builder-identity\n          echo wrapped\n",
    )
    reject(
        "c/identity-final-command",
        identity_wrapped_assertion != workflow,
        python_builder_workflow_error(contract, identity_wrapped_assertion),
        "python identity assertion in build must be the final unwrapped command",
    )

    identity_without_output = mutate_named_workflow_step(
        workflow,
        "build",
        "Assert python builder identity",
        "          EXPECTED_BUILDX_COMMIT: ${{ needs.changes.outputs.buildx_commit }}",
        "          EXPECTED_BUILDX_COMMIT: missing",
    )
    reject(
        "c/identity-output",
        identity_without_output != workflow,
        python_builder_workflow_error(contract, identity_without_output),
        "python identity step in build is not contract-derived: EXPECTED_BUILDX_COMMIT",
    )

    identity_without_observation = mutate_named_workflow_step(
        workflow,
        "build",
        "Assert python builder identity",
        "docker buildx version",
        "docker buildx-version",
    )
    reject(
        "c/identity-observation",
        identity_without_observation != workflow,
        python_builder_workflow_error(contract, identity_without_observation),
        "python identity step in build is missing observation: docker buildx version",
    )

    missing_build_step = mutate_named_workflow_step(
        workflow,
        "build",
        "Build the python image",
        "      - name: Build the python image\n",
        "      - name: Build the python image missing\n",
    )
    reject(
        "c/build-step",
        missing_build_step != workflow,
        python_builder_workflow_error(contract, missing_build_step),
        "python builder job build is missing step: Build the python image",
    )

    build_job = _workflow_job_block(workflow, "build")
    setup_step = _workflow_named_step(build_job, "Set up Docker Buildx")
    identity_step = _workflow_named_step(build_job, "Assert python builder identity")
    out_of_order_job = build_job.replace(setup_step + identity_step, identity_step + setup_step, 1)
    out_of_order_workflow = workflow.replace(build_job, out_of_order_job, 1)
    reject(
        "c/identity-order",
        out_of_order_workflow != workflow,
        python_builder_workflow_error(contract, out_of_order_workflow),
        "python builder identity in build must run after setup and before the build",
    )

    protected = copy.deepcopy(contract)
    protected["target"]["ci"]["context"] = "images/python"
    reject(
        "d/protected-context",
        protected != contract,
        python_bake_contract_error(protected),
        "python Bake target ci must not redeclare protected field: context",
    )

    target_key_set = copy.deepcopy(contract)
    target_key_set["target"]["fork"] = {"inherits": ["base"]}
    reject(
        "d/target-key-set",
        target_key_set != contract,
        python_bake_contract_error(target_key_set),
        "python Bake target key set must be exactly base, ci, release, and repro",
    )

    identity_mutations = [
        (
            "f/buildx-version",
            "buildx_version_output",
            f"github.com/docker/buildx v1.2.4 {'b' * 40}",
            "Buildx version mismatch: expected v1.2.3, observed v1.2.4",
        ),
        (
            "f/buildx-commit",
            "buildx_version_output",
            f"github.com/docker/buildx v1.2.3 {'e' * 40}",
            f"Buildx commit mismatch: expected {'b' * 40}, observed {'e' * 40}",
        ),
        (
            "f/buildx-asset-sha256",
            "buildx_asset_sha256",
            "sha256:" + "f" * 64,
            f"Buildx asset SHA-256 mismatch: expected sha256:{'c' * 64}, observed sha256:{'f' * 64}",
        ),
        (
            "f/buildkit-config-image",
            "buildkit_image",
            "docker.io/moby/buildkit:v4.5.6@sha256:" + "a" * 64,
            "BuildKit driver Config.Image mismatch: expected docker.io/moby/buildkit:v4.5.6@sha256:"
            + "d" * 64
            + ", observed docker.io/moby/buildkit:v4.5.6@sha256:"
            + "a" * 64,
        ),
        (
            "f/buildkit-node-version",
            "buildx_nodes",
            json.dumps([{"buildkit": "v4.5.7"}]),
            "BuildKit node version mismatch: expected v4.5.6, observed v4.5.7",
        ),
    ]
    for label, key, value, expected_error in identity_mutations:
        mutated = dict(identity_observed)
        mutated[key] = value
        errors = python_builder_identity_errors(identity_expected, mutated)
        reject(label, mutated != identity_observed, errors[0] if len(errors) == 1 else repr(errors), expected_error)

    manager_mutations: list[tuple[str, Any, str]] = []
    without_buildx_manager = copy.deepcopy(renovate)
    without_buildx_manager["customManagers"] = [
        manager
        for manager in without_buildx_manager["customManagers"]
        if not str(manager.get("description", "")).startswith("Track the Python Buildx release version")
    ]
    manager_mutations.append(
        (
            "g/buildx-manager",
            without_buildx_manager,
            "Renovate config must keep one complete Python Buildx github-releases manager",
        )
    )
    buildx_automerge = copy.deepcopy(renovate)
    next(rule for rule in buildx_automerge["packageRules"] if rule.get("matchPackageNames") == ["docker/buildx"])[
        "automerge"
    ] = True
    manager_mutations.append(
        ("g/buildx-automerge", buildx_automerge, "Python Buildx Renovate rule must set automerge: false")
    )
    without_buildkit_manager = copy.deepcopy(renovate)
    without_buildkit_manager["customManagers"] = [
        manager
        for manager in without_buildkit_manager["customManagers"]
        if not str(manager.get("description", "")).startswith("Track the version-plus-digest Python BuildKit")
    ]
    manager_mutations.append(
        (
            "g/buildkit-manager",
            without_buildkit_manager,
            "Renovate config must keep one complete Python BuildKit docker manager",
        )
    )
    buildkit_automerge = copy.deepcopy(renovate)
    next(
        rule
        for rule in buildkit_automerge["packageRules"]
        if rule.get("matchPackageNames") == ["docker.io/moby/buildkit"]
    )["automerge"] = True
    manager_mutations.append(
        ("g/buildkit-automerge", buildkit_automerge, "Python BuildKit Renovate rule must set automerge: false")
    )
    for label, mutated, expected_error in manager_mutations:
        reject(label, mutated != renovate, python_pin_renovate_error(mutated), expected_error)

    harness_negative = subprocess.run(
        [
            sys.executable,
            str(ROOT / "images/python/tools/assert-reproducible.py"),
            "--self-test",
            "--source-date-epoch",
            "1704067201",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    harness_reason = harness_negative.stderr.strip().splitlines()[-1] if harness_negative.stderr.strip() else ""
    reject(
        "h/harness-cli-resolution",
        harness_negative.returncode != harness_positive.returncode,
        harness_reason,
        "assert-reproducible.py: error: unrecognized arguments: --source-date-epoch 1704067201",
    )
    require(rejected == 68, f"python build input mutation inventory mismatch: expected 68, got {rejected}")
    print("python build input mutation probes: 7 classes, 68/68 rejected")


def check_renovate_config() -> None:
    relative_path = ".github/renovate.json"
    path = ROOT / relative_path
    try:
        config = json.loads(read(relative_path))
    except json.JSONDecodeError as exc:
        raise VerifyError(f"{relative_path} is not valid JSON: {exc}") from exc

    require(
        config.get("extends") == ["github>NWarila/.github"],
        "Renovate config must extend only the shared UBI9 platform preset",
    )
    text = path.read_text(encoding="utf-8")
    require("local>NWarila/.github" not in text, "Renovate config must use the GitHub-hosted preset form")

    for inherited_key in ["enabledManagers", "prConcurrentLimit", "prHourlyLimit", "branchConcurrentLimit"]:
        require(inherited_key not in config, f"Renovate config must inherit org default for {inherited_key}")

    ignore_paths = config.get("ignorePaths")
    require(isinstance(ignore_paths, list), "Renovate config must declare ignorePaths")
    require("rpm-lock/**" in ignore_paths, "Renovate config must ignore rpm-lock files")

    forbidden_literals = ["SOURCE_DATE_EPOCH", "SSG_VERSION", "SSG_TARBALL_SHA512", "rpm-lock/runtime."]
    present = [literal for literal in forbidden_literals if literal in text]
    require(not present, "Renovate config must not manage non-Renovate inputs: " + ", ".join(present))

    custom_managers = config.get("customManagers")
    require(isinstance(custom_managers, list), "Renovate config must declare customManagers")
    ubi_managers = [
        manager
        for manager in custom_managers
        if manager.get("datasourceTemplate") == "docker"
        and manager.get("packageNameTemplate") == "{{{depName}}}"
        and manager.get("currentValueTemplate") == "latest"
        and manager.get("versioningTemplate") == "redhat"
        and manager.get("autoReplaceStringTemplate") == "{{{depName}}}@{{{newDigest}}}"
        and any("github/workflows" in pattern for pattern in manager.get("managerFilePatterns", []))
        and any("registry\\.access\\.redhat\\.com/ubi9/ubi-" in pattern for pattern in manager.get("matchStrings", []))
        and any("currentDigest" in pattern for pattern in manager.get("matchStrings", []))
    ]
    require(ubi_managers, "Renovate config must target workflow UBI image digests with docker datasource")

    binfmt_manager_contract = {
        "managerFilePatterns": [
            r"/^\.github/workflows/(?:build|nightly|publish-image|python-ci|rpm-lock-refresh)\.yaml$/"
        ],
        "matchStrings": [
            (
                r"(?<linePrefix>^|\n[ \t]+)image: docker\.io/tonistiigi/binfmt@"
                r"(?<currentDigest>sha256:[a-f0-9]{64})[ \t]*(?:\n|$)"
            )
        ],
        "autoReplaceStringTemplate": ("{{{linePrefix}}}image: docker.io/tonistiigi/binfmt@{{{newDigest}}}\n"),
    }
    binfmt_managers = [
        manager
        for manager in custom_managers
        if manager.get("customType") == "regex"
        and manager.get("managerFilePatterns") == binfmt_manager_contract["managerFilePatterns"]
        and manager.get("matchStrings") == binfmt_manager_contract["matchStrings"]
        and manager.get("datasourceTemplate") == "docker"
        and manager.get("packageNameTemplate") == BINFMT_IMAGE
        and manager.get("currentValueTemplate") == "latest"
        and manager.get("versioningTemplate") == "docker"
        and manager.get("autoReplaceStringTemplate") == binfmt_manager_contract["autoReplaceStringTemplate"]
    ]
    require(
        len(binfmt_managers) == 1,
        "Renovate config must keep one complete workflow-scoped QEMU/binfmt docker digest manager",
    )

    shell_manager_contracts = {
        "minimal": {
            "managerFilePatterns": [r"/^tools/build\.sh$/"],
            "matchStrings": [
                (
                    r'(?<indentation>^|\n)ubi_minimal_image="\$\{UBI_MINIMAL_IMAGE:-'
                    r"(?<depName>registry\.access\.redhat\.com/ubi9/ubi-minimal)@"
                    r'(?<currentDigest>sha256:[a-f0-9]{64})\}"(?:\n|$)'
                )
            ],
            "autoReplaceStringTemplate": (
                '{{{indentation}}}ubi_minimal_image="${UBI_MINIMAL_IMAGE:-{{{depName}}}@'
                '{{{newDigest}}}{{! shell-parameter close}}}"\n'
            ),
        },
        "micro": {
            "managerFilePatterns": [r"/^tools/(?:build|run-test-gates)\.sh$/"],
            "matchStrings": [
                (
                    r'(?<indentation>^|\n)ubi_micro_image="\$\{UBI_MICRO_IMAGE:-'
                    r"(?<depName>registry\.access\.redhat\.com/ubi9/ubi-micro)@"
                    r'(?<currentDigest>sha256:[a-f0-9]{64})\}"(?:\n|$)'
                )
            ],
            "autoReplaceStringTemplate": (
                '{{{indentation}}}ubi_micro_image="${UBI_MICRO_IMAGE:-{{{depName}}}@'
                '{{{newDigest}}}{{! shell-parameter close}}}"\n'
            ),
        },
    }
    for image, contract in shell_manager_contracts.items():
        matching_managers = [
            manager
            for manager in custom_managers
            if manager.get("customType") == "regex"
            and manager.get("managerFilePatterns") == contract["managerFilePatterns"]
            and manager.get("matchStrings") == contract["matchStrings"]
            and manager.get("datasourceTemplate") == "docker"
            and manager.get("packageNameTemplate") == "{{{depName}}}"
            and manager.get("currentValueTemplate") == "latest"
            and manager.get("versioningTemplate") == "redhat"
            and manager.get("autoReplaceStringTemplate") == contract["autoReplaceStringTemplate"]
        ]
        require(
            len(matching_managers) == 1,
            f"Renovate config must keep one complete assignment-scoped tools manager for ubi-{image}",
        )

    package_rules = config.get("packageRules")
    require(isinstance(package_rules, list), "Renovate config must declare packageRules")

    action_pin_rule_index = None
    generator_rule_index = None
    ubi_rule_found = False
    binfmt_rule_found = False
    for index, rule in enumerate(package_rules):
        if (
            "github-actions" in rule.get("matchManagers", [])
            and rule.get("pinDigests") is True
            and "!/^slsa-framework\\/slsa-github-generator(?:\\/|$)/" in rule.get("matchPackageNames", [])
        ):
            action_pin_rule_index = index
        if (
            "github-actions" in rule.get("matchManagers", [])
            and rule.get("pinDigests") is False
            and rule.get("enabled") is False
            and "/^slsa-framework\\/slsa-github-generator(?:\\/|$)/" in rule.get("matchPackageNames", [])
        ):
            generator_rule_index = index
        if (
            "docker" in rule.get("matchDatasources", [])
            and set(rule.get("matchPackageNames", []))
            == {
                "registry.access.redhat.com/ubi9/ubi-minimal",
                "registry.access.redhat.com/ubi9/ubi-micro",
            }
            and rule.get("groupName") == "red hat ubi9 base image digests"
        ):
            ubi_rule_found = True
        if (
            rule.get("matchDatasources") == ["docker"]
            and rule.get("matchPackageNames") == [BINFMT_IMAGE]
            and rule.get("groupName") == "qemu binfmt emulator image digest"
            and rule.get("labels") == ["dependencies"]
            and rule.get("versioning") == "docker"
            and rule.get("semanticCommitType") == "build"
            and rule.get("semanticCommitScope") == "deps"
        ):
            binfmt_rule_found = True

    if action_pin_rule_index is None:
        raise VerifyError("Renovate config must keep ordinary GitHub Actions SHA-pinned")
    if generator_rule_index is None:
        raise VerifyError("Renovate config must carry the TD-1 SLSA generator tag-pin rule")
    require(
        generator_rule_index > action_pin_rule_index,
        "TD-1 generator rule must follow the general GitHub Actions pin rule so it overrides it",
    )
    require(ubi_rule_found, "Renovate config must group UBI minimal and micro digest refreshes")
    require(binfmt_rule_found, "Renovate config must group and label QEMU/binfmt digest refreshes")
    python_pin_error = python_pin_renovate_error(config)
    require(python_pin_error is None, python_pin_error or "Python pin Renovate contract failed")


def collect_dockerfile_forbidden_sources(root: Path = ROOT) -> list[tuple[str, str]]:
    paths = [
        root / "containers/Dockerfile",
        root / "tools/build-runtime-rootfs.py",
        root / "tools/write-fips-status.py",
        root / "tools/verify-fips-provider.py",
    ]
    scripts_dir = root / "containers/scripts"
    if scripts_dir.is_dir():
        paths.extend(sorted(scripts_dir.glob("*.sh")))

    sources: list[tuple[str, str]] = []
    for path in paths:
        relative_path = str(path.relative_to(root))
        require(path.is_file(), f"missing required forbidden-scan source: {relative_path}")
        sources.append((relative_path, path.read_text(encoding="utf-8")))
    return sources


def find_dockerfile_forbidden_markers(sources: list[tuple[str, str]]) -> list[str]:
    findings: list[str] = []
    for source, text in sources:
        findings.extend(f"{source}: {marker}" for marker in DOCKERFILE_FORBIDDEN_MARKERS if marker in text)
    return findings


def check_dockerfile_forbidden_scan_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        dockerfile = tmp_path / "containers/Dockerfile"
        script = tmp_path / "containers/scripts/strip.sh"
        helper = tmp_path / "tools/build-runtime-rootfs.py"
        writer = tmp_path / "tools/write-fips-status.py"
        verifier = tmp_path / "tools/verify-fips-provider.py"
        script.parent.mkdir(parents=True)
        helper.parent.mkdir(parents=True)
        dockerfile.parent.mkdir(parents=True, exist_ok=True)
        dockerfile.write_text("FROM scratch\n", encoding="utf-8")
        script.write_text("rm -rf /rootfs/var/lib/rpm\n", encoding="utf-8")
        helper.write_text("rm -rf /rootfs/var/lib/rpm\n", encoding="utf-8")
        writer.write_text("rm -rf /rootfs/var/lib/rpm\n", encoding="utf-8")
        verifier.write_text("rm -rf /rootfs/var/lib/rpm\n", encoding="utf-8")
        findings = find_dockerfile_forbidden_markers(collect_dockerfile_forbidden_sources(tmp_path))
    require(
        findings
        == [
            "tools/build-runtime-rootfs.py: rm -rf /rootfs/var/lib/rpm",
            "tools/write-fips-status.py: rm -rf /rootfs/var/lib/rpm",
            "tools/verify-fips-provider.py: rm -rf /rootfs/var/lib/rpm",
            "containers/scripts/strip.sh: rm -rf /rootfs/var/lib/rpm",
        ],
        "forbidden marker scan must cover rootfs-writing helpers and shell-script fixtures",
    )


def check_builder_toolchain_floor_self_test() -> None:
    baseline = "\n".join(
        [
            "rpm|rpm-0:1-1.x86_64",
            "rpm-libs|rpm-libs-0:1-1.x86_64",
            "sqlite-libs|sqlite-libs-0:1-1.x86_64",
            "glibc|glibc-0:1-1.x86_64",
            "glibc-common|glibc-common-0:1-1.x86_64",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        before = tmp_path / "before"
        after = tmp_path / "after"
        before.write_text(f"{baseline}\n", encoding="utf-8")
        after.write_text(f"{baseline}\n", encoding="utf-8")
        command = [
            "bash",
            str(ROOT / "tools/assert-builder-toolchain-floor.sh"),
            "--before",
            str(before),
            "--after",
            str(after),
        ]
        passing = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        require(passing.returncode == 0, f"builder toolchain floor positive test failed: {passing.stderr}")

        after.write_text(f"{baseline.replace('sqlite-libs-0:1-1', 'sqlite-libs-0:2-1')}\n", encoding="utf-8")
        failing = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        require(failing.returncode != 0, "builder toolchain floor mutation must fail")
        require(
            "builder toolchain package sqlite-libs moved" in failing.stderr,
            "builder toolchain floor mutation must name sqlite-libs",
        )


def rpm_lock_generator_errors(text: str) -> list[str]:
    """Return generator contract violations for source text, enabling real mutation probes."""

    errors: list[str] = []

    def expect(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    if "write_capture_dockerfile() {" not in text or "\nvalidate_runtime_lockfile()" not in text:
        return ["RPM lock generator capture function boundaries are missing"]
    capture = text.split("write_capture_dockerfile() {", 1)[1].split("\nvalidate_runtime_lockfile()", 1)[0]
    if "generate_one() {" not in text or "\nrun_check()" not in text:
        return ["RPM lock generator staging function boundaries are missing"]
    staging = text.split("generate_one() {", 1)[1].split("\nrun_check()", 1)[0]
    expect(
        'python3 "${repo_root}/tools/rpmlock.py" arg-default --repo-root "${repo_root}" --name "${name}"' in text,
        "RPM lock generator must consume rpmlock's public Dockerfile ARG reader",
    )
    expect('sed -n "s/^ARG ' not in text, "RPM lock generator retains the shell Dockerfile ARG parser")
    pre_strip_snapshot = (
        "rpm --root=/rootfs -qa \\\n"
        "  --qf '%{NEVRA}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SHA256HEADER}|%{SIGMD5}\\n' \\\n"
        "  | LC_ALL=C sort > /tmp/runtime.full.tsv"
    )
    strip_invocation = "python3.12 /tmp/build-runtime-rootfs.py strip-packages --rootfs /rootfs"
    post_strip_snapshot = "rpm --root=/rootfs -qa --qf '%{NEVRA}\\n' | LC_ALL=C sort > /tmp/runtime.final.nevras"
    floor_invocation = (
        "python3.12 /tmp/generate-runtime-lock.py validate-floor \\\n"
        "  --full-rows /tmp/runtime.full.tsv \\\n"
        "  --final-nevras /tmp/runtime.final.nevras"
    )
    render_invocation = (
        "python3.12 /tmp/generate-runtime-lock.py render \\\n"
        "  --full-rows /tmp/runtime.full.tsv \\\n"
        "  --final-nevras /tmp/runtime.final.nevras \\\n"
        "  --direct-results /tmp/runtime.direct.tsv \\\n"
        '  --arch "${TARGETARCH}" \\\n'
        '  --source-date-epoch "${SOURCE_DATE_EPOCH}" \\\n'
        '  --output "/out/runtime.${TARGETARCH}.txt"'
    )
    fips_candidate_invocation = (
        "python3.12 /tmp/generate-runtime-lock.py fips-candidate \\\n"
        "  --full-rows /tmp/runtime.full.tsv \\\n"
        '  --arch "${TARGETARCH}" \\\n'
        '  --base-url "${OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}" \\\n'
        "  > /tmp/fips.candidates.tsv"
    )
    fips_metadata_query = (
        "rpm -qp \\\n"
        "  --qf '%{NEVRA}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SHA256HEADER}|%{SIGMD5}\\n' \\\n"
        '  "${fetched_direct_rpm_path}" > /tmp/fips.full.tsv'
    )
    fips_render_invocation = (
        "python3.12 /tmp/generate-runtime-lock.py render-fips \\\n"
        "  --full-rows /tmp/runtime.full.tsv \\\n"
        "  --fips-rows /tmp/fips.full.tsv \\\n"
        "  --direct-results /tmp/fips.direct.tsv \\\n"
        '  --arch "${TARGETARCH}" \\\n'
        '  --source-date-epoch "${SOURCE_DATE_EPOCH}" \\\n'
        '  --output "/out/fips-verify.${TARGETARCH}.txt"'
    )

    for marker in [
        pre_strip_snapshot,
        strip_invocation,
        post_strip_snapshot,
        floor_invocation,
        fips_candidate_invocation,
        fips_metadata_query,
        render_invocation,
        fips_render_invocation,
    ]:
        expect(marker in capture, f"RPM lock generator missing capture-stage marker: {marker}")
    expect(text.count(strip_invocation) == 1, "RPM lock generator must invoke strip-packages exactly once")

    ordering_markers = [
        pre_strip_snapshot,
        strip_invocation,
        post_strip_snapshot,
        floor_invocation,
        fips_candidate_invocation,
        fips_metadata_query,
        render_invocation,
        fips_render_invocation,
    ]
    if all(marker in capture for marker in ordering_markers):
        expect(
            capture.index(pre_strip_snapshot)
            < capture.index(strip_invocation)
            < capture.index(post_strip_snapshot)
            < capture.index(floor_invocation)
            < capture.index(fips_candidate_invocation)
            < capture.index(fips_metadata_query)
            < capture.index(render_invocation)
            < capture.index(fips_render_invocation),
            "RPM lock generator must capture, verify, and render the atomic runtime/FIPS pair in order",
        )

    for marker in [
        "protected_deps",
        "removable_packages",
        "coreutils-single coreutils findutils grep sed",
        "LD_LIBRARY_PATH=/rootfs/usr/lib64 ldd",
    ]:
        expect(marker not in text, f"RPM lock generator retains shadow strip marker: {marker}")

    copy_markers = [
        "COPY rpm-lock/builder.amd64.txt rpm-lock/builder.arm64.txt /tmp/rpm-lock/",
        "COPY tools/assert-builder-toolchain-floor.sh /tmp/assert-builder-toolchain-floor.sh",
        "COPY tools/build-runtime-rootfs.py /tmp/build-runtime-rootfs.py",
        "COPY tools/fetch-builder-rpms.sh /tmp/fetch-builder-rpms.sh",
        "COPY fetch-openssl-fips-provider-rpms.sh /usr/local/bin/fetch-openssl-fips-provider-rpms.sh",
        "COPY tools/rpmlock.py /tmp/rpmlock.py",
        "COPY tools/generate-runtime-lock.py /tmp/generate-runtime-lock.py",
    ]
    for marker in copy_markers:
        expect(marker in capture, f"RPM lock generator missing exact capture COPY: {marker}")
    capture_inputs = capture.split("\nRUN <<'CAPTURE'", 1)[0]
    expect(
        capture_inputs.count("\nCOPY ") == 7,
        "RPM lock generator capture input block must contain exactly seven COPY statements",
    )

    staging_sources = [
        '"${repo_root}/rpm-lock/builder.amd64.txt"',
        '"${repo_root}/rpm-lock/builder.arm64.txt"',
        '"${repo_root}/tools/assert-builder-toolchain-floor.sh"',
        '"${repo_root}/tools/build-runtime-rootfs.py"',
        '"${repo_root}/tools/fetch-builder-rpms.sh"',
        '"${repo_root}/tools/fetch-openssl-fips-provider-rpms.sh"',
        '"${repo_root}/tools/rpmlock.py"',
        '"${repo_root}/tools/generate-runtime-lock.py"',
    ]
    for marker in staging_sources:
        expect(marker in staging, f"RPM lock generator missing staged source path: {marker}")
    pair_copy = (
        "  cp \\\n"
        '    "${tmpdir}/out/runtime.${platform_arch}.txt" \\\n'
        '    "${tmpdir}/out/fips-verify.${platform_arch}.txt" \\\n'
        '    "${output_dir}/"'
    )
    expect(pair_copy in staging, "RPM lock generator must publish the validated runtime/FIPS pair together")
    for marker in [
        'validate_runtime_lockfile "${tmpdir}/out/runtime.${platform_arch}.txt" "${platform_arch}"',
        'validate_fips_lockfile "${tmpdir}/out/fips-verify.${platform_arch}.txt" "${platform_arch}"',
        '"${tmpdir}/out/runtime.${platform_arch}.txt" \\\n    "${tmpdir}/out/fips-verify.${platform_arch}.txt"',
        '"${output_dir}/runtime.${platform_arch}.txt"',
        '"${output_dir}/fips-verify.${platform_arch}.txt"',
        "for lock_kind in runtime fips-verify; do",
        '"${repo_root}/rpm-lock/${lock_kind}.${platform_arch}.txt"',
        '"${generated_dir}/${lock_kind}.${platform_arch}.txt"',
        'validate_lock_pair \\\n      "${repo_root}/rpm-lock/runtime.${platform_arch}.txt"',
    ]:
        expect(marker in text, f"RPM lock generator missing atomic output/check marker: {marker}")

    builder_fetch = "bash /tmp/fetch-builder-rpms.sh"
    builder_install = 'rpm -Uvh --oldpackage --replacepkgs --excludedocs "${builder_rpm_paths[@]}"'
    builder_floor = "bash /tmp/assert-builder-toolchain-floor.sh --before"
    rootfs_assembly = "mkdir -p /rootfs /out /tmp/fips-provider-rpms"
    runtime_install = "microdnf install -y --installroot=/rootfs"
    for marker in [builder_fetch, builder_install, builder_floor, rootfs_assembly, runtime_install]:
        expect(marker in capture, f"RPM lock generator missing capture-stage builder ordering marker: {marker}")
    builder_markers = [builder_fetch, builder_install, builder_floor, rootfs_assembly, runtime_install]
    if all(marker in capture for marker in builder_markers):
        expect(
            capture.index(builder_fetch)
            < capture.index(builder_install)
            < capture.index(builder_floor)
            < capture.index(rootfs_assembly)
            < capture.index(runtime_install),
            "RPM lock generator must install and floor-check builder Python before /rootfs assembly",
        )

    for marker in [
        "python3.12 /tmp/generate-runtime-lock.py package-specs > /tmp/runtime-package-specs",
        "python3.12 /tmp/generate-runtime-lock.py candidates",
        "python3.12 /tmp/generate-runtime-lock.py fips-candidate",
        "python3.12 /tmp/generate-runtime-lock.py render-fips",
        'python3.12 /tmp/generate-runtime-lock.py signature-output --output "${signature_output}"',
        "curl -fL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2",
        'actual_sha="$(sha256sum "${tmp}" | awk \'{print $1}\')"',
        'rpm -K "${path}" | tee "${signature_output}"',
        'printf \'%s|%s|%s\\n\' "${package}" "${url}" "${actual_sha}" >> "${results_file}"',
        'test -s "${fetched_direct_rpm_path}"',
    ]:
        expect(marker in capture, f"RPM lock generator missing fail-closed helper/orchestration marker: {marker}")

    return errors


def _move_after(text: str, moved: str, anchor: str) -> str:
    without = text.replace(moved, "", 1)
    return without.replace(anchor, f"{anchor}\n{moved}", 1)


def check_python_trim_policy() -> None:
    declaration = load_json_object("images/python/rpm-lock/retained-payload-trim.json")
    require(declaration.get("version") == 2, "python trim declaration must use semantic contract version 2")
    architectures = declaration.get("architectures")
    require(isinstance(architectures, dict), "python trim declaration architectures must be an object")
    assert isinstance(architectures, dict)
    require(set(architectures) == {"amd64", "arm64"}, "python trim declaration must cover both architectures")
    for arch, expected_suffix in (
        ("amd64", "_sqlite3.cpython-312-x86_64-linux-gnu.so"),
        ("arm64", "_sqlite3.cpython-312-aarch64-linux-gnu.so"),
    ):
        architecture = architectures.get(arch)
        require(isinstance(architecture, dict), f"python trim {arch} declaration must be an object")
        assert isinstance(architecture, dict)
        require(
            set(architecture) == {"build_id_link", "entries"},
            f"python trim {arch} declaration must separate semantic and static entries",
        )
        build_id_link = architecture.get("build_id_link")
        require(isinstance(build_id_link, dict), f"python trim {arch} build_id_link must be an object")
        assert isinstance(build_id_link, dict)
        require(
            set(build_id_link) == {"package", "target"}
            and build_id_link.get("package") == "python3.12-libs"
            and str(build_id_link.get("target", "")).endswith(expected_suffix),
            f"python trim {arch} must semantically target the architecture-specific _sqlite3 extension",
        )
    require(
        "/usr/lib/.build-id/" not in json.dumps(declaration, sort_keys=True),
        "python trim declaration must not pin a concrete build-ID path",
    )

    helper = read("images/python/tools/retained_payload_trim.py")
    for marker in [
        "def materialize_trim_contract(",
        "def _gnu_build_id(",
        "ELF_MACHINE",
        "derived build-ID link target differs from RPM metadata",
        "derived build-ID link target is dangling",
        "build-ID link target escapes the rootfs",
        "additional or ambiguous build-ID link",
        "materialized trim contains duplicate concrete paths",
    ]:
        require(marker in helper, f"python trim materializer missing fail-closed marker: {marker}")
    require("readelf" not in helper, "python trim materializer must remain standard-library-only for ELF parsing")

    generator = read("images/python/tools/generate-python-lock.sh")
    generator_markers = [
        "microdnf install -y --installroot=/rootfs",
        "trim_contract = load_trim_contract(",
        "trim_entries = materialize_trim_contract(",
        "apply_retained_payload_trim(",
        "# Shipped derivation:",
    ]
    require(
        '"[%{FILENAMES}\\t%{FILELINKTOS}\\n]"' in generator,
        "python lock generator materialization must query RPM file/link records",
    )
    require(
        all(generator.count(marker) == 1 for marker in generator_markers),
        "python lock generator must contain one identifiable trim transaction/materialization sequence",
    )
    require(
        all(generator.index(before) < generator.index(after) for before, after in pairwise(generator_markers)),
        "python lock generator must materialize after the candidate transaction and apply before closure derivation",
    )

    builder = read("images/python/tools/build-python-rootfs.py")
    build_start = builder.index("def build(args: argparse.Namespace) -> None:")
    build_end = builder.index("\ndef self_test() -> None:", build_start)
    build_body = builder[build_start:build_end]
    builder_markers = [
        "trim_contract = load_trim_contract(",
        "run_transaction(rootfs, Path(args.rpm_dir), rows)",
        "trim_entries = materialize_trim_contract(",
        "apply_retained_payload_trim(",
        "protected = protected_paths(rootfs)",
    ]
    require(
        '"[%{FILENAMES}\\t%{FILELINKTOS}\\n]"' in build_body,
        "python build materialization must query RPM file/link records",
    )
    require(
        all(build_body.count(marker) == 1 for marker in builder_markers),
        "python build helper must contain one identifiable trim transaction/materialization sequence",
    )
    require(
        all(build_body.index(before) < build_body.index(after) for before, after in pairwise(builder_markers)),
        "python build helper must materialize after run_transaction and apply before protected-path derivation",
    )


def check_rpm_lock_generator() -> None:
    text = read("tools/generate-rpm-lock.sh")
    errors = rpm_lock_generator_errors(text)
    require(not errors, errors[0] if errors else "RPM lock generator contract failed")

    pre_snapshot = (
        "rpm --root=/rootfs -qa \\\n"
        "  --qf '%{NEVRA}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SHA256HEADER}|%{SIGMD5}\\n' \\\n"
        "  | LC_ALL=C sort > /tmp/runtime.full.tsv"
    )
    strip = "python3.12 /tmp/build-runtime-rootfs.py strip-packages --rootfs /rootfs"
    post_snapshot = "rpm --root=/rootfs -qa --qf '%{NEVRA}\\n' | LC_ALL=C sort > /tmp/runtime.final.nevras"
    render = "python3.12 /tmp/generate-runtime-lock.py render"
    render_fips = "python3.12 /tmp/generate-runtime-lock.py render-fips"
    fips_candidate = "python3.12 /tmp/generate-runtime-lock.py fips-candidate"
    fips_query = (
        "rpm -qp \\\n  --qf '%{NEVRA}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SHA256HEADER}|%{SIGMD5}\\n'"
    )
    mutations: list[tuple[str, str]] = [
        ("delete pre-strip snapshot", text.replace(pre_snapshot, "", 1)),
        ("move pre-strip snapshot below strip", _move_after(text, pre_snapshot, strip)),
        ("delete post-strip snapshot", text.replace(post_snapshot, "", 1)),
        ("move post-strip snapshot above strip", _move_after(text, post_snapshot, pre_snapshot)),
        ("move rendering above post-strip snapshot", _move_after(text, render, strip)),
        ("delete FIPS candidate derivation", text.replace(fips_candidate, "true", 1)),
        ("delete FIPS RPM metadata query", text.replace(fips_query, "true", 1)),
        ("delete FIPS companion render", text.replace(render_fips, "true", 1)),
        (
            "swap render full/final input",
            text.replace("--full-rows /tmp/runtime.full.tsv", "--full-rows /tmp/runtime.final.nevras", 2),
        ),
        ("remove render direct input", text.replace("  --direct-results /tmp/runtime.direct.tsv \\\n", "", 1)),
        ("remove FIPS render direct input", text.replace("  --direct-results /tmp/fips.direct.tsv \\\n", "", 1)),
        (
            "weaken signature checker",
            text.replace(
                'python3.12 /tmp/generate-runtime-lock.py signature-output --output "${signature_output}"',
                "true",
                1,
            ),
        ),
        (
            "omit FIPS companion from checks",
            text.replace("for lock_kind in runtime fips-verify; do", "for lock_kind in runtime; do", 1),
        ),
        (
            "omit FIPS companion from publication",
            text.replace(
                "  cp \\\n"
                '    "${tmpdir}/out/runtime.${platform_arch}.txt" \\\n'
                '    "${tmpdir}/out/fips-verify.${platform_arch}.txt" \\\n'
                '    "${output_dir}/"',
                '  cp "${tmpdir}/out/runtime.${platform_arch}.txt" "${output_dir}/"',
                1,
            ),
        ),
        (
            "remove generated pair validation",
            text.replace(
                '  validate_fips_lockfile "${tmpdir}/out/fips-verify.${platform_arch}.txt" "${platform_arch}"',
                "  true",
                1,
            ),
        ),
        ("weaken curl TLS", text.replace(" --proto '=https' --tlsv1.2", "", 1)),
        ("remove whole-RPM hash", text.replace("sha256sum", "printf", 1)),
        (
            "weaken final-floor checker",
            text.replace("python3.12 /tmp/generate-runtime-lock.py validate-floor", "true", 1),
        ),
        (
            "weaken public ARG reader",
            text.replace(
                'python3 "${repo_root}/tools/rpmlock.py" arg-default --repo-root "${repo_root}" --name "${name}"',
                "printf unknown",
                1,
            ),
        ),
    ]
    copy_markers = [line for line in text.splitlines() if line.startswith("COPY ")][:7]
    mutations.extend(
        (f"delete COPY {index}", text.replace(marker, "", 1)) for index, marker in enumerate(copy_markers, 1)
    )
    staging_sources = [
        '"${repo_root}/rpm-lock/builder.amd64.txt"',
        '"${repo_root}/rpm-lock/builder.arm64.txt"',
        '"${repo_root}/tools/assert-builder-toolchain-floor.sh"',
        '"${repo_root}/tools/build-runtime-rootfs.py"',
        '"${repo_root}/tools/fetch-builder-rpms.sh"',
        '"${repo_root}/tools/fetch-openssl-fips-provider-rpms.sh"',
        '"${repo_root}/tools/rpmlock.py"',
        '"${repo_root}/tools/generate-runtime-lock.py"',
    ]
    prefix, staging = text.split("generate_one() {", 1)
    for index, marker in enumerate(staging_sources, 1):
        mutations.append(
            (f"delete staged source {index}", prefix + "generate_one() {" + staging.replace(marker, "", 1))
        )

    for label, mutated in mutations:
        require(rpm_lock_generator_errors(mutated), f"RPM lock generator mutation was not rejected: {label}")
    print(f"RPM lock generator mutation probes: {len(mutations)}/{len(mutations)} rejected")


def check_dockerfile() -> None:
    text = read("containers/Dockerfile")
    required = [
        "# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-minimal",
        "# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-micro",
        "ARG UBI_MINIMAL_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal@sha256:",
        "ARG UBI_MICRO_IMAGE=registry.access.redhat.com/ubi9/ubi-micro@sha256:",
        "ARG TARGETARCH",
        f"ARG OPENSSL_FIPS_MODULE_VERSION={fips_module_version()}",
        f"ARG OPENSSL_FIPS_PROVIDER_NEVRA={fips_provider_nevra()}",
        f"ARG OPENSSL_FIPS_PROVIDER_RPM_BASE_URL={OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}",
        f"ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64={OPENSSL_FIPS_PROVIDER_RPM_SHA256_AMD64}",
        f"ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64={OPENSSL_FIPS_PROVIDER_RPM_SHA256_ARM64}",
        f"ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64={OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AMD64}",
        f"ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64={OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_ARM64}",
        f"ARG OPENSSL_FIPS_SO_SHA256_AMD64={fips_so_sha256('amd64')}",
        f"ARG OPENSSL_FIPS_SO_SHA256_ARM64={fips_so_sha256('arm64')}",
        "ARG SOURCE_DATE_EPOCH=1704067200",
        'amd64) rpm_arch="x86_64"',
        'arm64) rpm_arch="aarch64"',
        (
            'bash /tmp/fetch-runtime-rpms.sh --targetarch "${TARGETARCH}" '
            '--lockfile "${runtime_lockfile}" --dest /tmp/runtime-rpms'
        ),
        (
            'bash /tmp/fetch-builder-rpms.sh --targetarch "${TARGETARCH}" '
            '--lockfile "${builder_lockfile}" --dest /tmp/builder-rpms'
        ),
        "COPY rpm-lock/builder.amd64.txt rpm-lock/builder.arm64.txt /tmp/rpm-lock/",
        "rpm -Uvh --oldpackage --replacepkgs",
        "rpm -q --qf '%{NEVRA}\\n' \"${package}\"",
        'rpm -Uvh --oldpackage --replacepkgs --excludedocs "${builder_rpm_paths[@]}"',
        "bash /tmp/assert-builder-toolchain-floor.sh --before /tmp/builder-toolchain.before",
        "python3.12 -c 'import sys; print(sys.version)'",
        "python python3 python3.12",
        "COPY rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt /tmp/rpm-lock/",
        "COPY tools/assert-builder-toolchain-floor.sh /tmp/assert-builder-toolchain-floor.sh",
        "COPY tools/assert-rpm-lock-hashes.py /tmp/assert-rpm-lock-hashes.py",
        "COPY tools/build-runtime-rootfs.py /tmp/build-runtime-rootfs.py",
        "COPY contracts/image-manifest.json /tmp/image-manifest.json",
        "COPY tools/fetch-builder-rpms.sh /tmp/fetch-builder-rpms.sh",
        "COPY tools/fetch-runtime-rpms.sh /tmp/fetch-runtime-rpms.sh",
        "COPY tools/rpmlock.py /tmp/rpmlock.py",
        "COPY tools/verify-fips-provider.py /tmp/verify-fips-provider.py",
        "COPY tools/write-fips-status.py /tmp/write-fips-status.py",
        "dnf_repo_args=()",
        '"${dnf_repo_args[@]}"',
        'builder_rpm_paths+=("/tmp/builder-rpms/${name}-${version}-${release}.${arch}.rpm")',
        'test "${#builder_rpm_paths[@]}" -eq 7',
        "python3.12 /tmp/rpmlock.py rpm-filenames",
        '--source-date-epoch "${SOURCE_DATE_EPOCH}"',
        '--openssl-fips-provider-nevra "${OPENSSL_FIPS_PROVIDER_NEVRA}"',
        '--openssl-fips-provider-rpm-base-url "${OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}"',
        '--openssl-fips-provider-rpm-sha256-x86-64 "${OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64}"',
        '--openssl-fips-provider-rpm-sha256-aarch64 "${OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64}"',
        '--openssl-fips-provider-so-rpm-sha256-x86-64 "${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64}"',
        '--openssl-fips-provider-so-rpm-sha256-aarch64 "${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64}"',
        '> "${rt_tmp}"',
        'mapfile -t rt_names < "${rt_tmp}"',
        "locked_rpm_paths=()",
        'locked_rpm_paths+=("/tmp/runtime-rpms/${rt_name}")',
        'rm -f "${rt_tmp}"',
        'test "${#locked_rpm_paths[@]}" -gt 0',
        "python3.12 /tmp/assert-rpm-lock-hashes.py --root /rootfs --lockfile",
        "--direct-rpm-dir /tmp/runtime-rpms",
        "python3.12 /tmp/build-runtime-rootfs.py build",
        "python3.12 /tmp/write-fips-status.py --contract /tmp/image-manifest.json",
        '--runtime-lockfile "${runtime_lockfile}"',
        "--fips-proof /tmp/fips-proof",
        "--fips-openssl /tmp/fips-openssl",
        "--fips-lib64 /tmp/fips-lib64",
        '--target-arch "${TARGETARCH}"',
        '--provider-nevra "${OPENSSL_FIPS_PROVIDER_NEVRA}"',
        '--module-version "${OPENSSL_FIPS_MODULE_VERSION}"',
        'find /rootfs -xdev -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +',
        "rpm --root=/rootfs -Uvh --oldpackage --replacepkgs --excludedocs",
        '"${locked_rpm_paths[@]}"',
        "--nodocs --setopt=install_weak_deps=0",
        "FROM ${UBI_MICRO_IMAGE} AS runtime-common",
        "FROM runtime-common AS runtime-amd64",
        "FROM runtime-common AS runtime-arm64",
        "FROM runtime-${TARGETARCH} AS runtime",
        "FROM ${UBI_MICRO_IMAGE} AS dev",
        "COPY --from=rpm-rootfs /rootfs/ /",
        "COPY --from=dev-rootfs /rootfs/ /",
        "COPY containers/fips/openssl.cnf /etc/pki/tls/openssl-fips.cnf",
        "USER 65532:65532",
        "var/lib/rpm",
        "ca-certificates",
        "openssl-fips-provider",
        "OPENSSL_MODULES",
        "OPENSSL_CONF",
        "ossl-modules",
        f'org.nwarila.fips.cmvp="{fips_cmvp()}"',
        "org.nwarila.fips.module-version",
        "org.nwarila.fips.provider-nvr",
        "org.nwarila.fips.cmvp.oe-validated",
        "/etc/nwarila/fips-status.json",
        "/fips-proof/provider.nevra",
        "/fips-proof/expected-provider.nevra",
        "alternatives",
        "update-alternatives",
        "/usr/sbin/*",
        "/etc/alternatives",
        "/usr/libexec/coreutils",
        "/usr/lib64/libpcre2-posix.so*",
        "/usr/lib64/libpanel*.so*",
        "/usr/lib64/libpanelw*.so*",
    ]
    missing = [marker for marker in required if marker not in text]
    require(not missing, "Dockerfile missing required markers: " + ", ".join(missing))

    fips_verify = text.split("FROM ${UBI_MINIMAL_IMAGE} AS fips-verify", 1)[1].split(
        "FROM ${UBI_MINIMAL_IMAGE} AS rpm-rootfs", 1
    )[0]
    fips_bootstrap_array = "builder_rpm_paths=()"
    fips_bootstrap_count = 'test "${#builder_rpm_paths[@]}" -eq 7'
    fips_builder_fetch = "bash /tmp/fetch-builder-rpms.sh"
    fips_builder_install = 'rpm -Uvh --oldpackage --replacepkgs --excludedocs "${builder_rpm_paths[@]}"'
    fips_python_sanity = "python3.12 -c 'import sys; print(sys.version)'"
    fips_builder_cleanup = "rm -rf /tmp/builder-rpms"
    fips_runtime_fetch = (
        'bash /tmp/fetch-runtime-rpms.sh --targetarch "${TARGETARCH}" '
        '--lockfile "${runtime_lockfile}" --dest /tmp/runtime-rpms'
    )
    fips_lock_fetch = (
        'bash /tmp/fetch-runtime-rpms.sh --targetarch "${TARGETARCH}" '
        '--lockfile "${fips_lockfile}" --dest /tmp/fips-rpms'
    )
    fips_selector = "python3.12 /tmp/rpmlock.py fips-rpm-filenames"
    fips_selector_capture = (
        '--openssl-fips-provider-so-rpm-sha256-aarch64 "${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64}" \\\n'
        '      > "${fips_names_tmp}";'
    )
    fips_selector_mapfile = 'mapfile -t fips_rpm_names < "${fips_names_tmp}"'
    fips_selector_count = 'test "${#fips_rpm_names[@]}" -eq 3'
    fips_locked_install = (
        "rpm -Uvh --oldpackage --replacepkgs \\\n"
        '      "${openssl_cli_rpm}" \\\n'
        '      "${openssl_libs_rpm}" \\\n'
        '      "${crypto_policies_rpm}" \\\n'
        '      "/tmp/runtime-rpms/openssl-fips-provider-${fips_provider_nvr}.${rpm_arch}.rpm" \\\n'
        '      "/tmp/runtime-rpms/${OPENSSL_FIPS_PROVIDER_NEVRA}.${rpm_arch}.rpm";'
    )
    fips_microdnf_clean = "microdnf clean all"
    fips_verifier_invocation = "python3.12 /tmp/verify-fips-provider.py"

    def check_fips_verify_stage(stage: str) -> None:
        for marker in [
            "COPY rpm-lock/builder.amd64.txt rpm-lock/builder.arm64.txt /tmp/rpm-lock/",
            "COPY rpm-lock/fips-verify.amd64.txt rpm-lock/fips-verify.arm64.txt /tmp/rpm-lock/",
            "COPY tools/fetch-builder-rpms.sh /tmp/fetch-builder-rpms.sh",
            "COPY tools/fetch-runtime-rpms.sh /tmp/fetch-runtime-rpms.sh",
            "COPY tools/rpmlock.py /tmp/rpmlock.py",
            "COPY tools/verify-fips-provider.py /tmp/verify-fips-provider.py",
            "# The builder loop below bootstraps python, so it cannot use rpmlock.py (ADR-0014).",
            'fips_lockfile="/tmp/rpm-lock/fips-verify.amd64.txt"',
            'fips_lockfile="/tmp/rpm-lock/fips-verify.arm64.txt"',
            'test -s "${fips_lockfile}"',
            fips_bootstrap_array,
            fips_bootstrap_count,
            fips_builder_fetch,
            fips_builder_install,
            fips_python_sanity,
            fips_builder_cleanup,
            fips_selector,
            '--fips-lockfile "${fips_lockfile}"',
            '--runtime-lockfile "${runtime_lockfile}"',
            '--arch "${TARGETARCH}"',
            '--source-date-epoch "${SOURCE_DATE_EPOCH}"',
            fips_selector_capture,
            fips_selector_mapfile,
            fips_selector_count,
            'openssl_cli_rpm="/tmp/fips-rpms/${fips_rpm_names[0]}"',
            'openssl_libs_rpm="/tmp/runtime-rpms/${fips_rpm_names[1]}"',
            'crypto_policies_rpm="/tmp/runtime-rpms/${fips_rpm_names[2]}"',
            fips_runtime_fetch,
            fips_lock_fetch,
            fips_locked_install,
            fips_microdnf_clean,
            fips_verifier_invocation,
            '--target-arch "${TARGETARCH}"',
            '--provider-nevra "${OPENSSL_FIPS_PROVIDER_NEVRA}"',
            '--module-version "${OPENSSL_FIPS_MODULE_VERSION}"',
            '--expected-fips-so-sha256 "${expected_fips_so_sha256}"',
            "--openssl-cnf /tmp/openssl-fips.cnf",
            "--modules-dir /usr/lib64/ossl-modules",
            "--proof-dir /fips-proof",
        ]:
            require(marker in stage, f"fips-verify stage missing pinned orchestration marker: {marker}")
        normalized_stage = stage.replace("\\\n", " ")
        require(
            re.search(r"\bmicrodnf\s+install\b", normalized_stage) is None,
            "fips-verify must not resolve packages through live microdnf metadata",
        )
        require(
            "dnf_repo_args" not in stage and "--releasever=9" not in stage,
            "fips-verify retains live repository-resolution orchestration",
        )
        require(
            stage.count(fips_lock_fetch) == 1,
            "fips-verify must fetch the FIPS verification lock exactly once",
        )
        require(
            stage.count(fips_selector) == 1,
            "fips-verify must select the three identity-derived filenames exactly once",
        )
        require(
            "openssl-3.5.5" not in stage
            and "openssl-libs-3.5.5" not in stage
            and "crypto-policies-20260224" not in stage,
            "fips-verify retains literal observed-version RPM paths",
        )
        require(
            stage.count("rpm -Uvh --oldpackage --replacepkgs \\\n") == 1 and stage.count(fips_locked_install) == 1,
            "fips-verify must install exactly one five-RPM pinned OpenSSL closure transaction",
        )
        require(
            stage.index(fips_bootstrap_array)
            < stage.index(fips_bootstrap_count)
            < stage.index(fips_builder_fetch)
            < stage.index(fips_builder_install)
            < stage.index(fips_python_sanity)
            < stage.index(fips_builder_cleanup)
            < stage.index(fips_selector)
            < stage.index(fips_selector_capture)
            < stage.index(fips_selector_mapfile)
            < stage.index(fips_selector_count)
            < stage.index(fips_runtime_fetch)
            < stage.index(fips_lock_fetch)
            < stage.index(fips_locked_install)
            < stage.index(fips_microdnf_clean)
            < stage.index(fips_verifier_invocation),
            "fips-verify must bootstrap Python, fail closed on lock identities, fetch/install once, then verify",
        )
        require(
            stage.count(fips_verifier_invocation) == 1,
            "fips-verify must invoke verify-fips-provider.py exactly once",
        )
        for marker in [
            "providers_verbose=",
            "grep -A8",
            "openssl dgst -md5",
            "openssl dgst -sha256",
            "openssl enc -aes-256-cbc",
            "mkdir -p /fips-proof",
        ]:
            require(marker not in stage, f"fips-verify retains extracted inline verification marker: {marker}")
        require(
            re.search(r">{1,2}\s*/fips-proof/[^\s;\\]+", stage) is None,
            "fips-verify must not redirect to individual proof files",
        )

    check_fips_verify_stage(fips_verify)
    fips_mutations = [
        (
            "FIPS lock COPY deletion",
            fips_verify.replace(
                "COPY rpm-lock/fips-verify.amd64.txt rpm-lock/fips-verify.arm64.txt /tmp/rpm-lock/",
                "",
                1,
            ),
        ),
        ("FIPS lock fetch deletion", fips_verify.replace(fips_lock_fetch, "true", 1)),
        (
            "identity selector deletion",
            fips_verify.replace(fips_selector, "true", 1),
        ),
        (
            "runtime selector lock mismatch",
            fips_verify.replace(
                '--runtime-lockfile "${runtime_lockfile}"',
                '--runtime-lockfile "${fips_lockfile}"',
                1,
            ),
        ),
        (
            "identity cardinality deletion",
            fips_verify.replace(fips_selector_count, "true", 1),
        ),
        (
            "derived crypto-policies path deletion",
            fips_verify.replace('      "${crypto_policies_rpm}" \\\n', "", 1),
        ),
        (
            "live microdnf reintroduction",
            fips_verify.replace(
                fips_verifier_invocation,
                f"microdnf install openssl crypto-policies; {fips_verifier_invocation}",
                1,
            ),
        ),
    ]
    for label, mutation in fips_mutations:
        try:
            check_fips_verify_stage(mutation)
        except VerifyError:
            continue
        raise VerifyError(f"fips-verify mutation was not rejected: {label}")
    print(f"FIPS-verify mutation probes: {len(fips_mutations)}/{len(fips_mutations)} rejected")

    rpmlock_text = read("tools/rpmlock.py")
    for marker in [
        'openssl = _unique_named_row(fips_lockfile, "openssl")',
        'openssl_libs = _unique_named_row(runtime_lockfile, "openssl-libs")',
        'crypto_policies = _unique_named_row(runtime_lockfile, "crypto-policies")',
        "cli_evr == libraries_evr",
        "rpm_filename(openssl)",
        "rpm_filename(openssl_libs)",
        "rpm_filename(crypto_policies)",
    ]:
        require(marker in rpmlock_text, f"rpmlock FIPS identity selector missing marker: {marker}")

    rpm_rootfs = text.split("FROM ${UBI_MINIMAL_IMAGE} AS rpm-rootfs", 1)[1].split(
        "FROM ${UBI_MINIMAL_IMAGE} AS dev-rootfs", 1
    )[0]
    require("microdnf install" not in rpm_rootfs, "rpm-rootfs must not install builder Python through microdnf")
    runtime_filenames = "python3.12 /tmp/rpmlock.py rpm-filenames"
    require(
        "COPY tools/rpmlock.py /tmp/rpmlock.py" in rpm_rootfs and runtime_filenames in rpm_rootfs,
        "rpm-rootfs must copy and consume rpmlock.py for runtime RPM filenames",
    )
    require(
        "< <(" not in rpm_rootfs,
        "rpm-rootfs must not hide the rpm-filenames producer status behind process substitution",
    )
    runtime_capture = (
        '--openssl-fips-provider-so-rpm-sha256-aarch64 "${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64}" > "${rt_tmp}"'
    )
    runtime_mapfile = 'mapfile -t rt_names < "${rt_tmp}"'
    for marker, label in [
        ("set -eux;", "strict-mode marker"),
        (runtime_capture, "runtime filename capture"),
        (runtime_mapfile, "runtime filename mapfile read"),
    ]:
        require(marker in rpm_rootfs, f"rpm-rootfs missing {label} required for ordering")
    require(
        rpm_rootfs.index("set -eux;")
        < rpm_rootfs.index(runtime_filenames)
        < rpm_rootfs.index(runtime_capture)
        < rpm_rootfs.index(runtime_mapfile),
        "rpm-rootfs must status-check rpm-filenames under set -e before reading its temporary output",
    )
    require(rpm_rootfs.count(runtime_filenames) == 1, "rpm-rootfs must invoke rpm-filenames exactly once")
    builder_fetch = "bash /tmp/fetch-builder-rpms.sh"
    rootfs_assembly = "mkdir -p /rootfs"
    require(builder_fetch in rpm_rootfs, "rpm-rootfs missing builder RPM fetch required for ordering")
    require(rootfs_assembly in rpm_rootfs, "rpm-rootfs missing /rootfs assembly marker required for ordering")
    require(
        rpm_rootfs.index(builder_fetch) < rpm_rootfs.index(rootfs_assembly),
        "builder Python must be installed before any /rootfs assembly",
    )
    builder_install = 'rpm -Uvh --oldpackage --replacepkgs --excludedocs "${builder_rpm_paths[@]}"'
    runtime_install = 'rpm --root=/rootfs -Uvh --oldpackage --replacepkgs --excludedocs "${locked_rpm_paths[@]}"'
    microdnf_clean = "microdnf clean all"
    rootfs_cleanup = "rm -rf /rootfs/var/cache/* /var/cache/microdnf-installroot"
    hash_assertion = "python3.12 /tmp/assert-rpm-lock-hashes.py --root /rootfs --lockfile"
    helper_invocation = "python3.12 /tmp/build-runtime-rootfs.py build"
    writer_invocation = "python3.12 /tmp/write-fips-status.py --contract /tmp/image-manifest.json"
    terminal_touch = 'find /rootfs -xdev -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +'
    for marker, label in [
        (builder_install, "builder RPM install"),
        (runtime_install, "runtime RPM install"),
        (microdnf_clean, "microdnf cleanup"),
        (rootfs_cleanup, "rootfs cleanup"),
        (hash_assertion, "RPM lock hash assertion"),
        (helper_invocation, "production build helper"),
        (writer_invocation, "FIPS status writer"),
        (terminal_touch, "terminal rootfs touch"),
    ]:
        require(marker in rpm_rootfs, f"rpm-rootfs missing {label} required for ordering")
    require(
        rpm_rootfs.index(builder_install)
        < rpm_rootfs.index(runtime_filenames)
        < rpm_rootfs.index(runtime_install)
        < rpm_rootfs.index(microdnf_clean)
        < rpm_rootfs.index(rootfs_cleanup)
        < rpm_rootfs.index(hash_assertion)
        < rpm_rootfs.index(helper_invocation)
        < rpm_rootfs.index(writer_invocation)
        < rpm_rootfs.index(terminal_touch),
        "rpm-rootfs must retain runtime install < microdnf clean < rootfs cleanup < hash assertion < build helper "
        "< FIPS status writer < terminal touch",
    )
    for marker, label in [
        (runtime_install, "runtime RPM install"),
        (microdnf_clean, "microdnf cleanup"),
        (rootfs_cleanup, "rootfs cleanup"),
        (hash_assertion, "RPM lock hash assertion"),
        (helper_invocation, "production build helper"),
        (writer_invocation, "FIPS status writer"),
        (terminal_touch, "terminal rootfs touch"),
    ]:
        require(rpm_rootfs.count(marker) == 1, f"rpm-rootfs must contain {label} exactly once")
    require(
        "/rootfs" not in rpm_rootfs.split(terminal_touch, 1)[1],
        "the inline terminal touch must be the last rpm-rootfs mutation",
    )

    runtime_common = text.split("FROM ${UBI_MICRO_IMAGE} AS runtime-common", 1)[1].split(
        "FROM runtime-common AS runtime-amd64", 1
    )[0]
    for marker in [
        "test -s /tmp/fips-proof/proof.txt",
        'test "$(cat /tmp/fips-proof/provider.nevra)" = "${expected_provider_nevra}"',
        'test "$(cat /tmp/fips-proof/expected-provider.nevra)" = "${expected_provider_nevra}"',
        'test "$(cat /tmp/fips-proof/module.version)" = "${OPENSSL_FIPS_MODULE_VERSION}"',
        "test -s /etc/nwarila/fips-status.json",
    ]:
        require(marker in runtime_common, f"runtime-common missing retained FIPS assertion: {marker}")
    for marker in [
        "oe_validated=",
        "disclaimer=",
        "mkdir -p /etc/nwarila",
        '"arch":',
        '"module":',
        '"provider_nvr":',
        '"provider_nevra":',
        '"cmvp":',
        '"oe_validated":',
        '"disclaimer":',
    ]:
        require(marker not in runtime_common, f"runtime-common must not generate FIPS status JSON: {marker}")
    require(
        re.search(r">{1,2}\s*/etc/nwarila/fips-status\.json", runtime_common) is None,
        "runtime-common must not redirect output to the FIPS status path",
    )

    rootfs_helper = read("tools/build-runtime-rootfs.py")
    for marker in [
        "def strip_packages(rootfs: Path) -> list[str]:",
        "STRIP_CANDIDATES: Final",
        "check=True",
        "if not os.path.exists(rooted):",
        '_rpm(rootfs, ["-e", "--nodeps", "--noscripts", *removable])',
        '_run(["ldconfig", "-r", str(rootfs)])',
        '_run(["cp", "-a", str(zoneinfo / "UTC"), str(zone_tmp / "UTC")])',
        "raw_zone_tmp = tempfile.mkdtemp()",
        "zone_tmp.rename(zoneinfo)",
        "strip_packages(rootfs)",
        "_verify_runtime_lock_floor(rootfs, runtime_lockfile)",
        "_verify_fips(",
        "_trim_filesystem(rootfs, fips_openssl=fips_openssl, fips_lib64=fips_lib64)",
        'build_parser.add_argument("--runtime-lockfile", type=Path, required=True)',
        'build_parser.add_argument("--fips-proof", type=Path, required=True)',
        'build_parser.add_argument("--fips-openssl", type=Path, required=True)',
    ]:
        require(marker in rootfs_helper, f"runtime-rootfs helper missing locked marker: {marker}")
    require("--source-date-epoch" not in rootfs_helper, "runtime-rootfs helper must not own the terminal touch")
    build_body = rootfs_helper.split("def build(\n", 1)[1].split("\ndef _parser()", 1)[0]
    build_order_markers = [
        "strip_packages(rootfs)",
        "_verify_runtime_lock_floor(rootfs, runtime_lockfile)",
        "_verify_fips(",
        "_trim_filesystem(",
    ]
    for marker in build_order_markers:
        require(marker in build_body, f"production build helper body missing ordering marker: {marker}")
    require(
        build_body.index("strip_packages(rootfs)")
        < build_body.index("_verify_runtime_lock_floor(rootfs, runtime_lockfile)")
        < build_body.index("_verify_fips(")
        < build_body.index("_trim_filesystem("),
        "production build helper must run strip, lock floor, FIPS cross-checks, then filesystem trims",
    )

    status_writer = read("tools/write-fips-status.py")
    for marker in [
        'parser.add_argument("--contract", type=Path, required=True)',
        'parser.add_argument("--target-arch", choices=TARGET_ARCHES, required=True)',
        'parser.add_argument("--provider-nevra", required=True)',
        'parser.add_argument("--module-version", required=True)',
        'parser.add_argument("--output", type=Path, required=True)',
        'json.loads(contract.read_text(encoding="utf-8"))',
        "provider_nevra == contract_provider",
        "module_version == contract_module",
        '"provider_nevra": f"{contract_provider}.{rpm_arch}"',
        '"cmvp": f"#{cmvp}"',
        "json.dumps(payload, indent=2, ensure_ascii=True)",
        "output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)",
        "output.write_bytes(encoded)",
        "output.read_bytes()",
    ]:
        require(marker in status_writer, f"FIPS status writer missing locked marker: {marker}")

    fips_verifier = read("tools/verify-fips-provider.py")
    for marker in [
        "def parse_providers(transcript: bytes) -> dict[str, ProviderInfo]:",
        "duplicate OpenSSL provider",
        "duplicate {key} field in OpenSSL provider",
        "def raw_provider_slice(transcript: bytes, provider_name: str) -> bytes:",
        'return b"".join(lines[start_index : start_index + 9])',
        "env = os.environ.copy()",
        'env["OPENSSL_CONF"] = str(openssl_cnf)',
        'env["OPENSSL_MODULES"] = str(modules_dir)',
        "stderr=subprocess.STDOUT",
        "if md5.returncode == 0:",
        "md5 unexpectedly succeeded under OpenSSL FIPS approved mode",
        'raw_provider_slice(providers_verbose, "fips")',
        'raw_provider_slice(providers_verbose, "base")',
        'b"md5 failure:\\n"',
        'b"sha256 success:\\n"',
        "actual == PROOF_FILES",
        "path.is_file() and path.stat().st_size > 0",
    ]:
        require(marker in fips_verifier, f"FIPS provider verifier missing locked marker: {marker}")

    builder_fetch = read("tools/fetch-builder-rpms.sh")
    for marker in [
        "https://cdn-ubi.redhat.com/",
        "sha256sum",
        'sig_output="$(rpm -K',
        "digests signatures OK",
        "rpm -qp --qf '%{NEVRA}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SHA256HEADER}|%{SIGMD5}'",
    ]:
        require(marker in builder_fetch, f"builder RPM fetch helper missing pin-discipline marker: {marker}")
    require("microdnf" not in builder_fetch, "builder RPM fetch helper must not use microdnf")

    floor_guard = read("tools/assert-builder-toolchain-floor.sh")
    for package in ["rpm", "rpm-libs", "sqlite-libs", "glibc", "glibc-common"]:
        require(package in floor_guard, f"builder toolchain floor guard missing package: {package}")
    require("moved: before=" in floor_guard, "builder toolchain floor guard must name moved packages")

    from_lines = [line for line in text.splitlines() if line.startswith("FROM ")]
    require(from_lines, "Dockerfile must contain FROM lines")
    for line in from_lines:
        if "${UBI_" in line:
            continue
        if line in {
            "FROM runtime-common AS runtime-amd64",
            "FROM runtime-common AS runtime-arm64",
            "FROM runtime-${TARGETARCH} AS runtime",
        }:
            continue
        require("@sha256:" in line, f"Dockerfile FROM must be digest-pinned: {line}")

    present = find_dockerfile_forbidden_markers(collect_dockerfile_forbidden_sources())
    require(not present, "Dockerfile/script contains forbidden marker(s): " + ", ".join(present))


def rpm_lock_refresh_errors(text: str) -> list[str]:
    """Return verify-only routing and least-privilege violations for workflow text."""

    errors: list[str] = []

    def expect(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    if "\n  verify-only:\n" not in text or "\n  refresh:\n" not in text:
        return ["RPM lock refresh workflow must define separate verify-only and refresh jobs"]
    header, jobs = text.split("\njobs:\n", 1)
    verify_job, refresh_job = jobs.split("\n  refresh:\n", 1)
    verify_condition = "if: github.event_name == 'workflow_dispatch' && inputs.verify_only"
    refresh_condition = (
        "if: github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && !inputs.verify_only)"
    )
    lock_paths = (
        "rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt "
        "rpm-lock/fips-verify.amd64.txt rpm-lock/fips-verify.arm64.txt"
    )

    for marker in [
        "workflow_dispatch:",
        "verify_only:",
        "required: true",
        "default: false",
        "type: boolean",
        "permissions: {}",
    ]:
        expect(marker in header, f"RPM lock refresh workflow missing verify-only input boundary: {marker}")
    expect(verify_condition in verify_job, "verify-only job routing condition is missing or weakened")
    expect(refresh_condition in refresh_job, "refresh job routing condition is missing or weakened")
    expect("permissions:\n      contents: read" in verify_job, "verify-only job must grant contents: read only")
    for forbidden in [
        "contents: write",
        "pull-requests:",
        "GH_TOKEN",
        "git commit",
        "git push",
        "gh pr ",
        "gh auth setup-git",
    ]:
        expect(forbidden not in verify_job, f"verify-only job contains write-capable marker: {forbidden}")
    expect(
        "permissions:\n      contents: write\n      pull-requests: write" in refresh_job, "refresh permissions changed"
    )

    required_verify_markers = [
        "bash -n tools/generate-rpm-lock.sh",
        "bash tools/generate-rpm-lock.sh --self-test",
        "bash tools/generate-rpm-lock.sh --arch amd64",
        "bash tools/generate-rpm-lock.sh --arch arm64",
        f"git diff --quiet -- {lock_paths}",
        f"git diff -- {lock_paths}",
        "Runtime/FIPS RPM lock pairs already match the current UBI repositories.",
        "exit 1",
    ]
    for marker in required_verify_markers:
        expect(marker in verify_job, f"verify-only job missing fail-closed marker: {marker}")
    if all(marker in verify_job for marker in required_verify_markers[-4:]):
        expect(
            verify_job.index("git diff --quiet")
            < verify_job.index("git diff -- rpm-lock")
            < verify_job.index("exit 1"),
            "verify-only unified diff and non-zero exit ordering is invalid",
        )
    for marker in [
        f"git diff --quiet -- {lock_paths}",
        f"git diff -- {lock_paths}",
        f"git add {lock_paths}",
        '"Refresh runtime and FIPS RPM lockfiles"',
    ]:
        expect(marker in refresh_job, f"refresh job missing atomic runtime/FIPS marker: {marker}")
    return errors


def check_rpm_lock_refresh_workflow(text: str) -> None:
    errors = rpm_lock_refresh_errors(text)
    require(not errors, errors[0] if errors else "RPM lock refresh workflow contract failed")

    mutations = [
        ("write-capable verify token", text.replace("      contents: read", "      contents: write", 1)),
        (
            "verify pull-request token",
            text.replace("      contents: read", "      contents: read\n      pull-requests: write", 1),
        ),
        (
            "verify route overlap",
            text.replace(
                "if: github.event_name == 'workflow_dispatch' && inputs.verify_only", "if: workflow_dispatch", 1
            ),
        ),
        (
            "refresh route overlap",
            text.replace(
                (
                    "if: github.event_name == 'schedule' || "
                    "(github.event_name == 'workflow_dispatch' && !inputs.verify_only)"
                ),
                "if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
                1,
            ),
        ),
        (
            "verify commit",
            text.replace(
                "          set -euo pipefail",
                "          set -euo pipefail\n          git commit -am bad",
                1,
            ),
        ),
        (
            "verify push",
            text.replace("          set -euo pipefail", "          set -euo pipefail\n          git push", 1),
        ),
        (
            "verify PR",
            text.replace("          set -euo pipefail", "          set -euo pipefail\n          gh pr create", 1),
        ),
        (
            "remove unified diff",
            text.replace(
                (
                    "            git diff -- rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt "
                    "rpm-lock/fips-verify.amd64.txt rpm-lock/fips-verify.arm64.txt\n"
                ),
                "",
                1,
            ),
        ),
        (
            "omit FIPS companion from refresh staging",
            text.replace(
                (
                    "git add rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt "
                    "rpm-lock/fips-verify.amd64.txt rpm-lock/fips-verify.arm64.txt"
                ),
                "git add rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt",
                1,
            ),
        ),
        ("remove non-zero exit", text.replace("            exit 1\n", "", 1)),
    ]
    for label, mutated in mutations:
        require(rpm_lock_refresh_errors(mutated), f"RPM lock refresh mutation was not rejected: {label}")
    print(f"RPM lock refresh mutation probes: {len(mutations)}/{len(mutations)} rejected")


def workflow_job_block(text: str, job_id: str, source: str) -> str:
    match = re.search(
        rf"^  {re.escape(job_id)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise VerifyError(f"{source} missing job: {job_id}")
    return match.group(0)


def check_build_hardening_matrix(text: str) -> None:
    hardening = workflow_job_block(text, "hardening", "build workflow")
    aggregate = workflow_job_block(text, "build", "build workflow")

    matrix_shape = """    strategy:
      fail-fast: false
      matrix:
        include:
          - platform: linux/amd64
            arch: amd64
          - platform: linux/arm64
            arch: arm64
    env:
      PLATFORM: ${{ matrix.platform }}
"""
    require(matrix_shape in hardening, "build hardening job must keep the exact amd64/arm64 matrix shape")
    for marker in [
        "    name: hardening (${{ matrix.arch }})",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 15",
        "    needs: verify",
    ]:
        require(marker in hardening, f"build hardening job missing exact marker: {marker.strip()}")
    require(
        re.search(r"^    if:", hardening, flags=re.MULTILINE) is None,
        "build hardening matrix job must not have a job-level if condition",
    )
    require(
        len(list(BINFMT_SITE.finditer(hardening))) == 1,
        "build hardening job must contain exactly one fully pinned amd64/arm64 QEMU setup",
    )
    buildx = "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4.2.0"
    require(hardening.count(buildx) == 1, "build hardening job must contain exactly one pinned Buildx setup")
    require(
        hardening.count("      PLATFORM: ${{ matrix.platform }}") == 1,
        "build hardening job must derive PLATFORM once at job-level env",
    )

    for marker in [
        "    name: build and hardening",
        "    runs-on: ubuntu-24.04",
        "    needs: hardening",
        "    if: ${{ always() }}",
    ]:
        require(marker in aggregate, f"build hardening aggregate missing exact marker: {marker.strip()}")
    require(
        text.count("    name: build and hardening") == 1,
        "build workflow must expose exactly one bare build and hardening check context",
    )
    result_assertion = """      - name: Assert hardening matrix succeeded
        run: |
          if [ "${{ needs.hardening.result }}" != "success" ]; then
            echo "hardening matrix result: ${{ needs.hardening.result }}"
            exit 1
          fi
"""
    require(
        result_assertion in aggregate,
        "build hardening aggregate must fail unless the complete hardening matrix succeeds",
    )
    require("paths:" not in text and "paths-ignore:" not in text, "build workflow must not use path filters")


def check_nightly_hardening_matrix(text: str) -> None:
    hardening = workflow_job_block(text, "hardening", "nightly workflow")
    aggregate = workflow_job_block(text, "build", "nightly workflow")

    matrix_shape = """    strategy:
      fail-fast: false
      matrix:
        include:
          - platform: linux/amd64
            arch: amd64
          - platform: linux/arm64
            arch: arm64
    env:
      PLATFORM: ${{ matrix.platform }}
"""
    require(matrix_shape in hardening, "nightly hardening job must keep the exact amd64/arm64 matrix shape")
    for marker in [
        "    name: hardening (${{ matrix.arch }})",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 15",
        "    needs: verify",
    ]:
        require(marker in hardening, f"nightly hardening job missing exact marker: {marker.strip()}")
    teed_gate = (
        "      - name: Run full test-only gate set\n"
        "        id: hardening-gate\n"
        "        env:\n"
        "          ARCH: ${{ matrix.arch }}\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "          mkdir -p dist/failure-logs\n"
        '          bash tools/run-test-gates.sh 2>&1 | tee "dist/failure-logs/hardening.${ARCH}.log"'
    )
    require(teed_gate in hardening, "nightly hardening job must preserve the exact teed test-gate command")
    require(
        re.search(r"^    if:", hardening, flags=re.MULTILINE) is None,
        "nightly hardening matrix job must not have a job-level if condition",
    )
    require(
        len(list(BINFMT_SITE.finditer(hardening))) == 1,
        "nightly hardening job must contain exactly one fully pinned amd64/arm64 QEMU setup",
    )
    buildx = "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # v4.2.0"
    require(hardening.count(buildx) == 1, "nightly hardening job must contain exactly one pinned Buildx setup")
    require(
        hardening.count("      PLATFORM: ${{ matrix.platform }}") == 1,
        "nightly hardening job must derive PLATFORM once at job-level env",
    )

    for marker in [
        "    name: build and hardening",
        "    runs-on: ubuntu-24.04",
        "    needs: hardening",
        "    if: ${{ always() }}",
    ]:
        require(marker in aggregate, f"nightly hardening aggregate missing exact marker: {marker.strip()}")
    require(
        text.count("    name: build and hardening") == 1,
        "nightly workflow must expose exactly one bare build and hardening check context",
    )
    result_assertion = """      - name: Assert hardening matrix succeeded
        run: |
          if [ "${{ needs.hardening.result }}" != "success" ]; then
            echo "hardening matrix result: ${{ needs.hardening.result }}"
            exit 1
          fi
"""
    require(
        result_assertion in aggregate,
        "nightly hardening aggregate must fail unless the complete hardening matrix succeeds",
    )


def nightly_notification_state_errors(alert: str) -> list[str]:
    ping_condition = (
        '            if [[ "${issue_event}" == "create" || "${issue_event}" == "reopen" \\\n'
        '              || "${latest_signature}" != "${SIGNATURE}" ]]; then'
    )
    ping_post = """              gh api --method POST \\
                "repos/${REPOSITORY}/issues/${issue_number}/comments" \\
                --input "${alert_dir}/attention-comment-request.json" \\
                > "${alert_dir}/comment-response.json"
"""
    required = {
        "validated decision signature": (
            'SIGNATURE="$(jq -er \'.signature | select(type == "string" and '
            'test("^[0-9a-f]{64}$"))\' "${DECISION_FILE}")"'
        ),
        "versioned signature marker": (
            'signature_marker="<!-- ubi9-base-micro-nightly-drift-signature:v1:${SIGNATURE} -->"'
        ),
        "ordered issue timeline": '"repos/${REPOSITORY}/issues/${issue_number}/timeline?per_page=100"',
        "reopen incident boundary": '(.value.event == "reopened")',
        "clean-resolution incident boundary": 'startswith("resolved: clean on ")',
        "post-boundary alert selection": ".key > $incident_boundary",
        "latest in-incident alert selection": '| last // "") as $latest_alert',
        "latest signature extraction": "capture($signature_pattern).signature",
        "create/reopen/signature-change ping condition": ping_condition,
        "signature-bearing owner ping": (
            '--arg body "@${OWNER} nightly drift needs attention: ${RUN_URL}\\n\\n${signature_marker}"'
        ),
        "attention comment mutation": ping_post,
    }
    errors = [label for label, marker in required.items() if marker not in alert]
    if "ubi9-base-micro-nightly-drift-run:" in alert or "RUN_ID:" in alert:
        errors.append("obsolete per-run notification identity")
    return errors


def check_nightly_drift_alert(text: str) -> None:
    reproducibility = workflow_job_block(text, "reproducibility-gate", "nightly workflow")
    hardening = workflow_job_block(text, "hardening", "nightly workflow")
    alert = workflow_job_block(text, "alert", "nightly workflow")

    teed_repro_gate = (
        "      - name: Build twice and assert rootfs byte identity\n"
        "        id: repro-gate\n"
        "        env:\n"
        "          PLATFORM: ${{ matrix.platform }}\n"
        "          ARCH: ${{ matrix.arch }}\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        "          mkdir -p dist/failure-logs\n"
        "\n"
        "          python tools/assert-reproducible.py \\\n"
        '            --platform "${PLATFORM}" \\\n'
        "            --assert-byte-identical \\\n"
        '            --expect-from-contract "contracts/image-manifest.json" \\\n'
        '            --report "dist/reproducibility/base-micro.${ARCH}.reproducibility.json" \\\n'
        '            --summary "dist/reproducibility/base-micro.${ARCH}.reproducibility.txt" \\\n'
        '            --workdir "dist/reproducibility/work.${ARCH}" \\\n'
        '            2>&1 | tee "dist/failure-logs/repro.${ARCH}.log"\n'
        '          cat "dist/reproducibility/base-micro.${ARCH}.reproducibility.txt"\n'
    )
    require(
        teed_repro_gate in reproducibility,
        "nightly reproducibility job must preserve the exact teed reproducibility gate command",
    )

    for block, kind in [(reproducibility, "reproducibility"), (hardening, "hardening")]:
        emit = f"      - name: Emit {kind} decision envelope\n        if: ${{{{ always() }}}}"
        upload = f"      - name: Upload {kind} decision envelope\n        if: ${{{{ always() }}}}"
        require(emit in block, f"nightly {kind} producer must emit with if: always()")
        require(upload in block, f"nightly {kind} producer must upload with if: always()")
        require(block.index(emit) < block.index(upload), f"nightly {kind} envelope must be emitted before upload")

    guarded_failure_log_steps = [
        (
            reproducibility,
            "reproducibility",
            """      - name: Emit reproducibility decision envelope
        if: ${{ always() }}
        env:
          ARCH: ${{ matrix.arch }}
          GATE_OUTCOME: ${{ steps.repro-gate.outcome }}
        run: |
          args=(
            --kind repro
            --arch "${ARCH}"
            --contract contracts/image-manifest.json
            --output "dist/summary/base-micro.${ARCH}.repro.json"
          )
          if [ "${GATE_OUTCOME}" = "failure" ]; then
            args+=(--failure-log "dist/failure-logs/repro.${ARCH}.log")
          fi
          python3 tools/summarize-gates.py "${args[@]}"
""",
        ),
        (
            hardening,
            "hardening",
            """      - name: Emit hardening decision envelope
        if: ${{ always() }}
        env:
          ARCH: ${{ matrix.arch }}
          GATE_OUTCOME: ${{ steps.hardening-gate.outcome }}
        run: |
          args=(
            --kind hardening
            --arch "${ARCH}"
            --contract contracts/image-manifest.json
            --output "dist/summary/base-micro.${ARCH}.hardening.json"
          )
          if [ "${GATE_OUTCOME}" = "failure" ]; then
            args+=(--failure-log "dist/failure-logs/hardening.${ARCH}.log")
          fi
          python3 tools/summarize-gates.py "${args[@]}"
""",
        ),
    ]
    for block, kind, guarded_step in guarded_failure_log_steps:
        require(
            guarded_step in block and block.count("--failure-log") == 1,
            f"nightly {kind} producer must pass --failure-log only under its failed-step outcome guard",
        )
    require_action_sha_pin(text, "nightly workflow", "actions/upload-artifact", count=2)
    require_action_sha_pin(text, "nightly workflow", "actions/download-artifact", count=1)

    for marker in [
        "concurrency:\n  group: nightly-base-micro\n  cancel-in-progress: false",
        "    name: nightly drift alert",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 10",
        "    needs:\n      - hardening\n      - build\n      - reproducibility-gate",
        "    if: ${{ always() && github.event_name != 'pull_request' }}",
        "    permissions:\n      contents: read\n      issues: write",
        "      - name: Download all four nightly decision envelopes\n        if: ${{ always() }}",
        "      - name: Capture nightly job results and run context\n        if: ${{ always() }}",
        "      - name: Render nightly drift issue\n        if: ${{ always() }}",
        "      - name: Log nightly drift decision\n        if: ${{ always() }}",
        "      - name: Maintain sticky nightly drift issue\n        if: ${{ always() }}",
        "tools/render-drift-issue.py",
        "dist/nightly-alert/job-results.json",
        "dist/nightly-alert/run-context.json",
        "dist/nightly-alert/issue-body.md",
        "dist/nightly-alert/decision.json",
        "base-micro.amd64.hardening.json",
        "base-micro.arm64.hardening.json",
        "base-micro.amd64.repro.json",
        "base-micro.arm64.repro.json",
        "pattern: nightly-decision-*",
        '"repos/${REPOSITORY}/issues?state=all&per_page=100"',
        "gh api --paginate --slurp",
        "select(.pull_request == null)",
        '.user.login == $bot and .title == $title and ((.body // "") | contains($marker))',
        'ISSUE_TITLE: "Nightly drift: base-micro security sentinel"',
        'MARKER: "<!-- ubi9-base-micro-nightly-drift:v1 -->"',
        "OWNER: NWarila",
        "assignees: [$owner]",
        '"@${OWNER} nightly drift needs attention:',
        "Multiple matching nightly drift issues found; refusing an ambiguous mutation.",
        'state: "open", state_reason: "reopened"',
        'state: "closed", state_reason: "completed"',
        "resolved: clean on ${run_date}",
        "create-issue-request.json",
        "update-open-issue-request.json",
        "reopen-issue-request.json",
        "issue-timeline.json",
        "attention-comment-request.json",
        "resolved-comment-request.json",
        "close-issue-request.json",
        'signature_marker="<!-- ubi9-base-micro-nightly-drift-signature:v1:${SIGNATURE} -->"',
        '--rawfile body "${BODY_FILE}"',
        '--input "${alert_dir}/',
    ]:
        require(
            marker in text if marker.startswith("concurrency:") else marker in alert,
            f"nightly alert missing marker: {marker}",
        )

    for marker in [
        "nightly-decision-hardening-${{ matrix.arch }}",
        "nightly-decision-repro-${{ matrix.arch }}",
    ]:
        require(marker in text, f"nightly envelope producers missing marker: {marker}")

    permissions_match = re.search(r"^    permissions:\n(?P<body>(?:      [^\n]+\n)+)", alert, flags=re.MULTILINE)
    if permissions_match is None:
        raise VerifyError("nightly alert must declare job-scoped permissions")
    require(
        permissions_match.group("body") == "      contents: read\n      issues: write\n",
        "nightly alert permissions must contain only contents: read and issues: write",
    )
    first_steps = """    steps:
      - name: Harden runner
        uses: step-security/harden-runner@bf7454d06d71f1098171f2acdf0cd4708d7b5920 # v2.20.0
"""
    require(first_steps in alert, "nightly alert must run the pinned harden-runner action first")
    require(
        alert.count("--method ") == alert.count("--input ") == 6,
        "every nightly alert mutation must use an input file",
    )
    state_errors = nightly_notification_state_errors(alert)
    require(not state_errors, f"nightly notification state is incomplete: {', '.join(state_errors)}")
    ping_post = """              gh api --method POST \\
                "repos/${REPOSITORY}/issues/${issue_number}/comments" \\
                --input "${alert_dir}/attention-comment-request.json" \\
                > "${alert_dir}/comment-response.json"
"""
    without_ping = alert.replace(ping_post, "", 1)
    require(without_ping != alert, "nightly ping-removal mutation fixture did not change")
    require(
        nightly_notification_state_errors(without_ping),
        "nightly ping-removal mutation unexpectedly passed",
    )
    require(
        alert.index("      - name: Log nightly drift decision")
        < alert.index("      - name: Maintain sticky nightly drift issue"),
        "nightly drift body must be logged before the sticky issue lifecycle",
    )
    for forbidden in [
        "continue-on-" + "error",
        "id-token:",
        "packages:",
        "checks:",
        "statuses:",
        "pull-requests:",
    ]:
        require(forbidden not in alert, f"nightly alert has forbidden permission or soft-fail marker: {forbidden}")


NightlyDriftInputs = tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]


def nightly_drift_signature_fixture() -> NightlyDriftInputs:
    hardening_amd64: dict[str, Any] = {
        "schema_version": "1.1.0",
        "kind": "hardening",
        "arch": "amd64",
        "complete": True,
        "attention_reasons": ["amd64 hardening requires attention"],
        "stig": {"total_rule_results": 1532, "pass": 39, "fail": 1, "not_selected": 1492},
        "secrets": {"finding_count": 1, "passed": False},
        "footprint": {"regular_file_bytes": 23841246, "limit_bytes": 26214400, "passed": True},
    }
    hardening_arm64 = copy.deepcopy(hardening_amd64)
    hardening_arm64.update(
        {
            "arch": "arm64",
            "attention_reasons": [],
            "stig": {"total_rule_results": 1532, "pass": 39, "fail": 0, "not_selected": 1493},
            "secrets": {"finding_count": 0, "passed": True},
        }
    )

    def repro(arch: str) -> dict[str, Any]:
        return {
            "schema_version": "1.1.0",
            "kind": "repro",
            "arch": arch,
            "complete": True,
            "attention_reasons": [],
            "reproducibility": {
                "byte_identical": True,
                "rootfs_matches_contract": True,
                "rpmdb_matches_contract": True,
            },
        }

    envelopes = [hardening_amd64, hardening_arm64, repro("amd64"), repro("arm64")]
    job_results = {"hardening": "success", "build": "success", "reproducibility-gate": "success"}
    run_context = {
        "run_url": "https://github.com/NWarila/ubi9-base-micro/actions/runs/123",
        "date": "2026-07-13",
    }
    return envelopes, job_results, run_context


def nightly_drift_signature_from_cli(temp_root: Path, label: str, inputs: NightlyDriftInputs) -> str:
    envelopes, job_results, run_context = inputs
    envelope_paths = [
        temp_root / "hardening-amd64.json",
        temp_root / "hardening-arm64.json",
        temp_root / "repro-amd64.json",
        temp_root / "repro-arm64.json",
    ]
    for path, envelope in zip(envelope_paths, envelopes, strict=True):
        path.write_text(json.dumps(envelope, sort_keys=True) + "\n", encoding="utf-8")
    job_results_path = temp_root / "job-results.json"
    job_results_path.write_text(json.dumps(job_results, sort_keys=True) + "\n", encoding="utf-8")
    run_context_path = temp_root / "run-context.json"
    run_context_path.write_text(json.dumps(run_context, sort_keys=True) + "\n", encoding="utf-8")
    body_path = temp_root / "issue-body.md"
    decision_path = temp_root / "decision.json"

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/render-drift-issue.py"),
                "--hardening-amd64",
                str(envelope_paths[0]),
                "--hardening-arm64",
                str(envelope_paths[1]),
                "--repro-amd64",
                str(envelope_paths[2]),
                "--repro-arm64",
                str(envelope_paths[3]),
                "--job-results",
                str(job_results_path),
                "--run-context",
                str(run_context_path),
                "--body-output",
                str(body_path),
                "--decision-output",
                str(decision_path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise VerifyError(f"nightly drift signature mutation {label!r} could not invoke the renderer: {exc}") from exc
    require(
        result.returncode == 0,
        f"nightly drift signature mutation {label!r} failed to render:\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
    )
    try:
        decision_value: Any = json.loads(decision_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifyError(f"nightly drift signature mutation {label!r} produced no valid decision JSON: {exc}") from exc
    require(isinstance(decision_value, dict), f"nightly drift signature mutation {label!r} decision is not an object")
    signature = decision_value.get("signature")
    require(
        isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{64}", signature) is not None,
        f"nightly drift signature mutation {label!r} produced an invalid signature",
    )
    return cast(str, signature)


def mutate_nightly_drift_input(inputs: NightlyDriftInputs, path: tuple[str | int, ...], value: Any) -> None:
    require(bool(path), "nightly drift signature mutation path must not be empty")
    target: Any = inputs
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def check_nightly_drift_signature_self_test() -> None:
    baseline_inputs = nightly_drift_signature_fixture()
    severity_mutations: list[tuple[str, tuple[str | int, ...], Any]] = [
        ("STIG fail count 1-to-17", (0, 0, "stig", "fail"), 17),
        ("repro byte-identical boolean", (0, 2, "reproducibility", "byte_identical"), False),
        ("repro rootfs-contract boolean", (0, 2, "reproducibility", "rootfs_matches_contract"), False),
        ("repro RPMDB-contract boolean", (0, 2, "reproducibility", "rpmdb_matches_contract"), False),
        ("footprint pass-to-fail", (0, 0, "footprint", "passed"), False),
        ("job-result state", (1, "build"), "failure"),
        ("run-context validity", (2, "run_url"), "http://invalid.example/run/123"),
        ("producer-attention presence", (0, 0, "attention_reasons"), []),
        ("secret finding count", (0, 0, "secrets", "finding_count"), 3),
        ("safe failure_detail", (0, 2, "failure_detail"), "rpmdb digest mismatch: expected a, actual b"),
    ]
    stability_mutations: list[tuple[str, tuple[str | int, ...], Any]] = [
        ("run_url", (2, "run_url"), "https://github.com/NWarila/ubi9-base-micro/actions/runs/999"),
        ("date", (2, "date"), "2099-12-31"),
        ("footprint regular-file bytes", (0, 0, "footprint", "regular_file_bytes"), 1),
        ("footprint limit bytes", (0, 0, "footprint", "limit_bytes"), 30000000),
        ("STIG total results", (0, 0, "stig", "total_rule_results"), 9000),
        ("STIG pass count", (0, 0, "stig", "pass"), 8000),
        ("STIG not-selected count", (0, 0, "stig", "not_selected"), 1000),
    ]

    with tempfile.TemporaryDirectory(prefix=".verify-drift-signature-", dir=ROOT) as tmp:
        temp_root = Path(tmp)
        baseline_signature = nightly_drift_signature_from_cli(temp_root, "baseline", baseline_inputs)
        for label, path, value in severity_mutations:
            mutated_inputs = copy.deepcopy(baseline_inputs)
            mutate_nightly_drift_input(mutated_inputs, path, value)
            mutated_signature = nightly_drift_signature_from_cli(temp_root, label, mutated_inputs)
            require(
                mutated_signature != baseline_signature,
                f"nightly drift signature severity invariant failed for {label}: signature did not change",
            )
        for label, path, value in stability_mutations:
            mutated_inputs = copy.deepcopy(baseline_inputs)
            mutate_nightly_drift_input(mutated_inputs, path, value)
            mutated_signature = nightly_drift_signature_from_cli(temp_root, label, mutated_inputs)
            require(
                mutated_signature == baseline_signature,
                f"nightly drift signature stability invariant failed for {label}: signature changed",
            )
    print(
        f"Nightly drift signature mutation probes: {len(severity_mutations)}/{len(severity_mutations)} severity "
        f"mutations changed; {len(stability_mutations)}/{len(stability_mutations)} stability mutations preserved"
    )


def check_pr_decision_surface(text: str) -> None:
    reproducibility = workflow_job_block(text, "reproducibility-gate", "build workflow")
    hardening = workflow_job_block(text, "hardening", "build workflow")
    decision = workflow_job_block(text, "decision-surface", "build workflow")

    for block, kind in [(reproducibility, "reproducibility"), (hardening, "hardening")]:
        emit = f"      - name: Emit {kind} decision envelope\n        if: ${{{{ always() }}}}"
        upload = f"      - name: Upload {kind} decision envelope\n        if: ${{{{ always() }}}}"
        require(emit in block, f"{kind} decision producer must emit with if: always()")
        require(upload in block, f"{kind} decision producer must upload with if: always()")
        require(block.index(emit) < block.index(upload), f"{kind} decision envelope must be emitted before upload")
    require_action_sha_pin(text, "build workflow", "actions/upload-artifact", count=2)
    require_action_sha_pin(text, "build workflow", "actions/download-artifact", count=1)

    for marker in [
        "    name: PR decision surface",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 10",
        "    needs:\n      - reproducibility-gate\n      - hardening\n      - build",
        "    if: ${{ always() && github.event_name == 'pull_request' }}",
        (
            "    permissions:\n"
            "      contents: read\n"
            "      checks: read\n"
            "      statuses: read\n"
            "      pull-requests: write"
        ),
        "github.event.pull_request.head.sha",
        'select(.name == "Pull Request Gate" and .enforcement == "active")',
        "required_status_checks",
        "check-runs?per_page=100",
        "status-rollup.json",
        "for attempt in 1 2 3 4 5 6; do",
        "sleep 15",
        "tools/render-pr-decision.py",
        "cat dist/decision/pr-comment.md",
        'cat dist/decision/pr-comment.md >> "${GITHUB_STEP_SUMMARY}"',
        'if [[ "${HEAD_REPOSITORY}" != "${REPOSITORY}" ]]; then',
        "Fork PR trust boundary: sticky comment write skipped",
        '"repos/${REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100"',
        '.user.login == "github-actions[bot]"',
        'jq -n --rawfile body "${BODY_FILE}"',
        "gh api --method PATCH",
        "gh api --method POST",
        "<!-- ubi9-base-micro-pr-decision:v1 -->",
    ]:
        require(marker in decision, f"PR decision surface missing exact marker: {marker.strip()}")
    require(
        decision.index("      - name: Log PR decision")
        < decision.index("      - name: Post or update sticky PR decision"),
        "PR decision body must be logged before the sticky write",
    )
    for forbidden in ["continue-on-" + "error", "pull_request_target", "id-token:", "packages:", "issues:"]:
        require(forbidden not in decision, f"PR decision surface has forbidden permission/event marker: {forbidden}")


def check_workflow() -> None:
    workflows = sorted(path.name for path in (ROOT / ".github/workflows").glob("*.y*ml"))
    require(
        workflows
        == [
            "build.yaml",
            "codeql.yml",
            "dependency-review.yml",
            "lint.yaml",
            "nightly.yaml",
            "publish-image.yaml",
            "publish-python.yaml",
            "python-ci.yaml",
            "rpm-lock-refresh.yaml",
            "scorecard.yml",
            "zizmor.yml",
        ],
        "repo must ship exactly the expected baseline and supply-chain workflows",
    )

    build = read(".github/workflows/build.yaml")
    nightly = read(".github/workflows/nightly.yaml")
    refresh = read(".github/workflows/rpm-lock-refresh.yaml")
    check_build_hardening_matrix(build)
    check_pr_decision_surface(build)
    check_nightly_hardening_matrix(nightly)
    check_nightly_drift_alert(nightly)
    check_rpm_lock_refresh_workflow(refresh)
    gate_runner = read("tools/run-test-gates.sh")
    for source, source_text in [
        ("build workflow", build),
        ("nightly workflow", nightly),
        ("RPM lock refresh workflow", refresh),
    ]:
        require("runs-on: ubuntu-latest" not in source_text, f"{source} must not use moving ubuntu-latest runner")
        require("runs-on: ubuntu-24.04" in source_text, f"{source} must pin ubuntu-24.04 runner")

    for marker in [
        "pull_request:",
        "push:",
        "branches: [main]",
        "tags:",
        "workflow_dispatch:",
        "tools/verify.py",
        "tools/assert-sbom-rpms.py --self-test",
        "tools/assert-footprint.py --self-test",
        "tools/assert-no-phantom-packages.py --self-test",
        "tools/assert-reproducible.py --self-test",
        "python tools/assert-rpm-lock-hashes.py --self-test",
        "bash tools/generate-rpm-lock.sh --self-test",
        "tools/assert-scanner-db-freshness.py --self-test",
        "tools/assert-no-rootfs-secrets.py --self-test",
        "tools/generate-nist-800-190-predicate.py --self-test",
        "tools/assert-slsa-builder-id.py --self-test",
        "tools/assert-stig-tailoring.py --self-test",
        "tools/assert-rootfs-identity.py --self-test",
        "tools/assert-stig-arf.py --self-test",
        "tools/generate-stig-arf-predicate.py --self-test",
        "bash -n tools/run-test-gates.sh",
        "bash -n tools/fetch-runtime-rpms.sh",
        "bash -n tools/generate-rpm-lock.sh",
        "UBI_MICRO_IMAGE: registry.access.redhat.com/ubi9/ubi-micro@sha256:",
        'TRIVY_VERSION: "0.71.0"',
        'GRYPE_VERSION: "0.115.0"',
        'SCANNER_DB_MAX_AGE_DAYS: "7"',
        'SSG_VERSION: "0.1.81"',
        (
            'SSG_TARBALL_SHA512: "11e26cfa96a6f1bd98b3a131837e2f86c9a9851239337d86d624b01627faf10'
            'f7a03c395a5839ddab018e0fa47719ade05a9946f90d5ca96b1261776a9164379"'
        ),
        'STIG_PROFILE: "xccdf_org.nwarila.content_profile_ubi9_base_micro_stig"',
        'STIG_FAIL_ON: "low"',
        "reproducibility gate",
        "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8",
        "platform: linux/amd64",
        "platform: linux/arm64",
        "--assert-byte-identical",
        "--expect-from-contract",
        "contracts/image-manifest.json",
        "dist/reproducibility/base-micro.${ARCH}.reproducibility.json",
        "Run full test-only gate set",
        "tools/run-test-gates.sh",
        "ghcr.io/nwarila/ubi9-base-micro",
    ]:
        require(marker in build, f"build workflow missing marker: {marker}")

    for marker in [
        "schedule:",
        'cron: "23 4 * * *"',
        "workflow_dispatch:",
        "contents: read",
        "cancel-in-progress: false",
        "tools/verify.py",
        "python tools/assert-rpm-lock-hashes.py --self-test",
        "bash tools/generate-rpm-lock.sh --self-test",
        "tools/assert-scanner-db-freshness.py --self-test",
        "bash -n tools/run-test-gates.sh",
        "bash -n tools/fetch-runtime-rpms.sh",
        "bash -n tools/generate-rpm-lock.sh",
        "UBI_MICRO_IMAGE: registry.access.redhat.com/ubi9/ubi-micro@sha256:",
        'TRIVY_VERSION: "0.71.0"',
        'GRYPE_VERSION: "0.115.0"',
        'SCANNER_DB_MAX_AGE_DAYS: "7"',
        'SSG_VERSION: "0.1.81"',
        (
            'SSG_TARBALL_SHA512: "11e26cfa96a6f1bd98b3a131837e2f86c9a9851239337d86d624b01627faf10'
            'f7a03c395a5839ddab018e0fa47719ade05a9946f90d5ca96b1261776a9164379"'
        ),
        'STIG_PROFILE: "xccdf_org.nwarila.content_profile_ubi9_base_micro_stig"',
        'STIG_FAIL_ON: "low"',
        "reproducibility gate",
        "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8",
        "platform: linux/amd64",
        "platform: linux/arm64",
        "--assert-byte-identical",
        "--expect-from-contract",
        "contracts/image-manifest.json",
        "dist/reproducibility/base-micro.${ARCH}.reproducibility.json",
        "Run full test-only gate set",
        "tools/run-test-gates.sh",
        "ghcr.io/nwarila/ubi9-base-micro",
    ]:
        require(marker in nightly, f"nightly workflow missing marker: {marker}")

    require("pull_request:" not in nightly, "nightly workflow must not run as PR CI")
    require("\npush:" not in nightly, "nightly workflow must not run on push")
    check_cosign_before_test_gates(build, "build workflow")
    check_cosign_before_test_gates(nightly, "nightly workflow")

    for marker in [
        "schedule:",
        "workflow_dispatch:",
        "contents: write",
        "pull-requests: write",
        "cancel-in-progress: false",
        "bash -n tools/generate-rpm-lock.sh",
        "bash tools/generate-rpm-lock.sh --self-test",
        "bash tools/generate-rpm-lock.sh --arch amd64",
        "bash tools/generate-rpm-lock.sh --arch arm64",
        (
            "git diff --quiet -- rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt "
            "rpm-lock/fips-verify.amd64.txt rpm-lock/fips-verify.arm64.txt"
        ),
        (
            "git diff -- rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt "
            "rpm-lock/fips-verify.amd64.txt rpm-lock/fips-verify.arm64.txt"
        ),
        (
            "git add rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt "
            "rpm-lock/fips-verify.amd64.txt rpm-lock/fips-verify.arm64.txt"
        ),
        "github-actions[bot]",
        "gh pr list",
        "gh pr create",
        "--base main",
        '--head "${branch}"',
        "Refresh runtime and FIPS RPM lockfiles",
        "build and\n          hardening gates",
        "byte-for-byte reproducibility gates",
        "fixable-CVE gates",
        "RPM content-hash enforcement",
    ]:
        require(marker in refresh, f"RPM lock refresh workflow missing marker: {marker}")

    require("pull_request:" not in refresh, "RPM lock refresh workflow must not run as PR CI")
    require("\npush:" not in refresh, "RPM lock refresh workflow must not run on push")
    for marker in [
        "continue-on-" + "error",
        "gh pr merge",
        "--auto",
        "auto-merge",
        "packages:",
        "id-token:",
        "docker " + "push",
        "co" + "sign",
        "generator_container_" + "sl" + "sa3",
    ]:
        require(marker not in refresh, f"RPM lock refresh workflow contains forbidden marker: {marker}")

    for marker in [
        "bash tools/install-syft.sh",
        "bash tools/install-trivy.sh",
        "bash tools/install-grype.sh",
        "SCANNER_DB_MAX_AGE_DAYS",
        "dist/tools/trivy image --download-db-only",
        "dist/tools/grype db update",
        "tools/assert-scanner-db-freshness.py",
        "tools/assert-scanner-canary.py",
        "GRYPE_DB_VALIDATE_AGE=true",
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE",
        "bash tools/install-openscap.sh",
        "bash tools/build-stig-datastream.sh",
        "bash tools/build.sh",
        'bash tests/hardening.sh "${runtime_image}"',
        'bash tests/fips.sh "${runtime_image}"',
        "tools/assert-footprint.py",
        "dist/footprint/base-micro.${arch}.json",
        "bash tools/run-stig-arf.sh",
        "dist/tools/syft scan",
        "json=dist/sbom/base-micro.${arch}.syft.json",
        "spdx-json=dist/sbom/base-micro.${arch}.spdx.json",
        "cyclonedx-json=dist/sbom/base-micro.${arch}.cdx.json",
        '--source "dist/sbom/base-micro.${arch}.syft.json"',
        "tools/assert-no-phantom-packages.py",
        "dist/sbom/base-micro.${arch}.phantom-packages.json",
        "--expect-absent libacl",
        "--expect-absent libattr",
        "--expect-absent libcap",
        "--expect-absent coreutils-common",
        "--expect-absent pcre2-syntax",
        "--expect-absent alternatives",
        "dist/tools/trivy image",
        "--ignore-unfixed",
        "--severity MEDIUM,HIGH,CRITICAL",
        "--ignorefile security/cve-ignore.trivyignore.yaml",
        "--exit-code 1",
        "--only-fixed",
        "--fail-on medium",
        "-c security/cve-ignore.grype.yaml",
        "tools/assert-no-rootfs-secrets.py",
        "tools/generate-nist-800-190-predicate.py",
        '--validate "${predicate}"',
        "python3.12 /tmp/assert-rpm-lock-hashes.py --root /rootfs --lockfile",
    ]:
        require(
            marker in gate_runner or marker in read("containers/Dockerfile"),
            f"test gate runner missing marker: {marker}",
        )

    freshness_index = gate_runner.find("tools/assert-scanner-db-freshness.py")
    first_trivy_scan_index = gate_runner.find("--ignore-unfixed")
    first_grype_scan_index = gate_runner.find("--only-fixed")
    require(freshness_index >= 0, "test gate runner must invoke scanner DB freshness gate")
    require(first_trivy_scan_index >= 0, "test gate runner must keep Trivy fixable scan")
    require(first_grype_scan_index >= 0, "test gate runner must keep Grype fixable scan")
    require(
        freshness_index < first_trivy_scan_index and freshness_index < first_grype_scan_index,
        "scanner DB freshness gate must run before vulnerability scans",
    )
    trivy_gate_start = gate_runner.rfind("dist/tools/trivy image", 0, first_trivy_scan_index)
    grype_gate_start = gate_runner.rfind("dist/tools/grype", 0, first_grype_scan_index)
    grype_gate_end = gate_runner.find("\n\n", first_grype_scan_index)
    require(
        trivy_gate_start >= 0 and grype_gate_start > trivy_gate_start and grype_gate_end > grype_gate_start,
        "test gate runner must keep bounded native fixable scanner gates",
    )
    trivy_gate = gate_runner[trivy_gate_start:grype_gate_start]
    grype_gate = gate_runner[grype_gate_start:grype_gate_end]
    require(
        all(
            marker in trivy_gate
            for marker in (
                "--ignore-unfixed",
                "--severity MEDIUM,HIGH,CRITICAL",
                "--ignorefile security/cve-ignore.trivyignore.yaml",
                "--exit-code 1",
            )
        )
        and all(
            marker in grype_gate for marker in ("--only-fixed", "--fail-on medium", "-c security/cve-ignore.grype.yaml")
        ),
        "fixable scanner gate pass must use both explicit non-default ignore files",
    )
    for retired in (
        "assert-vex.py",
        "assert-ignore-scope.py",
        ".trivy.all.json",
        ".grype.all.json",
        ".grype.gate.json",
    ):
        require(retired not in gate_runner, f"test gate runner retains retired policy/report marker: {retired}")

    forbidden = [
        "NWarila/.github/.github/workflows/",
        "reusable-",
        "--" + "push",
        "docker " + "push",
        "generator_container_" + "sl" + "sa3",
        "attest-build-" + "provenance",
        "continue-on-" + "error",
    ]
    for source, source_text in [
        ("build workflow", build),
        ("nightly workflow", nightly),
        ("test gate runner", gate_runner),
        ("refresh workflow", refresh),
    ]:
        present = [marker for marker in forbidden if marker in source_text]
        require(not present, f"{source} contains out-of-scope marker(s): " + ", ".join(present))

    for source, source_text in [("test gate runner", gate_runner), ("refresh workflow", refresh)]:
        require("co" + "sign" not in source_text, f"{source} must not install or invoke Cosign")

    check_uses_pinned(build, "build workflow")
    check_uses_pinned(nightly, "nightly workflow")
    check_uses_pinned(refresh, "RPM lock refresh workflow")
    reviewdog_annotation = re.compile(
        r"uses:\s+reviewdog/action-actionlint@[^\s#]+\s+#\s+"
        r"(v?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?);\s+"
        r"bundles actionlint (v?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?)"
    )
    for source, source_text in [("build workflow", build), ("nightly workflow", nightly)]:
        require_action_sha_pin(source_text, source, "reviewdog/action-actionlint", count=1)
        annotation_match = reviewdog_annotation.search(source_text)
        if annotation_match is None:
            raise VerifyError(f"{source} must document version-shaped reviewdog and actionlint pins")
        require_version_literal(annotation_match.group(1), f"{source} reviewdog annotation")
        require_version_literal(annotation_match.group(2), f"{source} bundled actionlint annotation")


def check_supply_chain_workflows() -> None:
    gitignore = read(".gitignore")
    for relative_path in [".github/zizmor.yml", *SUPPLY_CHAIN_WORKFLOWS]:
        require(f"!/{relative_path}" in gitignore, f".gitignore must allowlist supply-chain path: {relative_path}")

    workflow_paths = [
        ".github/workflows/build.yaml",
        ".github/workflows/nightly.yaml",
        ".github/workflows/publish-image.yaml",
        ".github/workflows/python-ci.yaml",
        ".github/workflows/rpm-lock-refresh.yaml",
        *SUPPLY_CHAIN_WORKFLOWS,
    ]
    for relative_path in workflow_paths:
        text = read(relative_path)
        check_workflow_uses_present(text, relative_path)
        check_uses_pinned(text, relative_path)
        check_no_continue_on_error(text, relative_path)
        check_harden_runner_audit_steps(text, relative_path)
        require("runs-on: ubuntu-latest" not in text, f"{relative_path} must not use moving ubuntu-latest runner")

    scorecard = read(".github/workflows/scorecard.yml")
    for action in ["actions/checkout", "ossf/scorecard-action", "github/codeql-action/upload-sarif"]:
        require_action_sha_pin(scorecard, "scorecard workflow", action, count=1)
    for marker in [
        "name: OpenSSF Scorecard",
        "push:\n    branches: [main]",
        "schedule:",
        'cron: "17 6 * * 1"',
        "branch_protection_rule:",
        "types: [created, edited, deleted]",
        "permissions: {}",
        "permissions:\n      contents: read\n      id-token: write\n      security-events: write",
        "results_file: results.sarif",
        "results_format: sarif",
        "publish_results: true",
        "sarif_file: results.sarif",
    ]:
        require(marker in scorecard, f"scorecard workflow missing marker: {marker}")
    require("pull_request:" not in scorecard, "scorecard workflow must not run on pull_request")
    for forbidden in ["issues:", "pull-requests:", "checks:"]:
        require(forbidden not in scorecard, f"scorecard workflow has non-minimal permission marker: {forbidden}")

    codeql = read(".github/workflows/codeql.yml")
    for action in ["actions/checkout", "github/codeql-action/init", "github/codeql-action/analyze"]:
        require_action_sha_pin(codeql, "CodeQL workflow", action, count=1)
    for marker in [
        "name: CodeQL",
        "pull_request:\n    branches: [main]",
        "push:\n    branches: [main]",
        "schedule:",
        'cron: "37 6 * * 2"',
        "permissions: {}",
        "permissions:\n      actions: read\n      contents: read\n      security-events: write",
        "languages: python",
        "build-mode: none",
        "queries: security-extended",
        "paths:\n              - tools",
    ]:
        require(marker in codeql, f"CodeQL workflow missing marker: {marker}")
    for forbidden in ["id-token:", "packages:", "pull-requests:"]:
        require(forbidden not in codeql, f"CodeQL workflow has non-minimal permission marker: {forbidden}")

    dependency_review = read(".github/workflows/dependency-review.yml")
    for action in ["actions/checkout", "actions/dependency-review-action"]:
        require_action_sha_pin(dependency_review, "dependency review workflow", action, count=1)
    for marker in [
        "name: Dependency review",
        "pull_request:\n    branches: [main]",
        "permissions: {}",
        "permissions:\n      contents: read\n      pull-requests: read",
        "fail-on-severity: high",
    ]:
        require(marker in dependency_review, f"dependency review workflow missing marker: {marker}")
    for forbidden in ["push:", "schedule:", "id-token:", "packages:", "security-events:"]:
        require(forbidden not in dependency_review, f"dependency review workflow has non-minimal marker: {forbidden}")

    zizmor = read(".github/workflows/zizmor.yml")
    for action in ["actions/checkout", "zizmorcore/zizmor-action"]:
        require_action_sha_pin(zizmor, "zizmor workflow", action, count=1)
    zizmor_version_match = re.search(r"^\s+version:\s+([^\s#]+)\s*$", zizmor, flags=re.MULTILINE)
    if zizmor_version_match is None:
        raise VerifyError("zizmor workflow must declare a literal tool version")
    require_version_literal(zizmor_version_match.group(1), "zizmor workflow tool version")
    for marker in [
        "name: zizmor",
        "pull_request:\n    branches: [main]",
        "push:\n    branches: [main]",
        "permissions: {}",
        "permissions:\n      actions: read\n      contents: read\n      security-events: write",
        "inputs: .github/workflows/",
        "config: .github/zizmor.yml",
        "advanced-security: true",
    ]:
        require(marker in zizmor, f"zizmor workflow missing marker: {marker}")
    for forbidden in ["id-token:", "packages:", "pull-requests:"]:
        require(forbidden not in zizmor, f"zizmor workflow has non-minimal permission marker: {forbidden}")

    zizmor_config = read(".github/zizmor.yml")
    for marker in [
        "rules:",
        "unpinned-uses:",
        "policies:",
        'slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml": ref-pin',
        '"*": hash-pin',
    ]:
        require(marker in zizmor_config, f"zizmor config missing marker: {marker}")

    readme = read("README.md")
    for marker in [
        "https://api.scorecard.dev/projects/github.com/NWarila/ubi9-base-micro/badge",
        "https://scorecard.dev/viewer/?uri=github.com/NWarila/ubi9-base-micro",
        "https://github.com/NWarila/ubi9-base-micro/actions/workflows/codeql.yml/badge.svg",
        "https://github.com/NWarila/ubi9-base-micro/actions/workflows/codeql.yml",
    ]:
        require(marker in readme, f"README.md missing supply-chain badge marker: {marker}")
    forbidden_badges = [
        "bestpractices.coreinfrastructure.org",
        "bestpractices.coreinfrastructure",
        "CII Best Practices",
    ]
    present = [marker for marker in forbidden_badges if marker.lower() in readme.lower()]
    require(not present, "README.md must not add OpenSSF Best Practices / CII badge: " + ", ".join(present))


COSIGN_TRUST_EXACT_FLAGS = [
    "--private-infrastructure",
    "--trusted-root",
    "--ca-roots",
    "--certificate-chain",
    "--rekor-url",
    "--fulcio-url",
    "--timestamp-certificate-chain",
    "--key",
    "--sk",
]
COSIGN_TRUST_FAMILY_PREFIXES = ["--insecure-", "--tsa-", "--tuf-"]
COSIGN_TRUST_ENV_PREFIXES = ["SIGSTORE_", "TUF_"]
COSIGN_TRUST_MUTATIONS = [
    ("private-infrastructure", "--private-infrastructure"),
    ("trusted-root", "--trusted-root /tmp/trusted-root.json"),
    ("ca-roots", "--ca-roots /tmp/ca-roots.pem"),
    ("certificate-chain", "--certificate-chain /tmp/certificate-chain.pem"),
    ("rekor-url", "--rekor-url https://rekor.invalid"),
    ("fulcio-url", "--fulcio-url https://fulcio.invalid"),
    ("timestamp-certificate-chain", "--timestamp-certificate-chain /tmp/tsa-chain.pem"),
    ("insecure-family", "--insecure-future-flag"),
    ("tsa-family", "--tsa-future-override value"),
    ("tuf-family", "--tuf-future-override value"),
    ("cosign-initialize", "cosign initialize"),
    ("key", "--key /tmp/cosign.pub"),
    ("sk", "--sk"),
    ("sigstore-env", "SIGSTORE_ROOT_FILE=/tmp/trusted-root.json"),
    ("tuf-env", "TUF_ROOT=/tmp/tuf-root.json"),
]


def exact_shell_token_present(text: str, token: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_-]){re.escape(token)}(?![A-Za-z0-9_-])", text) is not None


def cosign_trust_substitution_errors(text: str) -> list[str]:
    code = uncommented_shell(text)
    errors: list[str] = []
    present_exact = [flag for flag in COSIGN_TRUST_EXACT_FLAGS if exact_shell_token_present(code, flag)]
    if present_exact:
        errors.append("Cosign trust-substitution flag(s) are forbidden: " + ", ".join(present_exact))

    present_families = [prefix for prefix in COSIGN_TRUST_FAMILY_PREFIXES if prefix in code]
    if present_families:
        errors.append("Cosign trust-substitution flag family/families are forbidden: " + ", ".join(present_families))

    if re.search(r"(?<![A-Za-z0-9_-])cosign\s+initialize(?![A-Za-z0-9_-])", code) is not None:
        errors.append("cosign initialize is forbidden because it can substitute the trust root")

    env_pattern = rf"(?<![A-Za-z0-9_])(?:{'|'.join(COSIGN_TRUST_ENV_PREFIXES)})[A-Za-z0-9_]*"
    present_env = sorted(set(re.findall(env_pattern, code)))
    if present_env:
        errors.append("Sigstore/TUF trust environment override(s) are forbidden: " + ", ".join(present_env))
    return errors


def publish_trust_policy_errors(text: str) -> list[str]:
    errors = cosign_trust_substitution_errors(text)
    code = uncommented_shell(text)
    if exact_shell_token_present(code, "--check-claims=false"):
        errors.append("Cosign --check-claims=false is forbidden because claim verification must remain enabled")
    return errors


def check_publish_trust_policy_mutations(text: str) -> int:
    require(not publish_trust_policy_errors(text), "publish trust-policy baseline fixture must pass")
    print("publish trust-policy baseline probe accepted")
    mutations = [*COSIGN_TRUST_MUTATIONS, ("check-claims-false", "--check-claims=false")]
    rejected = 0
    for label, marker in mutations:
        mutated = text + f"\n{marker}\n"
        require(mutated != text, f"publish trust-policy mutation fixture did not change: {label}")
        require(publish_trust_policy_errors(mutated), f"publish trust-policy mutation was not rejected: {label}")
        print(f"publish trust-policy mutation rejected: {label}")
        rejected += 1

        comment_only = text + f"\n# {marker}\n"
        require(comment_only != text, f"publish trust-policy comment fixture did not change: {label}")
        require(
            not publish_trust_policy_errors(comment_only),
            f"publish trust-policy full-line comment caused a false positive: {label}",
        )
        print(f"publish trust-policy comment probe accepted: {label}")
    return rejected


def check_publish_workflow() -> None:
    text = read(".github/workflows/publish-image.yaml")
    require("runs-on: ubuntu-latest" not in text, "publish workflow must not use moving ubuntu-latest runner")
    require("runs-on: ubuntu-24.04" in text, "publish workflow must pin ubuntu-24.04 runner")
    required = [
        "pull_request:",
        "push:",
        "branches: [main]",
        "tags:",
        "ghcr.io/nwarila/ubi9-base-micro",
        "github.event_name == 'push'",
        "--platform linux/amd64,linux/arm64",
        "--target runtime",
        "--provenance=mode=max",
        "--sbom=false",
        "--metadata-file dist/image-metadata.json",
        '--output "type=registry,rewrite-timestamp=true"',
        "OPENSSL_FIPS_MODULE_VERSION",
        f'OPENSSL_FIPS_MODULE_VERSION: "{fips_module_version()}"',
        f'OPENSSL_FIPS_PROVIDER_NEVRA: "{fips_provider_nevra()}"',
        "OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64",
        "OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64",
        "OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64",
        "OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64",
        "manifest[linux/amd64]:org.nwarila.fips.module-version",
        "manifest[linux/amd64]:org.nwarila.fips.provider-nvr",
        "manifest[linux/arm64]:org.nwarila.fips.module-version",
        "manifest[linux/arm64]:org.nwarila.fips.provider-nvr",
        'SOURCE_DATE_EPOCH: "1704067200"',
        'OCI_CREATED: "2024-01-01T00:00:00Z"',
        'SYFT_VERSION: "1.45.1"',
        'TRIVY_VERSION: "0.71.0"',
        'GRYPE_VERSION: "0.115.0"',
        'CRANE_VERSION: "v0.21.7"',
        'SCANNER_DB_MAX_AGE_DAYS: "7"',
        "tools/build-stig-datastream.sh",
        "tools/run-stig-arf.sh",
        f'NIST_800_190_PREDICATE_TYPE: "{predicate_type("nist_800_190")}"',
        f'STIG_ARF_PREDICATE_TYPE: "{predicate_type("stig_arf")}"',
        "sudo podman login ghcr.io",
        "Run tailored STIG ARF gates",
        "tools/install-syft.sh",
        "tools/install-trivy.sh",
        "tools/install-grype.sh",
        "bash tools/install-crane.sh",
        'crane export "${IMAGE}@${digest}" "${rootfs_tar}"',
        "--rootfs-tar",
        '--arch "${arch}"',
        "--expect-from-contract contracts/image-manifest.json",
        "Assert scanner DB freshness",
        "dist/tools/trivy image --download-db-only",
        "dist/tools/grype db update",
        "tools/assert-scanner-db-freshness.py",
        "GRYPE_DB_VALIDATE_AGE=true",
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE",
        "${GITHUB_ENV}",
        "docker buildx imagetools inspect --raw",
        "steps.platform_digests.outputs.amd64_digest",
        "steps.platform_digests.outputs.arm64_digest",
        "dist/tools/syft scan",
        "json=dist/sbom/base-micro.${arch}.syft.json",
        "spdx-json=dist/sbom/base-micro.${arch}.spdx.json",
        "cyclonedx-json=dist/sbom/base-micro.${arch}.cdx.json",
        "tools/assert-sbom-rpms.py",
        '--source "dist/sbom/base-micro.${arch}.syft.json"',
        "Run Trivy fixable vulnerability gates",
        "dist/tools/trivy image",
        "--list-all-pkgs",
        "--ignore-unfixed",
        "--severity MEDIUM,HIGH,CRITICAL",
        "--ignorefile security/cve-ignore.trivyignore.yaml",
        "--exit-code 1",
        "Run Grype fixable vulnerability gates",
        "--only-fixed",
        "--fail-on medium",
        "-c security/cve-ignore.grype.yaml",
        "Generate complete vulnerability reports",
        "--format json",
        "dist/tools/trivy convert",
        "--format sarif",
        '-o "json=${grype_json}"',
        '-o "sarif=${grype_sarif}"',
        "Seal complete vulnerability reports",
        "sha256sum --check SHA256SUMS",
        "Upload complete vulnerability reports",
        "retention-days: 90",
        "compression-level: 0",
        "github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9",
        "category: base-micro/trivy/amd64",
        "category: base-micro/grype/amd64",
        "category: base-micro/trivy/arm64",
        "category: base-micro/grype/arm64",
        f"cosign attest --type {predicate_type('spdx')}",
        f"cosign attest --type {predicate_type('cyclonedx')}",
        f"cosign verify-attestation --type {predicate_type('spdx')}",
        "Run runtime rootfs secret gates",
        "tools/assert-no-rootfs-secrets.py",
        "Generate NIST SP 800-190 image-control predicates",
        "tools/generate-nist-800-190-predicate.py",
        'cosign attest --type "${NIST_800_190_PREDICATE_TYPE}"',
        'cosign verify-attestation --type "${NIST_800_190_PREDICATE_TYPE}"',
        'cosign attest --type "${STIG_ARF_PREDICATE_TYPE}"',
        'cosign verify-attestation --type "${STIG_ARF_PREDICATE_TYPE}"',
        "rekor-rollup:",
        "Verify Rekor roll-up",
        "tools/assert-cosign-rekor.py",
        'verify_rekor "cosign signature index"',
        'verify_rekor "cosign signature ${arch}"',
        "assert_attestation_tlog",
        "cosign verify-attestation succeeded with Rekor transparency log enabled",
        "DSSE envelope(s)",
        "EXPECTED_BUILDER_ID",
        "tools/assert-slsa-builder-id.py",
        f"cosign verify-attestation --type {slsa_attestation_type()}",
        "STIG ARF",
        "OpenSCAP",
        'assert_attestation_tlog "SLSA provenance index"',
        f"cosign verify-attestation --type {predicate_type('spdx')}",
        'assert_attestation_tlog "SPDX SBOM ${arch}"',
        f"cosign verify-attestation --type {predicate_type('cyclonedx')}",
        'assert_attestation_tlog "CycloneDX SBOM ${arch}"',
        'assert_attestation_tlog "NIST 800-190 image ${arch}"',
        'assert_attestation_tlog "STIG ARF ${arch}"',
        'COSIGN_YES: "true"',
        slsa_generator_action() + "@" + slsa_generator_tag(),
        SLSA_GENERATOR_SHA,
        'gh api "repos/slsa-framework/slsa-github-generator/git/ref/tags/${SLSA_GENERATOR_TAG}"',
        "cosign sign --recursive",
        "cosign verify",
        cosign_workflow_certificate_identity(),
        f'--certificate-oidc-issuer "{cosign_oidc_issuer()}"',
        f"manifest[linux/amd64]:org.nwarila.fips.cmvp.oe-validated={str(fips_oe_validated('amd64')).lower()}",
        f"manifest[linux/arm64]:org.nwarila.fips.cmvp.oe-validated={str(fips_oe_validated('arm64')).lower()}",
        f'EXPECTED_BUILDER_ID: "{slsa_builder_id()}"',
        "publish-scope:",
        "name: publish scope",
        "tools/decide-publish-scope.py",
        "--no-renames --name-only -z",
        "--print-base",
    ]
    missing = [marker for marker in required if marker not in text]
    require(not missing, "publish workflow missing required marker(s): " + ", ".join(missing))
    release_installer_refs = cosign_installer_steps(text)
    require(
        len(release_installer_refs) == 1 and SHA40.fullmatch(release_installer_refs[0]) is not None,
        "publish workflow must contain exactly one explicit SHA-pinned Cosign v2.5.2 installer step",
    )
    require_action_sha_pin(text, "publish workflow", COSIGN_INSTALLER_ACTION, count=2)

    publish_start = text.find("\n  publish:\n")
    publish_end = text.find("\n  slsa-provenance:\n", publish_start)
    require(
        publish_start >= 0 and publish_end > publish_start,
        "publish workflow must contain an identifiable publish job",
    )
    publish_job = text[publish_start:publish_end]
    ordered_steps = {
        "build/push": "Build and push runtime image",
        "digest resolution": "Resolve platform image digests",
        "Crane installation": "Install Crane for published rootfs assertions",
        "rootfs assertion": "Assert published rootfs contracts",
        "Cosign signing": "Sign image digest with Cosign",
        "Cosign verification": "Verify Cosign signature",
        "first attestation": "Attest rpmdb SBOMs",
    }
    step_indexes = {name: publish_job.find(marker) for name, marker in ordered_steps.items()}
    missing_ordered_steps = [name for name, index in step_indexes.items() if index < 0]
    require(
        not missing_ordered_steps,
        "publish job missing ordered step marker(s): " + ", ".join(missing_ordered_steps),
    )
    required_order = [
        ("build/push", "digest resolution"),
        ("digest resolution", "rootfs assertion"),
        ("Crane installation", "rootfs assertion"),
        ("rootfs assertion", "Cosign signing"),
        ("Cosign signing", "Cosign verification"),
        ("Cosign verification", "first attestation"),
    ]
    violated_order = [
        f"{before} < {after}" for before, after in required_order if step_indexes[before] >= step_indexes[after]
    ]
    require(
        not violated_order,
        "publish job violates required dependency order: " + ", ".join(violated_order),
    )

    freshness_index = text.find("Assert scanner DB freshness")
    first_trivy_scan_index = text.find("Run Trivy fixable vulnerability gates")
    first_grype_scan_index = text.find("Run Grype fixable vulnerability gates")
    report_index = text.find("Generate complete vulnerability reports")
    require(freshness_index >= 0, "publish workflow must assert scanner DB freshness")
    require(
        freshness_index < first_trivy_scan_index < first_grype_scan_index < report_index,
        "publish workflow must run freshness, native fixable gates, then report-only scans",
    )

    trivy_gate = text[first_trivy_scan_index:first_grype_scan_index]
    grype_gate = text[first_grype_scan_index:report_index]
    report_end = text.find("\n      - name:", report_index + 1)
    require(report_end > report_index, "publish workflow must keep a bounded report-only step")
    report_pass = text[report_index:report_end]
    trivy_report_index = report_pass.find("dist/tools/trivy image")
    grype_report_index = report_pass.find('dist/tools/grype "${image_ref}"')
    require(
        0 <= trivy_report_index < grype_report_index,
        "publish report-only step must keep its Trivy -> Grype scan order",
    )
    trivy_report = report_pass[trivy_report_index:grype_report_index]
    grype_report = report_pass[grype_report_index:]
    require(
        all(
            marker in trivy_gate
            for marker in (
                "--ignore-unfixed",
                "--severity MEDIUM,HIGH,CRITICAL",
                "--ignorefile security/cve-ignore.trivyignore.yaml",
                "--exit-code 1",
            )
        ),
        "publish Trivy fixable gate must keep the native blocking flags and TD6 ignore file",
    )
    require(
        all(
            marker in grype_gate for marker in ("--only-fixed", "--fail-on medium", "-c security/cve-ignore.grype.yaml")
        ),
        "publish Grype fixable gate must keep the native blocking flags and TD6 config",
    )
    require(
        "--ignorefile" not in report_pass
        and "-c security/cve-ignore.grype.yaml" not in report_pass
        and "--exit-code" not in report_pass
        and "--fail-on" not in report_pass,
        "publish report-only pass must remain complete and non-blocking on findings",
    )
    require(
        '--output "${trivy_json}"' in trivy_report
        and "dist/tools/trivy convert" in trivy_report
        and '--output "${trivy_sarif}"' in trivy_report,
        "publish Trivy report pass must scan once to JSON and convert that JSON to SARIF",
    )
    require(
        'dist/tools/grype "${image_ref}" \\\n              --platform "linux/${arch}" \\\n' in grype_report
        and '-o "json=${grype_json}"' in grype_report
        and '-o "sarif=${grype_sarif}"' in grype_report,
        "publish Grype report-only scan must emit JSON and SARIF in one invocation",
    )
    require_action_sha_pin(text, "publish workflow", "actions/upload-artifact", count=1)
    require_action_sha_pin(text, "publish workflow", "github/codeql-action/upload-sarif", count=4)
    require(text.count("security-events: write") == 1, "only the publish job may write security events")
    require(
        "permissions:\n      contents: read\n      id-token: write\n      packages: write\n      security-events: write"
        in publish_job,
        "publish job must preserve contents/packages/id-token permissions and add security-events write",
    )
    for retired in ("assert-vex.py", "assert-ignore-scope.py", "openvex", "vex/"):
        require(retired not in text.lower(), f"publish workflow retains retired root OpenVEX marker: {retired}")

    forbidden = [
        "-regexp",
        "--sbom=true",
        "--tlog-upload=false",
        "attest-build-" + "provenance",
        "gh attestation verify",
        "continue-on-" + "error",
        "examples/image-manifest.json",
        "tools/build_app.sh",
        "tools/generate_build_args.py",
        'verify_rekor "SLSA provenance',
        'verify_rekor "SPDX SBOM',
        'verify_rekor "CycloneDX SBOM',
        'verify_rekor "NIST 800-190 image',
        'verify_rekor "OpenVEX',
    ]
    present = [marker for marker in forbidden if marker in text]
    require(not present, "publish workflow contains forbidden marker(s): " + ", ".join(present))
    trust_policy_errors = publish_trust_policy_errors(text)
    require(not trust_policy_errors, "publish workflow trust policy failed: " + "; ".join(trust_policy_errors))
    trust_mutations = check_publish_trust_policy_mutations(text)
    print(f"publish trust-policy mutation probes: {trust_mutations}/{trust_mutations} rejected")

    check_publish_slsa_pins(text)
    check_uses_pinned(text, "publish workflow")


PUBLISH_SCOPE_CONCURRENCY_BLOCK = (
    "concurrency:\n"
    "  group: publish-image-${{ github.event.pull_request.number || github.ref }}\n"
    "  cancel-in-progress: ${{ github.ref == 'refs/heads/main' }}\n"
)
PUBLISH_SCOPE_JOB_HEADER = (
    "  publish-scope:\n"
    "    name: publish scope\n"
    "    runs-on: ubuntu-24.04\n"
    "    timeout-minutes: 10\n"
    "    if: ${{ github.event_name == 'push' }}\n"
    "    permissions:\n"
    "      contents: read\n"
    "      packages: read\n"
    "    outputs:\n"
    "      publish: ${{ steps.scope.outputs.publish }}\n"
)
PUBLISH_SCOPE_HELPER_INVOCATION = (
    '          publish="$(\n'
    "            python3 tools/decide-publish-scope.py \\\n"
    '              --ref "${EVENT_REF}" \\\n'
    '              --diff-status "${diff_status}" \\\n'
    '              < "${changed_paths}"\n'
    '          )"\n'
)
PUBLISH_SCOPE_CASE_VALIDATION = '          case "${publish}" in\n            true | false) ;;\n'
PUBLISH_SCOPE_NEEDS_BLOCK = (
    "  publish:\n"
    "    name: publish signed image\n"
    "    needs:\n"
    "      - slsa-generator-tag-integrity\n"
    "      - publish-scope\n"
)
PUBLISH_SCOPE_DIFF_COMMAND = 'git diff --no-renames --name-only -z "${base}" "${GITHUB_SHA}" > "${changed_paths}"'
PUBLISH_SCOPE_CRANE_SOURCE = 'crane config "${IMAGE_REPOSITORY}:base-micro" --platform linux/amd64 \\'
PUBLISH_SCOPE_BASE_EXTRACTION = "| python3 tools/decide-publish-scope.py --print-base"
PUBLISH_SCOPE_BASE_VALIDATION = '[[ "${base}" =~ ^[0-9a-f]{40}$ ]]'
PUBLISH_SCOPE_BASE_REACHABILITY = 'git cat-file -e "${base}^{commit}"'
DOCKERFILE_REVISION_LABEL_SITE = 'org.opencontainers.image.revision="${OCI_REVISION}"'


def publish_scope_gate_errors(
    publish_text: str,
    dockerfile_text: str,
    dockerignore_text: str,
    gitignore_text: str,
) -> list[str]:
    errors: list[str] = []

    def expect(condition: object, message: str) -> None:
        if not condition:
            errors.append(message)

    expect(
        PUBLISH_SCOPE_CONCURRENCY_BLOCK in publish_text,
        "publish workflow must keep the exact concurrency group with main-only cancel-in-progress",
    )
    on_start = publish_text.find("\non:\n")
    on_end = publish_text.find("\npermissions:", on_start)
    expect(on_start >= 0 and on_end > on_start, "publish workflow must keep an identifiable on: block")
    if on_start >= 0 and on_end > on_start:
        on_block = publish_text[on_start:on_end]
        expect(
            "paths:" not in on_block and "paths-ignore:" not in on_block,
            "publish workflow must not use workflow-level path filters",
        )
    expect(
        publish_text.count("\n  publish-scope:\n") == 1,
        "publish workflow must contain exactly one publish-scope job",
    )
    expect(
        PUBLISH_SCOPE_JOB_HEADER in publish_text,
        "publish-scope job header (name/runner/timeout/if/permissions/outputs) must match exactly",
    )

    scope_match = re.search(
        r"^  publish-scope:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        publish_text,
        flags=re.MULTILINE | re.DOTALL,
    )
    expect(scope_match is not None, "publish workflow missing an identifiable publish-scope job block")
    if scope_match is not None:
        scope_block = scope_match.group(0)
        for fragment, label in [
            ("        id: scope\n", "scope step id"),
            ("          fetch-depth: 0\n", "full-history checkout"),
            ("persist-credentials: false", "credential-free checkout"),
            ("GHCR_TOKEN: ${{ github.token }}", "authenticated GHCR login"),
            ("bash tools/install-crane.sh", "pinned crane installation"),
            ('changed_paths="dist/publish-scope/changed-paths.zlist"', "named changed-paths file"),
            ("mkdir -p dist/publish-scope", "changed-paths directory creation"),
            (': > "${changed_paths}"', "changed-paths truncation before branching"),
            (PUBLISH_SCOPE_CRANE_SOURCE, "published-revision crane source"),
            (PUBLISH_SCOPE_BASE_EXTRACTION, "helper base extraction"),
            (PUBLISH_SCOPE_BASE_VALIDATION, "40-hex base validation"),
            (PUBLISH_SCOPE_BASE_REACHABILITY, "base reachability guard"),
            (PUBLISH_SCOPE_DIFF_COMMAND, "exact published-revision diff command"),
            (PUBLISH_SCOPE_HELPER_INVOCATION, "exact helper invocation"),
            (PUBLISH_SCOPE_CASE_VALIDATION, "exact true/false output validation"),
            ('echo "publish=${publish}" >> "${GITHUB_OUTPUT}"', "publish output mapping"),
        ]:
            expect(fragment in scope_block, f"publish-scope job missing {label}")
        expect(
            "IMAGE_REPOSITORY:" not in scope_block,
            "publish-scope job must not override IMAGE_REPOSITORY",
        )
        available_count = scope_block.count('diff_status="available"')
        expect(available_count == 1, "publish-scope job must assign diff_status=available exactly once")
        if available_count == 1:
            available_index = scope_block.index('diff_status="available"')
            for guard, label in [
                (PUBLISH_SCOPE_BASE_VALIDATION, "40-hex base validation"),
                (PUBLISH_SCOPE_BASE_REACHABILITY, "base reachability guard"),
                (PUBLISH_SCOPE_DIFF_COMMAND, "published-revision diff"),
            ]:
                guard_index = scope_block.find(guard)
                expect(
                    0 <= guard_index < available_index,
                    f"publish-scope job must assign diff_status=available only after the {label}",
                )

    expect(
        PUBLISH_SCOPE_NEEDS_BLOCK in publish_text,
        "publish job must need slsa-generator-tag-integrity and publish-scope exactly",
    )
    expect(
        "needs.publish-scope.outputs.publish == 'true'" in publish_text,
        "publish job must gate on the validated publish-scope decision",
    )
    expect(
        "\n  IMAGE_REPOSITORY: ghcr.io/nwarila/ubi9-base-micro\n" in publish_text,
        "publish workflow must pin the exact IMAGE_REPOSITORY",
    )
    expect(
        '--build-arg "OCI_REVISION=${GITHUB_SHA}"' in publish_text,
        "publish build must stamp OCI_REVISION from GITHUB_SHA",
    )
    publish_match = re.search(
        r"^  publish:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        publish_text,
        flags=re.MULTILINE | re.DOTALL,
    )
    expect(publish_match is not None, "publish workflow missing an identifiable publish job block")
    if publish_match is not None:
        expect(
            publish_match.group(0).count("--platform linux/amd64,linux/arm64") == 1,
            "publish job must contain exactly one two-platform build invocation",
        )

    expect(
        dockerfile_text.count(DOCKERFILE_REVISION_LABEL_SITE) == 2,
        "Dockerfile must write the revision label from OCI_REVISION at both label sites",
    )
    expect("images/" not in dockerfile_text, "Dockerfile must not reference the images/ family trees")

    dockerignore_rules = [
        line for line in dockerignore_text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    expect(
        bool(dockerignore_rules) and dockerignore_rules[0] == "**",
        ".dockerignore first effective rule must be the ** deny-all",
    )
    expect(
        not any("images" in rule for rule in dockerignore_rules),
        ".dockerignore must not negate or reference images/",
    )

    expect("\n!/images/\n" in gitignore_text, ".gitignore must allowlist /images/")
    expect("\n!/images/README.md\n" in gitignore_text, ".gitignore must allowlist /images/README.md")
    return errors


def check_publish_scope_gate() -> None:
    errors = publish_scope_gate_errors(
        read(".github/workflows/publish-image.yaml"),
        read("containers/Dockerfile"),
        read(".dockerignore"),
        read(".gitignore"),
    )
    require(not errors, "publish scope gate contract failed: " + "; ".join(errors))
    require(
        not (ROOT / "docs/decision-records/repo/0010-base-image-polyrepo-topology.md").exists(),
        "superseded ADR-0010 polyrepo filename must not reappear",
    )


def check_publish_scope_gate_self_test() -> None:
    publish_text = read(".github/workflows/publish-image.yaml")
    dockerfile_text = read("containers/Dockerfile")
    dockerignore_text = read(".dockerignore")
    gitignore_text = read(".gitignore")
    baseline = publish_scope_gate_errors(publish_text, dockerfile_text, dockerignore_text, gitignore_text)
    require(not baseline, "publish scope gate self-test baseline failed: " + "; ".join(baseline))

    scope_env_anchor = "        env:\n          EVENT_REF: ${{ github.ref }}"
    mutations: list[tuple[str, str, str]] = [
        (
            "diff-endpoint substitution",
            PUBLISH_SCOPE_DIFF_COMMAND,
            'git diff --no-renames --name-only -z HEAD^ "${GITHUB_SHA}" > "${changed_paths}"',
        ),
        ("rename detection removal", "--no-renames ", ""),
        ("base tag substitution", ':base-micro" --platform linux/amd64', ':latest" --platform linux/amd64'),
        (
            "base platform substitution",
            "--platform linux/amd64 \\",
            "--platform linux/arm64 \\",
        ),
        (
            "scope repository override",
            scope_env_anchor,
            "        env:\n          IMAGE_REPOSITORY: ghcr.io/other/repo\n          EVENT_REF: ${{ github.ref }}",
        ),
        (
            "cancel-in-progress flip",
            "cancel-in-progress: ${{ github.ref == 'refs/heads/main' }}",
            "cancel-in-progress: false",
        ),
        (
            "workflow-level path filter",
            "\non:\n  pull_request:",
            "\non:\n  pull_request:\n    paths:\n      - images/**",
        ),
        (
            "publish-scope needs removal",
            "      - slsa-generator-tag-integrity\n      - publish-scope\n",
            "      - slsa-generator-tag-integrity\n",
        ),
        (
            "scope condition inversion",
            "needs.publish-scope.outputs.publish == 'true'",
            "needs.publish-scope.outputs.publish != 'true'",
        ),
        ("case validation removal", PUBLISH_SCOPE_CASE_VALIDATION, ""),
        ("scope step id removal", "        id: scope\n", ""),
        (
            "job outputs removal",
            "    outputs:\n      publish: ${{ steps.scope.outputs.publish }}\n",
            "",
        ),
        (
            "output mapping removal",
            'echo "publish=${publish}" >> "${GITHUB_OUTPUT}"',
            "echo publish-scope done",
        ),
        (
            "early diff availability",
            'diff_status="unavailable"\n          base=""',
            'diff_status="available"\n          base=""',
        ),
    ]
    rejected = 0
    for label, old, new in mutations:
        require(old in publish_text, f"publish scope gate self-test anchor missing for mutation: {label}")
        mutated = publish_text.replace(old, new, 1)
        require(mutated != publish_text, f"publish scope gate self-test mutation is a no-op: {label}")
        mutated_errors = publish_scope_gate_errors(mutated, dockerfile_text, dockerignore_text, gitignore_text)
        require(bool(mutated_errors), f"publish scope gate mutation unexpectedly passed: {label}")
        rejected += 1

    token_removal = publish_text.replace("GHCR_TOKEN: ${{ github.token }}", "GHCR_TOKEN: none", 1)
    require(
        bool(publish_scope_gate_errors(token_removal, dockerfile_text, dockerignore_text, gitignore_text)),
        "publish scope gate mutation unexpectedly passed: token env removal",
    )
    rejected += 1

    dockerignore_mutations = [
        ("dockerignore deny-all removal", dockerignore_text.replace("**\n!containers/", "!containers/", 1)),
        ("dockerignore images negation", dockerignore_text + "!images/\n"),
    ]
    for label, mutated_dockerignore in dockerignore_mutations:
        require(mutated_dockerignore != dockerignore_text, f"publish scope gate self-test mutation is a no-op: {label}")
        require(
            bool(publish_scope_gate_errors(publish_text, dockerfile_text, mutated_dockerignore, gitignore_text)),
            f"publish scope gate mutation unexpectedly passed: {label}",
        )
        rejected += 1

    gitignore_removal = gitignore_text.replace("!/images/\n!/images/README.md\n", "", 1)
    require(gitignore_removal != gitignore_text, "publish scope gate self-test mutation is a no-op: gitignore removal")
    require(
        bool(publish_scope_gate_errors(publish_text, dockerfile_text, dockerignore_text, gitignore_removal)),
        "publish scope gate mutation unexpectedly passed: gitignore images allowlist removal",
    )
    rejected += 1

    print(f"publish scope gate mutation probes: {rejected}/{rejected} rejected")


PYTHON_STIG_PROFILE = "xccdf_org.nwarila.content_profile_ubi9_base_python_stig"
PYTHON_STIG_TAILORING = "images/python/stig/rhel9-base-python-tailoring.xml"
PYTHON_STIG_JUSTIFICATIONS = "images/python/stig/tailoring-justifications.json"
PYTHON_SSG_VERSION = "0.1.81"
PYTHON_SSG_TARBALL_SHA512 = (
    "11e26cfa96a6f1bd98b3a131837e2f86c9a9851239337d86d624b01627faf10f"
    "7a03c395a5839ddab018e0fa47719ade05a9946f90d5ca96b1261776a9164379"
)
PYTHON_STIG_FAIL_ON = "low"
PYTHON_EVIDENCE_STEP_ORDER = (
    "Install OpenSCAP STIG tooling",
    "Build RHEL9 STIG datastream",
    "Run tailored STIG ARF gate",
    "Install Syft for SBOM generation",
    "Generate and gate rpmdb SBOMs",
    "Assert scanner content canary",
    "Run canonical fixable vulnerability gates",
    "Generate complete vulnerability reports and prove raw SQLite absence",
    "Run rootfs secret gate",
    "Generate and validate NIST SP 800-190 predicate",
    "Upload evidence artifacts",
)
PYTHON_EVIDENCE_SHARED_DEPENDENCIES = (
    "^tools/build-stig-datastream\\.sh$",
    "^tools/install-(openscap|syft|trivy|grype|crane)\\.sh$",
    "^tools/assert-(stig-tailoring|stig-arf|rootfs-identity)\\.py$",
    "^tools/assert-(scanner-db-freshness|scanner-canary)\\.py$",
    "^tools/assert-no-phantom-packages\\.py$",
    "^tools/generate-stig-arf-predicate\\.py$",
    "^security/cve-ignore\\.(trivyignore|grype)\\.yaml$",
    "^stig/(rhel9-base-micro-tailoring\\.xml|tailoring-justifications\\.json)$",
    "^tests/fixtures/scanner-canary/log4shell\\.cdx\\.json$",
)
PYTHON_EVIDENCE_FORBIDDEN = (
    "cosign sign",
    "cosign attest",
    "generator_container_slsa3",
    "docker push",
    "crane push",
)
PYTHON_EVIDENCE_UPLOAD_PATHS = (
    "dist/python-evidence/stig/${{ matrix.arch }}/*.json",
    "dist/python-evidence/stig/${{ matrix.arch }}/*.xml",
    "dist/python-evidence/stig/${{ matrix.arch }}/*.html",
    "dist/python-evidence/sbom/*.json",
    "dist/python-evidence/vuln/*.json",
    "dist/python-evidence/vuln/*.sarif",
    "dist/python-evidence/attestations/*.json",
    "dist/python-evidence/base-python.${{ matrix.arch }}.secret-scan.json",
)
PYTHON_CI_WORKFLOW_SHA256 = "f2ed53077a320da53a96a834233c9fccd7ece1a381f770b1df15c4330fd2f021"
PYTHON_CI_WORKFLOW_BYTE_LENGTH = 30249
PYTHON_CI_JOB_IDS = ("changes", "self-tests", "build", "reproducibility", "python-required")
PYTHON_CI_TRIGGER_BLOCK = (
    "on:\n  pull_request:\n    branches: [main]\n  push:\n    branches: [main]\n  workflow_dispatch:\n\n"
)
PYTHON_CI_SELECTOR_LINES = (
    "selector='^images/python/'",
    'selector="${selector}|^\\.github/workflows/python-ci\\.yaml$"',
    'selector="${selector}|^tools/build-stig-datastream\\.sh$"',
    'selector="${selector}|^tools/install-(openscap|syft|trivy|grype|crane)\\.sh$"',
    'selector="${selector}|^tools/assert-(stig-tailoring|stig-arf|rootfs-identity)\\.py$"',
    'selector="${selector}|^tools/assert-(scanner-db-freshness|scanner-canary)\\.py$"',
    'selector="${selector}|^tools/assert-no-phantom-packages\\.py$"',
    'selector="${selector}|^tools/generate-stig-arf-predicate\\.py$"',
    'selector="${selector}|^security/cve-ignore\\.(trivyignore|grype)\\.yaml$"',
    'selector="${selector}|^stig/(rhel9-base-micro-tailoring\\.xml|tailoring-justifications\\.json)$"',
    'selector="${selector}|^tests/fixtures/scanner-canary/log4shell\\.cdx\\.json$"',
)
PYTHON_CI_EVENT_CASE = (
    'case "${EVENT_NAME}" in\n  pull_request) range_base="${BASE_SHA}" ;;\n  *) range_base="" ;;\nesac\n'
)
PYTHON_CI_ACTIVE_IF = "    if: ${{ github.event_name != 'pull_request' || needs.changes.outputs.python == 'true' }}"
PYTHON_CI_CONTRACT_STEP = "Assert gated image contract"


def _workflow_job_block(workflow: str, job: str) -> str:
    match = re.search(
        rf"^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [a-z0-9_-]+:\n|\Z)", workflow, re.MULTILINE | re.DOTALL
    )
    return match.group(0) if match is not None else ""


def _workflow_step_names(job_block: str) -> list[str]:
    return re.findall(r"^      - name: (.+)$", job_block, re.MULTILINE)


def _workflow_step_sequence(job_block: str) -> tuple[str | None, ...]:
    steps_marker = "    steps:\n"
    if job_block.count(steps_marker) != 1:
        return ()
    steps_block = job_block[job_block.index(steps_marker) + len(steps_marker) :]
    entries = re.findall(r"^      -(?: (.*))?$", steps_block, re.MULTILINE)
    return tuple(entry.removeprefix("name: ") if entry.startswith("name: ") else None for entry in entries)


def _workflow_named_steps_adjacent(job_block: str, first: str, second: str) -> bool:
    steps = _workflow_step_sequence(job_block)
    return steps.count(first) == 1 and steps.count(second) == 1 and steps.index(second) == steps.index(first) + 1


def _workflow_named_step(job_block: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    if job_block.count(marker) != 1:
        return ""
    start = job_block.index(marker)
    tail_start = start + len(marker)
    next_step = re.search(r"^      -(?: .*)?$", job_block[tail_start:], re.MULTILINE)
    end = len(job_block) if next_step is None else tail_start + next_step.start()
    return job_block[start:end]


def _workflow_upload_paths(step_block: str) -> tuple[str, ...]:
    path_block = re.search(
        r"^          path: \|\n(?P<paths>(?:^            \S.*(?:\n|\Z))+)",
        step_block,
        re.MULTILINE,
    )
    if path_block is None:
        return ()
    return tuple(line[12:] for line in path_block.group("paths").splitlines())


def _workflow_run_scalar(step_block: str) -> bytes:
    marker = "        run: |\n"
    if step_block.count(marker) != 1:
        return b""
    body = step_block.split(marker, 1)[1]
    scalar_lines: list[str] = []
    for line in body.splitlines(keepends=True):
        if not line.strip():
            scalar_lines.append("\n")
        elif line.startswith("          "):
            scalar_lines.append(line[10:])
        else:
            return b""
    scalar = "".join(scalar_lines)
    return (scalar.rstrip("\n") + "\n").encode() if scalar else b""


def _python_ci_permission_sites(workflow: str) -> list[tuple[str, tuple[tuple[str, str], ...]]]:
    lines = workflow.splitlines()
    sites: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    current_job = ""
    in_jobs = False
    for index, line in enumerate(lines):
        if line == "jobs:":
            in_jobs = True
            current_job = ""
            continue
        job_match = re.fullmatch(r"  ([a-z0-9_-]+):", line) if in_jobs else None
        if job_match is not None:
            current_job = job_match.group(1)
        permission_match = re.fullmatch(r"(?P<indent> *)permissions:(?P<inline>.*)", line)
        if permission_match is None:
            continue
        indent = permission_match.group("indent")
        inline = permission_match.group("inline").strip()
        if len(indent) == 0 and not in_jobs:
            scope = "workflow"
        elif len(indent) == 4 and current_job:
            scope = current_job
        else:
            scope = f"unexpected@{index + 1}"
        entries: list[tuple[str, str]] = []
        if inline:
            entries.append(("<inline>", inline))
        else:
            body_indent = indent + "  "
            for body_line in lines[index + 1 :]:
                if not body_line.strip():
                    continue
                if not body_line.startswith(body_indent) or body_line.startswith(body_indent + " "):
                    break
                entry_match = re.fullmatch(rf"{re.escape(body_indent)}([^:]+):\s*(.*)", body_line)
                if entry_match is None:
                    entries.append(("<invalid>", body_line.strip()))
                else:
                    entries.append((entry_match.group(1), entry_match.group(2)))
        sites.append((scope, tuple(entries)))
    return sites


def _python_ci_job_ids(workflow: str) -> list[str]:
    jobs_marker = "\njobs:\n"
    if jobs_marker not in workflow:
        return []
    return re.findall(r"^  ([a-z0-9_-]+):$", workflow.split(jobs_marker, 1)[1], re.MULTILINE)


def _python_ci_trigger_block(workflow: str) -> str:
    lines = workflow.splitlines(keepends=True)
    try:
        start = lines.index("on:\n")
    except ValueError:
        return ""
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and not line.startswith(" "):
            end = index
            break
    return "".join(lines[start:end]).rstrip("\n") + "\n\n"


def python_ci_preflight_errors(workflow: str) -> list[str]:
    errors: list[str] = []

    def reject(condition: object, message: str) -> None:
        if condition:
            errors.append(message)

    changes = _workflow_job_block(workflow, "changes")
    detect_step = _workflow_named_step(changes, "Detect python-tree changes")
    detect_scalar = _workflow_run_scalar(detect_step).decode(errors="replace")
    selector_lines = tuple(line.strip() for line in detect_scalar.splitlines() if line.strip().startswith("selector="))
    active_if_invalid = any(
        _workflow_job_block(workflow, job).count(PYTHON_CI_ACTIVE_IF) != 1
        for job in ("self-tests", "build", "reproducibility")
    )
    event_case_invalid = detect_scalar.count(PYTHON_CI_EVENT_CASE) != 1
    selector_invalid = selector_lines != PYTHON_CI_SELECTOR_LINES

    # CHECK: python-ci-active-jobs
    reject(active_if_invalid, "python CI push and dispatch jobs must run independently of the PR path selector")
    # CHECK: python-ci-event-case
    reject(event_case_invalid, "python CI detect logic must apply the diff range only to pull requests")
    # CHECK: python-ci-selector
    reject(selector_invalid, "python CI pull-request selector path list must remain exact")

    build = _workflow_job_block(workflow, "build")
    build_step = _workflow_named_step(build, "Build the python image")
    producer_step = _workflow_named_step(build, "Assert parent-subset invariance on the exported final image")
    contract_step = _workflow_named_step(build, PYTHON_CI_CONTRACT_STEP)
    contract_step_missing = not contract_step
    contract_step_order_invalid = bool(contract_step) and not (
        build.index(producer_step) < build.index(contract_step) if producer_step else False
    )
    contract_invocation = (
        "          python3 images/python/tools/assert-reproducible.py \\\n"
        '            --rootfs-tar "dist/python/final.${ARCH}.tar" \\\n'
        '            --arch "${ARCH}" \\\n'
        "            --expect-from-contract images/python/contracts/image-manifest.json\n"
    )
    contract_invocation_invalid = bool(contract_step) and contract_step.count(contract_invocation) != 1
    same_artifact_invalid = bool(contract_step) and not (
        producer_step.count('docker save "local/ubi9-base-python:ci-${ARCH}" -o "dist/python/final-image.${ARCH}.tar"')
        == 1
        and producer_step.count('entries = module.load_image_rootfs(Path(f"dist/python/final-image.{arch}.tar"))') == 1
        and producer_step.count('module.write_rootfs_tar(entries, Path(f"dist/python/final.{arch}.tar"))') == 1
        and build_step.count('--set "ci.tags=local/ubi9-base-python:ci-${ARCH}"') == 1
        and build.count("docker buildx bake --file images/python/docker-bake.json ci") == 1
        and "docker buildx bake" not in contract_step
    )

    # CHECK: python-ci-contract-step
    reject(contract_step_missing, "python CI build job must contain the gated-image contract step once")
    # CHECK: python-ci-contract-order
    reject(contract_step_order_invalid, "python CI gated-image contract step must follow final rootfs production")
    # CHECK: python-ci-contract-invocation
    reject(
        contract_invocation_invalid,
        "python CI gated-image contract step must assert the final rootfs with the committed contract",
    )
    # CHECK: python-ci-same-artifact
    reject(
        same_artifact_invalid,
        "python CI contract rootfs must come from the loaded ci image consumed by the build-job gates",
    )

    revision_invalid = bool(contract_step) and not (
        build_step.count('--set "ci.args.OCI_REVISION=${GITHUB_SHA}"') == 1
        and contract_step.count(
            "          actual_revision=\"$(docker image inspect --format '{{ index .Config.Labels "
            '"org.opencontainers.image.revision" }}\' "${image}")"\n'
        )
        == 1
        and contract_step.count('          test "${actual_revision}" = "${GITHUB_SHA}"\n') == 1
    )
    source_invalid = bool(contract_step) and not (
        build_step.count('--set "ci.args.OCI_SOURCE=https://github.com/${GITHUB_REPOSITORY}"') == 1
        and contract_step.count('          expected_source="https://github.com/${GITHUB_REPOSITORY}"\n') == 1
        and contract_step.count(
            "          actual_source=\"$(docker image inspect --format '{{ index .Config.Labels "
            '"org.opencontainers.image.source" }}\' "${image}")"\n'
        )
        == 1
        and contract_step.count('          test "${actual_source}" = "${expected_source}"\n') == 1
    )
    version_invalid = bool(contract_step) and not (
        build_step.count("          oci_version=\"$(tr -d '[:space:]' < images/python/VERSION)\"\n") == 1
        and build_step.count('--set "ci.args.OCI_VERSION=${oci_version}"') == 1
        and contract_step.count("          expected_version=\"$(tr -d '[:space:]' < images/python/VERSION)\"\n") == 1
        and contract_step.count(
            "          actual_version=\"$(docker image inspect --format '{{ index .Config.Labels "
            '"org.opencontainers.image.version" }}\' "${image}")"\n'
        )
        == 1
        and contract_step.count('          test "${actual_version}" = "${expected_version}"\n') == 1
    )
    created_invalid = bool(contract_step) and not (
        contract_step.count(
            "          print(json.load(open('images/python/docker-bake.json'))"
            "['target']['base']['args']['OCI_CREATED'])\n"
        )
        == 1
        and contract_step.count(
            "          actual_created=\"$(docker image inspect --format '{{ index .Config.Labels "
            '"org.opencontainers.image.created" }}\' "${image}")"\n'
        )
        == 1
        and contract_step.count('          test "${actual_created}" = "${expected_created}"\n') == 1
    )

    # CHECK: python-ci-revision-binding
    reject(revision_invalid, "python CI gated image revision label must equal GITHUB_SHA")
    # CHECK: python-ci-source-binding
    reject(source_invalid, "python CI gated image source label must equal the repository URL")
    # CHECK: python-ci-version-binding
    reject(version_invalid, "python CI gated image version label must equal the stripped committed VERSION")
    # CHECK: python-ci-created-binding
    reject(created_invalid, "python CI gated image created label must equal the fixed Bake contract value")

    expected_permission_sites = Counter(
        [
            ("workflow", (("contents", "read"),)),
            ("changes", (("contents", "read"),)),
            ("self-tests", (("contents", "read"),)),
            ("build", (("contents", "read"),)),
            ("reproducibility", (("contents", "read"),)),
            ("python-required", (("contents", "read"),)),
        ]
    )
    observed_permission_sites = Counter(_python_ci_permission_sites(workflow))
    permissions_invalid = (
        observed_permission_sites != expected_permission_sites or sum(observed_permission_sites.values()) != 6
    )
    triggers_invalid = _python_ci_trigger_block(workflow) != PYTHON_CI_TRIGGER_BLOCK
    job_ids_invalid = _python_ci_job_ids(workflow) != list(PYTHON_CI_JOB_IDS)
    reusable_job_invalid = re.search(r"^    uses:\s*", workflow, re.MULTILINE) is not None
    environment_invalid = re.search(r"^    environment:\s*", workflow, re.MULTILINE) is not None
    secret_reference_invalid = "${{ secrets." in workflow
    credentials_invalid = re.search(r"^\s+credentials:\s*", workflow, re.MULTILINE) is not None
    registry_login_invalid = re.search(r"^\s+uses:\s+[^\s#]*login-action@", workflow, re.MULTILINE) is not None
    build_output_override_invalid = re.search(r"--set\s+[\"']?ci\.output(?:=|\.)", workflow) is not None
    step_continue_invalid = re.search(r"^        continue-on-error:\s*", workflow, re.MULTILINE) is not None
    job_continue_invalid = re.search(r"^    continue-on-error:\s*", workflow, re.MULTILINE) is not None

    # CHECK: python-ci-permissions
    reject(
        permissions_invalid,
        "python CI permissions must occur once at workflow and every exact job with contents read only",
    )
    # CHECK: python-ci-triggers
    reject(triggers_invalid, "python CI trigger set must remain pull_request, push, and workflow_dispatch only")
    # CHECK: python-ci-job-ids
    reject(
        job_ids_invalid,
        "python CI job IDs must remain exactly changes, self-tests, build, reproducibility, python-required",
    )
    # CHECK: python-ci-reusable-job
    reject(reusable_job_invalid, "python CI must not call a reusable workflow at job level")
    # CHECK: python-ci-environment
    reject(environment_invalid, "python CI jobs must not declare an environment")
    # CHECK: python-ci-secret-reference
    reject(secret_reference_invalid, "python CI must not reference repository or environment secrets")
    # CHECK: python-ci-credentials
    reject(credentials_invalid, "python CI containers and services must not configure credentials")
    # CHECK: python-ci-registry-login
    reject(registry_login_invalid, "python CI must not use a registry login action")
    # CHECK: python-ci-build-output
    reject(build_output_override_invalid, "python CI must not override the ci Bake output")
    # CHECK: python-ci-step-continue
    reject(step_continue_invalid, "python CI steps must not use continue-on-error")
    # CHECK: python-ci-job-continue
    reject(job_continue_invalid, "python CI jobs must not use continue-on-error")
    return errors


def python_ci_surface_lock_errors(workflow_bytes: bytes) -> list[str]:
    errors: list[str] = []
    actual_digest = hashlib.sha256(workflow_bytes).hexdigest()
    actual_length = len(workflow_bytes)
    digest_invalid = actual_digest != PYTHON_CI_WORKFLOW_SHA256
    length_invalid = actual_length != PYTHON_CI_WORKFLOW_BYTE_LENGTH
    # CHECK: python-ci-surface-digest
    if digest_invalid:
        errors.append(
            "python CI executable surface SHA-256 mismatch: "
            f"expected {PYTHON_CI_WORKFLOW_SHA256}, observed {actual_digest}"
        )
    # CHECK: python-ci-surface-length
    if length_invalid:
        errors.append(
            "python CI executable surface byte-length mismatch: "
            f"expected {PYTHON_CI_WORKFLOW_BYTE_LENGTH}, observed {actual_length}"
        )
    return errors


def _python_ci_yaml_parse_error(workflow: str) -> str | None:
    try:
        result = subprocess.run(
            ["ruby", "--disable-gems", "-ryaml", "-e", "YAML.parse_stream(STDIN.read)"],
            cwd=ROOT,
            input=workflow,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        return str(exc)
    if result.returncode != 0:
        return result.stderr.strip() or result.stdout.strip() or f"ruby exited {result.returncode}"
    return None


def _replace_nth(source: str, old: str, new: str, occurrence: int) -> str:
    require(occurrence > 0, "replacement occurrence must be positive")
    start = 0
    found = -1
    for _ in range(occurrence):
        found = source.find(old, start)
        require(found >= 0, f"replacement occurrence {occurrence} is missing")
        start = found + len(old)
    return source[:found] + new + source[found + len(old) :]


def _swap_workflow_steps(source: str, first: str, second: str) -> str:
    first_marker = f"      - name: {first}\n"
    second_marker = f"      - name: {second}\n"
    first_start = source.find(first_marker)
    second_start = source.find(second_marker)
    require(first_start >= 0 and second_start > first_start, "workflow step-swap anchors missing or reversed")
    first_end = source.find("      - name: ", first_start + len(first_marker))
    require(first_end == second_start, "workflow step-swap fixtures must be adjacent")
    second_end = source.find("      - name: ", second_start + len(second_marker))
    if second_end < 0:
        second_end = len(source)
    return (
        source[:first_start] + source[second_start:second_end] + source[first_start:second_start] + source[second_end:]
    )


def _python_ci_semantic_fixtures(workflow: str) -> list[tuple[str, str, str]]:
    permission_error = "python CI permissions must occur once at workflow and every exact job with contents read only"
    top_permission = "permissions:\n  contents: read\n"
    job_permission = "    permissions:\n      contents: read\n"
    extra_top_permission = "permissions:\n  contents: read\n  packages: write\n"
    extra_job_permission = "    permissions:\n      contents: read\n      packages: write\n"
    contract_block = _workflow_named_step(_workflow_job_block(workflow, "build"), PYTHON_CI_CONTRACT_STEP)
    require(bool(contract_block), "python CI semantic fixtures require the contract step")
    without_contract = workflow.replace(contract_block, "", 1)
    same_artifact_mutant = workflow.replace(
        'docker save "local/ubi9-base-python:ci-${ARCH}" -o "dist/python/final-image.${ARCH}.tar"',
        'docker save "local/ubi9-base-python:other-${ARCH}" -o "dist/python/final-image.${ARCH}.tar"',
        1,
    )
    login_step = (
        "      - name: Log in to registry\n"
        "        uses: docker/login-action@1111111111111111111111111111111111111111\n\n"
    )
    fixtures = [
        (
            "push job path condition restored",
            workflow.replace(PYTHON_CI_ACTIVE_IF, "    if: ${{ needs.changes.outputs.python == 'true' }}", 1),
            "python CI push and dispatch jobs must run independently of the PR path selector",
        ),
        (
            "push-side range filtering restored",
            workflow.replace(
                '            pull_request) range_base="${BASE_SHA}" ;;\n            *) range_base="" ;;',
                '            pull_request) range_base="${BASE_SHA}" ;;\n'
                '            push) range_base="${BEFORE_SHA}" ;;\n'
                '            *) range_base="" ;;',
                1,
            ),
            "python CI detect logic must apply the diff range only to pull requests",
        ),
        (
            "pull-request selector changed",
            workflow.replace("selector='^images/python/'", "selector='^images/other/'", 1),
            "python CI pull-request selector path list must remain exact",
        ),
        (
            "contract step removed",
            without_contract,
            "python CI build job must contain the gated-image contract step once",
        ),
        (
            "contract step moved before rootfs production",
            _swap_workflow_steps(
                workflow,
                "Assert parent-subset invariance on the exported final image",
                PYTHON_CI_CONTRACT_STEP,
            ),
            "python CI gated-image contract step must follow final rootfs production",
        ),
        (
            "contract expectation flag dropped",
            workflow.replace("            --expect-from-contract images/python/contracts/image-manifest.json\n", "", 1),
            "python CI gated-image contract step must assert the final rootfs with the committed contract",
        ),
        (
            "contract rootfs retagged",
            same_artifact_mutant,
            "python CI contract rootfs must come from the loaded ci image consumed by the build-job gates",
        ),
        (
            "revision label expectation changed",
            workflow.replace(
                '          test "${actual_revision}" = "${GITHUB_SHA}"\n',
                '          test "${actual_revision}" = "${BEFORE_SHA}"\n',
                1,
            ),
            "python CI gated image revision label must equal GITHUB_SHA",
        ),
        (
            "source label expectation changed",
            workflow.replace(
                '          test "${actual_source}" = "${expected_source}"\n',
                '          test "${actual_source}" = "https://example.invalid/repository"\n',
                1,
            ),
            "python CI gated image source label must equal the repository URL",
        ),
        (
            "version label expectation changed",
            workflow.replace(
                '          test "${actual_version}" = "${expected_version}"\n',
                '          test "${actual_version}" = "dev"\n',
                1,
            ),
            "python CI gated image version label must equal the stripped committed VERSION",
        ),
        (
            "created label expectation changed",
            workflow.replace(
                '          test "${actual_created}" = "${expected_created}"\n',
                '          test "${actual_created}" = "1970-01-01T00:00:00Z"\n',
                1,
            ),
            "python CI gated image created label must equal the fixed Bake contract value",
        ),
        (
            "workflow permission removed",
            workflow.replace(top_permission, "", 1),
            permission_error,
        ),
        (
            "changes permission removed",
            _replace_nth(workflow, job_permission, "", 1),
            permission_error,
        ),
        (
            "self-tests permission removed",
            _replace_nth(workflow, job_permission, "", 2),
            permission_error,
        ),
        (
            "build permission removed",
            _replace_nth(workflow, job_permission, "", 3),
            permission_error,
        ),
        (
            "reproducibility permission removed",
            _replace_nth(workflow, job_permission, "", 4),
            permission_error,
        ),
        (
            "python-required permission removed",
            _replace_nth(workflow, job_permission, "", 5),
            permission_error,
        ),
        (
            "workflow write grant added",
            workflow.replace(top_permission, extra_top_permission, 1),
            permission_error,
        ),
        (
            "changes write grant added",
            _replace_nth(workflow, job_permission, extra_job_permission, 1),
            permission_error,
        ),
        (
            "self-tests write grant added",
            _replace_nth(workflow, job_permission, extra_job_permission, 2),
            permission_error,
        ),
        (
            "build write grant added",
            _replace_nth(workflow, job_permission, extra_job_permission, 3),
            permission_error,
        ),
        (
            "reproducibility write grant added",
            _replace_nth(workflow, job_permission, extra_job_permission, 4),
            permission_error,
        ),
        (
            "python-required write grant added",
            _replace_nth(workflow, job_permission, extra_job_permission, 5),
            permission_error,
        ),
        (
            "workflow permission site emptied",
            workflow.replace(top_permission, "permissions: {}\n", 1),
            permission_error,
        ),
        (
            "workflow permission site duplicated",
            workflow.replace(top_permission, top_permission + top_permission, 1),
            permission_error,
        ),
        (
            "workflow_call trigger added",
            workflow.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n  workflow_call:\n", 1),
            "python CI trigger set must remain pull_request, push, and workflow_dispatch only",
        ),
        (
            "unexpected job ID added",
            workflow.replace(
                "  python-required:\n",
                "  unexpected-job:\n    runs-on: ubuntu-24.04\n    steps: []\n\n  python-required:\n",
                1,
            ),
            "python CI job IDs must remain exactly changes, self-tests, build, reproducibility, python-required",
        ),
        (
            "job-level reusable workflow added",
            workflow.replace(
                "    runs-on: ubuntu-24.04\n    timeout-minutes: 45\n",
                "    runs-on: ubuntu-24.04\n"
                "    uses: example/repository/.github/workflows/reusable.yaml@"
                "1111111111111111111111111111111111111111\n"
                "    timeout-minutes: 45\n",
                1,
            ),
            "python CI must not call a reusable workflow at job level",
        ),
        (
            "job environment added",
            workflow.replace(
                "    runs-on: ubuntu-24.04\n    timeout-minutes: 45\n",
                "    runs-on: ubuntu-24.04\n    environment: preflight\n    timeout-minutes: 45\n",
                1,
            ),
            "python CI jobs must not declare an environment",
        ),
        (
            "secret reference added",
            workflow.replace(
                "          ARCH: ${{ matrix.arch }}\n        run: |\n",
                "          ARCH: ${{ matrix.arch }}\n"
                "          REGISTRY_PASSWORD: ${{ secrets.REGISTRY_PASSWORD }}\n"
                "        run: |\n",
                1,
            ),
            "python CI must not reference repository or environment secrets",
        ),
        (
            "container credentials added",
            workflow.replace(
                "    strategy:\n      fail-fast: false\n",
                "    container:\n"
                "      image: registry.example.invalid/build:latest\n"
                "      credentials:\n"
                "        username: fixture\n"
                "        password: fixture\n"
                "    strategy:\n"
                "      fail-fast: false\n",
                1,
            ),
            "python CI containers and services must not configure credentials",
        ),
        (
            "service credentials added",
            workflow.replace(
                "    strategy:\n      fail-fast: false\n",
                "    services:\n"
                "      registry:\n"
                "        image: registry.example.invalid/service:latest\n"
                "        credentials:\n"
                "          username: fixture\n"
                "          password: fixture\n"
                "    strategy:\n"
                "      fail-fast: false\n",
                1,
            ),
            "python CI containers and services must not configure credentials",
        ),
        (
            "registry login action added",
            workflow.replace("      - name: Install Crane\n", login_step + "      - name: Install Crane\n", 1),
            "python CI must not use a registry login action",
        ),
        (
            "ci Bake output override added",
            workflow.replace(
                "            --progress plain \\\n",
                '            --progress plain \\\n            --set "ci.output=type=registry" \\\n',
                1,
            ),
            "python CI must not override the ci Bake output",
        ),
        (
            "step continue-on-error added",
            workflow.replace(
                "      - name: Run python runtime gates\n",
                "      - name: Run python runtime gates\n        continue-on-error: true\n",
                1,
            ),
            "python CI steps must not use continue-on-error",
        ),
        (
            "job continue-on-error added",
            workflow.replace(
                "  build:\n    name: python build and gates\n",
                "  build:\n    name: python build and gates\n    continue-on-error: true\n",
                1,
            ),
            "python CI jobs must not use continue-on-error",
        ),
    ]
    for label, mutated, _ in fixtures:
        require(mutated != workflow, f"python CI semantic mutation is a no-op: {label}")
    return fixtures


def _python_ci_detect_oracle(workflow: str) -> None:
    changes = _workflow_job_block(workflow, "changes")
    scalar = _workflow_run_scalar(_workflow_named_step(changes, "Detect python-tree changes"))
    require(bool(scalar), "python CI detect oracle could not parse the committed run scalar")
    base_result = subprocess.run(
        ["git", "rev-parse", "79726ed^"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    tip_result = subprocess.run(
        ["git", "rev-parse", "79726ed"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    require(base_result.returncode == 0 and tip_result.returncode == 0, "python CI detect oracle history is missing")
    base = base_result.stdout.strip()
    tip = tip_result.stdout.strip()
    require(SHA40.fullmatch(base) is not None and SHA40.fullmatch(tip) is not None, "python CI oracle range is invalid")
    digest = hashlib.sha256(scalar).hexdigest()
    for event_name, expected in (("push", "true"), ("pull_request", "false")):
        with tempfile.TemporaryDirectory(prefix=".verify-python-detect-", dir=ROOT) as tmp:
            output_path = Path(tmp) / "github-output"
            environment = os.environ.copy()
            environment.update(
                {
                    "EVENT_NAME": event_name,
                    "BASE_SHA": base,
                    "BEFORE_SHA": base,
                    "GITHUB_SHA": tip,
                    "GITHUB_OUTPUT": str(output_path),
                }
            )
            result = subprocess.run(
                ["bash"],
                cwd=ROOT,
                env=environment,
                input=scalar,
                capture_output=True,
                check=False,
            )
            stdout = result.stdout.decode()
            stderr = result.stderr.decode()
            output = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
            require(
                result.returncode == 0, f"python CI detect oracle {event_name} exited {result.returncode}: {stderr}"
            )
            require(not stderr, f"python CI detect oracle {event_name} wrote stderr: {stderr!r}")
            require(
                stdout == f"python-tree change detection: python={expected}\n",
                f"python CI detect oracle {event_name} stdout mismatch: {stdout!r}",
            )
            require(
                output == f"python={expected}\n",
                f"python CI detect oracle {event_name} GITHUB_OUTPUT mismatch: {output!r}",
            )
            print(
                f"python detect oracle: scalar_sha256={digest} scalar_bytes={len(scalar)} "
                f"range={base}..{tip} event={event_name} exit=0 "
                f"stdout={stdout.strip()!r} GITHUB_OUTPUT={output.strip()!r}"
            )


def check_python_ci_preflight_semantic_self_test(only_label: str | None = None) -> None:
    workflow = read(".github/workflows/python-ci.yaml")
    baseline = python_ci_preflight_errors(workflow)
    require(not baseline, "python CI preflight semantic baseline failed: " + "; ".join(baseline))
    require(_python_ci_yaml_parse_error(workflow) is None, "python CI committed workflow must parse as YAML")
    if only_label is None:
        _python_ci_detect_oracle(workflow)

    selected = 0
    for label, mutated, expected_error in _python_ci_semantic_fixtures(workflow):
        if only_label is not None and label != only_label:
            continue
        selected += 1
        parse_error = _python_ci_yaml_parse_error(mutated)
        require(parse_error is None, f"python CI semantic mutation is not valid YAML [{label}]: {parse_error}")
        errors = python_ci_preflight_errors(mutated)
        if expected_error not in errors:
            raise VerifyError(f"python CI semantic mutation unexpectedly passed: {label}")
        require(
            errors == [expected_error],
            f"python CI semantic mutation returned an unexpected error set [{label}]: {errors}",
        )
        print(f"python CI semantic mutation rejected [{label}] parse=ok diagnostic={expected_error}")
    if only_label is not None:
        require(selected == 1, f"unknown python CI semantic fixture: {only_label}")
    else:
        fixture_count = len(_python_ci_semantic_fixtures(workflow))
        require(selected == fixture_count, "python CI semantic fixture count mismatch")
        print(f"python CI semantic mutation probes: {selected}/{fixture_count} rejected")


def _run_mutated_python_verifier(source: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=".verify-python-mutant-",
        suffix=".py",
        dir=ROOT / "tools",
    ) as mutant:
        mutant.write(source)
        mutant.flush()
        return subprocess.run(
            [sys.executable, mutant.name, *arguments],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )


def check_python_ci_preflight_checker_mutation_self_test() -> None:
    source = read("tools/verify.py")
    semantic_start = source.index("def python_ci_preflight_errors(")
    semantic_end = source.index("\ndef python_ci_surface_lock_errors(", semantic_start)
    semantic_source = source[semantic_start:semantic_end]
    guard_mutations = [
        ("python-ci-active-jobs", "reject(active_if_invalid,", "push job path condition restored"),
        ("python-ci-event-case", "reject(event_case_invalid,", "push-side range filtering restored"),
        ("python-ci-selector", "reject(selector_invalid,", "pull-request selector changed"),
        ("python-ci-contract-step", "reject(contract_step_missing,", "contract step removed"),
        (
            "python-ci-contract-order",
            "reject(contract_step_order_invalid,",
            "contract step moved before rootfs production",
        ),
        (
            "python-ci-contract-invocation",
            "reject(\n        contract_invocation_invalid,",
            "contract expectation flag dropped",
        ),
        ("python-ci-same-artifact", "reject(\n        same_artifact_invalid,", "contract rootfs retagged"),
        ("python-ci-revision-binding", "reject(revision_invalid,", "revision label expectation changed"),
        ("python-ci-source-binding", "reject(source_invalid,", "source label expectation changed"),
        ("python-ci-version-binding", "reject(version_invalid,", "version label expectation changed"),
        ("python-ci-created-binding", "reject(created_invalid,", "created label expectation changed"),
        ("python-ci-permissions", "reject(\n        permissions_invalid,", "workflow permission removed"),
        ("python-ci-triggers", "reject(triggers_invalid,", "workflow_call trigger added"),
        ("python-ci-job-ids", "reject(\n        job_ids_invalid,", "unexpected job ID added"),
        ("python-ci-reusable-job", "reject(reusable_job_invalid,", "job-level reusable workflow added"),
        ("python-ci-environment", "reject(environment_invalid,", "job environment added"),
        ("python-ci-secret-reference", "reject(secret_reference_invalid,", "secret reference added"),
        ("python-ci-credentials", "reject(credentials_invalid,", "container credentials added"),
        ("python-ci-registry-login", "reject(registry_login_invalid,", "registry login action added"),
        ("python-ci-build-output", "reject(build_output_override_invalid,", "ci Bake output override added"),
        ("python-ci-step-continue", "reject(step_continue_invalid,", "step continue-on-error added"),
        ("python-ci-job-continue", "reject(job_continue_invalid,", "job continue-on-error added"),
    ]
    markers = re.findall(r"^    # CHECK: (python-ci-(?!surface)[a-z-]+)$", source, re.MULTILINE)
    require(
        Counter(markers) == Counter(label for label, _, _ in guard_mutations) and len(markers) == len(guard_mutations),
        "python CI checker mutation list must cover every semantic rejection guard exactly once",
    )
    for guard, anchor, fixture in guard_mutations:
        require(semantic_source.count(anchor) == 1, f"python CI checker mutation anchor count changed: {guard}")
        replacement = "reject(\n        False," if "\n" in anchor else "reject(False,"
        mutated_semantic = semantic_source.replace(anchor, replacement, 1)
        mutated = source[:semantic_start] + mutated_semantic + source[semantic_end:]
        try:
            ast.parse(mutated, filename="tools/verify.py")
        except SyntaxError as exc:
            raise VerifyError(f"python CI checker mutation did not parse [{guard}]: {exc}") from exc
        result = _run_mutated_python_verifier(
            mutated,
            ["--check-python-preflight-semantic-fixture", fixture],
        )
        expected = f"verify failed: python CI semantic mutation unexpectedly passed: {fixture}"
        require(result.returncode == 1, f"python CI checker mutation {guard} returned {result.returncode}")
        require(
            result.stderr.strip() == expected,
            f"python CI checker mutation {guard} returned unexpected diagnostic: {result.stderr.strip()!r}",
        )
        location = source[: source.index(f"# CHECK: {guard}")].count("\n") + 1
        print(
            f"python CI checker mutation rejected [guard={guard} location=tools/verify.py:{location} "
            f"fixture={fixture} parse=ok import=ok run=ok diagnostic={expected}]"
        )
    print(f"python CI checker mutation probes: {len(guard_mutations)}/{len(guard_mutations)} rejected")


def _python_ci_surface_mutations(workflow_bytes: bytes) -> tuple[bytes, bytes]:
    workflow = workflow_bytes.decode()
    build = _workflow_job_block(workflow, "build")
    contract_step = _workflow_named_step(build, PYTHON_CI_CONTRACT_STEP)
    require(bool(contract_step), "python CI surface mutations require the contract step")
    step_offset = workflow.index(contract_step)
    marker = "          set -euo pipefail\n"
    marker_offset = workflow.index(marker, step_offset, step_offset + len(contract_step))
    content_offset = len(workflow[:marker_offset].encode()) + 10
    substitution = workflow_bytes[:content_offset] + b"S" + workflow_bytes[content_offset + 1 :]
    deletion_offset = content_offset + 2
    deletion = workflow_bytes[:deletion_offset] + workflow_bytes[deletion_offset + 1 :]
    require(len(substitution) == len(workflow_bytes), "python CI substitution fixture length changed")
    require(len(deletion) == len(workflow_bytes) - 1, "python CI deletion fixture length did not change by one")
    return substitution, deletion


def check_python_ci_surface_lock_self_test() -> None:
    workflow_bytes = (ROOT / ".github/workflows/python-ci.yaml").read_bytes()
    baseline = python_ci_surface_lock_errors(workflow_bytes)
    require(not baseline, "python CI surface lock baseline failed: " + "; ".join(baseline))
    substitution, deletion = _python_ci_surface_mutations(workflow_bytes)
    require(
        _python_ci_yaml_parse_error(substitution.decode()) is None,
        "python CI same-length surface mutation must still parse as YAML",
    )
    require(
        _python_ci_yaml_parse_error(deletion.decode()) is None,
        "python CI one-byte deletion surface mutation must still parse as YAML",
    )
    substitution_digest = hashlib.sha256(substitution).hexdigest()
    deletion_digest = hashlib.sha256(deletion).hexdigest()
    digest_prefix = "python CI executable surface SHA-256 mismatch:"
    length_prefix = "python CI executable surface byte-length mismatch:"
    substitution_errors = python_ci_surface_lock_errors(substitution)
    expected_substitution = [f"{digest_prefix} expected {PYTHON_CI_WORKFLOW_SHA256}, observed {substitution_digest}"]
    if not any(error.startswith(digest_prefix) for error in substitution_errors):
        raise VerifyError("python CI surface lock mutation unexpectedly passed: same-length substitution digest")
    require(
        substitution_errors == expected_substitution,
        f"python CI same-length substitution returned an unexpected complete error set: {substitution_errors}",
    )
    deletion_errors = python_ci_surface_lock_errors(deletion)
    expected_deletion = [
        f"{digest_prefix} expected {PYTHON_CI_WORKFLOW_SHA256}, observed {deletion_digest}",
        f"{length_prefix} expected {PYTHON_CI_WORKFLOW_BYTE_LENGTH}, observed {len(deletion)}",
    ]
    if not any(error.startswith(length_prefix) for error in deletion_errors):
        raise VerifyError("python CI surface lock mutation unexpectedly passed: one-byte deletion length")
    require(
        deletion_errors == expected_deletion,
        f"python CI one-byte deletion returned an unexpected complete error set: {deletion_errors}",
    )
    print(
        "python CI surface substitution rejected: parse=ok "
        f"bytes={len(substitution)} complete_errors={substitution_errors}"
    )
    print(f"python CI surface deletion rejected: parse=ok bytes={len(deletion)} complete_errors={deletion_errors}")


def check_python_ci_surface_lock_checker_mutation_self_test() -> None:
    source = read("tools/verify.py")
    lock_start = source.index("def python_ci_surface_lock_errors(")
    lock_end = source.index("\ndef _python_ci_yaml_parse_error(", lock_start)
    lock_source = source[lock_start:lock_end]
    mutations = [
        (
            "python-ci-surface-digest",
            "if digest_invalid:\n",
            "if False:\n",
            "verify failed: python CI surface lock mutation unexpectedly passed: same-length substitution digest",
        ),
        (
            "python-ci-surface-length",
            "if length_invalid:\n",
            "if False:\n",
            "verify failed: python CI surface lock mutation unexpectedly passed: one-byte deletion length",
        ),
    ]
    for guard, anchor, replacement, expected in mutations:
        require(lock_source.count(anchor) == 1, f"python CI surface checker mutation anchor count changed: {guard}")
        mutated_lock = lock_source.replace(anchor, replacement, 1)
        mutated = source[:lock_start] + mutated_lock + source[lock_end:]
        try:
            ast.parse(mutated, filename="tools/verify.py")
        except SyntaxError as exc:
            raise VerifyError(f"python CI surface checker mutation did not parse [{guard}]: {exc}") from exc
        result = _run_mutated_python_verifier(mutated, ["--check-python-ci-surface-lock-fixtures"])
        require(result.returncode == 1, f"python CI surface checker mutation {guard} returned {result.returncode}")
        require(
            result.stderr.strip() == expected,
            f"python CI surface checker mutation {guard} returned unexpected diagnostic: {result.stderr.strip()!r}",
        )
        location = source[: source.index(f"# CHECK: {guard}")].count("\n") + 1
        print(
            f"python CI surface checker mutation rejected [guard={guard} location=tools/verify.py:{location} "
            f"parse=ok import=ok run=ok diagnostic={expected}]"
        )
    print(f"python CI surface checker mutation probes: {len(mutations)}/{len(mutations)} rejected")


def check_python_ci_preflight() -> None:
    workflow_path = ROOT / ".github/workflows/python-ci.yaml"
    workflow_bytes = workflow_path.read_bytes()
    errors = python_ci_preflight_errors(workflow_bytes.decode())
    errors.extend(python_ci_surface_lock_errors(workflow_bytes))
    require(not errors, "python CI preflight contract failed: " + "; ".join(errors))


PUBLISH_PYTHON_WORKFLOW = ".github/workflows/publish-python.yaml"
PUBLISH_PYTHON_WORKFLOW_SHA256 = "ab01553fb26c685c8a3e91d88dfdec77ae36601f4604ff0db93af9e7ee79d6e3"
PUBLISH_PYTHON_WORKFLOW_BYTE_LENGTH = 85732


def _workflow_action_with_text(step: str) -> str:
    marker = "        with:\n"
    if step.count(marker) != 1:
        return ""
    body = step.split(marker, 1)[1]
    values: list[str] = []
    for line in body.splitlines():
        if line.startswith("          "):
            values.append(line[10:])
        elif line.strip():
            break
    return "\n".join(values)


def _shell_array_tokens(run: str, name: str) -> tuple[str, ...]:
    pattern = re.compile(
        rf"^[ ]*(?:readonly|local) -a {re.escape(name)}=\(\n(?P<body>.*?)(?=^[ ]*\)$)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(run)
    if match is None:
        return ()
    try:
        return tuple(shlex.split(match.group("body"), comments=False, posix=True))
    except ValueError:
        return ()


def publish_python_surface_lock_errors(workflow_bytes: bytes) -> list[str]:
    """Prevent drift from the review-authorized baseline; this is not an adversarial guarantee."""
    errors: list[str] = []
    actual_digest = hashlib.sha256(workflow_bytes).hexdigest()
    actual_length = len(workflow_bytes)
    digest_invalid = actual_digest != PUBLISH_PYTHON_WORKFLOW_SHA256
    length_invalid = actual_length != PUBLISH_PYTHON_WORKFLOW_BYTE_LENGTH
    # CHECK: publish-python-surface-digest
    if digest_invalid:
        errors.append(
            "publish Python executable surface SHA-256 mismatch: "
            f"expected {PUBLISH_PYTHON_WORKFLOW_SHA256}, observed {actual_digest}"
        )
    # CHECK: publish-python-surface-length
    if length_invalid:
        errors.append(
            "publish Python executable surface byte-length mismatch: "
            f"expected {PUBLISH_PYTHON_WORKFLOW_BYTE_LENGTH}, observed {actual_length}"
        )
    return errors


def _publish_python_surface_mutations(workflow_bytes: bytes) -> tuple[bytes, bytes]:
    marker = b"          set -euo pipefail\n"
    require(workflow_bytes.count(marker) >= 1, "publish Python surface fixture requires a strict-mode marker")
    content_offset = workflow_bytes.index(marker) + 10
    substitution = workflow_bytes[:content_offset] + b"S" + workflow_bytes[content_offset + 1 :]
    deletion_offset = content_offset + 2
    deletion = workflow_bytes[:deletion_offset] + workflow_bytes[deletion_offset + 1 :]
    require(len(substitution) == len(workflow_bytes), "publish Python substitution fixture length changed")
    require(len(deletion) == len(workflow_bytes) - 1, "publish Python deletion fixture length mismatch")
    return substitution, deletion


def check_publish_python_surface_lock_self_test() -> None:
    workflow_bytes = (ROOT / PUBLISH_PYTHON_WORKFLOW).read_bytes()
    baseline = publish_python_surface_lock_errors(workflow_bytes)
    require(not baseline, "publish Python surface lock baseline failed: " + "; ".join(baseline))
    substitution, deletion = _publish_python_surface_mutations(workflow_bytes)
    require(
        _python_ci_yaml_parse_error(substitution.decode()) is None,
        "publish Python same-length substitution must still parse as YAML",
    )
    require(
        _python_ci_yaml_parse_error(deletion.decode()) is None,
        "publish Python one-byte deletion must still parse as YAML",
    )
    digest_prefix = "publish Python executable surface SHA-256 mismatch:"
    length_prefix = "publish Python executable surface byte-length mismatch:"
    substitution_digest = hashlib.sha256(substitution).hexdigest()
    deletion_digest = hashlib.sha256(deletion).hexdigest()
    substitution_errors = publish_python_surface_lock_errors(substitution)
    expected_substitution = [
        f"{digest_prefix} expected {PUBLISH_PYTHON_WORKFLOW_SHA256}, observed {substitution_digest}"
    ]
    if not any(error.startswith(digest_prefix) for error in substitution_errors):
        raise VerifyError("publish Python surface lock mutation unexpectedly passed: same-length substitution digest")
    require(
        substitution_errors == expected_substitution,
        f"publish Python same-length substitution returned unexpected errors: {substitution_errors}",
    )
    deletion_errors = publish_python_surface_lock_errors(deletion)
    expected_deletion = [
        f"{digest_prefix} expected {PUBLISH_PYTHON_WORKFLOW_SHA256}, observed {deletion_digest}",
        f"{length_prefix} expected {PUBLISH_PYTHON_WORKFLOW_BYTE_LENGTH}, observed {len(deletion)}",
    ]
    if not any(error.startswith(length_prefix) for error in deletion_errors):
        raise VerifyError("publish Python surface lock mutation unexpectedly passed: one-byte deletion length")
    require(
        deletion_errors == expected_deletion,
        f"publish Python one-byte deletion returned unexpected errors: {deletion_errors}",
    )
    print(
        "publish Python surface substitution rejected: parse=ok "
        f"bytes={len(substitution)} complete_errors={substitution_errors}"
    )
    print(f"publish Python surface deletion rejected: parse=ok bytes={len(deletion)} complete_errors={deletion_errors}")


def check_publish_python_surface_lock_checker_mutation_self_test() -> None:
    source = read("tools/verify.py")
    checker_start = source.index("def publish_python_surface_lock_errors(")
    checker_end = source.index("\ndef _publish_python_surface_mutations(", checker_start)
    checker_source = source[checker_start:checker_end]
    mutations = [
        (
            "publish-python-surface-digest",
            "if digest_invalid:\n",
            "if False:\n",
            "verify failed: publish Python surface lock mutation unexpectedly passed: same-length substitution digest",
        ),
        (
            "publish-python-surface-length",
            "if length_invalid:\n",
            "if False:\n",
            "verify failed: publish Python surface lock mutation unexpectedly passed: one-byte deletion length",
        ),
    ]
    for guard, anchor, replacement, expected in mutations:
        require(checker_source.count(anchor) == 1, f"publish Python surface checker anchor changed: {guard}")
        mutated_checker = checker_source.replace(anchor, replacement, 1)
        mutated = source[:checker_start] + mutated_checker + source[checker_end:]
        try:
            ast.parse(mutated, filename="tools/verify.py")
        except SyntaxError as exc:
            raise VerifyError(f"publish Python surface checker mutation did not parse [{guard}]: {exc}") from exc
        result = _run_mutated_python_verifier(mutated, ["--check-publish-python-surface-lock-fixtures"])
        require(result.returncode == 1, f"publish Python surface checker mutation {guard} returned {result.returncode}")
        require(
            result.stderr.strip() == expected,
            f"publish Python surface checker mutation {guard} returned unexpected diagnostic: "
            f"{result.stderr.strip()!r}",
        )
        location = source[: source.index(f"# CHECK: {guard}")].count("\n") + 1
        print(
            f"publish Python surface checker mutation rejected [guard={guard} location=tools/verify.py:{location} "
            f"diagnostic={expected}]"
        )
    print(f"publish Python surface checker mutation probes: {len(mutations)}/{len(mutations)} rejected")


PUBLISH_PYTHON_TRIGGER = (
    "on:\n"
    "  pull_request:\n"
    "  push:\n"
    "    branches: [main]\n"
    '    tags: ["python/v*"]\n'
    "  workflow_dispatch:\n"
    "    inputs:\n"
    "      digest:\n"
    "        description: Published base-python index digest\n"
    "        required: true\n"
    "        type: string\n"
    "      publishing_sha:\n"
    "        description: Publishing commit SHA\n"
    "        required: true\n"
    "        type: string\n"
    "      publishing_ref:\n"
    "        description: Exact publishing ref\n"
    "        required: true\n"
    "        type: string\n\n"
)
PUBLISH_PYTHON_JOB_IDS = [
    "release-preflight",
    "slsa-generator-tag-integrity",
    "publish-scope",
    "publish",
    "gate-evidence",
    "sign-attest",
    "slsa-provenance",
    "rekor-rollup",
    "apply-aliases",
    "anonymous-verification",
]
PUBLISH_PYTHON_REPOSITORY_GUARD = "github.repository == 'NWarila/ubi9-base-micro'"


def publish_python_authorized(repository: str, event: str, ref: str, scope: str) -> bool:
    return (
        repository == "NWarila/ubi9-base-micro"
        and event == "push"
        and (ref == "refs/heads/main" or ref.startswith("refs/tags/python/v"))
        and scope == "true"
    )


def publish_python_workflow_errors(workflow: str) -> list[str]:
    """Lock the complete two-phase Python publication policy."""
    errors: list[str] = []

    def reject(condition: object, message: str) -> None:
        if condition:
            errors.append(message)

    publish = _workflow_job_block(workflow, "publish")
    gate_evidence = _workflow_job_block(workflow, "gate-evidence")
    sign_attest = _workflow_job_block(workflow, "sign-attest")
    generator = _workflow_job_block(workflow, "slsa-provenance")
    rekor = _workflow_job_block(workflow, "rekor-rollup")
    aliases = _workflow_job_block(workflow, "apply-aliases")
    anonymous = _workflow_job_block(workflow, "anonymous-verification")
    preflight = _workflow_job_block(workflow, "release-preflight")
    build_step = _workflow_named_step(publish, "Build and push unaliased candidate")
    gate_cosign_step = _workflow_named_step(gate_evidence, "Install Cosign")
    evidence_types = ("spdx", "cyclonedx", "openvex", "nist_800_190", "stig_arf")

    trigger_invalid = _python_ci_trigger_block(workflow) != PUBLISH_PYTHON_TRIGGER
    job_ids_invalid = _python_ci_job_ids(workflow) != PUBLISH_PYTHON_JOB_IDS
    concurrency_invalid = (
        workflow.count(
            "concurrency:\n  group: publish-python-ghcr-io-nwarila-ubi9-base-python\n  cancel-in-progress: false\n"
        )
        != 1
    )
    expected_permissions = Counter(
        [
            ("workflow", (("contents", "read"),)),
            ("release-preflight", (("contents", "read"),)),
            ("slsa-generator-tag-integrity", (("contents", "read"),)),
            ("publish-scope", (("contents", "read"), ("packages", "read"))),
            ("publish", (("contents", "read"), ("packages", "write"))),
            ("gate-evidence", (("contents", "read"), ("packages", "read"), ("security-events", "write"))),
            ("sign-attest", (("contents", "read"), ("id-token", "write"), ("packages", "write"))),
            (
                "slsa-provenance",
                (("actions", "read"), ("contents", "read"), ("id-token", "write"), ("packages", "write")),
            ),
            ("rekor-rollup", (("contents", "read"), ("packages", "read"))),
            ("apply-aliases", (("contents", "read"), ("packages", "write"))),
            ("anonymous-verification", (("contents", "read"),)),
        ]
    )
    permissions_invalid = Counter(_python_ci_permission_sites(workflow)) != expected_permissions
    guards_invalid = (
        workflow.count(PUBLISH_PYTHON_REPOSITORY_GUARD) != 9
        or any(
            PUBLISH_PYTHON_REPOSITORY_GUARD not in _workflow_job_block(workflow, job)
            for job in PUBLISH_PYTHON_JOB_IDS[1:]
        )
        or PUBLISH_PYTHON_REPOSITORY_GUARD in preflight
    )
    fail_closed_invalid = any(
        marker in workflow for marker in ("continue-on-error", "|| true", "--exit-code 0", "set +e")
    )
    gate_cosign_action_invalid = not gate_cosign_step or tuple(
        re.findall(r"^        uses: ([^\s#]+)", gate_cosign_step, re.MULTILINE)
    ) != ("sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",)
    gate_cosign_version_invalid = bool(gate_cosign_step) and (
        _workflow_action_with_text(gate_cosign_step) != "cosign-release: v2.5.2"
    )
    gate_cosign_order_invalid = bool(gate_cosign_step) and not _workflow_named_steps_adjacent(
        gate_evidence,
        "Install Cosign",
        "Install publication gate tools",
    )
    generator_invalid = not (
        "uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0" in generator
        and "continue-on-error" not in generator
        and "      - publish" in generator
        and "      - sign-attest" in generator
    )
    exporter_invalid = not all(
        marker in build_step
        for marker in (
            "RELEASE_REF: ${{ env.IMAGE_REPOSITORY }}",
            "--metadata-file",
            "dist/python-publish/image-metadata.json",
            '"type": "registry"',
            '"push-by-digest": "true"',
            '"name-canonical": "true"',
            '"rewrite-timestamp": "true"',
        )
    )
    release_tokens = _shell_array_tokens(_workflow_run_scalar(build_step).decode(errors="replace"), "release_argv")
    closed_caller_invalid = release_tokens != (
        "docker",
        "buildx",
        "bake",
        "--file",
        "images/python/docker-bake.json",
        "release",
        "--progress",
        "plain",
        "--metadata-file",
        "dist/python-publish/image-metadata.json",
    ) or any(token == "--set" or token.startswith("--set=") for token in release_tokens)
    oci_binding_invalid = not (
        all(
            marker in publish
            for marker in (
                "OCI_REVISION: ${{ github.sha }}",
                "OCI_SOURCE: https://github.com/${{ github.repository }}",
                "OCI_VERSION=\"$(tr -d '[:space:]' < images/python/VERSION)\"",
            )
        )
        and all(
            marker in gate_evidence
            for marker in (
                "org.opencontainers.image.revision",
                "org.opencontainers.image.source",
                "org.opencontainers.image.version",
                "org.opencontainers.image.created",
            )
        )
    )
    subject_matrix_invalid = any(
        not (
            f"steps.contract.outputs.{predicate}" in sign_attest
            and sign_attest.count(f"steps.contract.outputs.{predicate}") >= 2
        )
        for predicate in evidence_types
    ) or not (
        sign_attest.count("for arch in amd64 arm64; do") >= 10
        and sign_attest.count("steps.contract.outputs.trust_contract") == 3
        and generator.count("digest: ${{ needs.publish.outputs.digest }}") == 1
    )
    signing_invalid = not (
        'cosign sign --recursive "${IMAGE_REF}"' in sign_attest
        and 'for digest in "${INDEX_DIGEST}" "${AMD64_DIGEST}" "${ARM64_DIGEST}"; do' in sign_attest
        and sign_attest.count("--certificate-identity") >= 7
        and "--certificate-oidc-issuer" in sign_attest
        and "--certificate-github-workflow-sha" in sign_attest
        and "--certificate-github-workflow-ref" in sign_attest
    )
    trust_invalid = not all(
        marker in workflow
        for marker in (
            "https://nwarila.dev/attestations/python-trust-contract/v1",
            "git rev-parse HEAD:images/python",
            "tools/python-trust-contract.py",
            "--expected-statement",
            "--validate-statement",
        )
    )
    provenance_invalid = not all(
        marker in rekor
        for marker in (
            "slsa-verifier verify-image",
            "--source-uri github.com/NWarila/ubi9-base-micro",
            "--source-branch main",
            '--source-tag "${GITHUB_REF#refs/tags/}"',
            "--print-provenance",
            "tools/assert-python-provenance.py",
            "--certificate-github-workflow-sha",
            "--certificate-github-workflow-ref",
        )
    )
    alias_order_invalid = not (
        "- rekor-rollup" in aliases
        and aliases.count("crane tag") == 1
        and workflow.find("  apply-aliases:") > workflow.find("  rekor-rollup:")
        and "needs.publish.result == 'success' && needs.rekor-rollup.result == 'success'" in aliases
    )
    collision_invalid = not (
        "--phase pre-evidence" in publish
        and "--phase pre-apply" in aliases
        and "--phase post-apply" in aliases
        and 'commit_alias = f"base-python-{sha[:12]}"' in read("tools/assert-python-alias-policy.py")
        and "version=\"$(tr -d '[:space:]' < images/python/VERSION)\"" in aliases
    )
    independent_invalid = not (
        "Log in to GHCR for independent verification" in rekor
        and "cosign verify-attestation" in rekor
        and "slsa-verifier verify-image" in rekor
        and "docker login" not in anonymous
        and "podman login" not in anonymous
        and "cosign verify-attestation" in anonymous
        and "slsa-verifier verify-image" in anonymous
        and workflow.find("  rekor-rollup:") < workflow.find("  apply-aliases:")
    )
    contract_identity_invalid = not (
        sign_attest.count('Path("images/python/contracts/image-manifest.json")') >= 1
        and rekor.count('Path("images/python/contracts/image-manifest.json")') >= 1
        and anonymous.count("images/python/contracts/image-manifest.json") >= 2
    )
    scope_invalid = not (
        "tools/decide-python-publish-scope.py" in workflow
        and "--print-base" in workflow
        and "needs.publish-scope.outputs.publish == 'true'" in publish
    )
    gates_invalid = (
        not all(
            marker in gate_evidence
            for marker in (
                "assert-reproducible.py",
                "assert-parent-subset.py",
                "run-python-gates.sh",
                "assert-scanner-db-freshness.py",
                "assert-scanner-canary.py",
                "assert-no-phantom-packages.py",
                "--expect-absent sqlite-libs",
                "--expect-absent util-linux",
                "--expect-absent util-linux-core",
                "assert-raw-scanners-no-sqlite.py",
                "assert-no-rootfs-secrets.py",
                "generate-nist-800-190-predicate.py",
                "run-stig-arf.sh",
                "dist/tools/trivy convert",
                '-o "json=${vuln_dir}/base-python.grype.all.json"',
                '-o "sarif=${vuln_dir}/base-python.grype.all.sarif"',
                "find attestations sbom stig vuln -type f",
                "retention-days: 90",
                "category: base-python/trivy/amd64",
                "category: base-python/grype/amd64",
                "category: base-python/trivy/arm64",
                "category: base-python/grype/arm64",
            )
        )
        or gate_evidence.count("github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9") != 4
    )
    index_dataflow_invalid = not (
        publish.count('crane manifest "${IMAGE_REF}" > dist/python-index/index.json') == 1
        and workflow.count('crane manifest "${IMAGE_REF}" > dist/python-index/index.json') == 1
        and "PUSH_DIGEST: ${{ steps.image.outputs.digest }}" in publish
        and '--fetch-reference "${IMAGE_REF}"' in publish
        and workflow.count('set(metadata) != {"release"}') == 2
        and workflow.count('target = metadata["release"]') == 2
        and workflow.count('digest = target.get("containerimage.digest")') == 2
        and publish.count("tools/resolve-python-index.py") >= 1
        and gate_evidence.count("tools/resolve-python-index.py") >= 2
        and sign_attest.count("tools/resolve-python-index.py") >= 3
        and rekor.count("tools/resolve-python-index.py") >= 2
        and aliases.count("tools/resolve-python-index.py") >= 2
        and workflow.count("--bundle-root dist/python-index") == 4
        and workflow.count("--bundle-manifest dist/python-index/SHA256SUMS") == 4
        and workflow.count("--require-file index.json") == 4
        and '--consumer "sign=${INDEX_DIGEST}"' in sign_attest
        and '--consumer "attest=${INDEX_DIGEST}"' in sign_attest
        and '--consumer "alias=${INDEX_DIGEST}"' in aliases
        and "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f" in publish
        and gate_evidence.count("actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131") == 1
        and sign_attest.count("actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131") == 2
        and rekor.count("actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131") == 1
        and aliases.count("actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131") == 1
    )
    slsa_execution_invalid = not all(
        marker in rekor
        for marker in (
            "tools/assert-python-slsa-certificate.py",
            "cosign triangulate --type attestation",
            'crane blob "${IMAGE_REPOSITORY}@${layer_digest}"',
            "--attestation-manifest dist/python-independent/attestation-manifest.json",
            "--verified dist/python-independent/slsa.index.jsonl",
            '--sha "${GITHUB_SHA}"',
            '--ref "${GITHUB_REF}"',
        )
    ) or not all(
        oid in read("tools/assert-python-slsa-certificate.py")
        for oid in (
            "1.3.6.1.4.1.57264.1.10",
            "1.3.6.1.4.1.57264.1.13",
            "1.3.6.1.4.1.57264.1.14",
            "1.3.6.1.4.1.57264.1.18",
            "1.3.6.1.4.1.57264.1.19",
        )
    )
    pre_alias_invalid = not all(
        marker in preflight
        for marker in (
            'for alias in base-python "base-python-${short_sha}" "${OCI_VERSION}"; do',
            'if [[ "${status}" != "404" ]]; then',
            "pre-alias manifest must be absent",
        )
    )
    tag_isolation_invalid = not (
        'tags: ["python/v*"]' in workflow
        and "refs/tags/python/v" in workflow
        and "refs/tags/v*" not in workflow
        and "refs/tags/v" not in workflow
    )

    # CHECK: python-publish-trigger
    reject(trigger_invalid, "Python publish trigger contract mismatch")
    # CHECK: python-publish-jobs
    reject(job_ids_invalid, "Python publish job graph mismatch")
    # CHECK: python-publish-concurrency
    reject(concurrency_invalid, "Python publish concurrency contract mismatch")
    # CHECK: python-publish-permissions
    reject(permissions_invalid, "Python publish least-privilege inventory mismatch")
    # CHECK: python-publish-guards
    reject(guards_invalid, "Python publish base-repository guard mismatch")
    # CHECK: python-publish-fail-closed
    reject(fail_closed_invalid, "Python publish repository-authored gate is not fail-closed")
    # CHECK: python-publish-gate-cosign-action
    reject(gate_cosign_action_invalid, "Python publish gate-evidence Cosign action mismatch")
    # CHECK: python-publish-gate-cosign-version
    reject(gate_cosign_version_invalid, "Python publish gate-evidence Cosign version input mismatch")
    # CHECK: python-publish-gate-cosign-order
    reject(gate_cosign_order_invalid, "Python publish gate-evidence Cosign ordering mismatch")
    # CHECK: python-publish-generator
    reject(generator_invalid, "Python publish reusable SLSA generator caller mismatch")
    # CHECK: python-publish-exporter
    reject(exporter_invalid, "Python publish digest-only exporter contract mismatch")
    # CHECK: python-publish-closed-caller
    reject(closed_caller_invalid, "Python publish release caller is not closed")
    # CHECK: python-publish-oci-binding
    reject(oci_binding_invalid, "Python publish OCI label binding mismatch")
    # CHECK: python-publish-subject-matrix
    reject(subject_matrix_invalid, "Python publish attestation subject matrix mismatch")
    # CHECK: python-publish-signing
    reject(signing_invalid, "Python publish recursive signature verification mismatch")
    # CHECK: python-publish-trust
    reject(trust_invalid, "Python publish trust-contract binding mismatch")
    # CHECK: python-publish-provenance
    reject(provenance_invalid, "Python publish provenance policy mismatch")
    # CHECK: python-publish-alias-order
    reject(alias_order_invalid, "Python publish two-phase alias ordering mismatch")
    # CHECK: python-publish-collisions
    reject(collision_invalid, "Python publish create-once collision policy mismatch")
    # CHECK: python-publish-independent
    reject(independent_invalid, "Python publish independent-verification ordering mismatch")
    # CHECK: python-publish-contract-identity
    reject(contract_identity_invalid, "Python publish identity is not contract-derived")
    # CHECK: python-publish-scope
    reject(scope_invalid, "Python publish scope policy wiring mismatch")
    # CHECK: python-publish-gates
    reject(gates_invalid, "Python publish gate battery mismatch")
    # CHECK: python-publish-index-dataflow
    reject(index_dataflow_invalid, "Python publish trusted registry index dataflow mismatch")
    # CHECK: python-publish-slsa-execution
    reject(slsa_execution_invalid, "Python publish SLSA execution certificate binding mismatch")
    # CHECK: python-publish-pre-alias
    reject(pre_alias_invalid, "Python preflight consumer-alias absence proof mismatch")
    # CHECK: python-publish-tag-isolation
    reject(tag_isolation_invalid, "Python and micro release tag namespaces overlap")
    return errors


def _publish_python_workflow_fixtures(workflow: str) -> list[tuple[str, str, str]]:
    def changed(label: str, old: str, new: str, reason: str, occurrence: int = 1) -> tuple[str, str, str]:
        return label, _replace_nth(workflow, old, new, occurrence), reason

    return [
        changed("trigger", 'tags: ["python/v*"]', 'tags: ["v*"]', "Python publish trigger contract mismatch"),
        changed("jobs", "  anonymous-verification:\n", "  anonymous-check:\n", "Python publish job graph mismatch"),
        changed(
            "concurrency",
            "cancel-in-progress: false",
            "cancel-in-progress: true",
            "Python publish concurrency contract mismatch",
        ),
        changed(
            "permissions",
            "      packages: write\n",
            "      packages: read\n",
            "Python publish least-privilege inventory mismatch",
        ),
        changed(
            "guards",
            PUBLISH_PYTHON_REPOSITORY_GUARD,
            "github.repository != ''",
            "Python publish base-repository guard mismatch",
        ),
        changed(
            "fail-closed",
            "          set -euo pipefail\n",
            "          set +e\n",
            "Python publish repository-authored gate is not fail-closed",
        ),
        changed(
            "gate-cosign-deletion",
            "      - name: Install Cosign\n"
            "        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n"
            "        with:\n"
            "          cosign-release: v2.5.2\n",
            "",
            "Python publish gate-evidence Cosign action mismatch",
        ),
        changed(
            "gate-cosign-action-sha",
            "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2",
            "sigstore/cosign-installer@0000000000000000000000000000000000000000 # v4.1.2",
            "Python publish gate-evidence Cosign action mismatch",
        ),
        changed(
            "gate-cosign-version",
            "        with:\n          cosign-release: v2.5.2\n      - name: Install publication gate tools",
            "      - name: Install publication gate tools",
            "Python publish gate-evidence Cosign version input mismatch",
        ),
        changed(
            "gate-cosign-order",
            "          cosign-release: v2.5.2\n      - name: Install publication gate tools",
            "          cosign-release: v2.5.2\n"
            "      - name: Confirm Cosign version\n"
            "        run: cosign version\n"
            "      - name: Install publication gate tools",
            "Python publish gate-evidence Cosign ordering mismatch",
        ),
        changed(
            "gate-cosign-order-unnamed-run",
            "          cosign-release: v2.5.2\n      - name: Install publication gate tools",
            "          cosign-release: v2.5.2\n"
            "      - run: cosign version\n"
            "      - name: Install publication gate tools",
            "Python publish gate-evidence Cosign ordering mismatch",
        ),
        changed(
            "gate-cosign-order-unnamed-shell",
            "          cosign-release: v2.5.2\n      - name: Install publication gate tools",
            "          cosign-release: v2.5.2\n"
            "      - shell: bash\n"
            "        run: cosign version\n"
            "      - name: Install publication gate tools",
            "Python publish gate-evidence Cosign ordering mismatch",
        ),
        changed(
            "generator",
            "generator_container_slsa3.yml@v2.1.0",
            "generator_container_slsa3.yml@main",
            "Python publish reusable SLSA generator caller mismatch",
        ),
        changed(
            "exporter",
            '"push-by-digest": "true"',
            '"push-by-digest": "false"',
            "Python publish digest-only exporter contract mismatch",
            2,
        ),
        changed(
            "closed-caller",
            "            --metadata-file\n            dist/python-publish/image-metadata.json",
            "            --set\n            release.tags=example.invalid/candidate:latest",
            "Python publish release caller is not closed",
        ),
        changed(
            "oci-binding",
            "org.opencontainers.image.revision",
            "org.opencontainers.image.ref.name",
            "Python publish OCI label binding mismatch",
            1,
        ),
        (
            "subject-matrix",
            workflow.replace("steps.contract.outputs.cyclonedx", "steps.contract.outputs.missing_predicate"),
            "Python publish attestation subject matrix mismatch",
        ),
        changed(
            "signing",
            "cosign sign --recursive",
            "cosign sign",
            "Python publish recursive signature verification mismatch",
        ),
        changed(
            "trust",
            "git rev-parse HEAD:images/python",
            "git rev-parse HEAD:images",
            "Python publish trust-contract binding mismatch",
        ),
        changed(
            "provenance",
            "--source-uri github.com/NWarila/ubi9-base-micro",
            "--source-uri github.com/example/fork",
            "Python publish provenance policy mismatch",
        ),
        changed(
            "alias-order",
            "      - rekor-rollup\n",
            "      - slsa-provenance\n",
            "Python publish two-phase alias ordering mismatch",
        ),
        changed(
            "collisions", "--phase pre-apply", "--phase early", "Python publish create-once collision policy mismatch"
        ),
        changed(
            "independent",
            "Log in to GHCR for independent verification",
            "Prepare independent verification",
            "Python publish independent-verification ordering mismatch",
        ),
        changed(
            "contract-identity",
            'Path("images/python/contracts/image-manifest.json")',
            'Path("images/python/contracts/other.json")',
            "Python publish identity is not contract-derived",
            2,
        ),
        (
            "scope",
            workflow.replace("tools/decide-python-publish-scope.py", "tools/decide-publish-scope.py"),
            "Python publish scope policy wiring mismatch",
        ),
        changed(
            "gates",
            "assert-scanner-canary.py",
            "assert-scanner-canary-disabled.py",
            "Python publish gate battery mismatch",
        ),
        changed(
            "index-dataflow",
            'crane manifest "${IMAGE_REF}" > dist/python-index/index.json',
            'crane manifest "${IMAGE_REPOSITORY}:candidate" > dist/python-index/index.json',
            "Python publish trusted registry index dataflow mismatch",
        ),
        changed(
            "metadata-shape",
            'target = metadata["release"]',
            "target = metadata",
            "Python publish trusted registry index dataflow mismatch",
            2,
        ),
        (
            "slsa-execution",
            workflow.replace(
                "tools/assert-python-slsa-certificate.py",
                "tools/assert-python-slsa-certificate-disabled.py",
            ),
            "Python publish SLSA execution certificate binding mismatch",
        ),
        changed(
            "pre-alias",
            "pre-alias manifest must be absent",
            "pre-alias manifest was queried",
            "Python preflight consumer-alias absence proof mismatch",
        ),
        changed(
            "tag-isolation", "refs/tags/python/v", "refs/tags/v", "Python and micro release tag namespaces overlap", 1
        ),
    ]


def check_publish_python_workflow_self_test(only_label: str | None = None) -> None:
    workflow = read(PUBLISH_PYTHON_WORKFLOW)
    baseline = publish_python_workflow_errors(workflow)
    require(not baseline, "publish Python workflow baseline failed: " + "; ".join(baseline))
    fixtures = _publish_python_workflow_fixtures(workflow)
    selected = 0
    for label, mutated, expected in fixtures:
        if only_label is not None and label != only_label:
            continue
        selected += 1
        parse_error = _python_ci_yaml_parse_error(mutated)
        require(parse_error is None, f"publish Python workflow mutation is not valid YAML [{label}]: {parse_error}")
        if expected not in publish_python_workflow_errors(mutated):
            raise VerifyError(f"publish Python workflow mutation unexpectedly passed: {label}")
        print(f"publish Python workflow mutation rejected [{label}] parse=ok diagnostic={expected}")
    if only_label is None:
        require(selected == len(fixtures), "publish Python workflow fixture inventory mismatch")
        authorization_cases = [
            ("fork push:main", "someone/fork", "push", "refs/heads/main", "true", False),
            ("fork tag push", "someone/fork", "push", "refs/tags/python/v0.1.0", "true", False),
            ("fork PR", "someone/fork", "pull_request", "refs/pull/1/merge", "true", False),
            ("base PR", "NWarila/ubi9-base-micro", "pull_request", "refs/pull/1/merge", "true", False),
            ("base main push", "NWarila/ubi9-base-micro", "push", "refs/heads/main", "true", True),
            ("base release tag", "NWarila/ubi9-base-micro", "push", "refs/tags/python/v0.1.0", "true", True),
        ]
        for label, repository, event, ref, scope, authorized_expected in authorization_cases:
            require(
                publish_python_authorized(repository, event, ref, scope) is authorized_expected,
                f"publish Python authorization fixture failed: {label}",
            )
            print(f"publish Python authorization fixture [{label}] authorized={str(authorized_expected).lower()}")
        require(
            not "refs/tags/python/v0.1.0".startswith("refs/tags/v")
            and not "refs/tags/v0.1.0".startswith("refs/tags/python/v"),
            "Python and micro tag evaluators must be disjoint",
        )
        print("publish Python tag-isolation fixtures: python->micro=false micro->python=false")
        print(f"publish Python workflow mutation probes: {selected}/{len(fixtures)} rejected")
    else:
        require(selected == 1, f"unknown publish Python workflow fixture: {only_label}")


def check_publish_python_workflow_checker_mutation_self_test() -> None:
    source = read("tools/verify.py")
    checker_start = source.index("def publish_python_workflow_errors(")
    checker_end = source.index("\ndef _publish_python_workflow_fixtures(", checker_start)
    checker_source = source[checker_start:checker_end]
    guards = [
        ("python-publish-trigger", "trigger_invalid", "trigger"),
        ("python-publish-jobs", "job_ids_invalid", "jobs"),
        ("python-publish-concurrency", "concurrency_invalid", "concurrency"),
        ("python-publish-permissions", "permissions_invalid", "permissions"),
        ("python-publish-guards", "guards_invalid", "guards"),
        ("python-publish-fail-closed", "fail_closed_invalid", "fail-closed"),
        ("python-publish-gate-cosign-action", "gate_cosign_action_invalid", "gate-cosign-action-sha"),
        ("python-publish-gate-cosign-version", "gate_cosign_version_invalid", "gate-cosign-version"),
        (
            "python-publish-gate-cosign-order",
            "gate_cosign_order_invalid",
            ("gate-cosign-order", "gate-cosign-order-unnamed-run", "gate-cosign-order-unnamed-shell"),
        ),
        ("python-publish-generator", "generator_invalid", "generator"),
        ("python-publish-exporter", "exporter_invalid", "exporter"),
        ("python-publish-closed-caller", "closed_caller_invalid", "closed-caller"),
        ("python-publish-oci-binding", "oci_binding_invalid", "oci-binding"),
        ("python-publish-subject-matrix", "subject_matrix_invalid", "subject-matrix"),
        ("python-publish-signing", "signing_invalid", "signing"),
        ("python-publish-trust", "trust_invalid", "trust"),
        ("python-publish-provenance", "provenance_invalid", "provenance"),
        ("python-publish-alias-order", "alias_order_invalid", "alias-order"),
        ("python-publish-collisions", "collision_invalid", "collisions"),
        ("python-publish-independent", "independent_invalid", "independent"),
        ("python-publish-contract-identity", "contract_identity_invalid", "contract-identity"),
        ("python-publish-scope", "scope_invalid", "scope"),
        ("python-publish-gates", "gates_invalid", "gates"),
        ("python-publish-index-dataflow", "index_dataflow_invalid", "index-dataflow"),
        ("python-publish-slsa-execution", "slsa_execution_invalid", "slsa-execution"),
        ("python-publish-pre-alias", "pre_alias_invalid", "pre-alias"),
        ("python-publish-tag-isolation", "tag_isolation_invalid", "tag-isolation"),
    ]
    markers = re.findall(r"^    # CHECK: (python-publish-[a-z-]+)$", checker_source, re.MULTILINE)
    require(
        Counter(markers) == Counter(guard for guard, _, _ in guards) and len(markers) == len(guards),
        "publish Python workflow checker mutation list must cover every rejection guard exactly once",
    )
    probe_count = 0
    for guard, condition, fixture_labels in guards:
        anchor = f"reject({condition},"
        require(checker_source.count(anchor) == 1, f"publish Python workflow checker anchor changed: {guard}")
        mutated_checker = checker_source.replace(anchor, "reject(False,", 1)
        mutated = source[:checker_start] + mutated_checker + source[checker_end:]
        ast.parse(mutated, filename="tools/verify.py")
        fixtures = (fixture_labels,) if isinstance(fixture_labels, str) else fixture_labels
        for fixture in fixtures:
            probe_count += 1
            result = _run_mutated_python_verifier(mutated, ["--check-publish-python-workflow-fixture", fixture])
            expected = f"verify failed: publish Python workflow mutation unexpectedly passed: {fixture}"
            require(
                result.returncode == 1, f"publish Python workflow checker mutation {guard} returned {result.returncode}"
            )
            require(
                result.stderr.strip() == expected,
                f"publish Python workflow checker mutation {guard} returned unexpected diagnostic: "
                f"{result.stderr.strip()!r}",
            )
            location = source[: source.index(f"# CHECK: {guard}")].count("\n") + 1
            print(
                f"publish Python workflow checker mutation rejected [guard={guard} "
                f"location=tools/verify.py:{location} fixture={fixture} diagnostic={expected}]"
            )
    print(f"publish Python workflow checker mutation probes: {probe_count}/{probe_count} rejected")


def check_publish_python_workflow() -> None:
    workflow_bytes = (ROOT / PUBLISH_PYTHON_WORKFLOW).read_bytes()
    workflow = workflow_bytes.decode()
    errors = publish_python_workflow_errors(workflow)
    errors.extend(publish_python_surface_lock_errors(workflow_bytes))
    require(not errors, "publish Python workflow contract failed: " + "; ".join(errors))


def python_evidence_errors(workflow: str, tailoring: str, ledger: str, gitignore: str, codeowners: str) -> list[str]:
    errors: list[str] = []

    def expect(condition: object, message: str) -> None:
        if not condition:
            errors.append(message)

    # The python image must be scanned under its OWN profile and tailoring: micro's profile also
    # passes against this image, so a stale binding would be a false green rather than a failure.
    expect(PYTHON_STIG_PROFILE in tailoring, "python tailoring must declare the python profile id")
    expect(
        "ubi9_base_micro_stig" not in tailoring,
        "python tailoring must not retain the micro profile or tailoring id",
    )
    expect(f'"tailored_profile": "{PYTHON_STIG_PROFILE}"' in ledger, "python ledger must bind the python profile")
    expect("ubi9-base-micro" not in ledger, "python justification texts must not describe the micro image")

    micro_selects = set(re.findall(r'idref="([^"]+)"', read("stig/rhel9-base-micro-tailoring.xml")))
    python_selects = set(re.findall(r'idref="([^"]+)"', tailoring))
    expect(
        micro_selects == python_selects,
        "python tailoring must select exactly micro's rule set; "
        f"only-micro={sorted(micro_selects - python_selects)} only-python={sorted(python_selects - micro_selects)}",
    )

    expected_env = {
        "SSG_VERSION": PYTHON_SSG_VERSION,
        "SSG_TARBALL_SHA512": PYTHON_SSG_TARBALL_SHA512,
        "STIG_PROFILE": PYTHON_STIG_PROFILE,
        "STIG_FAIL_ON": PYTHON_STIG_FAIL_ON,
    }
    for name, value in expected_env.items():
        expect(
            re.search(rf'^  {re.escape(name)}: "{re.escape(value)}"$', workflow, re.MULTILINE) is not None,
            f"python CI must pin {name} exactly to {value}",
        )

    build_block = _workflow_job_block(workflow, "build")
    expect(bool(build_block), "python CI must retain the build job")
    build_steps = _workflow_step_names(build_block)
    positions: list[int] = []
    for step_name in PYTHON_EVIDENCE_STEP_ORDER:
        expect(build_steps.count(step_name) == 1, f"python CI build job must contain evidence step once: {step_name}")
        if step_name in build_steps:
            positions.append(build_steps.index(step_name))
    expect(
        len(positions) == len(PYTHON_EVIDENCE_STEP_ORDER) and positions == sorted(positions),
        "python CI evidence steps must retain the complete "
        "STIG -> SBOM -> fixable gates -> reports -> secret -> NIST order",
    )
    expect(
        build_steps.index("Run rootfs secret gate")
        < build_steps.index("Generate and validate NIST SP 800-190 predicate")
        if "Run rootfs secret gate" in build_steps and "Generate and validate NIST SP 800-190 predicate" in build_steps
        else False,
        "python CI secret gate must run before NIST predicate generation",
    )
    expect("continue-on-error" not in workflow, "python CI evidence chain must not use continue-on-error")

    for marker in (
        "images/python/tools/run-stig-arf.sh",
        "images/python/tools/assert-sbom-rpms.py",
        "tools/assert-no-phantom-packages.py",
        "--expect-absent sqlite-libs",
        "--expect-absent util-linux",
        "--expect-absent util-linux-core",
        "images/python/tools/assert-raw-scanners-no-sqlite.py",
        "images/python/tools/assert-no-rootfs-secrets.py",
        "images/python/tools/generate-nist-800-190-predicate.py",
        "tools/assert-scanner-canary.py",
        "--list-all-pkgs",
        "--severity MEDIUM,HIGH,CRITICAL",
        "--fail-on medium",
        "dist/tools/trivy convert",
        "*.sarif",
        "--validate",
        "timeout-minutes: 45",
    ):
        expect(marker in workflow, f"python CI missing evidence marker: {marker}")
    for pattern in PYTHON_EVIDENCE_SHARED_DEPENDENCIES:
        expect(pattern in workflow, f"python CI change filter missing shared dependency: {pattern}")
    for forbidden in PYTHON_EVIDENCE_FORBIDDEN:
        expect(forbidden not in workflow, f"python CI must not publish or attest: {forbidden}")
    expect(
        "evidence:" not in workflow and "needs.evidence" not in workflow,
        "python evidence must run inside the build job, not a separate job",
    )
    sbom_step = _workflow_named_step(build_block, "Generate and gate rpmdb SBOMs")
    expect(
        sbom_step.count("tools/assert-no-phantom-packages.py") == 1
        and all(
            len(
                re.findall(
                    rf"^\s*--expect-absent\s+{re.escape(package)}(?:\s+\\)?\s*$",
                    sbom_step,
                    re.MULTILINE,
                )
            )
            == 1
            for package in ("sqlite-libs", "util-linux", "util-linux-core")
        ),
        "python SBOM step must run the shared phantom-package gate once with all absence claims pinned",
    )
    report_step = _workflow_named_step(
        build_block,
        "Generate complete vulnerability reports and prove raw SQLite absence",
    )
    raw_gate = "images/python/tools/assert-raw-scanners-no-sqlite.py"
    expect(
        report_step.count(raw_gate) == 1
        and report_step.count("dist/tools/trivy image") == 1
        and report_step.count("dist/tools/trivy convert") == 1
        and report_step.count('dist/tools/grype "${image}"') == 1
        and all(
            report_step.count(suffix) >= 1
            for suffix in (".trivy.all.json", ".trivy.all.sarif", ".grype.all.json", ".grype.all.sarif")
        ),
        "python report step must scan once per scanner, emit JSON and SARIF, and prove raw SQLite absence",
    )
    upload_step = _workflow_named_step(build_block, "Upload evidence artifacts")
    expect(bool(upload_step), "python CI must contain one parseable Upload evidence artifacts step")
    upload_paths = _workflow_upload_paths(upload_step)
    expect(
        Counter(upload_paths) == Counter(PYTHON_EVIDENCE_UPLOAD_PATHS)
        and len(upload_paths) == len(PYTHON_EVIDENCE_UPLOAD_PATHS),
        "python evidence upload path set must contain exactly the allowlisted evidence globs, "
        "with no missing, extra, or duplicate paths",
    )

    for entry in ("!/images/python/stig/", "!/images/python/vex/"):
        expect(f"\n{entry}\n" in gitignore, f".gitignore must allowlist {entry} on its own line")
    for entry in ("/images/python/stig/ @NWarila", "/images/python/vex/ @NWarila"):
        expect(entry in codeowners, f"CODEOWNERS must gate {entry}")
    return errors


def check_python_evidence() -> None:
    errors = python_evidence_errors(
        read(".github/workflows/python-ci.yaml"),
        read(PYTHON_STIG_TAILORING),
        read(PYTHON_STIG_JUSTIFICATIONS),
        read(".gitignore"),
        read(".github/CODEOWNERS"),
    )
    require(not errors, "python evidence contract failed: " + "; ".join(errors))

    contract = json.loads(read("images/python/contracts/image-manifest.json"))
    provenance = contract.get("provenance", {})
    identity = provenance.get("cosign", {}).get("certificate_identity", "")
    require(
        identity.startswith("https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-python.yaml@"),
        f"python contract must record the publish-python identity template, got: {identity!r}",
    )
    require(
        provenance.get("cosign", {}).get("certificate_oidc_issuer") == cosign_oidc_issuer(),
        "python contract OIDC issuer must match the repository issuer",
    )
    require(
        provenance.get("slsa", {}).get("builder_id") == slsa_builder_id(),
        "python contract SLSA builder id must match the pinned generator identity",
    )
    require(
        set(provenance.get("attestation_predicate_types", {}))
        == {
            "spdx",
            "cyclonedx",
            "openvex",
            "nist_800_190",
            "stig_arf",
            "trust_contract",
        },
        "python contract must map exactly the six attestation predicate types",
    )
    check_python_nist()
    check_python_secret_classifier()


def check_python_evidence_self_test() -> None:
    workflow = read(".github/workflows/python-ci.yaml")
    tailoring = read(PYTHON_STIG_TAILORING)
    ledger = read(PYTHON_STIG_JUSTIFICATIONS)
    gitignore = read(".gitignore")
    codeowners = read(".github/CODEOWNERS")
    baseline = python_evidence_errors(workflow, tailoring, ledger, gitignore, codeowners)
    require(not baseline, "python evidence self-test baseline failed: " + "; ".join(baseline))

    def swap_adjacent_steps(source: str, first: str, second: str) -> str:
        first_marker = f"      - name: {first}\n"
        second_marker = f"      - name: {second}\n"
        first_start = source.find(first_marker)
        second_start = source.find(second_marker)
        require(first_start >= 0 and second_start >= 0, "python evidence step-swap mutation anchors missing")
        require(first_start < second_start, "python evidence step-swap mutation order changed")
        next_step = source.find("      - name: ", second_start + len(second_marker))
        second_end = len(source) if next_step < 0 else next_step
        require(
            source.find("      - name: ", first_start + len(first_marker)) == second_start,
            "python evidence secret/NIST mutation expects adjacent steps",
        )
        return (
            source[:first_start]
            + source[second_start:second_end]
            + source[first_start:second_start]
            + source[second_end:]
        )

    without_ssg_pins = workflow.replace(f'  SSG_VERSION: "{PYTHON_SSG_VERSION}"\n', "").replace(
        f'  SSG_TARBALL_SHA512: "{PYTHON_SSG_TARBALL_SHA512}"\n',
        "",
    )
    swapped_secret_nist = swap_adjacent_steps(
        workflow,
        "Run rootfs secret gate",
        "Generate and validate NIST SP 800-190 predicate",
    )
    continue_on_error = workflow.replace(
        "      - name: Run rootfs secret gate\n",
        "      - name: Run rootfs secret gate\n        continue-on-error: true\n",
        1,
    )
    broadened_sbom_upload = workflow.replace(
        "            dist/python-evidence/sbom/*.json\n",
        "            dist/python-evidence/sbom/*\n",
        1,
    )
    bare_dist_upload = workflow.replace(
        "            dist/python-evidence/sbom/*.json\n",
        "            dist/\n",
        1,
    )
    rootfs_upload = workflow.replace(
        "            dist/python-evidence/sbom/*.json\n",
        "            dist/python-evidence/sbom/*.json\n            dist/python-evidence/rootfs.${{ matrix.arch }}/**\n",
        1,
    )
    image_archive_upload = workflow.replace(
        "            dist/python-evidence/sbom/*.json\n",
        "            dist/python-evidence/sbom/*.json\n"
        "            dist/python-evidence/sbom/image.${{ matrix.arch }}.tar\n",
        1,
    )
    phantom_expectation_changed = workflow.replace(
        "--expect-absent sqlite-libs",
        "--expect-absent other-libs",
        1,
    )
    mutations: list[tuple[str, tuple[str, str, str, str, str]]] = [
        (
            "both SSG pins removed",
            (without_ssg_pins, tailoring, ledger, gitignore, codeowners),
        ),
        (
            "secret and NIST steps swapped",
            (swapped_secret_nist, tailoring, ledger, gitignore, codeowners),
        ),
        (
            "continue-on-error inserted",
            (continue_on_error, tailoring, ledger, gitignore, codeowners),
        ),
        (
            "micro profile restored",
            (
                workflow,
                tailoring.replace(PYTHON_STIG_PROFILE, "xccdf_org.nwarila.content_profile_ubi9_base_micro_stig"),
                ledger,
                gitignore,
                codeowners,
            ),
        ),
        (
            "micro justification text",
            (workflow, tailoring, ledger.replace("ubi9-base-python", "ubi9-base-micro", 1), gitignore, codeowners),
        ),
        (
            "rule dropped",
            (
                workflow,
                tailoring.replace("xccdf_org.ssgproject.content_rule_", "removed_rule_", 1),
                ledger,
                gitignore,
                codeowners,
            ),
        ),
        (
            "shared dependency dropped",
            (
                workflow.replace("^tools/generate-stig-arf-predicate\\.py$", "^tools/nope$"),
                tailoring,
                ledger,
                gitignore,
                codeowners,
            ),
        ),
        (
            "attestation added",
            (
                workflow.replace("python-tree change detection", "cosign attest --type openvex"),
                tailoring,
                ledger,
                gitignore,
                codeowners,
            ),
        ),
        (
            "separate evidence job",
            (
                workflow.replace("  self-tests:", "  evidence:\n    x: y\n  self-tests:"),
                tailoring,
                ledger,
                gitignore,
                codeowners,
            ),
        ),
        (
            "gitignore entry dropped",
            (workflow, tailoring, ledger, gitignore.replace("!/images/python/vex/\n", ""), codeowners),
        ),
        (
            "codeowners entry dropped",
            (workflow, tailoring, ledger, gitignore, codeowners.replace("/images/python/stig/ @NWarila\n", "")),
        ),
        (
            "SBOM upload glob broadened",
            (broadened_sbom_upload, tailoring, ledger, gitignore, codeowners),
        ),
        (
            "bare dist upload",
            (bare_dist_upload, tailoring, ledger, gitignore, codeowners),
        ),
        (
            "rootfs upload added",
            (rootfs_upload, tailoring, ledger, gitignore, codeowners),
        ),
        (
            "image archive upload added",
            (image_archive_upload, tailoring, ledger, gitignore, codeowners),
        ),
        (
            "phantom-package absent expectation changed",
            (phantom_expectation_changed, tailoring, ledger, gitignore, codeowners),
        ),
    ]
    rejected = 0
    for label, args in mutations:
        require(
            args != (workflow, tailoring, ledger, gitignore, codeowners),
            f"python evidence mutation is a no-op: {label}",
        )
        if python_evidence_errors(*args):
            rejected += 1
        else:
            raise VerifyError(f"python evidence mutation unexpectedly passed: {label}")
    print(f"python evidence mutation probes: {rejected}/{len(mutations)} rejected")


def _resolve_schema_ref(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    """Resolve a local JSON-Pointer $ref. Remote refs are refused: this validator is offline."""
    seen = 0
    while "$ref" in schema:
        seen += 1
        if seen > 16:
            raise VerifyError("schema $ref chain is too deep or cyclic")
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise VerifyError(f"schema $ref must be a local JSON pointer, got: {ref!r}")
        target: Any = root
        for raw_token in ref[2:].split("/"):
            token = raw_token.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or token not in target:
                raise VerifyError(f"schema $ref does not resolve: {ref}")
            target = target[token]
        if not isinstance(target, dict):
            raise VerifyError(f"schema $ref does not name an object: {ref}")
        schema = target
    return schema


def validate_against_schema(instance: Any, schema: dict[str, Any], root: dict[str, Any], path: str) -> list[str]:
    """Offline subset validator: the keywords these contracts actually use."""
    schema = _resolve_schema_ref(schema, root)
    errors: list[str] = []
    expected = schema.get("type")
    kinds: dict[str, type | tuple[type, ...]] = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "null": type(None),
    }
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not one of {schema['enum']!r}")
    if isinstance(expected, str) and expected in kinds and not isinstance(instance, kinds[expected]):
        errors.append(f"{path}: expected {expected}, got {type(instance).__name__}")
        return errors
    if isinstance(instance, str):
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, instance) is None:
            errors.append(f"{path}: {instance!r} does not match {pattern}")
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append(f"{path}: shorter than minLength {minimum}")
    if isinstance(instance, list):
        items = schema.get("items")
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append(f"{path}: fewer than minItems {minimum}")
        if isinstance(items, dict):
            for index, entry in enumerate(instance):
                errors.extend(validate_against_schema(entry, items, root, f"{path}[{index}]"))
    if isinstance(instance, dict):
        properties = schema.get("properties") or {}
        errors.extend(
            f"{path}: missing required property {name!r}"
            for name in schema.get("required") or []
            if name not in instance
        )
        if schema.get("additionalProperties") is False:
            errors.extend(
                f"{path}: additional property {name!r} is not permitted" for name in instance if name not in properties
            )
        for name, value in instance.items():
            if name in properties:
                errors.extend(validate_against_schema(value, properties[name], root, f"{path}.{name}"))
    return errors


def check_python_contract_schema() -> None:
    schema = json.loads(read("images/python/contracts/image-manifest.schema.json"))
    contract = json.loads(read("images/python/contracts/image-manifest.json"))
    errors = validate_against_schema(contract, schema, schema, "contract")
    require(not errors, "images/python contract violates its schema: " + "; ".join(errors))


def check_python_contract_schema_self_test() -> None:
    schema = json.loads(read("images/python/contracts/image-manifest.schema.json"))
    contract = json.loads(read("images/python/contracts/image-manifest.json"))
    require(
        not validate_against_schema(contract, schema, schema, "contract"),
        "python contract schema self-test baseline failed",
    )

    def mutate(apply: Any) -> dict[str, Any]:
        clone: dict[str, Any] = json.loads(json.dumps(contract))
        apply(clone)
        return clone

    def drop_member(clone: dict[str, Any]) -> None:
        del clone["provenance"]["slsa"]

    def add_nested(clone: dict[str, Any]) -> None:
        clone["provenance"]["cosign"]["unexpected"] = "x"

    def wrong_identity(clone: dict[str, Any]) -> None:
        clone["provenance"]["cosign"]["certificate_identity"] = "https://example.invalid/whatever@ref"

    def wrong_type(clone: dict[str, Any]) -> None:
        clone["provenance"]["attestation_predicate_types"]["spdx"] = 17

    def missing_trust_contract(clone: dict[str, Any]) -> None:
        del clone["provenance"]["attestation_predicate_types"]["trust_contract"]

    def extra_trust_contract_peer(clone: dict[str, Any]) -> None:
        clone["provenance"]["attestation_predicate_types"]["trust_contract_v2"] = "https://example.invalid/v2"

    def wrong_trust_contract_type(clone: dict[str, Any]) -> None:
        clone["provenance"]["attestation_predicate_types"]["trust_contract"] = 17

    rejected = 0
    for label, apply in [
        ("missing provenance member", drop_member),
        ("nested additional property", add_nested),
        ("wrong identity value", wrong_identity),
        ("wrong predicate type", wrong_type),
        ("missing trust-contract entry", missing_trust_contract),
        ("extra trust-contract entry", extra_trust_contract_peer),
        ("wrongly typed trust-contract entry", wrong_trust_contract_type),
    ]:
        mutation_errors = validate_against_schema(mutate(apply), schema, schema, "contract")
        if mutation_errors:
            rejected += 1
            print(f"python contract schema mutation rejected [{label}] reason={'; '.join(mutation_errors)}")
        else:
            raise VerifyError(f"python contract schema mutation unexpectedly passed: {label}")

    broken = json.loads(json.dumps(schema))
    broken["properties"]["provenance"]["$ref"] = "#/$defs/missing"
    try:
        validate_against_schema(contract, broken, broken, "contract")
    except VerifyError:
        rejected += 1
        print("python contract schema mutation rejected [broken $ref] reason=schema $ref does not resolve")
    else:
        raise VerifyError("python contract schema mutation unexpectedly passed: broken $ref")
    print(f"python contract schema mutation probes: {rejected}/8 rejected")


PYTHON_NIST_POSTURES = {
    "4.1.1": (
        "Fixable MEDIUM, HIGH, and CRITICAL OS/library findings fail closed through both Trivy and Grype. "
        "Complete findings are emitted report-only as JSON and SARIF, with rpmdb-derived package evidence."
    ),
    "4.1.2": (
        "The runtime is built from digest-pinned UBI micro, removes shell and package-manager executables, runs "
        "as USER 65532:65532, preserves the rpmdb, ships the RHEL CA bundle, and configures the OpenSSL FIPS "
        "provider in approved mode with architecture-scoped CMVP wording."
    ),
    "4.1.3": (
        "Package-content risk is constrained by a minimal rpmdb-enumerated rootfs and dual scanner gates over the "
        "locally built image package set. This is not a claim of arbitrary antivirus detection for opaque payloads."
    ),
    "4.1.4": (
        "The exported rootfs is scanned during pull-request CI for inherited high-confidence token patterns and "
        "credential-named assignments whose values match the inherited textual assignment pattern. Exact reviewed "
        "CPython false positives are exempted by path, statement span, the SHA-256 of exact physical source bytes, "
        "and a separate expected AST-kind proof. Files over 8 MiB or with a NUL in the first 65,536 bytes receive "
        "only sampled high-confidence coverage. A finding stops NIST predicate generation."
    ),
    "4.1.5": (
        "The runtime base is UBI micro pinned by sha256 digest and covered by Renovate metadata. "
        "This control presently relies on source-level base-image identity and the local build gates."
    ),
}
PYTHON_NIST_EVIDENCE = {
    "4.1.1": {
        (
            "workflow",
            ".github/workflows/python-ci.yaml#Run canonical fixable vulnerability gates",
            "Trivy fixable MEDIUM/HIGH/CRITICAL gate",
        ),
        (
            "workflow",
            ".github/workflows/python-ci.yaml#Run canonical fixable vulnerability gates",
            "Grype fixable MEDIUM/HIGH/CRITICAL gate",
        ),
        (
            "workflow",
            ".github/workflows/python-ci.yaml#Generate complete vulnerability reports and prove raw SQLite absence",
            "complete Trivy JSON and SARIF report-only evidence",
        ),
        (
            "workflow",
            ".github/workflows/python-ci.yaml#Generate complete vulnerability reports and prove raw SQLite absence",
            "complete Grype JSON and SARIF report-only evidence",
        ),
        ("script", "images/python/tools/assert-sbom-rpms.py", "rpmdb-backed SBOM assertion"),
    },
    "4.1.2": {
        (
            "dockerfile",
            "images/python/Dockerfile#runtime",
            "distroless runtime, non-root user, rpmdb, FIPS config, digest-pinned base",
        ),
        (
            "test",
            "images/python/tools/run-python-gates.sh",
            "no shell/package-manager and USER/rpmdb/CA assertions",
        ),
        (
            "test",
            "images/python/tools/run-python-gates.sh",
            "FIPS provider artifact and approved-mode assertions",
        ),
        ("doc", "docs/compliance/fips.md", "architecture-scoped FIPS claim and arm64 disclaimer"),
    },
    "4.1.3": {
        (
            "workflow",
            ".github/workflows/python-ci.yaml#Generate and gate rpmdb SBOMs",
            "locally built image package inventory from rpmdb",
        ),
        (
            "workflow",
            ".github/workflows/python-ci.yaml#Run canonical fixable vulnerability gates",
            "Trivy scan over locally built image contents",
        ),
        (
            "workflow",
            ".github/workflows/python-ci.yaml#Run canonical fixable vulnerability gates",
            "Grype scan over locally built image contents",
        ),
        (
            "dockerfile",
            "images/python/Dockerfile#python-rootfs",
            "minimal installroot with shell/package-manager removal",
        ),
    },
    "4.1.4": {
        (
            "script",
            "images/python/tools/assert-no-rootfs-secrets.py",
            "narrow textual-pattern scanner with exact CPython exemptions and coverage-limit self-test",
        ),
        (
            "workflow",
            ".github/workflows/python-ci.yaml#Run rootfs secret gate",
            "PR-time rootfs secret gate",
        ),
        (
            "workflow",
            ".github/workflows/python-ci.yaml#Run rootfs secret gate",
            "per-architecture rootfs secret gates in CI",
        ),
        ("report", "<secret-report>", "secret-scan JSON report for this predicate"),
    },
    "4.1.5": {
        (
            "dockerfile",
            "images/python/Dockerfile#ARG BASE_MICRO_IMAGE",
            "UBI micro base image is digest-pinned and Renovate-tracked",
        )
    },
}
PYTHON_NIST_LIMITATIONS = (
    "This predicate is NIST SP 800-190 section 4.1 image evidence, not CIS Docker Benchmark host or daemon evidence.",
    (
        "The embedded-malware entry is bounded to package-content scanning and minimal-image controls; it does not "
        "assert arbitrary malware detection."
    ),
    (
        "The clear-text-secret entry does not claim detection of encoded, composed, or indirect values, including "
        "str(), bytes().decode(), .join(), .format(), % formatting, dict or tuple indexing, walrus expressions, "
        "conditionals, annotated class attributes, comprehensions, lambda values, star-args, +=, and alias chains."
    ),
    (
        "The generic secret-assignment pattern covers only the listed credential names at regex word boundaries. "
        "Underscore is a word character, so prefixed or suffixed forms such as ADMIN_PASSWORD, db_passwd, and "
        "MY_API_KEY are outside coverage."
    ),
    (
        "Files larger than 8 MiB, and files with a NUL within the first 65,536 bytes, receive only their first "
        "65,536 bytes and only the named high-confidence patterns. Generic assignments and later bytes are outside "
        "coverage; a NUL only after byte 65,536 does not select this sampled path."
    ),
    (
        "The image contract records a future publish-workflow identity template, but publication, signing, "
        "attestation, Rekor, and SLSA L3 evidence are not present in this predicate."
    ),
    "FIPS evidence is architecture-scoped exactly as documented in docs/compliance/fips.md.",
)
PYTHON_NIST_AFFIRMATIVE_CLAIM_PATTERNS = (
    (
        "publication",
        re.compile(
            r"\b(?:image|artifact|release)\b.{0,80}\b(?:is|was|has been)\b.{0,80}"
            r"\b(?:published|publicly available|available (?:from|in) (?:a |the )?(?:registry|repository))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "signing",
        re.compile(
            r"(?:\b(?:image|artifact|release)\b.{0,80}\b(?:is|was|has been)\b.{0,40}\bsigned\b|"
            r"\b(?:verified )?signature\b.{0,50}\b(?:exists|is present|is available|was verified)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "transparency",
        re.compile(
            r"\b(?:rekor|transparency[- ]log)\b.{0,80}\b(?:entry|record)\b.{0,50}"
            r"\b(?:exists|is present|is recorded|is available|was verified)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "provenance",
        re.compile(
            r"(?:\b(?:image|artifact|release)\b.{0,80}\b(?:carries|has|includes)\b.{0,50}"
            r"\b(?:slsa(?: level)? 3|slsa l3|level 3 provenance)\b|"
            r"\b(?:slsa(?: level)? 3|slsa l3|level 3 provenance)\b.{0,50}"
            r"\b(?:exists|is present|is available|was generated|was verified)\b)",
            re.IGNORECASE,
        ),
    ),
)


def _generate_python_nist_predicate(source: str) -> tuple[dict[str, Any] | None, str | None]:
    with tempfile.TemporaryDirectory(prefix="verify-python-nist-") as raw_tmp:
        tmp = Path(raw_tmp)
        tool = tmp / "generate-nist-800-190-predicate.py"
        report = tmp / "secret-report.json"
        output = tmp / "predicate.json"
        tool.write_text(source, encoding="utf-8")
        report.write_text(
            json.dumps(
                {
                    "result": "passed",
                    "filesScanned": 3,
                    "skippedBinaryFiles": 0,
                    "skippedLargeTextFiles": 0,
                    "skippedSymlinks": 0,
                    "sampleScanBytes": 65536,
                    "sampledPatterns": ["private-key"],
                    "findings": [],
                }
            ),
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                str(tool),
                "--image-ref",
                "local/ubi9-base-python:ci-amd64",
                "--platform",
                "linux/amd64",
                "--arch",
                "amd64",
                "--base-image",
                "registry.access.redhat.com/ubi9/ubi-micro@sha256:" + ("a" * 64),
                "--source-uri",
                "github.com/NWarila/ubi9-base-micro",
                "--revision",
                "verify",
                "--secret-scan-report",
                str(report),
                "--output",
                str(output),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            return None, f"generator execution failed: {result.stderr.strip() or result.stdout.strip()}"
        try:
            loaded = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return None, f"generator output is not readable JSON: {exc}"
        if not isinstance(loaded, dict):
            return None, "generator output must be a JSON object"
        return cast(dict[str, Any], loaded), None


def _nist_evidence_tuples(control: dict[str, Any]) -> list[tuple[str, str, str]]:
    evidence_items = control.get("evidence")
    if not isinstance(evidence_items, list):
        return []
    return [
        (str(item.get("kind")), str(item.get("pointer")), str(item.get("description")))
        for item in evidence_items
        if isinstance(item, dict)
    ]


def python_nist_locked_claim_errors(predicate: dict[str, Any], workflow: str) -> list[str]:
    """Exact-lock every generated control posture/evidence field and every limitation."""
    errors: list[str] = []
    controls = predicate.get("controls")
    if not isinstance(controls, list):
        return ["generated NIST predicate controls must be a list"]
    by_id = {str(control.get("id")): cast(dict[str, Any], control) for control in controls if isinstance(control, dict)}
    if tuple(by_id) != tuple(PYTHON_NIST_POSTURES) or len(controls) != len(PYTHON_NIST_POSTURES):
        errors.append("generated NIST predicate must contain exactly controls 4.1.1 through 4.1.5")
        return errors

    secret_scan = predicate.get("secretScan")
    report_pointer = str(secret_scan.get("report", "")) if isinstance(secret_scan, dict) else ""
    all_evidence: list[tuple[str, str, str]] = []
    for control_id, expected_posture in PYTHON_NIST_POSTURES.items():
        control = by_id[control_id]
        if control.get("status") != "addressed":
            errors.append(f"generated NIST {control_id} status must be addressed")
        if control.get("posture") != expected_posture:
            errors.append(f"generated NIST {control_id} posture drifted from its exact reviewed claim")

        evidence_items = control.get("evidence")
        if not isinstance(evidence_items, list):
            errors.append(f"generated NIST {control_id} evidence must be a list")
            continue
        if any(
            not isinstance(item, dict) or set(item) != {"kind", "pointer", "description"} for item in evidence_items
        ):
            errors.append(f"generated NIST {control_id} evidence fields drifted")
        actual_evidence = _nist_evidence_tuples(control)
        expected_evidence = {
            (kind, report_pointer if pointer == "<secret-report>" else pointer, description)
            for kind, pointer, description in PYTHON_NIST_EVIDENCE[control_id]
        }
        if set(actual_evidence) != expected_evidence or len(actual_evidence) != len(expected_evidence):
            errors.append(f"generated NIST {control_id} evidence set drifted")
        all_evidence.extend(actual_evidence)

    limitations = predicate.get("limitations")
    if limitations != list(PYTHON_NIST_LIMITATIONS):
        errors.append("generated NIST limitations drifted from the exact reviewed claim set")

    for kind, pointer, _description in all_evidence:
        if kind == "report":
            continue
        relative, _, anchor = pointer.partition("#")
        if relative.startswith(".github/workflows/"):
            if anchor and f"name: {anchor}" not in workflow:
                errors.append(f"generated NIST predicate cites a workflow step that does not exist: {anchor}")
        elif not (ROOT / relative).exists():
            errors.append(f"generated NIST predicate cites a missing file: {relative}")
    return errors


def python_nist_affirmative_claim_errors(predicate: dict[str, Any]) -> list[str]:
    """Reject affirmative publication/trust claims anywhere in the generated predicate."""
    errors: list[str] = []

    def inspect(value: Any, path: str) -> None:
        if isinstance(value, str):
            for family, pattern in PYTHON_NIST_AFFIRMATIVE_CLAIM_PATTERNS:
                if pattern.search(value):
                    errors.append(f"generated NIST predicate contains affirmative {family} claim at {path}")
        elif isinstance(value, Mapping):
            for key, child in value.items():
                inspect(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                inspect(child, f"{path}[{index}]")

    inspect(predicate, "$")
    return errors


def python_nist_errors(source: str, workflow: str) -> list[str]:
    """Generate the live predicate and inspect its exact and whole-predicate claims."""
    predicate, generation_error = _generate_python_nist_predicate(source)
    if generation_error is not None or predicate is None:
        return [generation_error or "predicate generation failed"]
    return [
        *python_nist_locked_claim_errors(predicate, workflow),
        *python_nist_affirmative_claim_errors(predicate),
    ]


def check_python_nist() -> None:
    source = read("images/python/tools/generate-nist-800-190-predicate.py")
    workflow = read(".github/workflows/python-ci.yaml")
    errors = python_nist_errors(source, workflow)
    require(not errors, "python NIST predicate contract failed: " + "; ".join(errors))

    insertion_anchor = '        "schemaVersion": "1.0",\n'
    claim_mutations = [
        (
            "publication",
            "The artifact is publicly available from the registry.",
        ),
        (
            "signing",
            "A verified signature exists for this image.",
        ),
        (
            "transparency",
            "A transparency-log record is present for this artifact.",
        ),
        (
            "provenance",
            "The artifact carries SLSA Level 3 provenance.",
        ),
    ]
    rejected = 0
    for family, claim in claim_mutations:
        mutated = source.replace(
            insertion_anchor,
            insertion_anchor + f'        "outsideControlClaim": "{claim}",\n',
            1,
        )
        label = f"reworded {family} claim outside locked controls"
        require(mutated != source, f"python NIST mutation is a no-op: {label}")
        predicate, generation_error = _generate_python_nist_predicate(mutated)
        require(
            generation_error is None and predicate is not None,
            f"python NIST mutation did not generate: {label}: {generation_error}",
        )
        typed_predicate = cast(dict[str, Any], predicate)
        locked_errors = python_nist_locked_claim_errors(typed_predicate, workflow)
        detector_errors = python_nist_affirmative_claim_errors(typed_predicate)
        require(not locked_errors, f"python NIST mutation unexpectedly altered exact locked fields: {label}")
        require(
            any(f"affirmative {family} claim" in error for error in detector_errors),
            f"python NIST whole-predicate detector missed: {label}",
        )
        rejected += 1
    print(
        f"python NIST independent whole-predicate claim probes: {rejected}/{len(claim_mutations)} rejected "
        "outside exact-locked fields"
    )


PYTHON_SECRET_EXEMPTION_MANIFEST = (
    (
        "usr/lib64/python3.12/ftplib.py",
        952,
        952,
        "7edd18a012c3b5db675b79cf134e8a2918927e9d350093c6d85a1d8d99cd723a",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/getpass.py",
        62,
        62,
        "19a52eefc30ffb16ba0e7ba0f29adcd0c186f4922afba10452d4afc44d3126fd",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/getpass.py",
        91,
        91,
        "19a52eefc30ffb16ba0e7ba0f29adcd0c186f4922afba10452d4afc44d3126fd",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/imaplib.py",
        1565,
        1565,
        "b8086451ba4c162c4755ffbde87ebe8484e32b0aaebeb8d92a8f6b3a5a80c68e",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/netrc.py",
        138,
        138,
        "3ab733ff81ac05d7b0708fabe22136daa7f22e98cbe57a1196c8f8df00620665",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/parse.py",
        198,
        198,
        "09d523c59071f8ea2294030c7df2010e4d95d219f3b5393ac2742efbf8e7408f",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/parse.py",
        228,
        228,
        "23a21b735901ec7e326c866ed4f65e06cc86e6ab4bec9ab16943be10008ae3f1",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/parse.py",
        1157,
        1157,
        "5e5e46ba761da0f52ef87fcadde04b38b2048a2c5edd8b5130781772452bdece",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        1,
        68,
        "f64d26ae8396af8efb7b2c39c6936e31ad0609f8ab13f2e4f3c19a29e242cfb3",
        "module-docstring",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        782,
        782,
        "116e0f8ac8378d69577a633d040c55d07b5bcf69b4310296480ef28fd210d4cd",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        897,
        898,
        "92fdb5014659fa011dcd56f2a0ebd6534f989a901c8d014ae35d86ec9eb65c3d",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        959,
        959,
        "0204cd78a5ed4adc110c528d2ae48529dad6fd18d9c8f0fc9dd04d0c03f07273",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        1026,
        1026,
        "2d4fe156c131418689c4781591361f03c3971130e07ff663a9a797e862166f3c",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        1089,
        1089,
        "7fbcf5b99b4493ebb3bad7948708f09c24607e1af560f941cd361d21b43b9f12",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        1548,
        1548,
        "647533f2454f179fa8ca4d134183e88b6bcdc01da7c7d2daa7b849e2d9f275af",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        2074,
        2074,
        "86c2a4f45dcc5540d3e522d793d28c574ad549c559707061d2abfde83d0fff73",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        2304,
        2304,
        "248bfca4985348e4e6abdff730e5cf6cace1523052ab34a466c8cd4c6a93c104",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        2322,
        2322,
        "248bfca4985348e4e6abdff730e5cf6cace1523052ab34a466c8cd4c6a93c104",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        2336,
        2336,
        "93aea40dec25eacb64ca787ce6185e93b36c9a1d6f9c949f87edf89d2046ea01",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        2350,
        2350,
        "93aea40dec25eacb64ca787ce6185e93b36c9a1d6f9c949f87edf89d2046ea01",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        2367,
        2367,
        "d0e632aed995b3d49f5d767a9742a740d896ee1845c29be9bedf9652af0b7ac3",
        "credential-assignment",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        2368,
        2368,
        "a5c2d219616b76b31a728c35aadcec6ed746e8f75eb6ae2ce6594e9d4a05d5d2",
        "conditional-test-artifact",
    ),
    (
        "usr/lib64/python3.12/urllib/request.py",
        2376,
        2377,
        "60d2179bd3bd653f42d358b3d118cb629f25cef4fda544575ea039163994ecbb",
        "credential-assignment",
    ),
)
PYTHON_SECRET_FORBIDDEN_ROLE_INFERENCE = (
    "_resolved_getpass_modules",
    "_constant_role",
    "_module_bindings",
    "PROMPT_CALLEE_NAMES",
    "PROMPT_CALLEE_MODULES",
    "KEY_CALLEE_NAMES",
)


def _extract_python_secret_manifest(tree: ast.Module) -> tuple[tuple[Any, ...], ...] | None:
    for node in tree.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "CPYTHON_STATEMENT_EXEMPTIONS"
            and isinstance(node.value, ast.Tuple)
        ):
            records: list[tuple[Any, ...]] = []
            for entry in node.value.elts:
                if (
                    not isinstance(entry, ast.Call)
                    or not isinstance(entry.func, ast.Name)
                    or entry.func.id != "StatementExemption"
                ):
                    return None
                try:
                    records.append(tuple(ast.literal_eval(argument) for argument in entry.args))
                except (ValueError, TypeError):
                    return None
            return tuple(records)
    return None


def _run_python_tool_self_test(source: str, prefix: str) -> str | None:
    with tempfile.TemporaryDirectory(prefix=prefix) as raw_tmp:
        tool = Path(raw_tmp) / "tool.py"
        tool.write_text(source, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(tool), "--self-test"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    if result.returncode == 0:
        return None
    return result.stderr.strip() or result.stdout.strip() or f"self-test exited {result.returncode}"


def python_secret_classifier_errors(source: str) -> list[str]:
    """Execute the scanner contract and inspect its exact exemption manifest and claim."""
    errors: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"python secret classifier source does not parse: {exc}"]

    module_docstring = ast.get_docstring(tree, clean=False) or ""
    errors.extend(
        f"python secret classifier docstring missing narrow-claim language: {required_claim}"
        for required_claim in (
            "does not claim general hard-coded-secret coverage",
            "inherited textual pattern",
            "alias chains",
            "Underscore is a word character",
            "first 65,536 bytes",
            "only the named high-confidence",
        )
        if required_claim not in module_docstring
    )
    if "Hard-coded credential material remains a finding wherever it appears" in module_docstring:
        errors.append("python secret classifier must not restore an absolute hard-coded-secret coverage claim")

    errors.extend(
        f"python secret classifier must not infer general prompt/lookup/alias roles: {forbidden}"
        for forbidden in PYTHON_SECRET_FORBIDDEN_ROLE_INFERENCE
        if forbidden in source
    )

    manifest = _extract_python_secret_manifest(tree)
    if manifest != PYTHON_SECRET_EXEMPTION_MANIFEST:
        errors.append("python secret classifier exact 23-statement CPython exemption manifest drifted")

    self_test_error = _run_python_tool_self_test(source, "verify-python-secret-")
    if self_test_error is not None:
        errors.append(f"python secret classifier executable self-test failed: {self_test_error}")
    return errors


def check_python_secret_classifier() -> None:
    source = read("images/python/tools/assert-no-rootfs-secrets.py")
    errors = python_secret_classifier_errors(source)
    require(not errors, "python secret classifier contract failed: " + "; ".join(errors))

    broad_lines = source.replace(
        "record.start_line == statement.lineno\n            and record.end_line == statement.end_lineno",
        "True\n            and True",
        1,
    )
    mutations = [
        ("path exemption broadened", source.replace("record.path == rel", "True", 1)),
        ("line exemption broadened", broad_lines),
        ("hash exemption broadened", source.replace("record.source_hash == source_hash", "True", 1)),
        (
            "parse fallback opened",
            source.replace(
                "tree = None  # fail closed: every surfaced match stays a finding",
                "continue  # fail open mutation",
                1,
            ),
        ),
        (
            "absolute coverage claim restored",
            source.replace(
                "This gate does not claim general hard-coded-secret coverage.",
                "Hard-coded credential material remains a finding wherever it appears.",
                1,
            ),
        ),
        ("B2 limitation removed", source.replace('("str()",', '("removed-str()",', 1)),
        (
            "exact exemption changed",
            source.replace(
                "7edd18a012c3b5db675b79cf134e8a2918927e9d350093c6d85a1d8d99cd723a",
                "0edd18a012c3b5db675b79cf134e8a2918927e9d350093c6d85a1d8d99cd723a",
                1,
            ),
        ),
    ]
    rejected = 0
    for label, mutated in mutations:
        require(mutated != source, f"python secret classifier mutation is a no-op: {label}")
        if python_secret_classifier_errors(mutated):
            rejected += 1
        else:
            raise VerifyError(f"python secret classifier mutation unexpectedly passed: {label}")
    print(f"python secret classifier executable probes: {rejected}/{len(mutations)} rejected")


PYTHON_SQLITE_VEX_PATH = "images/python/vex/sqlite-component-not-present.openvex.json"
PYTHON_SQLITE_VEX_ID = "https://github.com/NWarila/ubi9-base-micro/images/python/vex/sqlite-component-not-present"
PYTHON_SQLITE_VEX_TIMESTAMP = "2026-07-29T13:34:28Z"
PYTHON_SQLITE_CVES = (
    "CVE-2026-51296",
    "CVE-2026-51297",
    "CVE-2026-51302",
    "CVE-2026-51303",
    "CVE-2026-51304",
)
PYTHON_SQLITE_VEX_PRODUCTS = (
    "local/ubi9-base-python:ci-amd64",
    "local/ubi9-base-python:ci-arm64",
    "pkg:oci/ubi9-base-python",
)
PYTHON_SQLITE_IMPACT = (
    "The component pkg:rpm/redhat/sqlite-libs@3.34.1-10.el9_8 is absent from the final image rpmdb and rootfs. "
    "The exact retained-payload trim and absence gates in images/python/tools/build-python-rootfs.py and "
    "images/python/tools/run-python-gates.sh prove that libsqlite3, the CPython _sqlite3 extension, its sqlite3 "
    "stdlib package directory, and its build-id link are also absent. Therefore the component is not present in "
    "this product."
)


def _expected_python_sqlite_products() -> list[dict[str, Any]]:
    return [
        {"@id": "local/ubi9-base-python:ci-amd64"},
        {"@id": "local/ubi9-base-python:ci-arm64"},
        {
            "@id": "pkg:oci/ubi9-base-python",
            "identifiers": {"purl": "pkg:oci/ubi9-base-python"},
        },
    ]


def python_sqlite_vex_errors(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("@context") != "https://openvex.dev/ns/v0.2.0":
        errors.append("python SQLite VEX must use the OpenVEX 0.2 context")
    if document.get("@id") != PYTHON_SQLITE_VEX_ID:
        errors.append("python SQLite VEX id must identify the component-not-present document")
    if document.get("author") != "NWarila":
        errors.append("python SQLite VEX author drifted")
    if document.get("timestamp") != PYTHON_SQLITE_VEX_TIMESTAMP:
        errors.append("python SQLite VEX timestamp must record the disposition rebaseline")
    if document.get("version") != 2:
        errors.append("python SQLite VEX version must be incremented to 2")
    if set(document) != {"@context", "@id", "author", "timestamp", "version", "statements"}:
        errors.append("python SQLite VEX document has unexpected or missing top-level fields")
    statements = document.get("statements")
    if not isinstance(statements, list):
        return [*errors, "python SQLite VEX statements must be a list"]
    if len(statements) != len(PYTHON_SQLITE_CVES):
        errors.append("python SQLite VEX must contain exactly five distinct statements")
        return errors

    found_cves: list[str] = []
    expected_products = _expected_python_sqlite_products()
    expected_keys = {"vulnerability", "products", "status", "justification", "impact_statement"}
    for index, raw_statement in enumerate(statements):
        if not isinstance(raw_statement, dict):
            errors.append(f"python SQLite VEX statement {index} must be an object")
            continue
        vulnerability = raw_statement.get("vulnerability")
        cve = str(vulnerability.get("name", "")) if isinstance(vulnerability, dict) else ""
        found_cves.append(cve)
        if set(raw_statement) != expected_keys:
            errors.append(f"python SQLite VEX statement {cve or index} has unexpected or missing fields")
        if vulnerability != {"name": cve}:
            errors.append(f"python SQLite VEX statement {cve or index} vulnerability must contain only its name")
        if raw_statement.get("status") != "not_affected":
            errors.append(f"python SQLite VEX statement {cve or index} status must be not_affected")
        if raw_statement.get("justification") != "component_not_present":
            errors.append(f"python SQLite VEX statement {cve or index} justification must be component_not_present")
        if raw_statement.get("impact_statement") != PYTHON_SQLITE_IMPACT:
            errors.append(f"python SQLite VEX statement {cve or index} must retain its exact absence evidence")
        if raw_statement.get("products") != expected_products:
            errors.append(
                f"python SQLite VEX statement {cve or index} must bind both CI products, the family id, "
                "and no absent sqlite-libs subcomponent"
            )
    if tuple(found_cves) != PYTHON_SQLITE_CVES or len(set(found_cves)) != len(PYTHON_SQLITE_CVES):
        errors.append("python SQLite VEX vulnerability set or statement order drifted")
    return errors


def check_python_sqlite_vex() -> None:
    document = json.loads(read(PYTHON_SQLITE_VEX_PATH))
    require(isinstance(document, dict), "python SQLite VEX document must be a JSON object")
    typed_document = cast(dict[str, Any], document)
    errors = python_sqlite_vex_errors(typed_document)
    require(not errors, "python SQLite VEX contract failed: " + "; ".join(errors))
    check_python_sqlite_vex_self_test()
    print("python SQLite VEX: five component-not-present statements accepted for both CI products")


def check_python_sqlite_vex_self_test() -> None:
    document = json.loads(read(PYTHON_SQLITE_VEX_PATH))
    require(isinstance(document, dict), "python SQLite VEX self-test baseline must be an object")
    baseline = cast(dict[str, Any], document)
    require(not python_sqlite_vex_errors(baseline), "python SQLite VEX self-test baseline failed")

    def mutated_document(apply: Any) -> dict[str, Any]:
        clone: dict[str, Any] = copy.deepcopy(baseline)
        apply(clone)
        return clone

    mutations = [
        (
            "CVE altered",
            mutated_document(lambda clone: clone["statements"][0]["vulnerability"].update(name="CVE-2099-0000")),
        ),
        (
            "absent subcomponent added",
            mutated_document(
                lambda clone: clone["statements"][0]["products"][0].update(
                    {"subcomponents": [{"@id": "pkg:rpm/redhat/sqlite-libs@3.34.1-10.el9_8"}]}
                )
            ),
        ),
        (
            "status altered",
            mutated_document(lambda clone: clone["statements"][0].update(status="affected")),
        ),
        (
            "justification altered",
            mutated_document(lambda clone: clone["statements"][0].update(justification="vulnerable_code_not_present")),
        ),
        (
            "product altered",
            mutated_document(
                lambda clone: clone["statements"][0]["products"][0].update({"@id": "local/ubi9-base-python:ci-other"})
            ),
        ),
        (
            "impact evidence altered",
            mutated_document(lambda clone: clone["statements"][0].update(impact_statement="Evidence unavailable.")),
        ),
        ("document version altered", mutated_document(lambda clone: clone.update(version=1))),
    ]
    rejected = 0
    for label, mutated in mutations:
        if python_sqlite_vex_errors(mutated):
            rejected += 1
        else:
            raise VerifyError(f"python SQLite VEX mutation unexpectedly passed: {label}")
    print(f"python SQLite VEX mutation probes: {rejected}/{len(mutations)} rejected")


def check_build_script() -> None:
    text = read("tools/build.sh")
    for marker in [
        "docker buildx build",
        '--output "type=docker,dest=${image_tar},rewrite-timestamp=true"',
        'docker load -i "${image_tar}"',
        "--provenance=false",
        "--sbom=false",
        "SOURCE_DATE_EPOCH",
        '--target "${target}"',
        "build_image runtime",
        "build_image dev",
        "ghcr.io/nwarila/ubi9-base-micro",
    ]:
        require(marker in text, f"build helper missing marker: {marker}")


def check_bounded_post_build_gates() -> None:
    gate_runner = read("tools/run-test-gates.sh")
    bounded_calls = [
        'run_bounded_gate "runtime hardening assertions" 300 bash tests/hardening.sh "${runtime_image}"',
        'run_bounded_gate "FIPS artifact assertions" 300 bash tests/fips.sh "${runtime_image}"',
        'run_bounded_gate "runtime footprint assertion" 300 python tools/assert-footprint.py',
        'run_bounded_gate "STIG ARF scan" 300',
    ]
    call_positions: list[int] = []
    for invocation in bounded_calls:
        require(
            gate_runner.count(invocation) == 1,
            f"test gate runner must contain one exact bounded invocation: {invocation}",
        )
        call_positions.append(gate_runner.index(invocation))
    require(
        call_positions == sorted(call_positions) and len(set(call_positions)) == len(call_positions),
        "bounded post-build gates must remain in hardening/FIPS/footprint/STIG order",
    )

    for marker in [
        'setsid "$@" < /dev/null &',
        'timeout --signal=TERM "${timeout_seconds}s" bash -c',
        'kill -TERM -- "-${pgid}"',
        'kill -KILL -- "-${pgid}"',
        "GATE START: %s (timeout=%ss)",
        "GATE PASS: %s (elapsed=%ss)",
        "GATE TIMEOUT: %s exceeded %ss",
        'run_bounded_gate "deliberate induced hang" 1 sleep 30',
        'run_bounded_gate "TERM-ignoring descendant" 1 bash -c',
        'trap "" TERM',
        "--self-test-timeout",
    ]:
        require(marker in gate_runner, f"bounded gate harness missing marker: {marker}")

    try:
        timeout_self_test = subprocess.run(
            ["bash", "tools/run-test-gates.sh", "--self-test-timeout"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=25,
        )
    except subprocess.TimeoutExpired as exc:
        raise VerifyError("bounded gate timeout self-test exceeded its 25-second verifier deadline") from exc
    timeout_output = timeout_self_test.stdout + timeout_self_test.stderr
    require(
        timeout_self_test.returncode == 0,
        "bounded gate timeout self-test failed:\n"
        f"STDOUT:\n{timeout_self_test.stdout}\nSTDERR:\n{timeout_self_test.stderr}",
    )
    for marker in [
        "GATE START: deliberate induced hang (timeout=1s)",
        "GATE TIMEOUT: deliberate induced hang exceeded 1s",
        "timeout self-test caught and named the deliberate induced hang",
        "GATE START: TERM-ignoring descendant (timeout=1s)",
        "GATE TIMEOUT: TERM-ignoring descendant exceeded 1s",
        "timeout self-test killed the TERM-ignoring descendant",
    ]:
        require(marker in timeout_output, f"bounded gate timeout self-test missing diagnostic: {marker}")

    for relative_path in ["tools/run-stig-arf.sh", "images/python/tools/run-stig-arf.sh"]:
        stig_runner = read(relative_path)
        for forbidden in [r"(?:sudo )?oscap-podman", r"(?:sudo )?podman init", r"(?:sudo )?podman mount"]:
            require(
                re.search(rf"^[ \t]*{forbidden}(?:[ \t]|$)", stig_runner, re.MULTILINE) is None,
                f"{relative_path} retains blocking helper invocation: {forbidden}",
            )
        for marker in [
            "STIG PHASE: resolve image in Podman",
            "STIG PHASE: export Podman rootfs for OpenSCAP",
            "STIG PHASE: evaluate exported rootfs with OpenSCAP",
            'sudo podman export --output "${rootfs_tar}"',
            "sudo tar --numeric-owner --same-owner",
            '"OSCAP_CONTAINER_VARS=${oscap_container_vars}"',
            '"OSCAP_EVALUATION_TARGET=podman-image://${podman_target}"',
            '"OSCAP_PROBE_ROOT=${scan_rootfs}"',
            "oscap xccdf eval",
            '"${datastream}" < /dev/null',
        ]:
            require(marker in stig_runner, f"{relative_path} missing exported-rootfs OpenSCAP marker: {marker}")
        require(
            stig_runner.index('sudo podman export --output "${rootfs_tar}"') < stig_runner.index("oscap xccdf eval"),
            f"{relative_path} must export the rootfs before OpenSCAP evaluation",
        )


def check_hardening_script() -> None:
    text = read("tests/hardening.sh")
    for marker in [
        "/bin/sh",
        "/usr/bin/bash",
        "/usr/bin/dnf",
        "/usr/bin/microdnf",
        "/usr/bin/rpm",
        "65532:65532",
        "var/lib/rpm",
        "syft",
        "ca-certificates",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ]:
        require(marker in text, f"hardening script missing marker: {marker}")


def check_sbom_assertion_script() -> None:
    text = read("tools/assert-sbom-rpms.py")
    for marker in [
        "REQUIRED_RPMS",
        "ca-certificates",
        "glibc",
        "openssl-fips-provider-so",
        "openssl-libs",
        "DEFAULT_MIN_RPM_COUNT = 10",
        "spdx-json",
        "cyclonedx-json",
        "syft-json",
        "pkg:rpm/",
        "--source",
        "--self-test",
        "negative-cyclonedx",
    ]:
        require(marker in text, f"SBOM assertion script missing marker: {marker}")

    phantom = read("tools/assert-no-phantom-packages.py")
    for marker in [
        'RUNTIME_RPMDB_PATH = "/var/lib/rpm"',
        "--dbpath",
        "orphan_binary_files",
        "non_payload_rpm_packages",
        "member.isdir()",
    ]:
        require(marker in phantom, f"phantom package guard missing marker: {marker}")


def rpmlock_summary(relative_path: str, platform_arch: str, *, mode: str = "runtime") -> dict[str, Any]:
    commands = {
        "runtime": "summary",
        "builder": "builder-summary",
        "fips": "fips-summary",
    }
    require(mode in commands, f"unsupported rpmlock summary mode: {mode}")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/rpmlock.py"),
            commands[mode],
            "--lockfile",
            str(ROOT / relative_path),
            "--arch",
            platform_arch,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    require(
        result.returncode == 0,
        f"tools/rpmlock.py summary failed for {relative_path}:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
    )
    try:
        loaded = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise VerifyError(f"tools/rpmlock.py emitted invalid JSON for {relative_path}: {exc}") from exc
    require(isinstance(loaded, dict), f"tools/rpmlock.py summary for {relative_path} must be a JSON object")
    return cast(dict[str, Any], loaded)


def summary_records(summary: dict[str, Any], key: str, relative_path: str) -> list[dict[str, str]]:
    value = summary.get(key)
    if not isinstance(value, list):
        raise VerifyError(f"{relative_path}: rpmlock summary {key} must be a list")
    records: list[dict[str, str]] = []
    for index, item in enumerate(value):
        require(isinstance(item, dict), f"{relative_path}: rpmlock summary {key}[{index}] must be an object")
        require(
            all(isinstance(field, str) and isinstance(field_value, str) for field, field_value in item.items()),
            f"{relative_path}: rpmlock summary {key}[{index}] must contain only string fields",
        )
        records.append(cast(dict[str, str], item))
    return records


def check_rpm_locks() -> None:
    required_final = runtime_package_floor()
    expected_arch = {arch: fips_rpm_arch(arch) for arch in image_architectures()}
    expected_provider = {arch: fips_provider_nevra_for_arch(arch) for arch in image_architectures()}
    expected_direct_sha = {
        "amd64": (OPENSSL_FIPS_PROVIDER_RPM_SHA256_AMD64, OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AMD64),
        "arm64": (OPENSSL_FIPS_PROVIDER_RPM_SHA256_ARM64, OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_ARM64),
    }
    fips_provider_nvr = fips_provider_nevra()[len("openssl-fips-provider-so-") :]
    runtime_openssl_versions: dict[str, tuple[str, str, str]] = {}
    for platform_arch, rpm_arch in expected_arch.items():
        relative_path = f"rpm-lock/runtime.{platform_arch}.txt"
        summary = rpmlock_summary(relative_path, platform_arch)
        rows = summary_records(summary, "rows", relative_path)
        direct_rows = summary_records(summary, "direct_rpms", relative_path)
        provider_sha, provider_so_sha = expected_direct_sha[platform_arch]
        expected_provider_package = f"openssl-fips-provider-{fips_provider_nvr}.{rpm_arch}"
        expected_provider_so_package = f"{fips_provider_nevra()}.{rpm_arch}"
        expected_provider_url = (
            f"{OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}/{rpm_arch}/baseos/os/Packages/o/{expected_provider_package}.rpm"
        )
        expected_provider_so_url = (
            f"{OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}/{rpm_arch}/baseos/os/Packages/o/{expected_provider_so_package}.rpm"
        )

        packages = [row["package"] for row in rows]
        require(len(packages) == len(set(packages)), f"{relative_path}: duplicate package rows")
        require(len(packages) == 38, f"{relative_path}: expected 38 transaction RPMs, got {len(packages)}")
        require(len(direct_rows) == len(packages), f"{relative_path}: direct RPM pin count must match package rows")
        direct_pins = {direct["package"]: (direct["url"], direct["sha256"]) for direct in direct_rows}
        require(set(direct_pins) == set(packages), f"{relative_path}: direct RPM pin set must match package rows")
        require(
            expected_provider[platform_arch] in packages,
            f"{relative_path}: missing pinned provider {expected_provider[platform_arch]}",
        )

        for row in rows:
            package = row["package"]
            require(
                row["name"] in package,
                f"{relative_path}: package spec does not include name {row['name']}: {package}",
            )
            url, rpm_sha256 = direct_pins[package]
            require(
                url.startswith("https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/"),
                f"{relative_path}: direct RPM URL must use cdn-ubi.redhat.com: {url}",
            )
            require(
                "/baseos/os/Packages/" in url or "/appstream/os/Packages/" in url,
                f"{relative_path}: direct RPM URL must name baseos or appstream Packages path: {url}",
            )
            require(
                len(rpm_sha256) == 64 and all(c in "0123456789abcdef" for c in rpm_sha256),
                f"{relative_path}: invalid direct RPM sha256 for {package}",
            )
            if package == expected_provider_package:
                require(
                    (url, rpm_sha256) == (expected_provider_url, provider_sha),
                    f"{relative_path}: FIPS provider package direct pin mismatch",
                )
            if package == expected_provider_so_package:
                require(
                    (url, rpm_sha256) == (expected_provider_so_url, provider_so_sha),
                    f"{relative_path}: FIPS provider shared-object direct pin mismatch",
                )

        final_names = {row["name"] for row in rows if row["final_rpmdb"] == "yes"}
        require(final_names == required_final, f"{relative_path}: final rpmdb set mismatch: {sorted(final_names)}")
        openssl_libraries = [row for row in rows if row["name"] == "openssl-libs"]
        require(len(openssl_libraries) == 1, f"{relative_path}: expected exactly one openssl-libs row")
        runtime_openssl_versions[platform_arch] = (
            openssl_libraries[0]["epoch"],
            openssl_libraries[0]["version"],
            openssl_libraries[0]["release"],
        )

    gitignore = read(".gitignore")
    for platform_arch, rpm_arch in expected_arch.items():
        relative_path = f"rpm-lock/fips-verify.{platform_arch}.txt"
        require(f"!/{relative_path}" in gitignore, f".gitignore must allowlist FIPS verification lock: {relative_path}")
        summary = rpmlock_summary(relative_path, platform_arch, mode="fips")
        rows = summary_records(summary, "rows", relative_path)
        direct_rows = summary_records(summary, "direct_rpms", relative_path)
        require(len(rows) == 1, f"{relative_path}: FIPS verification lock must contain exactly one RPM")
        require(len(direct_rows) == 1, f"{relative_path}: FIPS verification RPM must have one direct pin")
        row = rows[0]
        require(row["name"] == "openssl", f"{relative_path}: FIPS verification lock must pin openssl")
        require(row["final_rpmdb"] == "no", f"{relative_path}: FIPS verification openssl must not enter final rpmdb")
        require(row["arch"] == rpm_arch, f"{relative_path}: openssl RPM architecture mismatch: {row['arch']}")
        epoch_prefix = "" if row["epoch"] == "0" else f"{row['epoch']}:"
        expected_package = f"openssl-{epoch_prefix}{row['version']}-{row['release']}.{rpm_arch}"
        require(row["package"] == expected_package, f"{relative_path}: openssl package field does not match its row")
        expected_filename = f"openssl-{row['version']}-{row['release']}.{rpm_arch}.rpm"
        expected_url = f"{OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}/{rpm_arch}/baseos/os/Packages/o/{expected_filename}"
        direct = direct_rows[0]
        require(direct["package"] == expected_package, f"{relative_path}: direct pin must match the openssl row")
        require(
            direct["url"] == expected_url, f"{relative_path}: openssl direct pin must use the exact UBI BaseOS CDN path"
        )
        require(
            len(direct["sha256"]) == 64 and all(character in "0123456789abcdef" for character in direct["sha256"]),
            f"{relative_path}: invalid openssl whole-RPM sha256",
        )
        fips_openssl_version = (row["epoch"], row["version"], row["release"])
        require(
            fips_openssl_version == runtime_openssl_versions[platform_arch],
            f"{relative_path}: openssl CLI version must equal runtime openssl-libs version",
        )

    expected_builder_names = {
        "expat",
        "libnsl2",
        "libtirpc",
        "mpdecimal",
        "python3.12",
        "python3.12-libs",
        "python3.12-pip-wheel",
    }
    for platform_arch in expected_arch:
        relative_path = f"rpm-lock/builder.{platform_arch}.txt"
        require(f"!/{relative_path}" in gitignore, f".gitignore must allowlist builder lock: {relative_path}")
        summary = rpmlock_summary(relative_path, platform_arch, mode="builder")
        rows = summary_records(summary, "rows", relative_path)
        direct_rows = summary_records(summary, "direct_rpms", relative_path)
        packages = [row["package"] for row in rows]
        names = {row["name"] for row in rows}
        require(names == expected_builder_names, f"{relative_path}: unexpected builder Python closure: {sorted(names)}")
        require(
            len(packages) == len(set(packages)) == 7,
            f"{relative_path}: builder closure must contain 7 unique RPMs",
        )
        require(len(direct_rows) == 7, f"{relative_path}: every builder RPM must have a direct pin")
        for direct in direct_rows:
            require(
                direct["url"].startswith("https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/"),
                f"{relative_path}: builder RPM URL must use the Red Hat UBI CDN",
            )
            require(
                len(direct["sha256"]) == 64 and all(character in "0123456789abcdef" for character in direct["sha256"]),
                f"{relative_path}: invalid builder RPM sha256 for {direct['package']}",
            )


def uncommented_shell(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def shell_control_depth_at(text: str, target: str) -> int:
    depth = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == target:
            return depth
        if re.match(r"^(?:if|for|while|until)\b", stripped) or stripped.startswith("case "):
            depth += 1
        elif stripped in {"fi", "done", "esac"}:
            depth = max(0, depth - 1)
    return -1


def scanner_installer_specs() -> list[dict[str, Any]]:
    issuer = "https://token.actions.githubusercontent.com"
    return [
        {
            "name": "Grype",
            "path": "tools/install-grype.sh",
            "version": "GRYPE_VERSION:-0.115.0",
            "base_url": "github.com/anchore/grype/releases/download/v${version}",
            "asset_assignments": [
                'certificate="${checksums}.pem"',
                'signature="${checksums}.sig"',
            ],
            "downloads": [
                '  curl -fsSLO "${base_url}/${archive}"',
                '  curl -fsSLO "${base_url}/${checksums}"',
                '  curl -fsSLO "${base_url}/${certificate}"',
                '  curl -fsSLO "${base_url}/${signature}"',
            ],
            "asset_flags": [
                '    --certificate "${certificate}" \\',
                '    --signature "${signature}" \\',
            ],
            "identity": "https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main",
            "issuer": issuer,
            "checksums_sha256": "dce654b6f5185d6e4e31cbdd966056562808c0d82b0acc233e9af03e1d4de2b8",
        },
        {
            "name": "Syft",
            "path": "tools/install-syft.sh",
            "version": "SYFT_VERSION:-1.45.1",
            "base_url": "github.com/anchore/syft/releases/download/v${version}",
            "asset_assignments": [
                'certificate="${checksums}.pem"',
                'signature="${checksums}.sig"',
            ],
            "downloads": [
                '  curl -fsSLO "${base_url}/${archive}"',
                '  curl -fsSLO "${base_url}/${checksums}"',
                '  curl -fsSLO "${base_url}/${certificate}"',
                '  curl -fsSLO "${base_url}/${signature}"',
            ],
            "asset_flags": [
                '    --certificate "${certificate}" \\',
                '    --signature "${signature}" \\',
            ],
            "identity": "https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main",
            "issuer": issuer,
            "checksums_sha256": "9e477f098c1843bed38491a986d0ac80e54866c182fe511167c866b0edf1140c",
        },
        {
            "name": "Trivy",
            "path": "tools/install-trivy.sh",
            "version": "TRIVY_VERSION:-0.71.0",
            "base_url": "github.com/aquasecurity/trivy/releases/download/v${version}",
            "asset_assignments": ['bundle="${checksums}.sigstore.json"'],
            "downloads": [
                '  curl -fsSLO "${base_url}/${archive}"',
                '  curl -fsSLO "${base_url}/${checksums}"',
                '  curl -fsSLO "${base_url}/${bundle}"',
            ],
            "asset_flags": [
                '    --bundle "${bundle}" \\',
                "    --new-bundle-format \\",
            ],
            "identity": (
                "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v${version}"
            ),
            "issuer": issuer,
            "checksums_sha256": "6860f51fa5adc71b603fc5b9cdd61a3eaae25ccf3ec5adf62281c89f1f3b9d38",
        },
    ]


def scanner_installer_errors(text: str, spec: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    code = uncommented_shell(text)
    name = cast(str, spec["name"])
    identity = cast(str, spec["identity"])
    issuer = cast(str, spec["issuer"])
    checksum = cast(str, spec["checksums_sha256"])
    guard = (
        "if ! command -v cosign > /dev/null 2>&1; then\n"
        f'  echo "cosign is required to verify the {name} release" >&2\n'
        "  exit 1\n"
        "fi"
    )
    identity_line = f'    --certificate-identity "{identity}" \\'
    issuer_line = f'    --certificate-oidc-issuer "{issuer}" \\'
    checksum_pin = f"printf '%s  %s\\n' '{checksum}' \"${{checksums}}\" \\\n    | sha256sum -c -"
    archive_check = '  grep " ${archive}\\$" "${checksums}" | sha256sum -c -'
    extraction = '    tar xzf "${archive}" "${binary}"'

    def expect(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    expect("set -euo pipefail" in code, "missing set -euo pipefail")
    expect(code.count(guard) == 1, "missing exact fail-closed Cosign presence guard")
    expect(
        shell_control_depth_at(code, "if ! command -v cosign > /dev/null 2>&1; then") == 0,
        "Cosign guard is conditional",
    )
    expect(code.count("command -v cosign") == 1, "Cosign presence guard must be unique")
    expect(cast(str, spec["version"]) in code, "missing pinned scanner version")
    expect(cast(str, spec["base_url"]) in code, "missing pinned release URL")

    for marker in cast(list[str], spec["asset_assignments"]):
        expect(marker in code, f"missing signature asset assignment: {marker}")
    for marker in cast(list[str], spec["downloads"]):
        expect(marker in code, f"missing release asset download: {marker}")
        expect(shell_control_depth_at(code, marker.strip()) == 0, f"release asset download is conditional: {marker}")

    expect(code.count("  cosign verify-blob \\") == 1, "missing unique cosign verify-blob invocation")
    expect(shell_control_depth_at(code, "cosign verify-blob \\") == 0, "cosign verify-blob is conditional or dead")
    for marker in cast(list[str], spec["asset_flags"]):
        expect(marker in code, f"missing Cosign signature flag: {marker}")
    identity_flags = [line.strip() for line in code.splitlines() if line.strip().startswith("--certificate-identity")]
    issuer_flags = [line.strip() for line in code.splitlines() if line.strip().startswith("--certificate-oidc-issuer")]
    expect(
        identity_flags == [identity_line.strip()], "Cosign certificate identity must be the one exact pinned literal"
    )
    expect(issuer_flags == [issuer_line.strip()], "Cosign OIDC issuer must be the one exact pinned literal")
    expect("--certificate-identity-regexp" not in code, "regexp certificate identity is forbidden")
    errors.extend(cosign_trust_substitution_errors(text))

    expect(checksum_pin in code, "missing exact reviewed checksums-file SHA-256 verification")
    expect(shell_control_depth_at(code, checksum_pin.splitlines()[0].strip()) == 0, "checksums-file pin is conditional")
    expect(code.count(archive_check) == 1, "missing unique archive sha256sum verification")
    expect(shell_control_depth_at(code, archive_check.strip()) == 0, "archive sha256sum verification is conditional")
    expect(extraction in code, "missing archive extraction")

    download_positions = [code.find(marker) for marker in cast(list[str], spec["downloads"])]
    verify_position = code.find("  cosign verify-blob \\")
    pin_position = code.find(checksum_pin)
    archive_position = code.find(archive_check)
    extraction_position = code.find(extraction)
    positions_present = all(position >= 0 for position in download_positions) and all(
        position >= 0 for position in [verify_position, pin_position, archive_position, extraction_position]
    )
    expect(
        positions_present
        and max(download_positions) < verify_position < pin_position < archive_position < extraction_position,
        "required order is downloads < cosign verify < checksums-file pin < archive sha256sum < extraction",
    )

    soft_fail = re.search(r"\|\|\s*(?:true|:)(?:\s|$)|;\s*true(?:\s|$)|\bset\s+\+e\b", code)
    expect(soft_fail is None, "soft-fail token is forbidden")
    return errors


def extract_cosign_block(text: str) -> str:
    start_marker = "  cosign verify-blob \\"
    require(start_marker in text, "scanner installer missing Cosign verify-blob block start")
    start = text.index(start_marker)
    final_line = '    "${checksums}"'
    require(final_line in text[start:], "scanner installer Cosign verify-blob block missing final checksums line")
    end = text.index(final_line, start) + len(final_line)
    return text[start:end]


def check_scanner_installer_mutations(text: str, spec: dict[str, Any]) -> int:
    name = cast(str, spec["name"])
    identity = cast(str, spec["identity"])
    issuer = cast(str, spec["issuer"])
    checksum = cast(str, spec["checksums_sha256"])
    guard = (
        "if ! command -v cosign > /dev/null 2>&1; then\n"
        f'  echo "cosign is required to verify the {name} release" >&2\n'
        "  exit 1\n"
        "fi"
    )
    identity_line = f'    --certificate-identity "{identity}" \\'
    issuer_line = f'    --certificate-oidc-issuer "{issuer}" \\'
    archive_check = '  grep " ${archive}\\$" "${checksums}" | sha256sum -c -'
    cosign_block = extract_cosign_block(text)
    removal_markers = [
        ("strict-mode", "set -euo pipefail"),
        ("cosign-guard", guard),
        ("cosign-invocation", "  cosign verify-blob \\"),
        ("certificate-identity", identity_line),
        ("oidc-issuer", issuer_line),
        ("checksums-file-sha256", checksum),
        ("archive-sha256sum", archive_check),
        ("extraction", '    tar xzf "${archive}" "${binary}"'),
    ]
    removal_markers.extend(
        (f"asset-assignment-{index}", marker)
        for index, marker in enumerate(cast(list[str], spec["asset_assignments"]), start=1)
    )
    removal_markers.extend(
        (f"asset-download-{index}", marker) for index, marker in enumerate(cast(list[str], spec["downloads"]), start=1)
    )
    removal_markers.extend(
        (f"cosign-asset-flag-{index}", marker)
        for index, marker in enumerate(cast(list[str], spec["asset_flags"]), start=1)
    )

    mutations: list[tuple[str, str]] = []
    for label, marker in removal_markers:
        mutated = text.replace(marker, "", 1)
        require(mutated != text, f"{name} mutation fixture did not find marker: {label}")
        mutations.append((f"remove-{label}", mutated))

    without_cosign = text.replace(cosign_block + "\n", "", 1)
    mutations.extend(
        [
            (
                "reorder-cosign-after-archive-sha256",
                without_cosign.replace(archive_check, archive_check + "\n" + cosign_block, 1),
            ),
            (
                "comment-cosign-verification",
                text.replace(cosign_block, "\n".join(f"# {line}" for line in cosign_block.splitlines()), 1),
            ),
            (
                "dead-branch-cosign-verification",
                text.replace(cosign_block, "  if false; then\n" + cosign_block + "\n  fi", 1),
            ),
            (
                "conditional-skip-cosign-verification",
                text.replace(cosign_block, '  if [[ "${SKIP_VERIFY:-}" != "1" ]]; then\n' + cosign_block + "\n  fi", 1),
            ),
            ("soft-fail-or-true", text.replace(cosign_block, cosign_block + " || true", 1)),
            (
                "regexp-identity-substitution",
                text.replace("--certificate-identity ", "--certificate-identity-regexp ", 1),
            ),
            ("remove-pipefail", text.replace("set -euo pipefail", "set -eu", 1)),
        ]
    )
    mutations.extend(
        (
            f"forbidden-{flag.removeprefix('--')}",
            text.replace("  cosign verify-blob \\", f"  cosign verify-blob \\\n    {flag} \\", 1),
        )
        for flag in [
            "--insecure-ignore-tlog",
            "--insecure-ignore-sct",
            "--insecure-future-flag",
            "--private-infrastructure",
        ]
    )

    require(not scanner_installer_errors(text, spec), f"{name} installer trust-policy baseline fixture must pass")
    print(f"scanner installer trust-policy baseline probe accepted: {name.lower()}")
    rejected = 0
    for label, marker in COSIGN_TRUST_MUTATIONS:
        mutated = text.replace("  cosign verify-blob \\", f"  cosign verify-blob \\\n    {marker} \\", 1)
        require(mutated != text, f"{name} trust-policy mutation fixture did not change: {label}")
        mutation_errors = scanner_installer_errors(mutated, spec)
        require(mutation_errors, f"{name} trust-policy mutation was not rejected: {label}")
        require(cosign_trust_substitution_errors(mutated), f"{name} trust-policy helper missed mutation: {label}")
        print(f"scanner installer trust-policy mutation rejected: {name.lower()}/{label}")
        rejected += 1

        comment_only = text.replace("set -euo pipefail", f"set -euo pipefail\n# {marker}", 1)
        require(comment_only != text, f"{name} trust-policy comment fixture did not change: {label}")
        require(
            not scanner_installer_errors(comment_only, spec),
            f"{name} installer full-line trust-policy comment caused a false positive: {label}",
        )
        print(f"scanner installer trust-policy comment probe accepted: {name.lower()}/{label}")

    for label, mutated in mutations:
        require(scanner_installer_errors(mutated, spec), f"{name} installer mutation was not rejected: {label}")
        print(f"scanner installer mutation rejected: {name.lower()}/{label}")
        rejected += 1
    commented_flag = text.replace("set -euo pipefail", "set -euo pipefail\n# --insecure-future-flag", 1)
    require(
        not scanner_installer_errors(commented_flag, spec),
        f"{name} installer full-line insecure-flag comment caused a false positive",
    )
    print(f"scanner installer comment probe accepted: {name.lower()}/insecure-future-flag")
    return rejected


def check_scanner_install_scripts() -> None:
    total_mutations = 0
    for spec in scanner_installer_specs():
        text = read(cast(str, spec["path"]))
        errors = scanner_installer_errors(text, spec)
        require(not errors, f"{spec['name']} installer contract failed: " + "; ".join(errors))
        total_mutations += check_scanner_installer_mutations(text, spec)
    print(f"scanner installer mutation probes: {total_mutations}/{total_mutations} rejected")

    crane = read("tools/install-crane.sh")
    for marker in [
        "CRANE_VERSION:-v0.21.7",
        "github.com/google/go-containerregistry/releases/download/${version}",
        "go-containerregistry_${os}_${arch}.tar.gz",
        "archive_sha256=",
        "sha256sum -c -",
        '"${dest}/crane" version',
    ]:
        require(marker in crane, f"Crane installer missing marker: {marker}")

    freshness = read("tools/assert-scanner-db-freshness.py")
    for marker in [
        "DEFAULT_MAX_AGE_DAYS = 7",
        "MIN_GRYPE_SCHEMA_MAJOR = 6",
        "grype db status",
        "DownloadedAt",
        "NextUpdate",
        "--grype-status-json",
        "--trivy-metadata-json",
        "--self-test",
        "scanner DB freshness self-test: ok",
    ]:
        require(marker in freshness, f"scanner DB freshness helper missing marker: {marker}")


def scanner_canary_wiring_errors(
    text: str,
    source: str,
    freshness_marker: str,
    first_scan_marker: str,
) -> list[str]:
    errors: list[str] = []

    def expect(condition: object, message: str) -> None:
        if not condition:
            errors.append(f"{source}: {message}")

    grype_producer = 'GRYPE_DB_AUTO_UPDATE=false dist/tools/grype "sbom:${scanner_canary_fixture}" -o json -q'
    trivy_producer = 'dist/tools/trivy sbom "${scanner_canary_fixture}"'
    grype_output = (
        f'{grype_producer} \\\n            > "${{grype_canary_json}}"'
        if source == "publish workflow"
        else f'{grype_producer} > "${{grype_canary_json}}"'
    )
    assertion = "python tools/assert-scanner-canary.py"
    markers = [
        'scanner_canary_fixture="tests/fixtures/scanner-canary/log4shell.cdx.json"',
        'grype_canary_json="dist/vuln/scanner-canary.grype.json"',
        'trivy_canary_json="dist/vuln/scanner-canary.trivy.json"',
        ': > "${grype_canary_json}"',
        ': > "${trivy_canary_json}"',
        grype_producer,
        grype_output,
        trivy_producer,
        '--output "${trivy_canary_json}"',
        assertion,
        '--grype-json "${grype_canary_json}"',
        '--trivy-json "${trivy_canary_json}"',
        "--expect-cve CVE-2021-44228",
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
    ]
    for marker in markers:
        expect(text.count(marker) == 1, f"must contain exactly one canary marker: {marker}")

    freshness_index = text.find(freshness_marker)
    fixture_index = text.find('scanner_canary_fixture="tests/fixtures/scanner-canary/log4shell.cdx.json"')
    grype_truncate_index = text.find(': > "${grype_canary_json}"')
    trivy_truncate_index = text.find(': > "${trivy_canary_json}"')
    grype_index = text.find(grype_producer)
    trivy_index = text.find(trivy_producer)
    assertion_index = text.find(assertion)
    first_scan_index = text.find(first_scan_marker)
    expect(freshness_index >= 0, "must keep the scanner DB freshness gate")
    expect(first_scan_index >= 0, "must keep the first real vulnerability scan")
    expect(
        0 <= freshness_index < fixture_index < grype_truncate_index < grype_index < trivy_index < assertion_index,
        "canary must run after freshness with truncation before both producers and assertion last",
    )
    expect(
        0 <= fixture_index < trivy_truncate_index < trivy_index,
        "Trivy report must be truncated before its producer runs",
    )
    expect(assertion_index < first_scan_index, "canary assertion must precede the first real vulnerability scan")

    if 0 <= fixture_index < assertion_index:
        canary_end = text.find("\n\n", text.find("--expect-cve CVE-2021-44228", assertion_index))
        if canary_end < 0:
            canary_end = first_scan_index
        canary_block = text[fixture_index:canary_end]
        expect(canary_block.count("-q") == 2, "both canary scanner invocations must remain quiet")
        for forbidden in [
            "--fail-on",
            "--exit-code",
            "|| true",
            "continue-on-error",
            "--download-db-only",
            "db update",
            "\nif ",
            "\nfor ",
        ]:
            expect(forbidden not in canary_block, f"canary block contains forbidden marker: {forbidden}")

    if source == "publish workflow":
        step_start = text.rfind("      - name:", 0, fixture_index)
        step_end = text.find("\n      - name:", fixture_index)
        publish_block = text[step_start:step_end]
        expect("- name: Assert scanner content canary" in publish_block, "must use a dedicated canary step")
        expect("set -euo pipefail" in publish_block, "canary step must enable strict shell mode")
    else:
        expect("set -euo pipefail" in text[:fixture_index], "gate runner must enable strict shell mode")
    return errors


def scanner_canary_contract_errors(
    fixture: str | None,
    helper: str,
    gate_runner: str,
    publish_workflow: str,
    verify_source: str,
    gitignore: str,
    gates_doc: str,
) -> list[str]:
    errors: list[str] = []
    expected_fixture = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "log4j-core",
                "group": "org.apache.logging.log4j",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            }
        ],
    }
    if fixture is None:
        errors.append("fixture: missing scanner canary fixture")
    else:
        try:
            parsed_fixture = json.loads(fixture)
        except json.JSONDecodeError:
            errors.append("fixture: malformed scanner canary JSON")
        else:
            if parsed_fixture != expected_fixture:
                errors.append("fixture: must remain the pinned one-component log4j-core CycloneDX SBOM")

    helper_markers = [
        'DEFAULT_EXPECTED_CVE = "CVE-2021-44228"',
        'GRYPE_PRIMARY_ID = "GHSA-jfh8-c2jp-5v3q"',
        'match.get("relatedVulnerabilities", [])',
        'vulnerability.get("VulnerabilityID")',
        "class ScannerReportLoadError(ScannerCanaryError)",
        "class ScannerReportSchemaError(ScannerCanaryError)",
        "class ScannerDetectionError(ScannerCanaryError)",
        "--grype-json",
        "--trivy-json",
        "--expect-cve",
        "--self-test",
        "scanner content canary self-test: ok",
    ]
    errors.extend(
        f"helper: missing scanner canary marker: {marker}" for marker in helper_markers if marker not in helper
    )

    errors.extend(
        scanner_canary_wiring_errors(
            gate_runner,
            "test gate runner",
            "tools/assert-scanner-db-freshness.py",
            "--ignore-unfixed",
        )
    )
    errors.extend(
        scanner_canary_wiring_errors(
            publish_workflow,
            "publish workflow",
            "Assert scanner DB freshness",
            "Run Trivy fixable vulnerability gates",
        )
    )
    if "!/tests/fixtures/scanner-canary/log4shell.cdx.json" not in gitignore:
        errors.append(".gitignore: scanner canary fixture must be explicitly allowlisted")
    if "`tools/assert-scanner-canary.py`" not in gates_doc or "content validity, not image cataloging" not in gates_doc:
        errors.append("docs: gates reference must document the content-validity boundary")

    self_test_start = verify_source.find("\ndef check_helper_self_tests()")
    self_test_end = verify_source.find("\ndef ", self_test_start + 1)
    if self_test_start < 0 or self_test_end < 0:
        errors.append("verify: check_helper_self_tests must remain identifiable")
    else:
        self_test_block = verify_source[self_test_start:self_test_end]
        if self_test_block.count('"tools/assert-scanner-canary.py"') != 1:
            errors.append("verify: scanner canary must be registered once in check_helper_self_tests")
    return errors


def remove_scanner_canary_self_test_registration(verify_source: str) -> str:
    function_index = verify_source.find("\ndef check_helper_self_tests()")
    marker = '        "tools/assert-scanner-canary.py",\n'
    marker_index = verify_source.find(marker, function_index)
    require(function_index >= 0 and marker_index >= 0, "scanner canary self-test mutation fixture is missing")
    return verify_source[:marker_index] + verify_source[marker_index + len(marker) :]


def check_scanner_content_canary() -> None:
    fixture = read("tests/fixtures/scanner-canary/log4shell.cdx.json")
    helper = read("tools/assert-scanner-canary.py")
    gate_runner = read("tools/run-test-gates.sh")
    publish_workflow = read(".github/workflows/publish-image.yaml")
    verify_source = read("tools/verify.py")
    gitignore = read(".gitignore")
    gates_doc = read("docs/reference/gates.md")

    def errors(
        fixture_text: str | None = fixture,
        helper_text: str = helper,
        gate_text: str = gate_runner,
        publish_text: str = publish_workflow,
        verify_text: str = verify_source,
    ) -> list[str]:
        return scanner_canary_contract_errors(
            fixture_text,
            helper_text,
            gate_text,
            publish_text,
            verify_text,
            gitignore,
            gates_doc,
        )

    require(not errors(), "scanner content canary contract failed: " + "; ".join(errors()))

    gate_grype_marker = 'GRYPE_DB_AUTO_UPDATE=false dist/tools/grype "sbom:${scanner_canary_fixture}" -o json -q'
    gate_trivy_marker = 'dist/tools/trivy sbom "${scanner_canary_fixture}"'
    mutations = [
        (
            "test-runner-grype-producer-substitution",
            errors(gate_text=gate_runner.replace(gate_grype_marker, gate_grype_marker.replace("grype", "trivy"), 1)),
        ),
        (
            "test-runner-trivy-producer-substitution",
            errors(gate_text=gate_runner.replace(gate_trivy_marker, gate_trivy_marker.replace("trivy", "grype"), 1)),
        ),
        (
            "publish-grype-producer-deletion",
            errors(publish_text=publish_workflow.replace(gate_grype_marker, "", 1)),
        ),
        (
            "publish-trivy-producer-deletion",
            errors(publish_text=publish_workflow.replace(gate_trivy_marker, "", 1)),
        ),
        (
            "test-runner-distinct-consumer-substitution",
            errors(
                gate_text=gate_runner.replace(
                    '--trivy-json "${trivy_canary_json}"',
                    '--trivy-json "${grype_canary_json}"',
                    1,
                )
            ),
        ),
        (
            "publish-distinct-consumer-substitution",
            errors(
                publish_text=publish_workflow.replace(
                    '--grype-json "${grype_canary_json}"',
                    '--grype-json "${trivy_canary_json}"',
                    1,
                )
            ),
        ),
        ("fixture-deletion", errors(fixture_text=None)),
        (
            "expected-cve-blanking",
            errors(
                helper_text=helper.replace('DEFAULT_EXPECTED_CVE = "CVE-2021-44228"', 'DEFAULT_EXPECTED_CVE = ""', 1)
            ),
        ),
        (
            "expected-ghsa-blanking",
            errors(helper_text=helper.replace('GRYPE_PRIMARY_ID = "GHSA-jfh8-c2jp-5v3q"', 'GRYPE_PRIMARY_ID = ""', 1)),
        ),
        (
            "self-test-registration-deletion",
            errors(verify_text=remove_scanner_canary_self_test_registration(verify_source)),
        ),
    ]
    for label, mutation_errors in mutations:
        require(mutation_errors, f"scanner content canary mutation was not rejected: {label}")
        print(f"scanner content canary mutation rejected: {label}")
    print(f"scanner content canary mutation probes: {len(mutations)}/{len(mutations)} rejected")


def check_cve_ignore_policy() -> None:
    gitignore = read(".gitignore")
    for marker in (
        "!/security/",
        "!/security/cve-ignore.trivyignore.yaml",
        "!/security/cve-ignore.grype.yaml",
    ):
        require(marker in gitignore, f".gitignore must allowlist CVE ignore path: {marker}")

    expected_trivy = """# TD-6: openssl-fips-provider{,-so} held at 3.0.7-8.el9 (CMVP #4857-validated module).
# The fix 3.0.7-11.el9_8 is forbidden at tools/verify.py:86. See docs/TECH-DEBT.md TD-6.
# `purls` MUST be plural: a singular `purl` key is silently ignored by trivy and the
# suppression degrades to a global, id-only ignore.
vulnerabilities:
  - id: CVE-2026-31790
    purls:
      - pkg:rpm/redhat/openssl-fips-provider@3.0.7-8.el9
      - pkg:rpm/redhat/openssl-fips-provider-so@3.0.7-8.el9
    statement: "TD-6: held CMVP #4857 FIPS module; fixed provider build is forbidden by the validated module lock"
"""
    expected_grype = """# TD-6: exact native exception for the held CMVP #4857 FIPS module.
ignore:
  - vulnerability: CVE-2026-31790
    reason: "TD-6 held CMVP #4857 module; fixed provider build is forbidden by the validated module lock"
    package:
      name: openssl-fips-provider
      version: 3.0.7-8.el9
  - vulnerability: CVE-2026-31790
    reason: "TD-6 held CMVP #4857 module; fixed provider build is forbidden by the validated module lock"
    package:
      name: openssl-fips-provider-so
      version: 3.0.7-8.el9
"""
    require(
        read("security/cve-ignore.trivyignore.yaml") == expected_trivy,
        "Trivy TD-6 policy must remain the exact CVE/package/version native exception",
    )
    require(
        read("security/cve-ignore.grype.yaml") == expected_grype,
        "Grype TD-6 policy must remain the exact two-package/version native exception",
    )


def check_fips_config() -> None:
    text = read("containers/fips/openssl.cnf")
    for marker in [
        "openssl_conf = openssl_init",
        "[provider_sect]",
        "fips = fips_sect",
        "base = base_sect",
        "[fips_sect]",
        "activate = 1",
        "[algorithm_sect]",
        "default_properties = fips=yes",
    ]:
        require(marker in text, f"FIPS OpenSSL config missing marker: {marker}")

    lower = text.lower()
    require(".include" not in lower, "FIPS OpenSSL config must not include external files")
    require("fipsmodule.cnf" not in lower, "FIPS OpenSSL config must not reference fipsmodule.cnf")
    require("[default_sect]" not in lower, "FIPS OpenSSL config must not activate the default provider")
    require("legacy" not in lower, "FIPS OpenSSL config must not activate the legacy provider")


def check_fips_script() -> None:
    text = read("tests/fips.sh")
    for marker in [
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
        "openssl-fips.cnf",
        "fips.so",
        "libcrypto.so.3",
        "legacy.so",
        "etc/nwarila/fips-status.json",
        "oe_validated",
        "org.nwarila.fips.provider-nvr",
        "org.nwarila.fips.cmvp.oe-validated",
        fips_module_version(),
        fips_provider_nevra(),
        fips_disclaimer("amd64"),
        fips_disclaimer("arm64"),
    ]:
        require(marker in text, f"FIPS script missing marker: {marker}")


def check_vex() -> None:
    require(not (ROOT / "vex").exists(), "root OpenVEX publication directory must be removed")
    require(
        re.search(r"^/vex/\s", read(".github/CODEOWNERS"), re.MULTILINE) is None,
        "CODEOWNERS retains removed root VEX ownership",
    )

    python_vex_dir = ROOT / "images/python/vex"
    require(
        {path.name for path in python_vex_dir.iterdir()}
        == {
            "README.md",
            "cve-2026-53613.openvex.json",
            "sqlite-component-not-present.openvex.json",
        },
        "Python OpenVEX publication must contain exactly the two proof-backed documents and its README",
    )
    libuuid = load_json_object("images/python/vex/cve-2026-53613.openvex.json")
    expected_products = [
        {
            "@id": f"local/ubi9-base-python:ci-{arch}",
            "subcomponents": [{"@id": "pkg:rpm/redhat/libuuid@2.37.4-25.el9?epoch=0"}],
        }
        for arch in ("amd64", "arm64")
    ]
    expected_products.append(
        {
            "@id": "https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-python/published-platform-children",
            "subcomponents": [{"@id": "pkg:rpm/redhat/libuuid@2.37.4-25.el9?epoch=0"}],
        }
    )
    expected_libuuid = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://github.com/NWarila/ubi9-base-micro/images/python/vex/cve-2026-53613",
        "author": "NWarila",
        "timestamp": "2026-08-23T00:00:00Z",
        "version": 1,
        "statements": [
            {
                "@id": (
                    "https://github.com/NWarila/ubi9-base-micro/policy/"
                    "vulnerable-code-not-present?absent-packages=util-linux,util-linux-core"
                ),
                "vulnerability": {"name": "CVE-2026-53613"},
                "products": expected_products,
                "status": "not_affected",
                "justification": "vulnerable_code_not_present",
                "impact_statement": (
                    "The installed libuuid package is built from the util-linux source RPM, so Grype maps "
                    "CVE-2026-53613 to it. The vulnerable code is mount(8) at /usr/bin/mount, which is shipped "
                    "by util-linux-core. Neither util-linux nor util-linux-core is installed in either image "
                    "architecture; only libuuid 0:2.37.4-25.el9 is installed from that source RPM. Therefore "
                    "the vulnerable code is not present in this product."
                ),
            }
        ],
    }
    require(libuuid == expected_libuuid, "CVE-2026-53613 OpenVEX document drifted from its exact absence claim")

    python_ci = read(".github/workflows/python-ci.yaml")
    publish_python = read(".github/workflows/publish-python.yaml")
    ci_sbom = _workflow_named_step(_workflow_job_block(python_ci, "build"), "Generate and gate rpmdb SBOMs")
    publish_gates = _workflow_named_step(
        _workflow_job_block(publish_python, "gate-evidence"),
        "Run runtime and evidence gates",
    )
    for label, step in (("Python CI", ci_sbom), ("Python publish", publish_gates)):
        require(step.count("tools/assert-no-phantom-packages.py") == 1, f"{label} must run one absence proof")
        for package in ("sqlite-libs", "util-linux", "util-linux-core"):
            require(
                len(
                    re.findall(
                        rf"^\s*--expect-absent\s+{re.escape(package)}(?:\s+\\)?\s*$",
                        step,
                        re.MULTILINE,
                    )
                )
                == 1,
                f"{label} must pin {package} absent exactly once",
            )

    attest = _workflow_named_step(
        _workflow_job_block(publish_python, "sign-attest"),
        "Attest OpenVEX predicates on both children",
    )
    verify = _workflow_named_step(
        _workflow_job_block(publish_python, "sign-attest"),
        "Verify OpenVEX attestations on both children",
    )
    for marker in (
        "predicates=(images/python/vex/*.json)",
        "if (( ${#predicates[@]} == 0 )); then",
        'echo "no reviewed OpenVEX predicates were found for ${arch}" >&2',
        "exit 1",
    ):
        require(marker in attest, f"Python OpenVEX attestation lost fatal-on-empty marker: {marker}")
    for marker in (
        "expected=()",
        "for predicate in images/python/vex/*.json; do",
        "if (( ${#expected[@]} == 0 )); then",
        'echo "no OpenVEX verification expectations were found for ${arch}" >&2',
        "exit 1",
        "tools/assert-python-attestation.py",
    ):
        require(marker in verify, f"Python OpenVEX verification lost fatal-on-empty marker: {marker}")


def check_nist_800_190_scripts() -> None:
    generator = read("tools/generate-nist-800-190-predicate.py")
    for marker in [
        "PREDICATE_TYPE",
        predicate_type("nist_800_190"),
        "4.1.1",
        "4.1.2",
        "4.1.3",
        "4.1.4",
        "4.1.5",
        "notCisDocker",
        "a claim of arbitrary antivirus detection",
        "--validate",
        "--self-test",
    ]:
        require(marker in generator, f"NIST predicate generator missing marker: {marker}")
    generated_truth_markers = [
        "Fixable MEDIUM, HIGH, and CRITICAL OS/library findings fail closed through both",
        "Trivy fixable MEDIUM/HIGH/CRITICAL gate",
        "Grype fixable MEDIUM/HIGH/CRITICAL gate",
    ]
    for marker in generated_truth_markers:
        require(
            generator.count(marker) == 2,
            f"NIST predicate generator production and self-test must both pin marker: {marker}",
        )

    secrets = read("tools/assert-no-rootfs-secrets.py")
    for marker in [
        "private-key",
        "aws-access-key-id",
        "github-token",
        "generic-secret-assignment",
        "findings",
        "--self-test",
    ]:
        require(marker in secrets, f"rootfs secret scanner missing marker: {marker}")

    rekor = read("tools/assert-cosign-rekor.py")
    for marker in [
        "SignedEntryTimestamp",
        "logIndex",
        "integratedTime",
        "logID",
        "cosign container image signature",
        "self-test-dsse-attestation-envelope",
        "--self-test",
    ]:
        require(marker in rekor, f"Rekor assertion helper missing marker: {marker}")

    slsa = read("tools/assert-slsa-builder-id.py")
    for marker in [
        "runDetails",
        "builder",
        "--builder-id",
        slsa_builder_id().removeprefix("https://github.com/"),
        "--self-test",
    ]:
        require(marker in slsa, f"SLSA builderID helper missing marker: {marker}")


def check_helper_self_tests() -> None:
    for relative_path in [
        "tools/decide-publish-scope.py",
        "tools/decide-python-publish-scope.py",
        "tools/assert-python-alias-policy.py",
        "tools/assert-python-attestation.py",
        "tools/assert-python-provenance.py",
        "tools/assert-python-slsa-certificate.py",
        "tools/python-trust-contract.py",
        "images/python/tools/rpmlock.py",
        "images/python/tools/assert-no-rootfs-secrets.py",
        "images/python/tools/assert-sbom-rpms.py",
        "images/python/tools/generate-nist-800-190-predicate.py",
        "images/python/tools/build-python-rootfs.py",
        "images/python/tools/assert-reproducible.py",
        "images/python/tools/assert-parent-subset.py",
        "images/python/tools/assert-raw-scanners-no-sqlite.py",
        "images/python/tools/retained_payload_trim.py",
        "tools/assert-rpm-lock-hashes.py",
        "tools/assert-no-rootfs-secrets.py",
        "tools/generate-nist-800-190-predicate.py",
        "tools/assert-footprint.py",
        "tools/assert-no-phantom-packages.py",
        "tools/assert-reproducible.py",
        "tools/assert-scanner-db-freshness.py",
        "tools/assert-scanner-canary.py",
        "tools/assert-cosign-rekor.py",
        "tools/assert-slsa-builder-id.py",
        "tools/assert-stig-tailoring.py",
        "tools/assert-rootfs-identity.py",
        "tools/assert-stig-arf.py",
        "tools/generate-stig-arf-predicate.py",
    ]:
        result = subprocess.run(
            [sys.executable, str(ROOT / relative_path), "--self-test"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        require(
            result.returncode == 0,
            f"{relative_path} --self-test failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
        )


def check_stig() -> None:
    codeowners = read(".github/CODEOWNERS")
    require("/stig/ @NWarila" in codeowners, "CODEOWNERS must gate stig/ with @NWarila")

    gitignore = read(".gitignore")
    for marker in ["!/stig/", "!/stig/*.xml", "!/stig/*.json"]:
        require(marker in gitignore, f".gitignore must allowlist STIG evidence path: {marker}")

    tailoring = read("stig/rhel9-base-micro-tailoring.xml")
    for marker in [
        "xccdf_org.nwarila.content_profile_ubi9_base_micro_stig",
        "file_permissions_etc_group",
        "file_permissions_etc_passwd",
        "accounts_no_uid_except_zero",
        "file_permissions_etc_shadow",
        "file_permissions_backup_etc_shadow",
        "file_permissions_library_dirs",
        "file_ownership_binary_dirs",
        "file_permissions_unauthorized_world_writable",
        "file_permissions_unauthorized_suid",
        "file_permissions_unauthorized_sgid",
    ]:
        require(marker in tailoring, f"STIG tailoring missing marker: {marker}")

    justifications = read("stig/tailoring-justifications.json")
    for marker in [
        "0.1.81",
        "11e26cfa96a6f1bd98b3a131837e2f86c9a9851239337d86d624b01627faf10f7a03c395a5839ddab018e0fa47719ade05a9946f90d5ca96b1261776a9164379",
        "selected_controls",
        "supplemental_selected_rules",
        "omission_groups",
        "RHEL-09-232010",
        "RHEL-09-232055",
        "RHEL-09-232270",
        "RHEL-09-411100",
        "host_filesystem_mounts",
        "absent_audit_tool_and_config_paths",
        "host_selinux_device_labeling",
        "interactive_account_and_pam_policy",
    ]:
        require(marker in justifications, f"STIG justification ledger missing marker: {marker}")

    for relative_path in [
        "tools/assert-stig-tailoring.py",
        "tools/assert-rootfs-identity.py",
        "tools/assert-stig-arf.py",
        "tools/generate-stig-arf-predicate.py",
        "tools/build-stig-datastream.sh",
        "tools/run-stig-arf.sh",
    ]:
        read(relative_path)


def check_decision_records() -> None:
    index = read("docs/decision-records/README.md")
    require("repository-scope Architecture Decision Records" in index, "decision-records index must define scope")
    require(
        "do not mirror shared organization or template ADRs" in index, "decision-records index must stay repo-scoped"
    )
    require("| ADR | Status | Decision |" in index, "decision-records index must contain an ADR table")
    require("repo/" in index, "decision-records index must point to repo ADRs")

    index_paths = re.findall(r"^\| \[[^]]+\]\((repo/[^)]+\.md)\) \|", index, flags=re.MULTILINE)
    registered_paths = [path.removeprefix("docs/decision-records/") for path, _ in REPO_ADRS]
    require(
        index_paths == registered_paths,
        "decision-records index links must exactly match REPO_ADRS in order",
    )

    expected_numbers = [f"{number:04d}" for number in range(1, len(REPO_ADRS) + 1)]
    date_overrides = {
        "0012": "2026-06-25",
        "0013": "2026-06-25",
        "0014": "2026-07-10",
        "0015": "2026-07-11",
        "0016": "2026-07-29",
    }
    for number, (relative_path, title) in zip(expected_numbers, REPO_ADRS, strict=True):
        text = read(relative_path)
        require(text.startswith(f"# ADR-{number}: {title}\n"), f"{relative_path} has wrong ADR heading")
        expected_date = date_overrides.get(number, "2026-06-21")
        expected_status = "Superseded" if number == "0007" else "Accepted"
        for marker in [
            f"- Status: {expected_status}",
            f"- Date: {expected_date}",
            "- Scope: repo",
            "## Context",
            "## Decision",
            "## Consequences",
            "## References",
        ]:
            require(marker in text, f"{relative_path} missing ADR marker: {marker}")
        require(relative_path.replace("docs/decision-records/", "") in index, f"index missing {relative_path}")

    joined = "\n".join(read(path) for path, _ in REPO_ADRS)
    for marker in [
        "tools/assert-reproducible.py --assert-byte-identical",
        f"CMVP certificate #{fips_cmvp()}",
        "oe_validated",
        SLSA_GENERATOR_SHA,
        "tools/assert-no-phantom-packages.py",
        ".github/workflows/rpm-lock-refresh.yaml",
        "stig/rhel9-base-micro-tailoring.xml",
        predicate_type("nist_800_190"),
        "base-micro@sha256:<digest>",
        "runs-on: ubuntu-24.04",
        "fetch-runtime-rpms.sh",
        "cdn-ubi.redhat.com",
        "contracts/image-manifest.json",
    ]:
        require(marker in joined, f"repo ADRs missing load-bearing marker: {marker}")


_ENFORCEMENT_CLAIM_MARKER = (
    "The active `Pull Request Gate` ruleset requires its 11 named status-check contexts, which "
    "block non-bypass merges. Its Repository Admin bypass (`RepositoryRole` 5, "
    "`bypass_mode=always`) can bypass every rule in this ruleset; the solo maintainer "
    "uses that bypass routinely because the approval requirements cannot be "
    "self-satisfied. Required status checks have `strict=false`, so the pull-request "
    "head need not be current with the base branch."
)
_FORBIDDEN_ENFORCEMENT_CLAIMS = [
    (r"required status checks\s+are\s+not\s+enforced", "obsolete non-enforcement"),
    (r"not\s+claimed\s+to\s+block\s+merges?", "checks-not-claimed-to-block"),
    (r"\bnone\b[^.]{0,60}\bblock(?:ing)?\s+(?:a\s+|the\s+)?merges?", "none-can-block-merge"),
    (r"\bno\s+(?:named\s+)?checks?\b[^.]{0,40}\bblock", "no-checks-block"),
    (r"\bcan(?:not|\s+not|'?t)\b[^.]{0,40}\bblock(?:ing)?\s+(?:a\s+|the\s+)?merges?", "checks-cannot-block-merge"),
    (r"\bcan(?:not|\s+not|'?t)\s+be\s+bypass(?:ed)?", "cannot-be-bypassed overclaim"),
    (r"\bunbypassable\b", "unbypassable overclaim"),
    (r"\bno\s+(?:actor|one|admin\w*)\s+can\s+bypass", "no-actor-can-bypass overclaim"),
]


def _forbidden_enforcement_claim(acceptance_text: str) -> str | None:
    for pattern, label in _FORBIDDEN_ENFORCEMENT_CLAIMS:
        if re.search(pattern, acceptance_text, re.IGNORECASE):
            return label
    return None


def check_acceptance_enforcement_claim_self_test() -> None:
    # true canonical statement must be accepted (no forbidden hit)
    if _forbidden_enforcement_claim(_ENFORCEMENT_CLAIM_MARKER) is not None:
        raise AssertionError("enforcement self-test: true marker wrongly flagged as false claim")
    # each regression variant must be rejected
    mutants = [
        "Required status checks are not enforced.",
        "In practice, none of the named checks can block a merge.",
        "All merges are blocked until all checks pass; no actor can bypass them.",
        "The named checks cannot block a merge.",
        "These contexts are not claimed to block merges.",
        "The admin bypass is unbypassable in practice.",
    ]
    for m in mutants:
        if _forbidden_enforcement_claim(m) is None:
            raise AssertionError(f"enforcement self-test: false claim not rejected: {m!r}")
    # a realistic regression (true text + a capitalized re-add) must still be caught
    if _forbidden_enforcement_claim(_ENFORCEMENT_CLAIM_MARKER + " Required status checks are NOT enforced.") is None:
        raise AssertionError("enforcement self-test: capitalized re-add not caught")


_VERIFY_DOC_CHILD_ATTESTATIONS = {
    predicate_type("spdx"): 2,
    predicate_type("cyclonedx"): 1,
    predicate_type("nist_800_190"): 1,
    predicate_type("stig_arf"): 1,
}
_VERIFY_HOWTO_CHILD_ATTESTATIONS = {
    predicate_type("spdx"): 1,
    predicate_type("cyclonedx"): 1,
    predicate_type("nist_800_190"): 1,
    predicate_type("stig_arf"): 1,
}


def _logical_shell_statements(loop_body: str) -> tuple[list[str], bool]:
    statements: list[str] = []
    continued_parts: list[str] = []

    for line in loop_body.splitlines():
        stripped_right = line.rstrip()
        trailing_backslashes = len(stripped_right) - len(stripped_right.rstrip("\\"))
        is_continued = trailing_backslashes % 2 == 1
        part = stripped_right[:-1] if is_continued else stripped_right

        if not continued_parts and (not part.strip() or part.lstrip().startswith("#")):
            continue
        continued_parts.append(part.strip())
        if is_continued:
            continue

        statement = " ".join(continued_parts).strip()
        if statement and not statement.startswith("#"):
            statements.append(statement)
        continued_parts = []

    return statements, bool(continued_parts)


def _contains_unescaped_lone_ampersand(statement: str) -> bool:
    quote: str | None = None
    escaped = False

    for index, character in enumerate(statement):
        if escaped:
            escaped = False
            continue
        if quote == "'":
            if character == quote:
                quote = None
            continue
        if character == "\\":
            escaped = True
            continue
        if quote == '"':
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            continue
        if character == "&" and not (
            (index > 0 and statement[index - 1] == "&") or (index + 1 < len(statement) and statement[index + 1] == "&")
        ):
            return True

    return False


def _child_attestations_are_looped(
    doc_text: str,
    expected_child_attestations: Mapping[str, int],
) -> str | None:
    fence_pattern = re.compile(r"^```sh[ \t]*\n(?P<body>.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
    fenced_blocks: list[tuple[str, int, list[tuple[int, int]], list[tuple[int, int]]]] = []
    attestation_loop_opener = 'for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do'
    loop_openers = {attestation_loop_opener, "for ARCH in amd64 arm64; do"}

    for fence in fence_pattern.finditer(doc_text):
        body = fence.group("body")
        loop_spans: list[tuple[int, int]] = []
        attestation_loop_bodies: list[tuple[int, int]] = []
        active_loop_start: int | None = None
        active_loop_body_start: int | None = None
        active_loop_is_attestation = False
        fail_closed_offsets: list[int] = []
        offset = 0

        for line in body.splitlines(keepends=True):
            token = line.strip()
            if token == "set -euo pipefail":
                fail_closed_offsets.append(offset)
            if active_loop_start is not None and re.fullmatch(r"for\b.*;\s*do", token):
                return "nested-loop"
            if token in loop_openers:
                if not any(fail_closed_offset < offset for fail_closed_offset in fail_closed_offsets):
                    return "loop-missing-positional-fail-closed"
                active_loop_start = offset
                active_loop_body_start = offset + len(line)
                active_loop_is_attestation = token == attestation_loop_opener
            elif token == "done":
                if active_loop_start is None:
                    return "unmatched-done"
                loop_spans.append((active_loop_start, offset + len(line)))
                if active_loop_is_attestation:
                    if active_loop_body_start is None:
                        return "attestation-loop-missing-body-start"
                    attestation_loop_bodies.append((active_loop_body_start, offset))
                active_loop_start = None
                active_loop_body_start = None
                active_loop_is_attestation = False
            offset += len(line)

        if active_loop_start is not None:
            return "unmatched-loop-opener"
        fenced_blocks.append((body, fence.start("body"), loop_spans, attestation_loop_bodies))

    if not fenced_blocks:
        return "missing-sh-fences"

    fenced_text = "\n".join(body for body, _, _, _ in fenced_blocks)
    resolution_markers = {
        "index-ref": 'INDEX_REF="${IMAGE}@${INDEX_DIGEST}"',
        "amd64-digest-from-index": 'AMD64_DIGEST="$(crane digest --platform linux/amd64 "${INDEX_REF}")"',
        "amd64-ref": 'AMD64_REF="${IMAGE}@${AMD64_DIGEST}"',
        "arm64-digest-from-index": 'ARM64_DIGEST="$(crane digest --platform linux/arm64 "${INDEX_REF}")"',
        "arm64-ref": 'ARM64_REF="${IMAGE}@${ARM64_DIGEST}"',
    }
    for label, marker in resolution_markers.items():
        if marker not in fenced_text:
            return f"missing-resolution:{label}"

    known_child_types = tuple(predicate_type(name) for name in ["spdx", "cyclonedx", "nist_800_190", "stig_arf"])
    expected = Counter(expected_child_attestations)
    if set(expected) != set(known_child_types) or any(count < 1 for count in expected.values()):
        return "invalid-expected-child-attestation-multiset"

    type_alternation = "|".join(re.escape(attestation_type) for attestation_type in known_child_types)
    attestation_command = re.compile(
        rf'^cosign verify-attestation --type (?P<type>{type_alternation}) "\$\{{CHILD_REF\}}"(?=\s|$)'
    )
    anchored_child_command = re.compile(
        r'^[ \t]*cosign verify-attestation --type (?P<type>\S+) "\$\{CHILD_REF\}"(?=\s|$)',
        re.MULTILINE,
    )
    observed: Counter[str] = Counter()
    attestation_body_doc_spans: list[tuple[int, int]] = []

    for body, body_doc_start, _, attestation_loop_bodies in fenced_blocks:
        for start, end in attestation_loop_bodies:
            attestation_body_doc_spans.append((body_doc_start + start, body_doc_start + end))
            statements, unterminated_continuation = _logical_shell_statements(body[start:end])
            if unterminated_continuation:
                return "attestation-loop-unterminated-continuation"
            for statement in statements:
                match = attestation_command.match(statement.lstrip())
                if match is None:
                    return "attestation-loop-non-cosign-statement"
                if any(operator in statement for operator in [";", "||", "&&"]):
                    return "attestation-loop-failure-suppression"
                if _contains_unescaped_lone_ampersand(statement):
                    return "attestation-loop-backgrounded-command"
                observed[match.group("type")] += 1

    for match in anchored_child_command.finditer(doc_text):
        if not any(start <= match.start() < end for start, end in attestation_body_doc_spans):
            return f"child-attestation-outside-loop:{match.group('type')}"

    if observed != expected:
        return f"child-attestation-multiset:expected={dict(expected)}:observed={dict(observed)}"

    index_bound_markers = {
        "cosign-signature": 'cosign verify "${INDEX_REF}"',
        "cosign-slsa": 'cosign verify-attestation --type slsaprovenance "${INDEX_REF}"',
        "slsa-verifier": 'slsa-verifier verify-image "${INDEX_REF}"',
    }
    for label, marker in index_bound_markers.items():
        fenced_total = sum(body.count(marker) for body, _, _, _ in fenced_blocks)
        if fenced_total == 0:
            return f"missing-index-bound-command:{label}"
        inside = sum(
            body[start:end].count(marker) for body, _, loop_spans, _ in fenced_blocks for start, end in loop_spans
        )
        if inside != 0:
            return f"index-bound-command-inside-child-loop:{label}"

    return None


def check_verify_docs_child_loop_self_test() -> None:
    shipped_docs = {
        "docs/reference/verify.md": _VERIFY_DOC_CHILD_ATTESTATIONS,
        "docs/how-to/verify-a-published-image.md": _VERIFY_HOWTO_CHILD_ATTESTATIONS,
    }
    for relative_path, expected_child_attestations in shipped_docs.items():
        failure = _child_attestations_are_looped(read(relative_path), expected_child_attestations)
        if failure is not None:
            raise AssertionError(f"verify-doc child-loop self-test: shipped {relative_path} rejected: {failure}")

    child_commands = [
        'cosign verify-attestation --type spdxjson "${CHILD_REF}"',
        'cosign verify-attestation --type cyclonedx "${CHILD_REF}"',
        f'cosign verify-attestation --type {predicate_type("nist_800_190")} "${{CHILD_REF}}"',
        f'cosign verify-attestation --type {predicate_type("stig_arf")} "${{CHILD_REF}}"',
    ]
    loop_body = "\n".join(f"  {command}" for command in child_commands)
    child_loop_fence = (
        f'```sh\nset -euo pipefail\nfor CHILD_REF in "${{AMD64_REF}}" "${{ARM64_REF}}"; do\n{loop_body}\ndone\n```'
    )
    minimal_valid = (
        "```sh\n"
        'INDEX_REF="${IMAGE}@${INDEX_DIGEST}"\n'
        'AMD64_DIGEST="$(crane digest --platform linux/amd64 "${INDEX_REF}")"\n'
        'AMD64_REF="${IMAGE}@${AMD64_DIGEST}"\n'
        'ARM64_DIGEST="$(crane digest --platform linux/arm64 "${INDEX_REF}")"\n'
        'ARM64_REF="${IMAGE}@${ARM64_DIGEST}"\n'
        'cosign verify "${INDEX_REF}"\n'
        'cosign verify-attestation --type slsaprovenance "${INDEX_REF}"\n'
        'slsa-verifier verify-image "${INDEX_REF}"\n'
        "```\n\n"
        f"{child_loop_fence}\n"
    )
    if _child_attestations_are_looped(minimal_valid, _VERIFY_HOWTO_CHILD_ATTESTATIONS) is not None:
        raise AssertionError("verify-doc child-loop self-test: minimal valid fixture rejected")

    spdx_command = child_commands[0]
    moved_outside = minimal_valid.replace(f"  {spdx_command}\n", "", 1).replace(
        "done\n```", f"done\n{spdx_command}\n```", 1
    )
    empty_loop = minimal_valid.replace(f"{loop_body}\n", "", 1).replace(
        "done\n```", f"done\n{'\n'.join(child_commands)}\n```", 1
    )
    cross_fence = minimal_valid.replace(
        child_loop_fence,
        (
            "```sh\n"
            "set -euo pipefail\n"
            'for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do\n'
            "```\n\n"
            "```sh\n"
            f"{loop_body}\n"
            "```\n\n"
            "```sh\n"
            "done\n"
            "```"
        ),
        1,
    )
    no_fail_closed = minimal_valid.replace("set -euo pipefail\n", "", 1)
    late_fail_closed = no_fail_closed.replace("done\n```", "done\nset -euo pipefail\n```", 1)
    no_op_substitution = minimal_valid.replace(
        child_commands[1],
        "printf '%s\\n' --type cyclonedx \"${CHILD_REF}\"",
        1,
    )
    echo_prefixed = minimal_valid.replace(child_commands[1], f"echo {child_commands[1]}", 1)
    commented_only_statement = minimal_valid.replace(loop_body, f"  # {spdx_command}", 1)
    backgrounded = minimal_valid.replace(child_commands[1], f"{child_commands[1]} &", 1)
    backgrounded_then_true = minimal_valid.replace(child_commands[1], f"{child_commands[1]} & true", 1)
    backgrounded_then_colon = minimal_valid.replace(child_commands[1], f"{child_commands[1]} & :", 1)
    one_of_two_spdx_nooped = read("docs/reference/verify.md").replace(
        spdx_command,
        "printf '%s\\n' --type spdxjson \"${CHILD_REF}\"",
        1,
    )
    extra_non_cosign = minimal_valid.replace(f"  {spdx_command}\n", f"  {spdx_command}\n  echo done\n", 1)
    or_true = minimal_valid.replace(child_commands[1], f"{child_commands[1]} || true", 1)
    semicolon_true = minimal_valid.replace(child_commands[1], f"{child_commands[1]}; true", 1)
    colon_prefixed = minimal_valid.replace(child_commands[1], f": {child_commands[1]}", 1)
    mutants = {
        "command-outside-loop": (moved_outside, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "empty-loop": (empty_loop, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "cross-fence": (cross_fence, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "missing-fail-closed": (no_fail_closed, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "late-fail-closed": (late_fail_closed, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "no-op-command-substitution": (no_op_substitution, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "echo-prefixed": (echo_prefixed, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "commented-only-statement": (commented_only_statement, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "backgrounded": (backgrounded, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "backgrounded-then-true": (backgrounded_then_true, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "backgrounded-then-colon": (backgrounded_then_colon, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "one-of-two-spdx-nooped": (one_of_two_spdx_nooped, _VERIFY_DOC_CHILD_ATTESTATIONS),
        "extra-non-cosign-statement": (extra_non_cosign, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "or-true": (or_true, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "semicolon-true": (semicolon_true, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
        "colon-prefixed": (colon_prefixed, _VERIFY_HOWTO_CHILD_ATTESTATIONS),
    }
    for label, (mutant, expected_child_attestations) in mutants.items():
        if _child_attestations_are_looped(mutant, expected_child_attestations) is None:
            raise AssertionError(f"verify-doc child-loop self-test: mutant unexpectedly passed: {label}")


ACCEPTANCE_PUBLICATION_POINTER = (
    "[canonical publication evidence contract]"
    "(../reference/verification-contract.md#image-family-publication-evidence-contract)"
)
REPRODUCIBILITY_PUBLICATION_POINTER = ACCEPTANCE_PUBLICATION_POINTER
CANONICAL_PUBLICATION_HEADING = "## Image family publication evidence contract"


def replace_last(text: str, old: str, new: str) -> str:
    before, separator, after = text.rpartition(old)
    return text if not separator else before + new + after


def image_family_publication_contract_errors(
    acceptance: str,
    reproducibility: str,
    readme: str,
    verification_contract: str,
) -> list[str]:
    errors: list[str] = []

    acceptance_section = markdown_peer_section(acceptance, "## Scope and enforcement boundaries")
    if acceptance_section is None or ACCEPTANCE_PUBLICATION_POINTER not in acceptance_section:
        errors.append("acceptance.md missing canonical publication pointer in scope boundary")

    reproducibility_section = markdown_peer_section(reproducibility, "## Determinism Controls")
    determinism_item = None
    if reproducibility_section is not None:
        item_start = reproducibility_section.find("- The base-micro local, CI, and publish exporter paths")
        if item_start >= 0:
            item_end = reproducibility_section.find("\n- ", item_start + 2)
            determinism_item = reproducibility_section[item_start : item_end if item_end >= 0 else None]
    if determinism_item is None or REPRODUCIBILITY_PUBLICATION_POINTER not in determinism_item:
        errors.append("reproducibility.md missing canonical publication pointer in determinism control")

    readme_section = markdown_peer_section(readme, "## Image Family")
    readme_pointer = PYTHON_PUBLICATION_POINTERS["README.md"][1]
    if readme_section is None or readme_pointer not in readme_section:
        errors.append("README.md missing canonical publication pointer in Image Family")

    canonical_section = markdown_peer_section(verification_contract, CANONICAL_PUBLICATION_HEADING)
    if canonical_section is None:
        errors.append("verification-contract.md missing canonical publication evidence section")
        return errors
    canonical_markers = [
        "Only an `@sha256` image reference is immutable",
        "subject matrix is exact",
        "python-trust-contract/v1",
        ".github/workflows/publish-python.yaml@${PUBLISH_REF}",
        "--source-tag python/v<version>",
        "--source-branch main",
        "--print-provenance",
        "not atomic",
    ]
    errors.extend(
        f"verification-contract.md canonical section missing marker: {marker}"
        for marker in canonical_markers
        if marker not in canonical_section
    )

    python_evidence_record = markdown_peer_section(
        canonical_section,
        "### Verified base-python evidence record",
    )
    if python_evidence_record is None:
        errors.append("verification-contract.md canonical section missing base-python evidence record")
        return errors
    if re.search(r"ghcr\.io/nwarila/ubi9-base-python@sha256:[0-9a-f]{64}", python_evidence_record) is None:
        errors.append("verification-contract.md evidence record missing immutable Python digest")
    if re.search(r"commit `[0-9a-f]{40}`", python_evidence_record) is None:
        errors.append("verification-contract.md Python evidence record missing publishing commit")
    if (
        re.search(
            r"https://github\.com/NWarila/ubi9-base-micro/actions/runs/\d+/(?:attempts/\d+|job/\d+)",
            python_evidence_record,
        )
        is None
    ):
        errors.append("verification-contract.md Python evidence record missing immutable run-attempt or job URL")
    verification_markers = ["For that same digest", "anonymous", "Cosign", "transparency-log", "SLSA", "slsa-verifier"]
    errors.extend(
        f"verification-contract.md Python evidence record missing digest-bound verification: {marker}"
        for marker in verification_markers
        if marker not in python_evidence_record
    )
    if (
        "Alias snapshot" in python_evidence_record
        and re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", python_evidence_record) is None
    ):
        errors.append("verification-contract.md Python alias snapshot missing observation timestamp")

    micro_evidence_record = markdown_peer_section(
        canonical_section,
        "### Verified base-micro evidence record",
    )
    if micro_evidence_record is None:
        errors.append("verification-contract.md canonical section missing base-micro evidence record")
        return errors
    micro_digest_pattern = r"ghcr\.io/nwarila/ubi9-base-micro@sha256:([0-9a-f]{64})"
    micro_digests = set(re.findall(micro_digest_pattern, micro_evidence_record))
    if not micro_digests:
        errors.append("verification-contract.md evidence record missing immutable base-micro digest")
    if len(micro_digests) < 3:
        errors.append("verification-contract.md base-micro evidence record missing exact platform child digests")
    if re.search(r"commit `[0-9a-f]{40}`", micro_evidence_record) is None:
        errors.append("verification-contract.md base-micro evidence record missing publishing commit")
    if (
        re.search(
            r"https://github\.com/NWarila/ubi9-base-micro/actions/runs/\d+/(?:attempts/\d+|job/\d+)",
            micro_evidence_record,
        )
        is None
    ):
        errors.append("verification-contract.md base-micro evidence record missing immutable run-attempt or job URL")
    micro_verification_markers = [
        "For that same index digest",
        "anonymous",
        "Cosign",
        "transparency-log",
        "OpenVEX",
        "CVE-2026-14456",
        "SLSA",
        "slsa-verifier",
    ]
    errors.extend(
        f"verification-contract.md base-micro evidence record missing digest-bound verification: {marker}"
        for marker in micro_verification_markers
        if marker not in micro_evidence_record
    )
    if re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", micro_evidence_record) is None:
        errors.append("verification-contract.md base-micro service observation missing timestamp")
    if (
        "Alias snapshot" in micro_evidence_record
        and re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", micro_evidence_record) is None
    ):
        errors.append("verification-contract.md base-micro alias snapshot missing observation timestamp")
    return errors


def check_docs() -> None:
    for relative_path in [
        "docs/tutorials",
        "docs/how-to",
        "docs/reference",
        "docs/explanation",
        "docs/compliance",
        "docs/decision-records",
    ]:
        require((ROOT / relative_path).is_dir(), f"missing Diataxis docs directory: {relative_path}")

    for relative_path in [
        "docs/compliance/acceptance.md",
        "docs/compliance/fips.md",
        "docs/compliance/nist-800-190.md",
        "docs/compliance/stig.md",
        "docs/compliance/vex.md",
        "docs/explanation/footprint.md",
        "docs/explanation/fips-mechanism.md",
        "docs/explanation/reproducibility.md",
        "docs/how-to/consume-base-micro-as-from-base.md",
        "docs/how-to/refresh-the-rpm-lock.md",
        "docs/how-to/reproduce-a-build-byte-for-byte.md",
        "docs/how-to/run-a-gate-locally.md",
        "docs/how-to/verify-a-published-image.md",
        "docs/reference/gates.md",
        "docs/reference/verification-contract.md",
        "docs/reference/verify.md",
        "docs/tutorials/getting-started-build-and-verify.md",
        "contracts/image-manifest.schema.json",
        "contracts/image-manifest.json",
        "contracts/examples/README.md",
        "contracts/examples/fips-status.amd64.json",
        "contracts/examples/fips-status.arm64.json",
    ]:
        require((ROOT / relative_path).is_file(), f"missing migrated or Diataxis docs file: {relative_path}")

    for relative_path in [
        "docs/acceptance.md",
        "docs/fips.md",
        "docs/footprint.md",
        "docs/nist-800-190.md",
        "docs/reproducibility.md",
        "docs/stig.md",
        "docs/vex.md",
    ]:
        require(not (ROOT / relative_path).exists(), f"flat docs path must stay migrated: {relative_path}")

    readme = read("README.md")
    acceptance = read("docs/compliance/acceptance.md")
    fips = read("docs/compliance/fips.md")
    tech_debt = read("docs/TECH-DEBT.md")
    for debt_id in ("TD-1", "TD-3"):
        require(
            re.search(
                rf"^## {re.escape(debt_id)}(?:\s*:\s*.+)?$",
                tech_debt,
                re.MULTILINE,
            )
            is not None,
            f"docs/TECH-DEBT.md must define ## {debt_id}",
        )
    docs_index = read("docs/README.md")
    verify = read("docs/reference/verify.md")
    adr_0001 = read("docs/decision-records/repo/0001-byte-for-byte-rootfs-reproducibility.md")
    adr_0006 = read("docs/decision-records/repo/0006-rpm-lock-cve-absorption-loop.md")
    adr_0007 = read("docs/decision-records/repo/0007-dual-scanner-openvex-default-deny.md")
    gates = read("docs/reference/gates.md")
    verification_contract = read("docs/reference/verification-contract.md")
    fips_mechanism = read("docs/explanation/fips-mechanism.md")
    vex_doc = read("docs/compliance/vex.md")
    nist_doc = read("docs/compliance/nist-800-190.md")
    nist_generator = read("tools/generate-nist-800-190-predicate.py")
    footprint_doc = read("docs/explanation/footprint.md")
    reproducibility_doc = read("docs/explanation/reproducibility.md")
    stig_doc = read("docs/compliance/stig.md")
    verify_howto = read("docs/how-to/verify-a-published-image.md")
    reproduce_howto = read("docs/how-to/reproduce-a-build-byte-for-byte.md")
    refresh_howto = read("docs/how-to/refresh-the-rpm-lock.md")
    gate_howto = read("docs/how-to/run-a-gate-locally.md")
    consume_howto = read("docs/how-to/consume-base-micro-as-from-base.md")
    tutorial = read("docs/tutorials/getting-started-build-and-verify.md")
    for marker in [
        "The builder is also an image input",
        "images/python/docker-bake.json",
        "independently verified Linux-amd64 release-asset",
        "built-and-gated `base-python` path",
        "non-Python Buildx and BuildKit paths remain",
    ]:
        require(marker in adr_0001, f"ADR-0001 missing Python builder-toolchain decision marker: {marker}")
    for marker in [
        "The Python build path now pins Buildx",
        "Eight non-Python setup sites remain unpinned",
        ".github/workflows/build.yaml",
        "publish-image.yaml",
        "nightly.yaml",
        "rpm-lock-refresh.yaml",
    ]:
        require(marker in tech_debt, f"docs/TECH-DEBT.md TD-5 missing builder-scope marker: {marker}")
    for marker in [
        "`base-python` is a separate pre-publication image path",
        "no publisher",
        "does not pin the micro build path",
        "Pre-publication base-python build identity",
    ]:
        require(marker in acceptance, f"acceptance.md missing pre-publication Python marker: {marker}")
    for marker in [
        "Micro's Buildx and BuildKit remain unpinned",
        "Base-python's `repro` target",
        "shared target owns the graph inputs",
    ]:
        require(marker in reproducibility_doc, f"reproducibility.md missing profile-specific marker: {marker}")
    publication_contract_errors = image_family_publication_contract_errors(
        acceptance,
        reproducibility_doc,
        readme,
        verification_contract,
    )
    require(
        not publication_contract_errors,
        publication_contract_errors[0]
        if publication_contract_errors
        else "Image family publication docs contract failed",
    )
    python_record_gutted = re.sub(
        r"(?ms)^### Verified base-python evidence record[ \t]*$.*?(?=^### Verified base-micro evidence record[ \t]*$)",
        "### Verified base-python evidence record\n\n",
        verification_contract,
        count=1,
    )
    micro_record_gutted = re.sub(
        r"(?ms)^### Verified base-micro evidence record[ \t]*$.*?(?=^### Base-python publication mechanism[ \t]*$)",
        "### Verified base-micro evidence record\n\n",
        verification_contract,
        count=1,
    )
    publication_contract_fixtures = [
        (
            "acceptance pointer",
            acceptance.replace(ACCEPTANCE_PUBLICATION_POINTER, "Publication evidence unavailable", 1),
            reproducibility_doc,
            readme,
            verification_contract,
            "acceptance.md missing canonical publication pointer in scope boundary",
        ),
        (
            "reproducibility pointer",
            acceptance,
            replace_last(
                reproducibility_doc,
                REPRODUCIBILITY_PUBLICATION_POINTER,
                "Publication evidence unavailable",
            ),
            readme,
            verification_contract,
            "reproducibility.md missing canonical publication pointer in determinism control",
        ),
        (
            "README pointer",
            acceptance,
            reproducibility_doc,
            readme.replace(PYTHON_PUBLICATION_POINTERS["README.md"][1], "Publication evidence unavailable", 1),
            verification_contract,
            "README.md missing canonical publication pointer in Image Family",
        ),
        (
            "base-python evidence record",
            acceptance,
            reproducibility_doc,
            readme,
            python_record_gutted,
            "verification-contract.md evidence record missing immutable Python digest",
        ),
        (
            "base-micro evidence record",
            acceptance,
            reproducibility_doc,
            readme,
            micro_record_gutted,
            "verification-contract.md evidence record missing immutable base-micro digest",
        ),
    ]
    for (
        label,
        mutated_acceptance,
        mutated_reproducibility,
        mutated_readme,
        mutated_contract,
        expected,
    ) in publication_contract_fixtures:
        errors = image_family_publication_contract_errors(
            mutated_acceptance,
            mutated_reproducibility,
            mutated_readme,
            mutated_contract,
        )
        require(expected in errors, f"Image family publication docs contract mutation unexpectedly passed: {label}")
        print(f"Image family publication docs contract mutation rejected [{label}] diagnostic={expected}")
    verify_lines = verify.splitlines()
    verify_summary_marker = "gates fixable MEDIUM, HIGH, and CRITICAL findings with both Trivy and Grype"
    require(
        len(verify_lines) >= 3 and verify_summary_marker in verify_lines[2],
        "docs/reference/verify.md line 3 must state the fixable MEDIUM/HIGH/CRITICAL gate",
    )
    cve_heading = "## Vulnerability Policy"
    sbom_heading = "## SBOM Source"
    cve_start = verify.find(cve_heading)
    cve_end = verify.find(sbom_heading, cve_start + len(cve_heading))
    require(cve_start >= 0 and cve_end > cve_start, "docs/reference/verify.md must retain the CVE policy section")
    verify_cve_policy = verify[cve_start:cve_end]
    for marker in [
        "fixable MEDIUM, HIGH, and CRITICAL",
        "--severity MEDIUM,HIGH,CRITICAL",
        "--ignore-unfixed",
        "--exit-code 1",
        "security/cve-ignore.trivyignore.yaml",
        "--only-fixed",
        "--fail-on medium",
        "security/cve-ignore.grype.yaml",
        "TD-6",
        "CVE-2026-31790",
        "`openssl-fips-provider`",
        "`openssl-fips-provider-so`",
        "3.0.7-8.el9",
        "report-only",
        "complete JSON",
        "SARIF",
        "90 days",
    ]:
        require(marker in verify_cve_policy, f"docs/reference/verify.md CVE policy missing marker: {marker}")
    require(
        "The nightly sentinel detects fixable MEDIUM, HIGH, and CRITICAL findings" in adr_0006,
        "ADR-0006 must state that the nightly sentinel detects fixable MEDIUM/HIGH/CRITICAL findings",
    )
    require(
        re.search(r"Fixable MEDIUM, HIGH, and CRITICAL findings still block", adr_0007) is not None,
        "ADR-0007 must state that fixable MEDIUM/HIGH/CRITICAL findings remain blocking",
    )
    require(
        "Fixable MEDIUM, HIGH, and CRITICAL OS/library findings fail closed through both Trivy and Grype." in nist_doc,
        "docs/compliance/nist-800-190.md must state the fixable MEDIUM/HIGH/CRITICAL posture",
    )
    reject_stale_fixable_cve_claims(
        {
            "docs/reference/verify.md": verify,
            "docs/decision-records/repo/0006-rpm-lock-cve-absorption-loop.md": adr_0006,
            "docs/decision-records/repo/0007-dual-scanner-openvex-default-deny.md": adr_0007,
            "docs/compliance/nist-800-190.md": nist_doc,
            "tools/generate-nist-800-190-predicate.py": nist_generator,
        }
    )
    verify_hero_heading = "## Verify From a Clean Machine (No Auth)"
    verify_headings = re.findall(r"^## Verify(?:[ \t]+.*)?$", readme, flags=re.MULTILINE)
    require(
        verify_headings == [verify_hero_heading],
        "README.md must contain exactly one verify section: the clean-machine hero",
    )
    verify_hero_start = readme.index(verify_hero_heading)
    verify_hero_tail = readme[verify_hero_start + len(verify_hero_heading) :]
    verify_hero_end_match = re.search(r"^## ", verify_hero_tail, re.MULTILINE)
    if verify_hero_end_match is None:
        raise VerifyError("README.md verify hero must be followed by another section")
    verify_hero_end = verify_hero_start + len(verify_hero_heading) + verify_hero_end_match.start()
    verify_hero = readme[verify_hero_start:verify_hero_end]
    for marker in [
        "ghcr.io/nwarila/ubi9-base-micro:base-micro",
        'INDEX_DIGEST="$(crane digest "${IMAGE}:${TAG}")"',
        'INDEX_REF="${IMAGE}@${INDEX_DIGEST}"',
        'CHILD_DIGEST="$(crane digest --platform linux/amd64 "${INDEX_REF}")"',
        'CHILD_REF="${IMAGE}@${CHILD_DIGEST}"',
        'cosign verify "${INDEX_REF}"',
        f'cosign verify-attestation --type {predicate_type("spdx")} "${{CHILD_REF}}"',
        f'cosign verify-attestation --type {predicate_type("cyclonedx")} "${{CHILD_REF}}"',
        f'cosign verify-attestation --type {predicate_type("nist_800_190")} "${{CHILD_REF}}"',
        f'cosign verify-attestation --type {predicate_type("stig_arf")} "${{CHILD_REF}}"',
        f'cosign verify-attestation --type {slsa_attestation_type()} "${{INDEX_REF}}"',
        'slsa-verifier verify-image "${INDEX_REF}"',
        "docs/reference/verify.md",
    ]:
        require(marker in verify_hero, f"README.md verify hero missing or misrouting marker: {marker}")
    pipeline_heading = "## Supply Chain Pipeline"
    comparison_heading = "## Comparison at a Glance"
    image_family_heading = "## Image Family"
    require(
        pipeline_heading in readme[verify_hero_end:],
        "README.md supply-chain pipeline heading must follow the verify hero",
    )
    pipeline_start = readme.index(pipeline_heading, verify_hero_end)
    require(
        image_family_heading in readme[pipeline_start:],
        "README.md image-family heading must follow the supply-chain pipeline",
    )
    image_family_start = readme.index(image_family_heading, pipeline_start)
    showcase = readme[pipeline_start:image_family_start]
    require(
        showcase.count("```mermaid") == 1,
        "README.md supply-chain showcase must contain exactly one Mermaid fence",
    )
    for marker in [
        pipeline_heading,
        comparison_heading,
        "`ubi9-base-micro`",
        "Stock `ubi9/ubi-micro`",
        "Chainguard",
        "Canonical rocks",
    ]:
        require(marker in showcase, f"README.md supply-chain showcase missing marker: {marker}")
    for marker in [
        "The published artifact is the `base-micro` runtime image",
        "built for local and pull-request tests but is not published, signed, attested",
        "must push the OCI index before it can export and compare the registry-served child rootfs bytes",
        "cannot retract the pushed manifest or tag update",
        "verifies the Cosign signature on that index",
        "SPDX, CycloneDX, NIST SP 800-190, and tailored STIG ARF on each platform child",
        "`slsa-verifier` result on the index against exact identities",
        "jq -r '.payload | @base64d | fromjson | .predicate.packages[].name'",
        "grep -q glibc",
        "independently for `linux/amd64` and `linux/arm64`",
        "published-child `--expect-from-contract` assertion",
        "no shell or package-manager executable",
        "Fixable vulnerability policy",
        "reject fixable MEDIUM, HIGH, and CRITICAL findings",
        "CVE-2026-31790",
        "`openssl-fips-provider` and `openssl-fips-provider-so`",
        "3.0.7-8.el9",
        "Unfixed vulnerability policy",
        "Unfixed vendor findings never block",
        "Complete findings are retained as JSON and SARIF",
        "distinct code-scanning categories and sealed 90-day raw evidence",
        "Absence-proof OpenVEX",
        "sqlite-libs",
        "util-linux-core",
        "documents do not suppress findings",
        "Scanner database freshness",
        "parseable, schema-compatible, and no older than",
        "rpmdb-derived SPDX and CycloneDX attestations",
        "phantom-package checks corroborate",
        "Rootfs secret exclusion",
        "must pass the secret scan before NIST evidence is generated",
        "Tailored STIG evidence",
        "no unaccounted mass-N/A omissions",
        "NIST SP 800-190 evidence",
        "image evidence, not a CIS Docker host claim",
        "Only `linux/amd64` is within certificate #4857",
        "`linux/arm64` is approved-mode configured and self-test passing",
        "must not exceed 25 MiB (26,214,400 bytes)",
        "No both-architecture footprint ceiling is claimed",
        "Scheduled sentinel capability",
        "It does not publish, prove a historical green streak",
        "../how-to/verify-a-published-image.md",
        "../reference/verify.md",
    ]:
        require(marker in acceptance, f"acceptance.md missing load-bearing marker: {marker}")
    stale_publish_order_phrases = [
        "signs the index first",
        "signature is written before the published-rootfs assertion",
        "cannot retract the already-written signature",
    ]
    stale_publish_order = [marker for marker in stale_publish_order_phrases if marker in acceptance]
    require(
        not stale_publish_order,
        "acceptance.md contains stale publish-order phrase(s): " + ", ".join(stale_publish_order),
    )
    enforced_bypass_marker = _ENFORCEMENT_CLAIM_MARKER
    require(
        enforced_bypass_marker in " ".join(acceptance.split()),
        "acceptance.md must state the active required-check enforcement and always-available admin bypass",
    )
    forbidden = _forbidden_enforcement_claim(acceptance)
    require(
        forbidden is None,
        f"acceptance.md must not reintroduce a false enforcement claim ({forbidden})",
    )
    require(
        "cosign " + "download sbom" not in acceptance,
        "acceptance.md must use verified attestation payloads rather than attached SBOM download",
    )
    require("Byte-for-byte reproducible (HARD gate)" in acceptance, "acceptance.md must carry hard F3 wording")
    require("explicitly retracted" not in acceptance, "acceptance.md must not preserve the old F3 retract escape")
    require("fipsinstall`-generated" not in acceptance, "acceptance.md must not preserve stale fipsinstall mechanism")
    require(f"#{fips_cmvp()}" in fips, "docs/compliance/fips.md must record the OpenSSL CMVP ledger")
    require(
        fips_module_version() in fips,
        "docs/compliance/fips.md must record the validated OpenSSL provider version",
    )
    require(
        fips_module_version() in fips,
        "docs/compliance/fips.md must record the arm64 OpenSSL provider version",
    )
    require(
        fips_provider_nevra() in fips,
        "docs/compliance/fips.md must record the amd64 provider NVR",
    )
    require(
        fips_provider_nevra() in fips,
        "docs/compliance/fips.md must record the arm64 provider NVR",
    )
    require(
        "approved mode" in fips,
        "docs/compliance/fips.md must scope the OpenSSL claim to approved mode",
    )
    require(
        "fips_enabled" in fips and "= 0" in fips,
        "docs/compliance/fips.md must state the non-FIPS-host caveat",
    )
    require(
        "Per-architecture validation scope" in fips,
        "docs/compliance/fips.md must describe per-architecture validation scope",
    )
    require("TD-3" in fips, "docs/compliance/fips.md must reference TD-3")
    require("oe_validated" in fips, "docs/compliance/fips.md must document fips-status.json oe_validated")
    require("provider_nvr" in fips, "docs/compliance/fips.md must document fips-status.json provider_nvr")
    require(
        fips_disclaimer("arm64") in fips,
        "docs/compliance/fips.md missing arm64 disclaimer",
    )
    require(
        "x86_64" in fips and "IBM Z" in fips and "POWER" in fips and "aarch64" in fips,
        "docs/compliance/fips.md must cite tested OE architecture scope",
    )
    require(
        f"certificate/{fips_cmvp()}" in fips and f"140sp{fips_cmvp()}.pdf" in fips,
        "docs/compliance/fips.md must cite NIST sources",
    )

    for marker in [
        "`ubi9-base-micro` is the root image",
        "`base-python`",
        "`base-node`",
        "`base-java`",
        "`FROM base-micro@sha256:<digest>`",
        "cosign keyless",
        "SLSA L3 provenance",
        "SPDX and CycloneDX SBOMs",
        "Grype fixable-CVE gates",
        "complete report-only JSON and SARIF",
        "absence-proof OpenVEX",
        "NIST SP 800-190 section 4.1",
        "image evidence",
        "tailored RHEL9 STIG ARF",
        "byte-for-byte reproducibility",
        "Rekor-logged",
        "Responsibility boundary",
        "standard hardened floor",
        "rpmdb preserved",
        "Java `jdeps`/`jlink`",
        "stdlib pruning",
        "docs/decision-records/repo/",
    ]:
        require(marker in readme, f"README.md missing G1 marker: {marker}")
    for marker in [
        "## Verify base-python",
        "base-python-<first-12-lowercase-hex-of-publishing-sha>",
        ".github/workflows/publish-python.yaml@${PUBLISH_REF}",
        "python-trust-contract/v1",
        "--certificate-github-workflow-sha",
        "--certificate-github-workflow-ref",
        "tools/assert-python-provenance.py",
        "--source-tag",
        "--source-branch main",
    ]:
        require(marker in verify_howto, f"verify-a-published-image.md missing Python publish marker: {marker}")
    for marker in [
        "## TD-10: Base-python create-once alias external-writer race",
        "not an atomic create-once",
    ]:
        require(marker in tech_debt, f"docs/TECH-DEBT.md missing Python publication debt marker: {marker}")

    for marker in [
        f"#{fips_cmvp()}, FIPS 140-3 Level 1 | ACTIVE",
        "base-micro` ships only the OpenSSL provider",
        "Go Cryptographic Module v1.0.0",
        "#5247 ACTIVE",
        "BC-FJA v2.0.0",
        "#4743 ACTIVE",
        "Node.js",
        "No independent CMVP certificate",
        "Out-of-scope certificates",
        "Do not claim these certificates",
        "RHEL 9.0 OpenSSL #4746",
        "BC-FJA 2.1.0 interim #4943",
        "Go module v1.26.0 is Pending Review",
        "module-scoped and approved-mode-scoped",
        "never an OS-scoped, host-scoped, container-scoped",
        "uses a FIPS-validated module in approved mode",
        "fips_enabled = 0",
        "does not run `openssl fipsinstall`",
        "self-verifies when it loads",
    ]:
        require(marker in fips, f"docs/compliance/fips.md missing G2/G2a/G3 marker: {marker}")
    require(
        "tailored RHEL9 STIG ARF gate" in readme and "docs/compliance/stig.md" in readme,
        "README.md must describe current STIG gate scope",
    )
    for marker in [
        "tutorials/",
        "how-to/",
        "reference/",
        "explanation/",
        "compliance/",
        "decision-records/",
        "TECH-DEBT.md",
        "reference/verify.md",
        "reference/gates.md",
        "reference/verification-contract.md",
        "explanation/fips-mechanism.md",
        "compliance/nist-800-190.md",
        "explanation/footprint.md",
        "explanation/reproducibility.md",
        "compliance/stig.md",
        "compliance/vex.md",
        "build-failing hard gate",
    ]:
        require(marker in docs_index, f"docs README must index marker: {marker}")
    for marker in [
        "images/python/vex/sqlite-component-not-present.openvex.json",
        "images/python/vex/cve-2026-53613.openvex.json",
        "sqlite-libs",
        "util-linux",
        "util-linux-core",
        "does not suppress scanner findings",
    ]:
        require(marker in vex_doc, f"docs/compliance/vex.md missing absence-proof marker: {marker}")
    for source, source_text in [
        ("docs/TECH-DEBT.md", tech_debt),
        ("docs/reference/gates.md", gates),
    ]:
        for marker in [
            "CVE-2026-31790",
            "3.0.7-8.el9",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        ]:
            require(marker in source_text, f"{source} missing fixable-CVE policy marker: {marker}")
    for marker in ["report-only", "JSON", "SARIF"]:
        require(marker in gates, f"docs/reference/gates.md missing report-only evidence marker: {marker}")
    for marker in [
        "## TD-6:",
        "CVE-2026-31790",
        "openssl-fips-provider{,-so}",
        "3.0.7-8.el9",
        "CMVP certificate #4857",
        "Any fixable MEDIUM, HIGH, or CRITICAL finding",
        "outside this exception fails the gate",
    ]:
        require(marker in tech_debt, f"docs/TECH-DEBT.md missing TD-6 marker: {marker}")
    for marker in [
        "SOURCE_DATE_EPOCH=1704067200",
        "tools/assert-reproducible.py --assert-byte-identical",
        "--expect-from-contract",
        "rewrite-timestamp=true",
        "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8",
        "emulator-relative",
        "contracts/image-manifest.json",
        "canonical_rootfs_digest",
        "rpmdb_sha256",
        "path|type|mode|uid|gid|uname|gname|mtime|size|linkname|sha256",
        "rpm-lock/",
        "linux/amd64",
        "linux/arm64",
        "SHA256HEADER",
        "SIGMD5",
        "tools/generate-rpm-lock.sh --check",
        ".github/workflows/rpm-lock-refresh.yaml",
        "nightly sentinel detects",
        "Refresh runtime and FIPS RPM lockfiles",
        "rpm-lock/fips-verify.<arch>.txt",
        "unique resolved `openssl-libs` row",
        "direct CDN RPM URLs",
        "rpm -Uvh",
        "Vulnerability Database Freshness",
        "deliberately non-hermetic",
        "DB freshness, not DB pinning",
        "tools/assert-scanner-db-freshness.py",
    ]:
        require(marker in reproducibility_doc, f"docs/explanation/reproducibility.md missing marker: {marker}")
    require(
        "same microdnf installroot" not in reproducibility_doc,
        "reproducibility doc must not preserve pre-direct-CDN refresh wording",
    )
    require(
        "report-mode scope" not in docs_index,
        "docs/README.md must not describe reproducibility as report-mode scope",
    )

    for marker in [
        f"{footprint_limit_bytes() // (1024 * 1024)} * 1024 * 1024 bytes",
        "exported-rootfs-regular-file-bytes",
        "tools/assert-footprint.py",
        "tools/assert-no-phantom-packages.py",
        "raised from 16 MiB to 25 MiB",
        "FIPS library closure",
        "rpmdb",
    ]:
        require(marker in footprint_doc, f"docs/explanation/footprint.md missing marker: {marker}")

    for marker in [
        predicate_type("nist_800_190"),
        "NIST SP 800-190 section 4.1",
        "not CIS Docker",
        "4.1.1",
        "4.1.2",
        "4.1.3",
        "4.1.4",
        "4.1.5",
        "tools/assert-no-rootfs-secrets.py",
        "not a claim of arbitrary antivirus detection",
    ]:
        require(marker in nist_doc, f"docs/compliance/nist-800-190.md missing marker: {marker}")

    for marker in [
        "stig/rhel9-base-micro-tailoring.xml",
        "stig/tailoring-justifications.json",
        predicate_type("stig_arf"),
        "ComplianceAsCode/content",
        "mass-N/A guard",
        "CODEOWNERS-gated",
        "tools/assert-rootfs-identity.py",
        "must-verify selected rule returning `notapplicable`",
        "every `rule-result` as `idref`",
    ]:
        require(marker in stig_doc, f"docs/compliance/stig.md missing marker: {marker}")

    for marker in [
        'cosign verify "${INDEX_REF}"',
        f"cosign verify-attestation --type {predicate_type('spdx')}",
        f"cosign verify-attestation --type {predicate_type('cyclonedx')}",
        f"cosign verify-attestation --type {predicate_type('nist_800_190')}",
        f"cosign verify-attestation --type {predicate_type('stig_arf')}",
        "full attestation set is Rekor-logged",
        "tools/assert-cosign-rekor.py",
        "signature JSON",
        "DSSE envelopes",
        "tools/assert-slsa-builder-id.py",
        "@base64d",
        "grep -q glibc",
        "Trivy",
        "Grype",
        "tools/assert-scanner-db-freshness.py",
        "complete JSON and SARIF",
        "Unfixed findings do not fail",
        f"cosign verify-attestation --type {slsa_attestation_type()}",
        "STIG ARF",
        "OpenSCAP",
        "per-rule `idref` result",
        "rootfs identity assertion report",
        "slsa-verifier verify-image",
        slsa_builder_id().removeprefix("https://github.com/"),
        "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a",
        "gh attestation verify` is not part of this contract",
        "BuildKit SBOM generation is disabled",
        "Syft rpmdb-derived",
    ]:
        require(marker in verify, f"docs/reference/verify.md missing marker: {marker}")

    verify_child_loop_failure = _child_attestations_are_looped(verify, _VERIFY_DOC_CHILD_ATTESTATIONS)
    require(
        verify_child_loop_failure is None,
        f"docs/reference/verify.md child attestation routing is not fail-closed: {verify_child_loop_failure}",
    )
    howto_child_loop_failure = _child_attestations_are_looped(verify_howto, _VERIFY_HOWTO_CHILD_ATTESTATIONS)
    require(
        howto_child_loop_failure is None,
        "docs/how-to/verify-a-published-image.md child attestation routing is not fail-closed: "
        f"{howto_child_loop_failure}",
    )
    for residue in ["P1.8", "one-time owner visibility change"]:
        require(residue not in verify, f"docs/reference/verify.md retains false anonymous-pull residue: {residue}")

    for marker in [
        "tools/assert-reproducible.py",
        "tools/assert-rpm-lock-hashes.py",
        "tools/assert-scanner-db-freshness.py",
        "tools/assert-scanner-canary.py",
        "tools/assert-no-rootfs-secrets.py",
        "tools/assert-stig-arf.py",
        "tools/generate-stig-arf-predicate.py",
        "fail-closed",
    ]:
        require(marker in gates, f"docs/reference/gates.md missing marker: {marker}")

    for marker in [
        "Pull request",
        "Publish",
        "Post-publish audit",
        "slsa-verifier",
        "gh attestation verify",
    ]:
        require(marker in verification_contract, f"docs/reference/verification-contract.md missing marker: {marker}")

    for marker in [
        "config-only approved-mode mechanism",
        fips_provider_nevra(),
        fips_module_version(),
        "linux/amd64",
        "linux/arm64",
        f"CMVP #{fips_cmvp()}",
        "not a CMVP-validated operational environment",
        "fips_enabled =",
    ]:
        require(marker in fips_mechanism, f"docs/explanation/fips-mechanism.md missing marker: {marker}")

    for marker in [
        "cosign verify",
        f"cosign verify-attestation --type {predicate_type('spdx')}",
        "slsa-verifier verify-image",
        "Do not substitute `gh attestation verify`",
    ]:
        require(marker in verify_howto, f"verify how-to missing marker: {marker}")
    require(
        "--assert-byte-identical" in reproduce_howto and "linux/arm64" in reproduce_howto,
        "reproduce how-to must cover both-arch byte identity",
    )
    require(
        "tools/generate-rpm-lock.sh --check" in refresh_howto and "rpm -Uvh" in refresh_howto,
        "RPM-lock how-to must cover controlled direct-RPM refresh",
    )
    require(
        "python tools/verify.py" in gate_howto
        and "bash tools/run-test-gates.sh" in gate_howto
        and "Cosign v2.5.2" in gate_howto
        and "required local prerequisite" in gate_howto,
        "local gate how-to must cover the verifier, full gate harness, and pinned Cosign prerequisite",
    )
    require(
        "FROM ghcr.io/nwarila/ubi9-base-micro@sha256:<digest>" in consume_howto,
        "FROM-base how-to must require digest pinning",
    )
    require(
        "make build" in tutorial and "python tools/verify.py" in tutorial, "tutorial must walk through build and verify"
    )


def check_lint_setup() -> None:
    gitignore = read(".gitignore")
    for relative_path in LINT_CONFIG_FILES:
        require((ROOT / relative_path).is_file(), f"missing lint path: {relative_path}")
        require(f"!/{relative_path}" in gitignore, f".gitignore must allowlist lint path: {relative_path}")

    shellcheck = read(".shellcheckrc")
    for marker in ["shell=bash", "external-sources=true", "source-path=SCRIPTDIR", "enable=all"]:
        require(marker in shellcheck, f".shellcheckrc missing marker: {marker}")
    require("disable=" not in shellcheck, ".shellcheckrc must not carry broad ShellCheck disables")

    pyproject = read("pyproject.toml")
    for marker in [
        "[tool.ruff]",
        'target-version = "py312"',
        "line-length = 120",
        "[tool.ruff.lint]",
        "[tool.ruff.format]",
        "[tool.mypy]",
        'python_version = "3.12"',
        "strict = true",
        "warn_unused_ignores = true",
        "warn_redundant_casts = true",
        "warn_unreachable = true",
    ]:
        require(marker in pyproject, f"pyproject.toml missing lint marker: {marker}")
    require("ignore = [" not in pyproject, "ruff config must not blanket-ignore selected rules")

    yamllint = read(".yamllint")
    for marker in [
        "extends: default",
        "document-start:",
        "present: false",
        "max: 160",
        'allowed-values: ["true", "false", "on"]',
    ]:
        require(marker in yamllint, f".yamllint missing marker: {marker}")

    hadolint = read(".hadolint.yaml")
    for marker in [
        "failure-threshold: info",
        "trustedRegistries:",
        "registry.access.redhat.com",
        "ghcr.io",
    ]:
        require(marker in hadolint, f".hadolint.yaml missing marker: {marker}")
    require("ignored:" not in hadolint, ".hadolint.yaml must not ignore hadolint rules")

    precommit = read(".pre-commit-config.yaml")
    minimum_version_match = re.search(
        r'^minimum_pre_commit_version:\s+"([^"\s]+)"\s*$',
        precommit,
        flags=re.MULTILINE,
    )
    if minimum_version_match is None:
        raise VerifyError(".pre-commit-config.yaml must pin minimum_pre_commit_version")
    require_version_literal(minimum_version_match.group(1), "minimum_pre_commit_version")
    hook_repositories = [
        "https://github.com/shellcheck-py/shellcheck-py",
        "https://github.com/scop/pre-commit-shfmt",
        "https://github.com/astral-sh/ruff-pre-commit",
        "https://github.com/pre-commit/mirrors-mypy",
        "https://github.com/adrienverge/yamllint",
        "https://github.com/DavidAnson/markdownlint-cli2",
        "https://github.com/hadolint/hadolint",
        "https://github.com/rhysd/actionlint",
    ]
    for repository in hook_repositories:
        require_precommit_hook_pin(precommit, repository)
    require_hadolint_image_digest(precommit)
    for marker in [
        "default_language_version:",
        "python: python3",
        "repo: https://github.com/shellcheck-py/shellcheck-py",
        "id: shellcheck",
        "args: [--severity=style]",
        "repo: https://github.com/scop/pre-commit-shfmt",
        "id: shfmt",
        'args: [-w, -i, "2", -ci, -sr, -bn]',
        "repo: https://github.com/astral-sh/ruff-pre-commit",
        "id: ruff",
        "args: [--fix]",
        "id: ruff-format",
        "repo: https://github.com/pre-commit/mirrors-mypy",
        "id: mypy",
        "pass_filenames: false",
        "args: [--config-file=pyproject.toml, tools]",
        "additional_dependencies: [pytest==8.4.1]",
        "repo: https://github.com/adrienverge/yamllint",
        "id: yamllint",
        "args: [--strict, -c, .yamllint]",
        "repo: https://github.com/DavidAnson/markdownlint-cli2",
        "id: markdownlint-cli2",
        "files: ^.*\\.md$",
        "repo: https://github.com/hadolint/hadolint",
        "id: hadolint-docker",
        "args: [--config, .hadolint.yaml]",
        "repo: https://github.com/rhysd/actionlint",
        "id: actionlint",
        "repo: local",
        "id: rpmlock-pytest",
        "name: rpmlock pytest",
        "entry: python -m pytest tools/tests/test_rpmlock.py -q",
        "id: build-runtime-rootfs-pytest",
        "name: build runtime rootfs pytest",
        "entry: python -m pytest tools/tests/test_build_runtime_rootfs.py -q",
        "id: write-fips-status-pytest",
        "name: write FIPS status pytest",
        "entry: python -m pytest tools/tests/test_write_fips_status.py -q",
        "id: verify-fips-provider-pytest",
        "name: verify FIPS provider pytest",
        "entry: python -m pytest tools/tests/test_verify_fips_provider.py -q",
        "id: assert-rpm-lock-hashes-pytest",
        "name: assert RPM lock hashes pytest",
        "entry: python -m pytest tools/tests/test_assert_rpm_lock_hashes.py -q",
        "id: generate-runtime-lock-pytest",
        "name: generate runtime lock pytest",
        "entry: python -m pytest tools/tests/test_generate_runtime_lock.py -q",
        "id: decision-surface-pytest",
        "name: decision surface pytest",
        (
            "entry: python -m pytest tools/tests/test_summarize_gates.py tools/tests/test_render_pr_decision.py "
            "tools/tests/test_render_drift_issue.py -q"
        ),
        "language: python",
        "always_run: true",
    ]:
        require(marker in precommit, f".pre-commit-config.yaml missing marker: {marker}")
    require(precommit.count("repo: local") == 1, ".pre-commit-config.yaml must carry exactly one local hook block")
    require(
        precommit.count("pass_filenames: false") == 9,
        ".pre-commit-config.yaml must keep exactly two mypy and seven pytest hooks filename-independent",
    )
    status_hook = precommit.split("- id: write-fips-status-pytest", 1)[1]
    for marker in [
        "name: write FIPS status pytest",
        "entry: python -m pytest tools/tests/test_write_fips_status.py -q",
        "language: python",
        "additional_dependencies: [pytest==8.4.1]",
        "pass_filenames: false",
        "always_run: true",
        (
            "files: ^(tools/write-fips-status\\.py|tools/tests/test_write_fips_status\\.py|"
            "contracts/(image-manifest\\.json|examples/fips-status\\.(amd64|arm64)\\.json))$"
        ),
    ]:
        require(marker in status_hook, f"FIPS status pytest hook missing locked marker: {marker}")

    verifier_hook = precommit.split("- id: verify-fips-provider-pytest", 1)[1]
    for marker in [
        "name: verify FIPS provider pytest",
        "entry: python -m pytest tools/tests/test_verify_fips_provider.py -q",
        "language: python",
        "additional_dependencies: [pytest==8.4.1]",
        "pass_filenames: false",
        "always_run: true",
        ("files: ^(tools/verify-fips-provider\\.py|tools/tests/test_verify_fips_provider\\.py|containers/Dockerfile)$"),
    ]:
        require(marker in verifier_hook, f"FIPS provider pytest hook missing locked marker: {marker}")

    rpm_hash_hook = precommit.split("- id: assert-rpm-lock-hashes-pytest", 1)[1]
    for marker in [
        "name: assert RPM lock hashes pytest",
        "entry: python -m pytest tools/tests/test_assert_rpm_lock_hashes.py -q",
        "language: python",
        "additional_dependencies: [pytest==8.4.1]",
        "pass_filenames: false",
        "always_run: true",
        (
            "files: ^(tools/assert-rpm-lock-hashes\\.py|tools/rpmlock\\.py|"
            "tools/tests/test_assert_rpm_lock_hashes\\.py)$"
        ),
    ]:
        require(marker in rpm_hash_hook, f"RPM lock hash pytest hook missing locked marker: {marker}")

    generator_hook = precommit.split("- id: generate-runtime-lock-pytest", 1)[1]
    for marker in [
        "name: generate runtime lock pytest",
        "entry: python -m pytest tools/tests/test_generate_runtime_lock.py -q",
        "language: python",
        "additional_dependencies: [pytest==8.4.1]",
        "pass_filenames: false",
        "always_run: true",
        ("files: ^(tools/generate-runtime-lock\\.py|tools/rpmlock\\.py|tools/tests/test_generate_runtime_lock\\.py)$"),
    ]:
        require(marker in generator_hook, f"runtime lock generator pytest hook missing locked marker: {marker}")

    decision_hook = precommit.split("- id: decision-surface-pytest", 1)[1]
    for marker in [
        "name: decision surface pytest",
        (
            "entry: python -m pytest tools/tests/test_summarize_gates.py tools/tests/test_render_pr_decision.py "
            "tools/tests/test_render_drift_issue.py -q"
        ),
        "language: python",
        "additional_dependencies: [pytest==8.4.1]",
        "pass_filenames: false",
        "always_run: true",
        (
            "files: ^(tools/(summarize-gates|render-pr-decision|render-drift-issue)\\.py|"
            "tools/tests/test_(summarize_gates|render_pr_decision|render_drift_issue)\\.py)$"
        ),
    ]:
        require(marker in decision_hook, f"decision surface pytest hook missing locked marker: {marker}")

    lint = read(".github/workflows/lint.yaml")
    require_action_sha_pin(lint, "lint workflow", HARDEN_RUNNER, count=1)
    require_action_sha_pin(lint, "lint workflow", "actions/checkout", count=1)
    precommit_install_matches = re.findall(r"\bpre-commit==([^\s]+)", lint)
    require(len(precommit_install_matches) == 1, "lint workflow must contain exactly one pinned pre-commit install")
    require_version_literal(precommit_install_matches[0], "lint workflow pre-commit install")
    for marker in [
        "name: Lint",
        "pull_request:\n    branches: [main]",
        "push:\n    branches: [main]",
        "workflow_dispatch:",
        "permissions: {}",
        "permissions:\n      contents: read",
        "runs-on: ubuntu-24.04",
        "egress-policy: audit",
        "pre-commit run --all-files --show-diff-on-failure",
    ]:
        require(marker in lint, f"lint workflow missing marker: {marker}")
    for forbidden in ["id-token:", "packages:", "pull-requests:", "security-events:", "continue-on-" + "error"]:
        require(forbidden not in lint, f"lint workflow has non-minimal or soft-fail marker: {forbidden}")


def check_no_attribution_residue() -> None:
    fragments = [
        "[" + "cod" + "ex" + "]",
        "[" + "cla" + "ude" + "]",
        "co-" + "authored" + "-by",
        "generated" + " with",
    ]
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        if path.suffix.lower() not in {
            ".cnf",
            ".json",
            ".md",
            ".py",
            ".sh",
            ".xml",
            ".yaml",
            ".yml",
            ".dockerignore",
            ".gitignore",
            "",
        }:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        for fragment in fragments:
            if fragment in text:
                findings.append(str(path.relative_to(ROOT)))
                break
    require(not findings, "attribution residue found in: " + ", ".join(sorted(findings)))


INTERNAL_PROCESS_RESIDUE_PATTERNS = [
    ("ledger label", re.compile(r"\bP\d+\.\d+[a-z]?\b", re.IGNORECASE)),
    ("numbered work label", re.compile(r"\bSTEP\d{3}\b", re.IGNORECASE)),
    ("internal directive", re.compile(r"\bMANDATE\b", re.IGNORECASE)),
    ("ratification label", re.compile(r"\bowner-ratified\b", re.IGNORECASE)),
    ("revision label", re.compile(r"\brev\.\s*b\b", re.IGNORECASE)),
    ("internal namespace", re.compile(r"\bnwarila-platform\b", re.IGNORECASE)),
    ("fleet-size label", re.compile(r"\b8\s+images\b", re.IGNORECASE)),
]


def collect_internal_process_docs(root: Path = ROOT) -> list[tuple[str, str]]:
    readme = root / "README.md"
    docs_dir = root / "docs"
    images_dir = root / "images"
    require(readme.is_file(), "missing public README.md for internal-process residue scan")
    require(docs_dir.is_dir(), "missing docs directory for internal-process residue scan")
    paths = [readme, *sorted(docs_dir.rglob("*.md"))]
    if images_dir.is_dir():
        paths.extend(sorted(images_dir.rglob("*.md")))
    return [(str(path.relative_to(root)), path.read_text(encoding="utf-8")) for path in paths]


def find_internal_process_residue(sources: list[tuple[str, str]]) -> list[str]:
    findings: list[str] = []
    for relative_path, text in sources:
        for line_number, line in enumerate(text.splitlines(), start=1):
            for label, pattern in INTERNAL_PROCESS_RESIDUE_PATTERNS:
                if pattern.search(line):
                    findings.append(f"{relative_path}:{line_number}: {label}")
    return findings


def assert_no_internal_process_residue(sources: list[tuple[str, str]]) -> None:
    findings = find_internal_process_residue(sources)
    require(not findings, "internal-process residue found in: " + "; ".join(findings))


def check_internal_process_residue_self_test() -> None:
    positive_fixtures = [
        ("ledger label", "P1.5a"),
        ("numbered work label", "step024"),
        ("internal directive", "MANDATE"),
        ("ratification label", "OWNER-RATIFIED"),
        ("revision label", "Rev.   B"),
        ("internal namespace", "NWarila-Platform"),
        ("fleet-size label", "8 Images"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        nested_docs = root / "docs/nested"
        nested_docs.mkdir(parents=True)
        images_docs = root / "images"
        images_docs.mkdir()
        (root / "README.md").write_text(
            "\n".join(fixture for _, fixture in positive_fixtures[:4]) + "\n",
            encoding="utf-8",
        )
        (nested_docs / "fixture.md").write_text(
            "\n".join(fixture for _, fixture in positive_fixtures[4:6]) + "\n",
            encoding="utf-8",
        )
        (images_docs / "fixture.md").write_text(
            "\n".join(fixture for _, fixture in positive_fixtures[6:]) + "\n",
            encoding="utf-8",
        )
        (root / "outside.md").write_text("P9.9 STEP999 MANDATE\n", encoding="utf-8")
        positive_findings = find_internal_process_residue(collect_internal_process_docs(root))
        positive_labels = {finding.rsplit(": ", 1)[1] for finding in positive_findings}
        require(
            len(positive_findings) == len(INTERNAL_PROCESS_RESIDUE_PATTERNS)
            and positive_labels == {label for label, _ in INTERNAL_PROCESS_RESIDUE_PATTERNS},
            "internal-process residue self-test must detect every pattern across README.md, nested docs, and images",
        )

        rejected = 0
        for label, fixture in positive_fixtures:
            try:
                assert_no_internal_process_residue([("README.md", fixture)])
            except VerifyError as exc:
                require(label in str(exc), f"internal-process residue mutation must report {label}")
                rejected += 1
            else:
                raise VerifyError(f"internal-process residue mutation unexpectedly passed: {label}")

        (root / "README.md").write_text(
            "This behavior is mandated. Complete the next step carefully.\n"
            "This is revision b, while the unrelated abbreviated revision is rev. c.\n"
            "XP1.5a P1.5aa XSTEP001 STEP001x preowner-ratified owner-ratifieds\n",
            encoding="utf-8",
        )
        (nested_docs / "fixture.md").write_text(
            "preview. b xnwarila-platform nwarila-platformx\n",
            encoding="utf-8",
        )
        (images_docs / "fixture.md").write_text(
            "18 images 8 imageset\n",
            encoding="utf-8",
        )
        negative_findings = find_internal_process_residue(collect_internal_process_docs(root))
        require(
            not negative_findings,
            "internal-process residue self-test must accept boundary and prose near misses",
        )
        print(
            f"Internal-process residue mutation probes: {rejected}/{len(positive_fixtures)} rejected; "
            "near-miss fixtures accepted"
        )


def check_no_internal_process_residue() -> None:
    check_internal_process_residue_self_test()
    assert_no_internal_process_residue(collect_internal_process_docs())


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["--check-python-builder-identity"]:
        return check_python_builder_identity_environment()
    if len(arguments) == 2 and arguments[0] == "--check-python-preflight-semantic-fixture":
        try:
            check_python_ci_preflight_semantic_self_test(arguments[1])
        except VerifyError as exc:
            print(f"verify failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if arguments == ["--check-python-ci-surface-lock-fixtures"]:
        try:
            check_python_ci_surface_lock_self_test()
        except VerifyError as exc:
            print(f"verify failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if len(arguments) == 2 and arguments[0] == "--check-python-release-bake-fixture":
        try:
            check_python_release_bake_self_test(arguments[1])
        except VerifyError as exc:
            print(f"verify failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if len(arguments) == 2 and arguments[0] == "--check-publish-python-workflow-fixture":
        try:
            check_publish_python_workflow_self_test(arguments[1])
        except VerifyError as exc:
            print(f"verify failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if arguments == ["--check-publish-python-surface-lock-fixtures"]:
        try:
            check_publish_python_surface_lock_self_test()
        except VerifyError as exc:
            print(f"verify failed: {exc}", file=sys.stderr)
            return 1
        return 0
    if arguments:
        print(f"verify failed: unsupported arguments: {' '.join(arguments)}", file=sys.stderr)
        return 2
    checks = [
        check_required_files,
        check_gitattributes_archive_visibility,
        check_image_contract_files,
        check_community_profile,
        check_python_publication_docs_self_test,
        check_renovate_config,
        check_python_build_input_contract,
        check_python_build_input_contract_self_test,
        check_python_release_bake_self_test,
        check_python_release_bake_checker_mutation_self_test,
        check_ubi_digest_equality,
        check_ubi_digest_equality_self_test,
        check_binfmt_digest_equality,
        check_binfmt_digest_equality_self_test,
        check_pin_invariant_self_test,
        check_nightly_drift_signature_self_test,
        check_acceptance_enforcement_claim_self_test,
        check_verify_docs_child_loop_self_test,
        check_dockerfile,
        check_python_trim_policy,
        check_rpm_lock_generator,
        check_dockerfile_forbidden_scan_self_test,
        check_builder_toolchain_floor_self_test,
        check_rpm_locks,
        check_workflow,
        check_supply_chain_workflows,
        check_lint_setup,
        check_publish_workflow,
        check_publish_scope_gate,
        check_publish_scope_gate_self_test,
        check_python_ci_preflight,
        check_python_ci_preflight_semantic_self_test,
        check_python_ci_preflight_checker_mutation_self_test,
        check_python_ci_surface_lock_self_test,
        check_python_ci_surface_lock_checker_mutation_self_test,
        check_publish_python_workflow,
        check_publish_python_workflow_self_test,
        check_publish_python_workflow_checker_mutation_self_test,
        check_publish_python_surface_lock_self_test,
        check_publish_python_surface_lock_checker_mutation_self_test,
        check_python_evidence,
        check_python_evidence_self_test,
        check_python_sqlite_vex,
        check_python_contract_schema,
        check_python_contract_schema_self_test,
        check_build_script,
        check_bounded_post_build_gates,
        check_hardening_script,
        check_sbom_assertion_script,
        check_scanner_install_scripts,
        check_scanner_content_canary,
        check_cve_ignore_policy,
        check_fips_config,
        check_fips_script,
        check_vex,
        check_nist_800_190_scripts,
        check_stig,
        check_decision_records,
        check_stale_fixable_cve_claims_self_test,
        check_docs,
        check_helper_self_tests,
        check_no_attribution_residue,
        check_no_internal_process_residue,
    ]
    try:
        for check in checks:
            check()
            print(f"{check.__name__}: ok")
    except VerifyError as exc:
        print(f"verify failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
