#!/usr/bin/env python3
# Purpose: Repository contract checks (pinned SHAs/tags, FIPS RPM digests, required files/ADRs) for ubi9-base-micro
# Role: governance
# Micro-container candidate: no - repo-tree-coupled contract verifier (run via `make verify`), validates the repo, not
# an image

"""Repository contract checks for ubi9-base-micro."""

from __future__ import annotations

import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Mapping
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
        "docs/decision-records/repo/0010-base-image-polyrepo-topology.md",
        "Keep The Base-Image Family As Polyrepos Rooted At Base Micro",
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


def check_required_files() -> None:
    for relative_path in [
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
        "tools/generate-rpm-lock.sh",
        "tools/install-syft.sh",
        "tools/install-trivy.sh",
        "tools/install-grype.sh",
        "tools/install-crane.sh",
        "tools/assert-ignore-scope.py",
        "tools/assert-scanner-db-freshness.py",
        "tools/assert-scanner-canary.py",
        "tools/assert-sbom-rpms.py",
        "tools/assert-vex.py",
        "tools/assert-no-rootfs-secrets.py",
        "tools/generate-nist-800-190-predicate.py",
        "tools/assert-cosign-rekor.py",
        "tools/assert-slsa-builder-id.py",
        "tools/assert-stig-tailoring.py",
        "tools/assert-rootfs-identity.py",
        "tools/assert-stig-arf.py",
        "tools/generate-stig-arf-predicate.py",
        "tools/install-openscap.sh",
        "tools/build-stig-datastream.sh",
        "tools/run-stig-arf.sh",
        "tools/verify.py",
        "stig/rhel9-base-micro-tailoring.xml",
        "stig/tailoring-justifications.json",
        "vex/.gitkeep",
        "vex/cve-2026-31790.openvex.json",
        "vex/README.md",
        "tests/fixtures/scanner-canary/log4shell.cdx.json",
    ]:
        require((ROOT / relative_path).is_file(), f"missing required file: {relative_path}")
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
        "planned `base-python`, `base-node`, or `base-java`",
    ]:
        require(marker in support, f"SUPPORT.md missing marker: {marker}")

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

    if action_pin_rule_index is None:
        raise VerifyError("Renovate config must keep ordinary GitHub Actions SHA-pinned")
    if generator_rule_index is None:
        raise VerifyError("Renovate config must carry the TD-1 SLSA generator tag-pin rule")
    require(
        generator_rule_index > action_pin_rule_index,
        "TD-1 generator rule must follow the general GitHub Actions pin rule so it overrides it",
    )
    require(ubi_rule_found, "Renovate config must group UBI minimal and micro digest refreshes")


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

    if "write_capture_dockerfile() {" not in text or "\nvalidate_lockfile()" not in text:
        return ["RPM lock generator capture function boundaries are missing"]
    capture = text.split("write_capture_dockerfile() {", 1)[1].split("\nvalidate_lockfile()", 1)[0]
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

    for marker in [
        pre_strip_snapshot,
        strip_invocation,
        post_strip_snapshot,
        floor_invocation,
        render_invocation,
    ]:
        expect(marker in capture, f"RPM lock generator missing capture-stage marker: {marker}")
    expect(text.count(strip_invocation) == 1, "RPM lock generator must invoke strip-packages exactly once")

    ordering_markers = [pre_strip_snapshot, strip_invocation, post_strip_snapshot, floor_invocation, render_invocation]
    if all(marker in capture for marker in ordering_markers):
        expect(
            capture.index(pre_strip_snapshot)
            < capture.index(strip_invocation)
            < capture.index(post_strip_snapshot)
            < capture.index(floor_invocation)
            < capture.index(render_invocation),
            "RPM lock generator must preserve pre-snapshot, strip, post-snapshot, floor, render ordering",
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
        "python3.12 /tmp/generate-runtime-lock.py signature-output --output /tmp/runtime.signature-output",
        "curl -fL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2",
        'actual_sha="$(sha256sum "${tmp}" | awk \'{print $1}\')"',
        'rpm -K "${path}" | tee /tmp/runtime.signature-output',
    ]:
        expect(marker in capture, f"RPM lock generator missing fail-closed helper/orchestration marker: {marker}")

    return errors


def _move_after(text: str, moved: str, anchor: str) -> str:
    without = text.replace(moved, "", 1)
    return without.replace(anchor, f"{anchor}\n{moved}", 1)


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
    mutations: list[tuple[str, str]] = [
        ("delete pre-strip snapshot", text.replace(pre_snapshot, "", 1)),
        ("move pre-strip snapshot below strip", _move_after(text, pre_snapshot, strip)),
        ("delete post-strip snapshot", text.replace(post_snapshot, "", 1)),
        ("move post-strip snapshot above strip", _move_after(text, post_snapshot, pre_snapshot)),
        ("move rendering above post-strip snapshot", _move_after(text, render, strip)),
        (
            "swap render full/final input",
            text.replace("--full-rows /tmp/runtime.full.tsv", "--full-rows /tmp/runtime.final.nevras", 2),
        ),
        ("remove render direct input", text.replace("  --direct-results /tmp/runtime.direct.tsv \\\n", "", 1)),
        (
            "weaken signature checker",
            text.replace(
                "python3.12 /tmp/generate-runtime-lock.py signature-output --output /tmp/runtime.signature-output",
                "true",
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
    fips_runtime_fetch = "bash /tmp/fetch-runtime-rpms.sh"
    fips_microdnf_install = "microdnf install -y --releasever=9"
    fips_provider_install = '"/tmp/runtime-rpms/openssl-fips-provider-${fips_provider_nvr}.${rpm_arch}.rpm"'
    fips_microdnf_clean = "microdnf clean all"
    fips_verifier_invocation = "python3.12 /tmp/verify-fips-provider.py"
    for marker in [
        "COPY rpm-lock/builder.amd64.txt rpm-lock/builder.arm64.txt /tmp/rpm-lock/",
        "COPY tools/fetch-builder-rpms.sh /tmp/fetch-builder-rpms.sh",
        "COPY tools/verify-fips-provider.py /tmp/verify-fips-provider.py",
        "# The builder loop below bootstraps python, so it cannot use rpmlock.py (ADR-0014).",
        fips_bootstrap_array,
        fips_bootstrap_count,
        fips_builder_fetch,
        fips_builder_install,
        fips_python_sanity,
        fips_builder_cleanup,
        fips_runtime_fetch,
        fips_microdnf_install,
        fips_provider_install,
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
        require(marker in fips_verify, f"fips-verify stage missing locked orchestration marker: {marker}")
    require(
        fips_verify.index(fips_bootstrap_array)
        < fips_verify.index(fips_bootstrap_count)
        < fips_verify.index(fips_builder_fetch)
        < fips_verify.index(fips_builder_install)
        < fips_verify.index(fips_python_sanity)
        < fips_verify.index(fips_builder_cleanup)
        < fips_verify.index(fips_runtime_fetch)
        < fips_verify.index(fips_microdnf_install)
        < fips_verify.index(fips_provider_install)
        < fips_verify.index(fips_microdnf_clean)
        < fips_verify.index(fips_verifier_invocation),
        "fips-verify must install builder Python first, retain provider orchestration, then invoke the verifier",
    )
    require(
        fips_verify.count(fips_verifier_invocation) == 1,
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
        require(marker not in fips_verify, f"fips-verify retains extracted inline verification marker: {marker}")
    require(
        re.search(r">{1,2}\s*/fips-proof/[^\s;\\]+", fips_verify) is None,
        "fips-verify must not redirect to individual proof files",
    )

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
        "git diff --quiet -- rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt",
        "git diff -- rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt",
        "RPM lockfiles already match the current UBI repositories.",
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
                "            git diff -- rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt\n",
                "",
                1,
            ),
        ),
        ("remove non-zero exit", text.replace("            exit 1\n", "", 1)),
    ]
    for label, mutated in mutations:
        require(rpm_lock_refresh_errors(mutated), f"RPM lock refresh mutation was not rejected: {label}")
    print(f"RPM lock refresh mutation probes: {len(mutations)}/{len(mutations)} rejected")


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
            "rpm-lock-refresh.yaml",
            "scorecard.yml",
            "zizmor.yml",
        ],
        "repo must ship exactly the expected baseline and supply-chain workflows",
    )

    build = read(".github/workflows/build.yaml")
    nightly = read(".github/workflows/nightly.yaml")
    refresh = read(".github/workflows/rpm-lock-refresh.yaml")
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
        "tools/assert-vex.py --self-test",
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
        "docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130",
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
        "docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130",
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
        "git diff --quiet -- rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt",
        "github-actions[bot]",
        "gh pr list",
        "gh pr create",
        "--base main",
        '--head "${branch}"',
        "Refresh runtime RPM lockfiles",
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
        "tools/assert-ignore-scope.py",
        "dist/tools/trivy image",
        "--ignore-unfixed",
        "--severity MEDIUM,HIGH,CRITICAL",
        "--ignorefile security/cve-ignore.trivyignore.yaml",
        "--exit-code 1",
        "--only-fixed",
        "--fail-on medium",
        "-c security/cve-ignore.grype.yaml",
        "--show-suppressed",
        '--grype-report "${grype_gate_json}"',
        "--format json",
        '--file "${grype_json}"',
        "tools/assert-vex.py",
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
    ignore_scope_index = gate_runner.find("python tools/assert-ignore-scope.py")
    first_trivy_scan_index = gate_runner.find("--ignore-unfixed")
    first_grype_scan_index = gate_runner.find("--only-fixed")
    require(freshness_index >= 0, "test gate runner must invoke scanner DB freshness gate")
    require(ignore_scope_index >= 0, "test gate runner must invoke fixable-CVE ignore scope gate")
    require(first_trivy_scan_index >= 0, "test gate runner must keep Trivy fixable scan")
    require(first_grype_scan_index >= 0, "test gate runner must keep Grype fixable scan")
    require(
        freshness_index < first_trivy_scan_index and freshness_index < first_grype_scan_index,
        "scanner DB freshness gate must run before vulnerability scans",
    )
    require(
        ignore_scope_index < first_trivy_scan_index and ignore_scope_index < first_grype_scan_index,
        "fixable-CVE ignore scope gate must run before vulnerability scans",
    )

    report_start = gate_runner.find('trivy_json="dist/vuln/base-micro.${arch}.trivy.all.json"')
    vex_start = gate_runner.find("python tools/assert-vex.py")
    require(
        report_start >= 0 and vex_start > report_start, "test gate runner must keep an identifiable VEX report pass"
    )
    gate_pass = gate_runner[:report_start]
    report_pass = gate_runner[report_start:vex_start]
    require(
        "--ignorefile security/cve-ignore.trivyignore.yaml" in gate_pass
        and "-c security/cve-ignore.grype.yaml" in gate_pass,
        "fixable scanner gate pass must use both explicit non-default ignore files",
    )
    require(
        "--ignorefile" not in report_pass and "-c security/cve-ignore.grype.yaml" not in report_pass,
        "VEX report pass must remain unfiltered",
    )
    require("--severity HIGH,CRITICAL" in report_pass, "Trivy VEX report severity scope must remain HIGH,CRITICAL")

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
        "Assert fixable-CVE ignore scope",
        "tools/assert-ignore-scope.py",
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
        "--ignore-unfixed",
        "--severity MEDIUM,HIGH,CRITICAL",
        "--ignorefile security/cve-ignore.trivyignore.yaml",
        "--exit-code 1",
        "Run Grype fixable vulnerability gates",
        "--only-fixed",
        "--fail-on medium",
        "-c security/cve-ignore.grype.yaml",
        "--show-suppressed",
        '--grype-report "${grype_gate_json}"',
        "Run OpenVEX default-deny gates",
        "--format json",
        '--file "${grype_json}"',
        "tools/assert-vex.py",
        f"cosign attest --type {predicate_type('spdx')}",
        f"cosign attest --type {predicate_type('cyclonedx')}",
        f"cosign verify-attestation --type {predicate_type('spdx')}",
        f"cosign attest --type {predicate_type('openvex')}",
        f"cosign verify-attestation --type {predicate_type('openvex')}",
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
        'assert_attestation_tlog "OpenVEX ${arch}"',
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
    ignore_scope_index = text.find("Assert fixable-CVE ignore scope")
    first_trivy_scan_index = text.find("Run Trivy fixable vulnerability gates")
    first_grype_scan_index = text.find("Run Grype fixable vulnerability gates")
    require(freshness_index >= 0, "publish workflow must assert scanner DB freshness")
    require(ignore_scope_index >= 0, "publish workflow must assert fixable-CVE ignore scope")
    require(
        freshness_index < first_trivy_scan_index and freshness_index < first_grype_scan_index,
        "publish workflow scanner DB freshness gate must run before vulnerability scans",
    )
    require(
        ignore_scope_index < first_trivy_scan_index and ignore_scope_index < first_grype_scan_index,
        "publish workflow fixable-CVE ignore scope gate must run before vulnerability scans",
    )

    trivy_gate = text[first_trivy_scan_index:first_grype_scan_index]
    vex_report_index = text.find("Run OpenVEX default-deny gates")
    require(vex_report_index > first_grype_scan_index, "publish workflow must keep an identifiable VEX report pass")
    grype_gate = text[first_grype_scan_index:vex_report_index]
    report_pass = text[vex_report_index:]
    require(
        "--ignorefile security/cve-ignore.trivyignore.yaml" in trivy_gate,
        "publish Trivy fixable gate must use the explicit non-default ignore file",
    )
    require(
        "-c security/cve-ignore.grype.yaml" in grype_gate,
        "publish Grype fixable gate must use the explicit non-default ignore file",
    )
    require(
        "--ignorefile" not in report_pass and "-c security/cve-ignore.grype.yaml" not in report_pass,
        "publish VEX report pass must remain unfiltered",
    )
    require("--severity HIGH,CRITICAL" in report_pass, "publish Trivy VEX report scope must remain HIGH,CRITICAL")

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


def rpmlock_summary(relative_path: str, platform_arch: str, *, builder: bool = False) -> dict[str, Any]:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/rpmlock.py"),
            "builder-summary" if builder else "summary",
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

    expected_builder_names = {
        "expat",
        "libnsl2",
        "libtirpc",
        "mpdecimal",
        "python3.12",
        "python3.12-libs",
        "python3.12-pip-wheel",
    }
    gitignore = read(".gitignore")
    for platform_arch in expected_arch:
        relative_path = f"rpm-lock/builder.{platform_arch}.txt"
        require(f"!/{relative_path}" in gitignore, f".gitignore must allowlist builder lock: {relative_path}")
        summary = rpmlock_summary(relative_path, platform_arch, builder=True)
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
    for marker in [
        "!/security/",
        "!/security/cve-ignore.trivyignore.yaml",
        "!/security/cve-ignore.grype.yaml",
    ]:
        require(marker in gitignore, f".gitignore must allowlist CVE ignore path: {marker}")

    helper = read("tools/assert-ignore-scope.py")
    for marker in [
        'ALLOWED_CVE = "CVE-2026-31790"',
        '"openssl-fips-provider"',
        '"openssl-fips-provider-so"',
        'ALLOWED_VERSION = "3.0.7-8.el9"',
        "REVIEW_DATE = date(2026, 10, 10)",
        "appliedIgnoreRules",
        "--grype-report",
        "--self-test",
    ]:
        require(marker in helper, f"CVE ignore scope helper missing marker: {marker}")

    trivy_ignore = read("security/cve-ignore.trivyignore.yaml")
    grype_ignore = read("security/cve-ignore.grype.yaml")
    require("\n    purls:\n" in trivy_ignore, "Trivy ignore must use the plural purls key")
    require("\n    purl:" not in trivy_ignore, "Trivy ignore must never use the singular purl key")
    require("expired_at: 2026-10-10" in trivy_ignore, "Trivy ignore must pin the TD-6 review date")
    require(
        grype_ignore.count("review-by 2026-10-10") == 2,
        "each Grype ignore must pin the TD-6 review date in its reason",
    )

    vex_helper = read("tools/assert-vex.py")
    require(
        'HIGH_CRITICAL = {"HIGH", "CRITICAL"}' in vex_helper,
        "OpenVEX default-deny scope must remain HIGH/CRITICAL",
    )

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/assert-ignore-scope.py")],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    require(
        result.returncode == 0,
        f"committed CVE ignore scope validation failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
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
    require((ROOT / "vex").is_dir(), "missing VEX directory")
    codeowners = read(".github/CODEOWNERS")
    require("/vex/ @NWarila" in codeowners, "CODEOWNERS must gate vex/ with @NWarila")

    read("vex/README.md")
    require((ROOT / "vex/.gitkeep").is_file(), "vex/.gitkeep must remain present")

    vex_path = "vex/cve-2026-31790.openvex.json"
    vex = load_json_object(vex_path)
    require(vex.get("@context") == "https://openvex.dev/ns/v0.2.0", f"{vex_path} must use OpenVEX v0.2.0")
    require(
        vex.get("@id") == "https://github.com/NWarila/ubi9-base-micro/vex/cve-2026-31790",
        f"{vex_path} must carry its stable document IRI",
    )
    require(vex.get("author") == "NWarila", f"{vex_path} must identify the human author")
    require(vex.get("timestamp") == "2026-07-10T00:00:00Z", f"{vex_path} must pin its issue timestamp")
    require(vex.get("version") == 1, f"{vex_path} must start at version 1")

    raw_statements = vex.get("statements")
    require(isinstance(raw_statements, list) and len(raw_statements) == 1, f"{vex_path} must contain one statement")
    statements = cast(list[Any], raw_statements)
    require(isinstance(statements[0], dict), f"{vex_path} statement must be an object")
    statement = cast(dict[str, Any], statements[0])
    require(
        statement.get("vulnerability") == {"name": "CVE-2026-31790"},
        f"{vex_path} must identify CVE-2026-31790",
    )
    require(statement.get("status") == "affected", f"{vex_path} status must remain affected")
    require(
        statement.get("action_statement_timestamp") == "2026-07-10T00:00:00Z",
        f"{vex_path} action statement timestamp must match its issue date",
    )
    raw_action_statement = statement.get("action_statement")
    require(
        isinstance(raw_action_statement, str) and raw_action_statement.strip(),
        f"{vex_path} requires mitigation guidance",
    )
    action_statement = cast(str, raw_action_statement)
    for marker in ["3.0.7-8.el9", "TD-6", "2026-10-10", "CMVP #4857"]:
        require(marker in action_statement, f"{vex_path} action statement missing policy marker: {marker}")

    raw_products = statement.get("products")
    require(isinstance(raw_products, list) and len(raw_products) == 1, f"{vex_path} must identify one base product")
    products = cast(list[Any], raw_products)
    require(isinstance(products[0], dict), f"{vex_path} product must be an object")
    product = cast(dict[str, Any], products[0])
    require(product.get("@id") == "pkg:oci/ubi9-base-micro", f"{vex_path} must identify the base image")
    require(
        product.get("identifiers") == {"purl": "pkg:oci/ubi9-base-micro"},
        f"{vex_path} base product purl must match its identifier",
    )
    raw_subcomponents = product.get("subcomponents")
    require(isinstance(raw_subcomponents, list), f"{vex_path} must identify affected subcomponents")
    subcomponents = cast(list[Any], raw_subcomponents)
    subcomponent_ids = {
        item.get("@id") for item in subcomponents if isinstance(item, dict) and isinstance(item.get("@id"), str)
    }
    require(
        subcomponent_ids
        == {
            "pkg:rpm/redhat/openssl-fips-provider@3.0.7-8.el9",
            "pkg:rpm/redhat/openssl-fips-provider-so@3.0.7-8.el9",
        },
        f"{vex_path} must scope the affected statement to both held provider packages",
    )

    script = read("tools/assert-vex.py")
    for marker in [
        "parse_trivy",
        "parse_grype",
        "--self-test",
        "synthetic-unvexed-critical",
        "not_affected",
        "justification",
        "fixed",
        "under_investigation",
        "affected",
        "un-vexed unfixed HIGH/CRITICAL findings",
    ]:
        require(marker in script, f"VEX assertion script missing marker: {marker}")

    vex_readme = read("vex/README.md")
    for marker in [
        "default-deny",
        "Trivy",
        "Grype",
        "CODEOWNERS",
        f"cosign attest --type {predicate_type('openvex')}",
    ]:
        require(marker in vex_readme, f"vex/README.md missing marker: {marker}")

    with tempfile.TemporaryDirectory(prefix="verify-openvex-") as raw_tmp:
        tmp = Path(raw_tmp)
        trivy_json = tmp / "trivy.json"
        grype_json = tmp / "grype.json"
        trivy_json.write_text('{"Results": []}\n', encoding="utf-8")
        grype_json.write_text('{"matches": []}\n', encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/assert-vex.py"),
                "--product",
                "ghcr.io/nwarila/ubi9-base-micro@sha256:" + ("0" * 64),
                "--trivy-json",
                str(trivy_json),
                "--grype-json",
                str(grype_json),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    require(
        result.returncode == 0 and "unfixed HIGH/CRITICAL findings requiring VEX: 0" in result.stdout,
        f"committed OpenVEX document failed assert-vex.py:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}",
    )


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
        "tools/assert-rpm-lock-hashes.py",
        "tools/assert-no-rootfs-secrets.py",
        "tools/generate-nist-800-190-predicate.py",
        "tools/assert-footprint.py",
        "tools/assert-no-phantom-packages.py",
        "tools/assert-reproducible.py",
        "tools/assert-ignore-scope.py",
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
    }
    for number, (relative_path, title) in zip(expected_numbers, REPO_ADRS, strict=True):
        text = read(relative_path)
        require(text.startswith(f"# ADR-{number}: {title}\n"), f"{relative_path} has wrong ADR heading")
        expected_date = date_overrides.get(number, "2026-06-21")
        for marker in [
            "- Status: Accepted",
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
        "tools/assert-vex.py",
        "stig/rhel9-base-micro-tailoring.xml",
        predicate_type("nist_800_190"),
        "base-micro@sha256:<digest>",
        "runs-on: ubuntu-24.04",
        "fetch-runtime-rpms.sh",
        "cdn-ubi.redhat.com",
        "contracts/image-manifest.json",
    ]:
        require(marker in joined, f"repo ADRs missing load-bearing marker: {marker}")


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
    verify_lines = verify.splitlines()
    verify_summary_marker = "gates fixable MEDIUM, HIGH, and CRITICAL findings with both Trivy and Grype"
    require(
        len(verify_lines) >= 3 and verify_summary_marker in verify_lines[2],
        "docs/reference/verify.md line 3 must state the fixable MEDIUM/HIGH/CRITICAL gate",
    )
    cve_heading = "## CVE And OpenVEX Policy"
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
        "2026-10-10",
    ]:
        require(marker in verify_cve_policy, f"docs/reference/verify.md CVE policy missing marker: {marker}")
    require(
        "The nightly sentinel detects fixable MEDIUM, HIGH, and CRITICAL findings" in adr_0006,
        "ADR-0006 must state that the nightly sentinel detects fixable MEDIUM/HIGH/CRITICAL findings",
    )
    require(
        re.search(
            r"Fixable MEDIUM, HIGH,\s+and CRITICAL findings fail closed in either scanner\.",
            adr_0007,
        )
        is not None,
        "ADR-0007 must state that fixable MEDIUM/HIGH/CRITICAL findings fail closed",
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
        f'cosign verify-attestation --type {predicate_type("openvex")} "${{CHILD_REF}}"',
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
        "Cosign signature on that index",
        "attestations on each platform child",
        "`slsa-verifier` result on the index",
        "jq -r '.payload | @base64d | fromjson | .predicate.packages[].name'",
        "grep -q glibc",
        "independently for `linux/amd64` and `linux/arm64`",
        "published-child `--expect-from-contract` assertion",
        "no shell or package-manager executable",
        "Fixable vulnerability policy",
        "reject fixable MEDIUM, HIGH, and CRITICAL findings",
        "repository's `TD-6`",
        "`openssl-fips-provider` and `openssl-fips-provider-so`",
        "expiring on `2026-10-10`",
        "Unfixed vulnerability policy",
        "every unfixed HIGH or CRITICAL finding",
        "default-denied",
        "statement is `affected`; it is disclosure only and clears nothing",
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
    require(
        re.search(r"required status checks\s+are not enforced", acceptance) is not None,
        "acceptance.md must not claim merge-blocking checks",
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
        "Only `ubi9-base-micro` exists in",
        "read as published artifacts from this repo",
        "`base-python`",
        "`base-node`",
        "`base-java`",
        "`FROM base-micro@sha256:<digest>`",
        "cosign keyless",
        "SLSA L3 provenance",
        "SPDX and CycloneDX SBOMs",
        "Grype fixable-CVE gates",
        "OpenVEX default-deny",
        "NIST SP 800-190 section 4.1 image evidence",
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
    require(
        "CODEOWNERS-gated" in vex_doc and f"cosign attest --type {predicate_type('openvex')}" in vex_doc,
        "docs/compliance/vex.md must describe VEX review and attestation flow",
    )
    for source, source_text in [
        ("docs/TECH-DEBT.md", tech_debt),
        ("docs/reference/gates.md", gates),
        ("docs/compliance/vex.md", vex_doc),
    ]:
        for marker in [
            "CVE-2026-31790",
            "3.0.7-8.el9",
            "2026-10-10",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
            "delta is zero",
            "forward-looking",
        ]:
            require(marker in source_text, f"{source} missing fixable-CVE policy marker: {marker}")
    for marker in [
        "## TD-6:",
        "CVSS 3.1 base score of 5.9",
        "CVE-2026-2673",
        "CVE-2026-5435",
        "CVE-2026-5928",
        "CVE-2026-6238",
        "openssl-libs",
        "glibc-common",
        "glibc-minimal-langpack",
    ]:
        require(marker in tech_debt, f"docs/TECH-DEBT.md missing TD-6 marker: {marker}")
    for marker in [
        "SOURCE_DATE_EPOCH=1704067200",
        "tools/assert-reproducible.py --assert-byte-identical",
        "--expect-from-contract",
        "rewrite-timestamp=true",
        "docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130",
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
        "Refresh runtime RPM lockfiles",
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
        f"cosign verify-attestation --type {predicate_type('openvex')}",
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
        "OpenVEX default-deny",
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

    for doc_name, doc in [
        ("docs/reference/verify.md", verify),
        ("docs/how-to/verify-a-published-image.md", verify_howto),
    ]:
        for marker in [
            'INDEX_REF="${IMAGE}@${INDEX_DIGEST}"',
            'CHILD_REF="${IMAGE}@${CHILD_DIGEST}"',
            'cosign verify "${INDEX_REF}"',
            'cosign verify-attestation --type spdxjson "${CHILD_REF}"',
            'cosign verify-attestation --type cyclonedx "${CHILD_REF}"',
            'cosign verify-attestation --type openvex "${CHILD_REF}"',
            f'cosign verify-attestation --type {predicate_type("nist_800_190")} "${{CHILD_REF}}"',
            f'cosign verify-attestation --type {predicate_type("stig_arf")} "${{CHILD_REF}}"',
            'cosign verify-attestation --type slsaprovenance "${INDEX_REF}"',
            'slsa-verifier verify-image "${INDEX_REF}"',
        ]:
            require(marker in doc, f"{doc_name} missing digest-routing marker: {marker}")
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
        "language: python",
        "always_run: true",
    ]:
        require(marker in precommit, f".pre-commit-config.yaml missing marker: {marker}")
    require(precommit.count("repo: local") == 1, ".pre-commit-config.yaml must carry exactly one local hook block")
    require(
        precommit.count("pass_filenames: false") == 7,
        ".pre-commit-config.yaml must keep exactly mypy and six pytest hooks filename-independent",
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
    require(readme.is_file(), "missing public README.md for internal-process residue scan")
    require(docs_dir.is_dir(), "missing docs directory for internal-process residue scan")
    paths = [readme, *sorted(docs_dir.rglob("*.md"))]
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
        (root / "README.md").write_text(
            "\n".join(fixture for _, fixture in positive_fixtures[:4]) + "\n",
            encoding="utf-8",
        )
        (nested_docs / "fixture.md").write_text(
            "\n".join(fixture for _, fixture in positive_fixtures[4:]) + "\n",
            encoding="utf-8",
        )
        (root / "outside.md").write_text("P9.9 STEP999 MANDATE\n", encoding="utf-8")
        positive_findings = find_internal_process_residue(collect_internal_process_docs(root))
        positive_labels = {finding.rsplit(": ", 1)[1] for finding in positive_findings}
        require(
            len(positive_findings) == len(INTERNAL_PROCESS_RESIDUE_PATTERNS)
            and positive_labels == {label for label, _ in INTERNAL_PROCESS_RESIDUE_PATTERNS},
            "internal-process residue self-test must detect every pattern across README.md and nested docs",
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
            "preview. b xnwarila-platform nwarila-platformx 18 images 8 imageset\n",
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


def main() -> int:
    checks = [
        check_required_files,
        check_gitattributes_archive_visibility,
        check_image_contract_files,
        check_community_profile,
        check_renovate_config,
        check_ubi_digest_equality,
        check_ubi_digest_equality_self_test,
        check_pin_invariant_self_test,
        check_dockerfile,
        check_rpm_lock_generator,
        check_dockerfile_forbidden_scan_self_test,
        check_builder_toolchain_floor_self_test,
        check_rpm_locks,
        check_workflow,
        check_supply_chain_workflows,
        check_lint_setup,
        check_publish_workflow,
        check_build_script,
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
