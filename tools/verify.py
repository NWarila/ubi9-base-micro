#!/usr/bin/env python3
# Purpose: Repository contract checks (pinned SHAs/tags, FIPS RPM digests, required files/ADRs) for ubi9-base-micro
# Role: governance
# Micro-container candidate: no - repo-tree-coupled contract verifier (run via `make verify`), validates the repo, not
# an image

"""Repository contract checks for ubi9-base-micro."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_USES = re.compile(r"uses:\s+([^@\s]+)@([^\s#]+)")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SLSA_GENERATOR = "slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml"
SLSA_GENERATOR_TAG = "v2.1.0"
SLSA_GENERATOR_SHA = "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a"
HARDEN_RUNNER = "step-security/harden-runner"
HARDEN_RUNNER_SHA = "9af89fc71515a100421586dfdb3dc9c984fbf411"
CHECKOUT_SHA = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
SCORECARD_ACTION_SHA = "4eaacf0543bb3f2c246792bd56e8cdeffafb205a"
CODEQL_ACTION_SHA = "8aad20d150bbac5944a9f9d289da16a4b0d87c1e"
DEPENDENCY_REVIEW_ACTION_SHA = "a1d282b36b6f3519aa1f3fc636f609c47dddb294"
ZIZMOR_ACTION_SHA = "5f14fd08f7cf1cb1609c1e344975f152c7ee938d"
ZIZMOR_VERSION = "1.25.2"
PRE_COMMIT_VERSION = "4.6.0"
SHELLCHECK_HOOK_REV = "v0.11.0.1"
SHFMT_HOOK_REV = "v3.13.1-1"
RUFF_HOOK_REV = "v0.15.18"
MYPY_HOOK_REV = "v2.1.0"
YAMLLINT_HOOK_REV = "v1.38.0"
MARKDOWNLINT_HOOK_REV = "v0.22.1"
HADOLINT_HOOK_REV = "v2.14.0"
HADOLINT_IMAGE_DIGEST = "sha256:27086352fd5e1907ea2b934eb1023f217c5ae087992eb59fde121dce9c9ff21e"
ACTIONLINT_HOOK_REV = "v1.7.12"
ACTIONLINT_REVIEWDOG_ACTION_SHA = "6fb7acc99f4a1008869fa8a0f09cfca740837d9d"
ACTIONLINT_REVIEWDOG_ACTION_TAG = "v1.72.0"
ACTIONLINT_REVIEWDOG_TOOL_VERSION = "1.7.12"
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
OPENSSL_FIPS_MODULE_VERSION = "3.0.7-395c1a240fbfffd8"
OPENSSL_FIPS_PROVIDER_NEVRA = "openssl-fips-provider-so-3.0.7-8.el9"
OPENSSL_FIPS_PROVIDER_RPM_BASE_URL = "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9"
OPENSSL_FIPS_PROVIDER_RPM_SHA256_AMD64 = "bbf25303def8e1270675531c47bdad432f6ad8ef4c327556ae65bd6abaf8edb5"
OPENSSL_FIPS_PROVIDER_RPM_SHA256_ARM64 = "0cfe7b281ae2ca3cb0ceaa1a0b84f8c087c4ac16662ebb9c19b5681cf39f99a9"
OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AMD64 = "ab48d98504fae6f8636de027a1ee06d21d5e9c27b7beb247017a6fe55567c5e9"
OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_ARM64 = "18c77b9b37e7abf0e8cf1dac4b3de770efe895547bdcab8aea8d8d8592954947"
OPENSSL_FIPS_MODULE_VERSION_AMD64 = OPENSSL_FIPS_MODULE_VERSION
OPENSSL_FIPS_PROVIDER_NEVRA_AMD64 = OPENSSL_FIPS_PROVIDER_NEVRA
OPENSSL_FIPS_MODULE_VERSION_ARM64 = OPENSSL_FIPS_MODULE_VERSION
OPENSSL_FIPS_PROVIDER_NEVRA_ARM64 = OPENSSL_FIPS_PROVIDER_NEVRA
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


def check_uses_pinned(text: str, source: str) -> None:
    uses = WORKFLOW_USES.findall(text)
    require(uses, f"{source} should pin external actions explicitly")
    bad_refs: list[str] = []
    for action, ref in uses:
        if action == SLSA_GENERATOR and ref == SLSA_GENERATOR_TAG:
            continue
        if not SHA40.fullmatch(ref):
            bad_refs.append(f"{action}@{ref}")
    require(not bad_refs, f"{source} uses entries must be pinned to 40-char SHA: " + ", ".join(bad_refs))


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
                f"uses: {HARDEN_RUNNER}@{HARDEN_RUNNER_SHA} # v2.19.4" in block,
                f"{source} harden-runner must be pinned to v2.19.4 SHA",
            )
            require("egress-policy: audit" in block, f"{source} harden-runner must use audit egress policy")
    require(step_blocks > 0, f"{source} must contain at least one job steps block")
    require(
        text.count(f"{HARDEN_RUNNER}@{HARDEN_RUNNER_SHA}") == text.count("egress-policy: audit"),
        f"{source} harden-runner entries must all use egress-policy: audit",
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
        "rpm-lock/runtime.amd64.txt",
        "rpm-lock/runtime.arm64.txt",
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
        "tools/assert-no-phantom-packages.py",
        "tools/assert-reproducible.py",
        "tools/assert-rpm-lock-hashes.sh",
        "tools/fetch-runtime-rpms.sh",
        "tools/generate-rpm-lock.sh",
        "tools/install-syft.sh",
        "tools/install-trivy.sh",
        "tools/install-grype.sh",
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
        "vex/README.md",
    ]:
        require((ROOT / relative_path).is_file(), f"missing required file: {relative_path}")
    dockerignore = read(".dockerignore")
    require(
        "!tools/fetch-runtime-rpms.sh" in dockerignore,
        ".dockerignore must allowlist runtime direct-CDN RPM fetch helper",
    )
    for relative_path, _ in REPO_ADRS:
        require((ROOT / relative_path).is_file(), f"missing required ADR: {relative_path}")


def check_community_profile() -> None:
    gitignore = read(".gitignore")
    for relative_path in COMMUNITY_PROFILE_FILES:
        require((ROOT / relative_path).is_file(), f"missing community profile file: {relative_path}")
        require(f"!/{relative_path}" in gitignore, f".gitignore must allowlist community profile file: {relative_path}")

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
        "no git tags",
        "GitHub releases",
        "docs/reference/verify.md",
        "cosign verify",
        "cosign verify-attestation",
        "slsa-verifier verify-image",
        "GitHub Actions OIDC issuer",
        "Do not substitute `gh attestation verify`",
    ]:
        require(marker in security, f"SECURITY.md missing marker: {marker}")
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
        "no git tags",
        "GitHub releases",
        "Community health files",
    ]:
        require(marker in changelog, f"CHANGELOG.md missing marker: {marker}")
    require("## [0.1.0]" not in changelog, "CHANGELOG.md must not claim an unreleased VERSION as a release")

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


def check_dockerfile() -> None:
    text = read("containers/Dockerfile")
    required = [
        "# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-minimal",
        "# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-micro",
        "ARG UBI_MINIMAL_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal@sha256:",
        "ARG UBI_MICRO_IMAGE=registry.access.redhat.com/ubi9/ubi-micro@sha256:",
        "ARG TARGETARCH",
        f"ARG OPENSSL_FIPS_MODULE_VERSION={OPENSSL_FIPS_MODULE_VERSION}",
        f"ARG OPENSSL_FIPS_PROVIDER_NEVRA={OPENSSL_FIPS_PROVIDER_NEVRA}",
        f"ARG OPENSSL_FIPS_PROVIDER_RPM_BASE_URL={OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}",
        f"ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64={OPENSSL_FIPS_PROVIDER_RPM_SHA256_AMD64}",
        f"ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64={OPENSSL_FIPS_PROVIDER_RPM_SHA256_ARM64}",
        f"ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64={OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AMD64}",
        f"ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64={OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_ARM64}",
        "ARG SOURCE_DATE_EPOCH=1704067200",
        'amd64) rpm_arch="x86_64"',
        'arm64) rpm_arch="aarch64"',
        (
            'bash /tmp/fetch-runtime-rpms.sh --targetarch "${TARGETARCH}" '
            '--lockfile "${runtime_lockfile}" --dest /tmp/runtime-rpms'
        ),
        "rpm -Uvh --oldpackage --replacepkgs",
        'expected_provider_nevra="${OPENSSL_FIPS_PROVIDER_NEVRA}.${rpm_arch}"',
        "COPY rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt /tmp/rpm-lock/",
        "COPY tools/assert-rpm-lock-hashes.sh /tmp/assert-rpm-lock-hashes.sh",
        "COPY tools/fetch-runtime-rpms.sh /tmp/fetch-runtime-rpms.sh",
        "dnf_repo_args=()",
        '"${dnf_repo_args[@]}"',
        "locked_packages=()",
        "locked_rpm_paths=()",
        'locked_packages+=("${package}")',
        'locked_rpm_paths+=("/tmp/runtime-rpms/${name}-${version}-${release}.${arch}.rpm")',
        "final runtime RPM lock floor verified",
        "bash /tmp/assert-rpm-lock-hashes.sh --root /rootfs --lockfile",
        "--direct-rpm-dir /tmp/runtime-rpms",
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
        "org.nwarila.fips.cmvp",
        "org.nwarila.fips.module-version",
        "org.nwarila.fips.provider-nvr",
        "org.nwarila.fips.cmvp.oe-validated",
        "/etc/nwarila/fips-status.json",
        "provider_nvr",
        "provider_nevra",
        "oe_validated=false",
        "NOT in CMVP #4857's validated or vendor-affirmed list",
        "/fips-proof/provider.nevra",
        "/fips-proof/expected-provider.nevra",
        "/fips-proof/libs.nevra",
        "/fips-proof/fips.so.sha256",
        "rpm --root=/rootfs -q --qf '%{NEVRA}\\n' openssl-fips-provider-so",
        "shipped_libs_nevra",
        "ldd-protected FIPS/glibc runtime dependency paths:",
        'rpm --root=/rootfs -e --nodeps --noscripts "${removable_packages[@]}"',
        "ldconfig -r /rootfs",
        "/rootfs/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/rootfs/usr/lib/locale/C.utf8",
        "/rootfs/usr/share/zoneinfo/Etc/UTC",
        "openssl verify",
        "alternatives",
        "update-alternatives",
        "/usr/sbin/*",
        "/etc/alternatives",
        "/usr/libexec/coreutils",
        "/usr/lib64/libpcre2-posix.so*",
        "/usr/lib64/libpanel*.so*",
        "/usr/lib64/libpanelw*.so*",
        "ln -sfn usr/lib64 /rootfs/lib64",
    ]
    missing = [marker for marker in required if marker not in text]
    require(not missing, "Dockerfile missing required markers: " + ", ".join(missing))

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

    forbidden = [
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
    present = [marker for marker in forbidden if marker in text]
    require(not present, "Dockerfile contains forbidden marker(s): " + ", ".join(present))


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
    gate_runner = read("tools/run-test-gates.sh")
    reviewdog_actionlint_marker = (
        f"reviewdog/action-actionlint@{ACTIONLINT_REVIEWDOG_ACTION_SHA} # "
        f"{ACTIONLINT_REVIEWDOG_ACTION_TAG}; bundles actionlint {ACTIONLINT_REVIEWDOG_TOOL_VERSION}"
    )

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
        "bash tools/assert-rpm-lock-hashes.sh --self-test",
        "bash tools/generate-rpm-lock.sh --self-test",
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
        'GRYPE_VERSION: "0.87.0"',
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
        "bash tools/generate-rpm-lock.sh --self-test",
        "bash -n tools/run-test-gates.sh",
        "bash -n tools/fetch-runtime-rpms.sh",
        "bash -n tools/generate-rpm-lock.sh",
        "UBI_MICRO_IMAGE: registry.access.redhat.com/ubi9/ubi-micro@sha256:",
        'TRIVY_VERSION: "0.71.0"',
        'GRYPE_VERSION: "0.87.0"',
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
        "dist/reproducibility/base-micro.${ARCH}.reproducibility.json",
        "Run full test-only gate set",
        "tools/run-test-gates.sh",
        "ghcr.io/nwarila/ubi9-base-micro",
    ]:
        require(marker in nightly, f"nightly workflow missing marker: {marker}")

    require("pull_request:" not in nightly, "nightly workflow must not run as PR CI")
    require("\npush:" not in nightly, "nightly workflow must not run on push")

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
        "--severity HIGH,CRITICAL",
        "--exit-code 1",
        'dist/tools/grype "${runtime_image}" --only-fixed --fail-on high',
        "--format json",
        '--file "${grype_json}"',
        "tools/assert-vex.py",
        "tools/assert-no-rootfs-secrets.py",
        "tools/generate-nist-800-190-predicate.py",
        '--validate "${predicate}"',
        "bash /tmp/assert-rpm-lock-hashes.sh --root /rootfs --lockfile",
    ]:
        require(
            marker in gate_runner or marker in read("containers/Dockerfile"),
            f"test gate runner missing marker: {marker}",
        )

    forbidden = [
        "NWarila/.github/.github/workflows/",
        "reusable-",
        "--" + "push",
        "docker " + "push",
        "co" + "sign",
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

    check_uses_pinned(build, "build workflow")
    check_uses_pinned(nightly, "nightly workflow")
    check_uses_pinned(refresh, "RPM lock refresh workflow")
    require(reviewdog_actionlint_marker in build, "build workflow must document the bundled actionlint 1.7.12 pin")
    require(reviewdog_actionlint_marker in nightly, "nightly workflow must document the bundled actionlint 1.7.12 pin")


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
    for marker in [
        "name: OpenSSF Scorecard",
        "push:\n    branches: [main]",
        "schedule:",
        'cron: "17 6 * * 1"',
        "branch_protection_rule:",
        "types: [created, edited, deleted]",
        "permissions: {}",
        "permissions:\n      contents: read\n      id-token: write\n      security-events: write",
        f"actions/checkout@{CHECKOUT_SHA}",
        f"ossf/scorecard-action@{SCORECARD_ACTION_SHA}",
        "results_file: results.sarif",
        "results_format: sarif",
        "publish_results: true",
        f"github/codeql-action/upload-sarif@{CODEQL_ACTION_SHA}",
        "sarif_file: results.sarif",
    ]:
        require(marker in scorecard, f"scorecard workflow missing marker: {marker}")
    require("pull_request:" not in scorecard, "scorecard workflow must not run on pull_request")
    for forbidden in ["issues:", "pull-requests:", "checks:"]:
        require(forbidden not in scorecard, f"scorecard workflow has non-minimal permission marker: {forbidden}")

    codeql = read(".github/workflows/codeql.yml")
    for marker in [
        "name: CodeQL",
        "pull_request:\n    branches: [main]",
        "push:\n    branches: [main]",
        "schedule:",
        'cron: "37 6 * * 2"',
        "permissions: {}",
        "permissions:\n      actions: read\n      contents: read\n      security-events: write",
        f"actions/checkout@{CHECKOUT_SHA}",
        f"github/codeql-action/init@{CODEQL_ACTION_SHA}",
        "languages: python",
        "build-mode: none",
        "queries: security-extended",
        "paths:\n              - tools",
        f"github/codeql-action/analyze@{CODEQL_ACTION_SHA}",
    ]:
        require(marker in codeql, f"CodeQL workflow missing marker: {marker}")
    for forbidden in ["id-token:", "packages:", "pull-requests:"]:
        require(forbidden not in codeql, f"CodeQL workflow has non-minimal permission marker: {forbidden}")

    dependency_review = read(".github/workflows/dependency-review.yml")
    for marker in [
        "name: Dependency review",
        "pull_request:\n    branches: [main]",
        "permissions: {}",
        "permissions:\n      contents: read\n      pull-requests: read",
        f"actions/checkout@{CHECKOUT_SHA}",
        f"actions/dependency-review-action@{DEPENDENCY_REVIEW_ACTION_SHA}",
        "fail-on-severity: high",
    ]:
        require(marker in dependency_review, f"dependency review workflow missing marker: {marker}")
    for forbidden in ["push:", "schedule:", "id-token:", "packages:", "security-events:"]:
        require(forbidden not in dependency_review, f"dependency review workflow has non-minimal marker: {forbidden}")

    zizmor = read(".github/workflows/zizmor.yml")
    for marker in [
        "name: zizmor",
        "pull_request:\n    branches: [main]",
        "push:\n    branches: [main]",
        "permissions: {}",
        "permissions:\n      actions: read\n      contents: read\n      security-events: write",
        f"actions/checkout@{CHECKOUT_SHA}",
        f"zizmorcore/zizmor-action@{ZIZMOR_ACTION_SHA}",
        "inputs: .github/workflows/",
        "config: .github/zizmor.yml",
        "advanced-security: true",
        f"version: {ZIZMOR_VERSION}",
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
        "OPENSSL_FIPS_PROVIDER_NEVRA",
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
        'GRYPE_VERSION: "0.87.0"',
        "tools/build-stig-datastream.sh",
        "tools/run-stig-arf.sh",
        'NIST_800_190_PREDICATE_TYPE: "https://nwarila.dev/attestations/nist-sp-800-190-image/v1"',
        'STIG_ARF_PREDICATE_TYPE: "https://nwarila.dev/attestations/stig-arf/v1"',
        "sudo podman login ghcr.io",
        "Run tailored STIG ARF gates",
        "tools/install-syft.sh",
        "tools/install-trivy.sh",
        "tools/install-grype.sh",
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
        "--severity HIGH,CRITICAL",
        "--exit-code 1",
        "Run Grype fixable vulnerability gates",
        "--only-fixed --fail-on high",
        "Run OpenVEX default-deny gates",
        "--format json",
        '--file "${grype_json}"',
        "tools/assert-vex.py",
        "cosign attest --type spdxjson",
        "cosign attest --type cyclonedx",
        "cosign verify-attestation --type spdxjson",
        "cosign attest --type openvex",
        "cosign verify-attestation --type openvex",
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
        "cosign verify-attestation --type slsaprovenance",
        "STIG ARF",
        "OpenSCAP",
        'assert_attestation_tlog "SLSA provenance index"',
        "cosign verify-attestation --type spdxjson",
        'assert_attestation_tlog "SPDX SBOM ${arch}"',
        "cosign verify-attestation --type cyclonedx",
        'assert_attestation_tlog "CycloneDX SBOM ${arch}"',
        'assert_attestation_tlog "NIST 800-190 image ${arch}"',
        'assert_attestation_tlog "STIG ARF ${arch}"',
        'assert_attestation_tlog "OpenVEX ${arch}"',
        'COSIGN_YES: "true"',
        SLSA_GENERATOR + "@" + SLSA_GENERATOR_TAG,
        SLSA_GENERATOR_SHA,
        'gh api "repos/slsa-framework/slsa-github-generator/git/ref/tags/${SLSA_GENERATOR_TAG}"',
        "cosign sign --recursive",
        "cosign verify",
        "https://github.com/${{ github.repository }}/.github/workflows/publish-image.yaml@${{ github.ref }}",
        '--certificate-oidc-issuer "https://token.actions.githubusercontent.com"',
        "manifest[linux/amd64]:org.nwarila.fips.cmvp.oe-validated=true",
        "manifest[linux/arm64]:org.nwarila.fips.cmvp.oe-validated=false",
    ]
    missing = [marker for marker in required if marker not in text]
    require(not missing, "publish workflow missing required marker(s): " + ", ".join(missing))

    forbidden = [
        "-regexp",
        "--sbom=true",
        "--tlog-upload=false",
        "--insecure-ignore-tlog",
        "--rekor-url",
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

    uses = WORKFLOW_USES.findall(text)
    generator_uses = [(action, ref) for action, ref in uses if action == SLSA_GENERATOR]
    require(
        generator_uses == [(SLSA_GENERATOR, SLSA_GENERATOR_TAG)],
        "publish workflow must use exactly one SLSA generator tag pin",
    )
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


def check_rpm_locks() -> None:
    required_final = {
        "basesystem",
        "ca-certificates",
        "crypto-policies",
        "filesystem",
        "glibc",
        "glibc-common",
        "glibc-minimal-langpack",
        "libgcc",
        "openssl-fips-provider",
        "openssl-fips-provider-so",
        "openssl-libs",
        "redhat-release",
        "setup",
        "tzdata",
        "zlib",
    }
    expected_arch = {"amd64": "x86_64", "arm64": "aarch64"}
    expected_provider = {
        "amd64": f"{OPENSSL_FIPS_PROVIDER_NEVRA_AMD64}.x86_64",
        "arm64": f"{OPENSSL_FIPS_PROVIDER_NEVRA_ARM64}.aarch64",
    }
    expected_direct_sha = {
        "amd64": (OPENSSL_FIPS_PROVIDER_RPM_SHA256_AMD64, OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AMD64),
        "arm64": (OPENSSL_FIPS_PROVIDER_RPM_SHA256_ARM64, OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_ARM64),
    }
    fips_provider_nvr = OPENSSL_FIPS_PROVIDER_NEVRA[len("openssl-fips-provider-so-") :]
    for platform_arch, rpm_arch in expected_arch.items():
        relative_path = f"rpm-lock/runtime.{platform_arch}.txt"
        lock_text = read(relative_path)
        provider_sha, provider_so_sha = expected_direct_sha[platform_arch]
        expected_provider_package = f"openssl-fips-provider-{fips_provider_nvr}.{rpm_arch}"
        expected_provider_so_package = f"{OPENSSL_FIPS_PROVIDER_NEVRA}.{rpm_arch}"
        expected_provider_url = (
            f"{OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}/{rpm_arch}/baseos/os/Packages/o/{expected_provider_package}.rpm"
        )
        expected_provider_so_url = (
            f"{OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}/{rpm_arch}/baseos/os/Packages/o/{expected_provider_so_package}.rpm"
        )
        direct_pins: dict[str, tuple[str, str]] = {}
        rows: list[dict[str, str]] = []

        for raw in lock_text.splitlines():
            if raw.startswith("# direct_rpm: "):
                parts = raw.removeprefix("# direct_rpm: ").split("|")
                require(len(parts) == 3, f"{relative_path}: malformed direct RPM pin: {raw}")
                package, url, rpm_sha256 = parts
                require(package, f"{relative_path}: direct RPM pin has empty package: {raw}")
                require(package not in direct_pins, f"{relative_path}: duplicate direct RPM pin: {package}")
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
                direct_pins[package] = (url, rpm_sha256)
                continue
            if not raw or raw.startswith("#"):
                continue
            parts = raw.split("|")
            require(len(parts) == 9, f"{relative_path}: malformed lock row: {raw}")
            package, final_rpmdb, name, epoch, version, release, arch, sha256_header, sigmd5 = parts
            require(final_rpmdb in {"yes", "no"}, f"{relative_path}: invalid final_rpmdb for {package}")
            require(arch in {"noarch", rpm_arch}, f"{relative_path}: invalid arch for {package}: {arch}")
            require(
                len(sha256_header) == 64 and all(c in "0123456789abcdef" for c in sha256_header),
                f"{relative_path}: invalid SHA256HEADER for {package}",
            )
            require(
                len(sigmd5) == 32 and all(c in "0123456789abcdef" for c in sigmd5),
                f"{relative_path}: invalid SIGMD5 for {package}",
            )
            require(name in package, f"{relative_path}: package spec does not include name {name}: {package}")
            require(epoch.isdigit(), f"{relative_path}: epoch must be numeric for {package}")
            require(version and release, f"{relative_path}: missing version/release for {package}")
            rows.append(
                {
                    "package": package,
                    "final_rpmdb": final_rpmdb,
                    "name": name,
                    "version": version,
                    "release": release,
                    "arch": arch,
                }
            )

        packages = [row["package"] for row in rows]
        require(len(packages) == len(set(packages)), f"{relative_path}: duplicate package rows")
        require(len(packages) == 38, f"{relative_path}: expected 38 transaction RPMs, got {len(packages)}")
        require(set(direct_pins) == set(packages), f"{relative_path}: direct RPM pin set must match package rows")
        require(
            expected_provider[platform_arch] in packages,
            f"{relative_path}: missing pinned provider {expected_provider[platform_arch]}",
        )

        for row in rows:
            package = row["package"]
            url, rpm_sha256 = direct_pins[package]
            expected_filename = f"{row['name']}-{row['version']}-{row['release']}.{row['arch']}.rpm"
            require(
                url.endswith(f"/{expected_filename}"),
                f"{relative_path}: direct RPM URL filename mismatch for {package}",
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


def check_scanner_install_scripts() -> None:
    trivy = read("tools/install-trivy.sh")
    for marker in [
        "TRIVY_VERSION:-0.71.0",
        "github.com/aquasecurity/trivy/releases/download/v${version}",
        "trivy_${version}_checksums.txt",
        "sha256sum -c -",
        "curl -fsSLO",
        "tar xzf",
    ]:
        require(marker in trivy, f"Trivy installer missing marker: {marker}")

    grype = read("tools/install-grype.sh")
    for marker in [
        "GRYPE_VERSION:-0.87.0",
        "github.com/anchore/grype/releases/download/v${version}",
        "grype_${version}_checksums.txt",
        "sha256sum -c -",
        "curl -fsSLO",
        "tar xzf",
    ]:
        require(marker in grype, f"Grype installer missing marker: {marker}")


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
        OPENSSL_FIPS_MODULE_VERSION_AMD64,
        OPENSSL_FIPS_PROVIDER_NEVRA_AMD64,
        OPENSSL_FIPS_MODULE_VERSION_ARM64,
        OPENSSL_FIPS_PROVIDER_NEVRA_ARM64,
    ]:
        require(marker in text, f"FIPS script missing marker: {marker}")


def check_vex() -> None:
    require((ROOT / "vex").is_dir(), "missing VEX directory")
    codeowners = read(".github/CODEOWNERS")
    require("/vex/ @NWarila" in codeowners, "CODEOWNERS must gate vex/ with @NWarila")

    read("vex/README.md")
    require((ROOT / "vex/.gitkeep").is_file(), "vex/.gitkeep must preserve the empty VEX directory")

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
        "cosign attest --type openvex",
    ]:
        require(marker in vex_readme, f"vex/README.md missing marker: {marker}")


def check_nist_800_190_scripts() -> None:
    generator = read("tools/generate-nist-800-190-predicate.py")
    for marker in [
        "PREDICATE_TYPE",
        "https://nwarila.dev/attestations/nist-sp-800-190-image/v1",
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
        "generator_container_slsa3.yml@refs/tags/v2.1.0",
        "--self-test",
    ]:
        require(marker in slsa, f"SLSA builderID helper missing marker: {marker}")


def check_helper_self_tests() -> None:
    for relative_path in [
        "tools/assert-no-rootfs-secrets.py",
        "tools/generate-nist-800-190-predicate.py",
        "tools/assert-footprint.py",
        "tools/assert-no-phantom-packages.py",
        "tools/assert-reproducible.py",
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

    expected_numbers = [f"{number:04d}" for number in range(1, len(REPO_ADRS) + 1)]
    for number, (relative_path, title) in zip(expected_numbers, REPO_ADRS, strict=True):
        text = read(relative_path)
        require(text.startswith(f"# ADR-{number}: {title}\n"), f"{relative_path} has wrong ADR heading")
        expected_date = "2026-06-25" if number == "0012" else "2026-06-21"
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
        "CMVP certificate #4857",
        "oe_validated",
        SLSA_GENERATOR_SHA,
        "tools/assert-no-phantom-packages.py",
        ".github/workflows/rpm-lock-refresh.yaml",
        "tools/assert-vex.py",
        "stig/rhel9-base-micro-tailoring.xml",
        "https://nwarila.dev/attestations/nist-sp-800-190-image/v1",
        "base-micro@sha256:<digest>",
        "runs-on: ubuntu-24.04",
        "fetch-runtime-rpms.sh",
        "cdn-ubi.redhat.com",
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
    docs_index = read("docs/README.md")
    verify = read("docs/reference/verify.md")
    gates = read("docs/reference/gates.md")
    verification_contract = read("docs/reference/verification-contract.md")
    fips_mechanism = read("docs/explanation/fips-mechanism.md")
    vex_doc = read("docs/compliance/vex.md")
    nist_doc = read("docs/compliance/nist-800-190.md")
    footprint_doc = read("docs/explanation/footprint.md")
    reproducibility_doc = read("docs/explanation/reproducibility.md")
    stig_doc = read("docs/compliance/stig.md")
    verify_howto = read("docs/how-to/verify-a-published-image.md")
    reproduce_howto = read("docs/how-to/reproduce-a-build-byte-for-byte.md")
    refresh_howto = read("docs/how-to/refresh-the-rpm-lock.md")
    gate_howto = read("docs/how-to/run-a-gate-locally.md")
    consume_howto = read("docs/how-to/consume-base-micro-as-from-base.md")
    tutorial = read("docs/tutorials/getting-started-build-and-verify.md")
    legacy_namespace = "ghcr.io/nwarila-" + "platform/*"
    require(legacy_namespace in acceptance, "acceptance copy should preserve source DoD text")
    require("superseded for this repository" in acceptance, "acceptance.md must flag the legacy platform namespace")
    require("Byte-for-byte reproducible (HARD gate)" in acceptance, "acceptance.md must carry hard F3 wording")
    require("explicitly retracted" not in acceptance, "acceptance.md must not preserve the old F3 retract escape")
    require("fipsinstall`-generated" not in acceptance, "acceptance.md must not preserve stale fipsinstall mechanism")
    require("#4857" in fips, "docs/compliance/fips.md must record the OpenSSL CMVP #4857 ledger")
    require(
        OPENSSL_FIPS_MODULE_VERSION_AMD64 in fips,
        "docs/compliance/fips.md must record the validated OpenSSL provider version",
    )
    require(
        OPENSSL_FIPS_MODULE_VERSION_ARM64 in fips,
        "docs/compliance/fips.md must record the arm64 OpenSSL provider version",
    )
    require(
        OPENSSL_FIPS_PROVIDER_NEVRA_AMD64 in fips,
        "docs/compliance/fips.md must record the amd64 provider NVR",
    )
    require(
        OPENSSL_FIPS_PROVIDER_NEVRA_ARM64 in fips,
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
        "this aarch64 operational environment is NOT in CMVP #4857's validated or vendor-affirmed list" in fips
        and "this is NOT a CMVP-validated configuration on this architecture" in fips,
        "docs/compliance/fips.md missing arm64 disclaimer",
    )
    require(
        "x86_64" in fips and "IBM Z" in fips and "POWER" in fips and "aarch64" in fips,
        "docs/compliance/fips.md must cite tested OE architecture scope",
    )
    require(
        "certificate/4857" in fips and "140sp4857.pdf" in fips, "docs/compliance/fips.md must cite NIST #4857 sources"
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
        "#4857, FIPS 140-3 Level 1 | ACTIVE",
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
        "CODEOWNERS-gated" in vex_doc and "cosign attest --type openvex" in vex_doc,
        "docs/compliance/vex.md must describe VEX review and attestation flow",
    )
    for marker in [
        "SOURCE_DATE_EPOCH=1704067200",
        "tools/assert-reproducible.py --assert-byte-identical",
        "rewrite-timestamp=true",
        "docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130",
        "emulator-relative",
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
        "33c07782",
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
        "25 * 1024 * 1024 bytes",
        "exported-rootfs-regular-file-bytes",
        "tools/assert-footprint.py",
        "tools/assert-no-phantom-packages.py",
        "FIPS library closure",
        "rpmdb",
        "STEP022/STEP023",
    ]:
        require(marker in footprint_doc, f"docs/explanation/footprint.md missing marker: {marker}")

    for marker in [
        "https://nwarila.dev/attestations/nist-sp-800-190-image/v1",
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
        "https://nwarila.dev/attestations/stig-arf/v1",
        "ComplianceAsCode/content",
        "mass-N/A guard",
        "CODEOWNERS-gated",
        "tools/assert-rootfs-identity.py",
        "must-verify selected rule returning `notapplicable`",
        "every `rule-result` as `idref`",
    ]:
        require(marker in stig_doc, f"docs/compliance/stig.md missing marker: {marker}")

    for marker in [
        'cosign verify "${IMAGE_REF}"',
        "cosign verify-attestation --type spdxjson",
        "cosign verify-attestation --type cyclonedx",
        "cosign verify-attestation --type openvex",
        "cosign verify-attestation --type https://nwarila.dev/attestations/nist-sp-800-190-image/v1",
        "cosign verify-attestation --type https://nwarila.dev/attestations/stig-arf/v1",
        "full attestation set is Rekor-logged",
        "tools/assert-cosign-rekor.py",
        "signature JSON",
        "DSSE envelopes",
        "tools/assert-slsa-builder-id.py",
        'cosign download sbom "${IMAGE_REF}" | grep -q glibc',
        "Trivy",
        "Grype",
        "OpenVEX default-deny",
        "cosign verify-attestation --type slsaprovenance",
        "STIG ARF",
        "OpenSCAP",
        "per-rule `idref` result",
        "rootfs identity assertion report",
        "slsa-verifier verify-image",
        "generator_container_slsa3.yml@refs/tags/v2.1.0",
        "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a",
        "gh attestation verify` is not part of this contract",
        "BuildKit SBOM generation is disabled",
        "Syft rpmdb-derived",
        "P1.8",
    ]:
        require(marker in verify, f"docs/reference/verify.md missing marker: {marker}")

    for marker in [
        "tools/assert-reproducible.py",
        "tools/assert-rpm-lock-hashes.sh",
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
        OPENSSL_FIPS_PROVIDER_NEVRA,
        OPENSSL_FIPS_MODULE_VERSION,
        "linux/amd64",
        "linux/arm64",
        "CMVP #4857",
        "not a CMVP-validated operational environment",
        "fips_enabled =",
    ]:
        require(marker in fips_mechanism, f"docs/explanation/fips-mechanism.md missing marker: {marker}")

    for marker in [
        "cosign verify",
        "cosign verify-attestation --type spdxjson",
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
        "python tools/verify.py" in gate_howto and "bash tools/run-test-gates.sh" in gate_howto,
        "local gate how-to must cover verifier and full gate harness",
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
    for marker in [
        f'minimum_pre_commit_version: "{PRE_COMMIT_VERSION}"',
        "default_language_version:",
        "python: python3",
        "repo: https://github.com/shellcheck-py/shellcheck-py",
        f"rev: {SHELLCHECK_HOOK_REV}",
        "id: shellcheck",
        "args: [--severity=style]",
        "repo: https://github.com/scop/pre-commit-shfmt",
        f"rev: {SHFMT_HOOK_REV}",
        "id: shfmt",
        'args: [-w, -i, "2", -ci, -sr, -bn]',
        "repo: https://github.com/astral-sh/ruff-pre-commit",
        f"rev: {RUFF_HOOK_REV}",
        "id: ruff",
        "args: [--fix]",
        "id: ruff-format",
        "repo: https://github.com/pre-commit/mirrors-mypy",
        f"rev: {MYPY_HOOK_REV}",
        "id: mypy",
        "pass_filenames: false",
        "args: [--config-file=pyproject.toml, tools]",
        "repo: https://github.com/adrienverge/yamllint",
        f"rev: {YAMLLINT_HOOK_REV}",
        "id: yamllint",
        "args: [--strict, -c, .yamllint]",
        "repo: https://github.com/DavidAnson/markdownlint-cli2",
        f"rev: {MARKDOWNLINT_HOOK_REV}",
        "id: markdownlint-cli2",
        "files: ^.*\\.md$",
        "repo: https://github.com/hadolint/hadolint",
        f"rev: {HADOLINT_HOOK_REV}",
        "id: hadolint-docker",
        f"ghcr.io/hadolint/hadolint@{HADOLINT_IMAGE_DIGEST} hadolint",
        "args: [--config, .hadolint.yaml]",
        "repo: https://github.com/rhysd/actionlint",
        f"rev: {ACTIONLINT_HOOK_REV}",
        "id: actionlint",
    ]:
        require(marker in precommit, f".pre-commit-config.yaml missing marker: {marker}")
    require("repo: local" not in precommit, ".pre-commit-config.yaml must use pinned upstream hook repos")

    lint = read(".github/workflows/lint.yaml")
    for marker in [
        "name: Lint",
        "pull_request:\n    branches: [main]",
        "push:\n    branches: [main]",
        "workflow_dispatch:",
        "permissions: {}",
        "permissions:\n      contents: read",
        "runs-on: ubuntu-24.04",
        f"step-security/harden-runner@{HARDEN_RUNNER_SHA} # v2.19.4",
        "egress-policy: audit",
        f"actions/checkout@{CHECKOUT_SHA}",
        f"pre-commit=={PRE_COMMIT_VERSION}",
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


def main() -> int:
    checks = [
        check_required_files,
        check_community_profile,
        check_renovate_config,
        check_dockerfile,
        check_rpm_locks,
        check_workflow,
        check_supply_chain_workflows,
        check_lint_setup,
        check_publish_workflow,
        check_build_script,
        check_hardening_script,
        check_sbom_assertion_script,
        check_scanner_install_scripts,
        check_fips_config,
        check_fips_script,
        check_vex,
        check_nist_800_190_scripts,
        check_stig,
        check_decision_records,
        check_docs,
        check_helper_self_tests,
        check_no_attribution_residue,
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
