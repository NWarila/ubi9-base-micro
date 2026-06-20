#!/usr/bin/env python3
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


class VerifyError(Exception):
    pass


def require(condition: bool, message: str) -> None:
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


def check_required_files() -> None:
    for relative_path in [
        ".dockerignore",
        ".editorconfig",
        ".github/CODEOWNERS",
        ".github/renovate.json",
        ".github/workflows/build.yaml",
        ".github/workflows/nightly.yaml",
        ".github/workflows/publish-image.yaml",
        ".gitignore",
        "Makefile",
        "README.md",
        "VERSION",
        "containers/Dockerfile",
        "containers/fips/openssl.cnf",
        "rpm-lock/runtime.amd64.txt",
        "rpm-lock/runtime.arm64.txt",
        "docs/README.md",
        "docs/acceptance.md",
        "docs/fips.md",
        "docs/nist-800-190.md",
        "docs/footprint.md",
        "docs/reproducibility.md",
        "docs/stig.md",
        "docs/reference/verify.md",
        "docs/vex.md",
        "tests/fips.sh",
        "tests/hardening.sh",
        "tools/build.sh",
        "tools/run-test-gates.sh",
        "tools/assert-footprint.py",
        "tools/assert-no-phantom-packages.py",
        "tools/assert-reproducible.py",
        "tools/assert-rpm-lock-hashes.sh",
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

    require(action_pin_rule_index is not None, "Renovate config must keep ordinary GitHub Actions SHA-pinned")
    require(generator_rule_index is not None, "Renovate config must carry the TD-1 SLSA generator tag-pin rule")
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
        "ARG OPENSSL_FIPS_MODULE_VERSION=3.0.7-395c1a240fbfffd8",
        "ARG OPENSSL_FIPS_PROVIDER_NEVRA=openssl-fips-provider-so-3.0.7-8.el9",
        "ARG SOURCE_DATE_EPOCH=1704067200",
        "amd64) rpm_arch=\"x86_64\"",
        "arm64) rpm_arch=\"aarch64\"",
        "expected_provider_nevra=\"${OPENSSL_FIPS_PROVIDER_NEVRA}.${rpm_arch}\"",
        "COPY rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt /tmp/rpm-lock/",
        "COPY tools/assert-rpm-lock-hashes.sh /tmp/assert-rpm-lock-hashes.sh",
        "locked_packages=\"\"",
        "final runtime RPM lock floor verified",
        "bash /tmp/assert-rpm-lock-hashes.sh --root /rootfs --lockfile",
        "find /rootfs -xdev -exec touch -h -d \"@${SOURCE_DATE_EPOCH}\" {} +",
        "microdnf install -y --installroot=/rootfs",
        "--nodocs --setopt=install_weak_deps=0",
        "FROM ${UBI_MICRO_IMAGE} AS runtime",
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
        "/etc/nwarila/fips-status.json",
        "oe_validated=false",
        "NOT in CMVP #4857's validated or vendor-affirmed list",
        "/fips-proof/provider.nevra",
        "/fips-proof/expected-provider.nevra",
        "/fips-proof/libs.nevra",
        "/fips-proof/fips.so.sha256",
        "rpm --root=/rootfs -q --qf '%{NEVRA}\\n' openssl-fips-provider-so",
        "shipped_libs_nevra",
        "ldd-protected FIPS/glibc runtime dependency paths:",
        "rpm --root=/rootfs -e --nodeps --noscripts ${removable_packages}",
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
        require("@sha256:" in line, f"Dockerfile FROM must be digest-pinned: {line}")

    forbidden = [
        "rm -rf /rootfs/var/lib/rpm",
        "rm -rf /var/lib/rpm",
        "ghcr.io/nwarila-" + "platform",
        "fips" + "install",
        "OPENSSL_FIPS_PROVIDER_NEVRA=openssl-fips-provider-so-3.0.7-8.el9.x86_64",
    ]
    present = [marker for marker in forbidden if marker in text]
    require(not present, "Dockerfile contains forbidden marker(s): " + ", ".join(present))


def check_workflow() -> None:
    workflows = sorted(path.name for path in (ROOT / ".github/workflows").glob("*.y*ml"))
    require(
        workflows == ["build.yaml", "nightly.yaml", "publish-image.yaml"],
        "repo must ship exactly build.yaml, nightly.yaml, and publish-image.yaml",
    )

    build = read(".github/workflows/build.yaml")
    nightly = read(".github/workflows/nightly.yaml")
    gate_runner = read("tools/run-test-gates.sh")

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
        "tools/assert-vex.py --self-test",
        "tools/assert-no-rootfs-secrets.py --self-test",
        "tools/generate-nist-800-190-predicate.py --self-test",
        "tools/assert-slsa-builder-id.py --self-test",
        "tools/assert-stig-tailoring.py --self-test",
        "tools/assert-rootfs-identity.py --self-test",
        "tools/assert-stig-arf.py --self-test",
        "tools/generate-stig-arf-predicate.py --self-test",
        "bash -n tools/run-test-gates.sh",
        "UBI_MICRO_IMAGE: registry.access.redhat.com/ubi9/ubi-micro@sha256:",
        "TRIVY_VERSION: \"0.71.0\"",
        "GRYPE_VERSION: \"0.87.0\"",
        "SSG_VERSION: \"0.1.81\"",
        "SSG_TARBALL_SHA512: \"11e26cfa96a6f1bd98b3a131837e2f86c9a9851239337d86d624b01627faf10f7a03c395a5839ddab018e0fa47719ade05a9946f90d5ca96b1261776a9164379\"",
        "STIG_PROFILE: \"xccdf_org.nwarila.content_profile_ubi9_base_micro_stig\"",
        "STIG_FAIL_ON: \"low\"",
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
        "cron: \"23 4 * * *\"",
        "workflow_dispatch:",
        "contents: read",
        "cancel-in-progress: false",
        "tools/verify.py",
        "bash -n tools/run-test-gates.sh",
        "UBI_MICRO_IMAGE: registry.access.redhat.com/ubi9/ubi-micro@sha256:",
        "TRIVY_VERSION: \"0.71.0\"",
        "GRYPE_VERSION: \"0.87.0\"",
        "SSG_VERSION: \"0.1.81\"",
        "SSG_TARBALL_SHA512: \"11e26cfa96a6f1bd98b3a131837e2f86c9a9851239337d86d624b01627faf10f7a03c395a5839ddab018e0fa47719ade05a9946f90d5ca96b1261776a9164379\"",
        "STIG_PROFILE: \"xccdf_org.nwarila.content_profile_ubi9_base_micro_stig\"",
        "STIG_FAIL_ON: \"low\"",
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
        "bash tools/install-syft.sh",
        "bash tools/install-trivy.sh",
        "bash tools/install-grype.sh",
        "bash tools/install-openscap.sh",
        "bash tools/build-stig-datastream.sh",
        "bash tools/build.sh",
        "bash tests/hardening.sh \"${runtime_image}\"",
        "bash tests/fips.sh \"${runtime_image}\"",
        "tools/assert-footprint.py",
        "dist/footprint/base-micro.${arch}.json",
        "bash tools/run-stig-arf.sh",
        "dist/tools/syft scan",
        "json=dist/sbom/base-micro.${arch}.syft.json",
        "spdx-json=dist/sbom/base-micro.${arch}.spdx.json",
        "cyclonedx-json=dist/sbom/base-micro.${arch}.cdx.json",
        "--source \"dist/sbom/base-micro.${arch}.syft.json\"",
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
        "dist/tools/grype \"${runtime_image}\" --only-fixed --fail-on high",
        "--format json",
        "--file \"${grype_json}\"",
        "tools/assert-vex.py",
        "tools/assert-no-rootfs-secrets.py",
        "tools/generate-nist-800-190-predicate.py",
        "--validate \"${predicate}\"",
        "bash /tmp/assert-rpm-lock-hashes.sh --root /rootfs --lockfile",
    ]:
        require(marker in gate_runner or marker in read("containers/Dockerfile"), f"test gate runner missing marker: {marker}")

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
    ]:
        present = [marker for marker in forbidden if marker in source_text]
        require(not present, f"{source} contains out-of-scope marker(s): " + ", ".join(present))

    check_uses_pinned(build, "build workflow")
    check_uses_pinned(nightly, "nightly workflow")

def check_publish_workflow() -> None:
    text = read(".github/workflows/publish-image.yaml")
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
        "--output \"type=registry,rewrite-timestamp=true\"",
        "OPENSSL_FIPS_MODULE_VERSION",
        "OPENSSL_FIPS_PROVIDER_NEVRA",
        "SOURCE_DATE_EPOCH: \"1704067200\"",
        "OCI_CREATED: \"2024-01-01T00:00:00Z\"",
        "SYFT_VERSION: \"1.45.1\"",
        "TRIVY_VERSION: \"0.71.0\"",
        "GRYPE_VERSION: \"0.87.0\"",
        "tools/build-stig-datastream.sh",
        "tools/run-stig-arf.sh",
        "NIST_800_190_PREDICATE_TYPE: \"https://nwarila.dev/attestations/nist-sp-800-190-image/v1\"",
        "STIG_ARF_PREDICATE_TYPE: \"https://nwarila.dev/attestations/stig-arf/v1\"",
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
        "--source \"dist/sbom/base-micro.${arch}.syft.json\"",
        "Run Trivy fixable vulnerability gates",
        "dist/tools/trivy image",
        "--ignore-unfixed",
        "--severity HIGH,CRITICAL",
        "--exit-code 1",
        "Run Grype fixable vulnerability gates",
        "--only-fixed --fail-on high",
        "Run OpenVEX default-deny gates",
        "--format json",
        "--file \"${grype_json}\"",
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
        "cosign attest --type \"${NIST_800_190_PREDICATE_TYPE}\"",
        "cosign verify-attestation --type \"${NIST_800_190_PREDICATE_TYPE}\"",
        "cosign attest --type \"${STIG_ARF_PREDICATE_TYPE}\"",
        "cosign verify-attestation --type \"${STIG_ARF_PREDICATE_TYPE}\"",
        "rekor-rollup:",
        "Verify Rekor roll-up",
        "tools/assert-cosign-rekor.py",
        "verify_rekor \"cosign signature index\"",
        "verify_rekor \"cosign signature ${arch}\"",
        "assert_attestation_tlog",
        "cosign verify-attestation succeeded with Rekor transparency log enabled",
        "DSSE envelope(s)",
        "EXPECTED_BUILDER_ID",
        "tools/assert-slsa-builder-id.py",
        "cosign verify-attestation --type slsaprovenance",
        "STIG ARF",
        "OpenSCAP",
        "assert_attestation_tlog \"SLSA provenance index\"",
        "cosign verify-attestation --type spdxjson",
        "assert_attestation_tlog \"SPDX SBOM ${arch}\"",
        "cosign verify-attestation --type cyclonedx",
        "assert_attestation_tlog \"CycloneDX SBOM ${arch}\"",
        "assert_attestation_tlog \"NIST 800-190 image ${arch}\"",
        "assert_attestation_tlog \"STIG ARF ${arch}\"",
        "assert_attestation_tlog \"OpenVEX ${arch}\"",
        "COSIGN_YES: \"true\"",
        SLSA_GENERATOR + "@" + SLSA_GENERATOR_TAG,
        SLSA_GENERATOR_SHA,
        "gh api \"repos/slsa-framework/slsa-github-generator/git/ref/tags/${SLSA_GENERATOR_TAG}\"",
        "cosign sign --recursive",
        "cosign verify",
        "https://github.com/${{ github.repository }}/.github/workflows/publish-image.yaml@${{ github.ref }}",
        "--certificate-oidc-issuer \"https://token.actions.githubusercontent.com\"",
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
        "verify_rekor \"SLSA provenance",
        "verify_rekor \"SPDX SBOM",
        "verify_rekor \"CycloneDX SBOM",
        "verify_rekor \"NIST 800-190 image",
        "verify_rekor \"OpenVEX",
    ]
    present = [marker for marker in forbidden if marker in text]
    require(not present, "publish workflow contains forbidden marker(s): " + ", ".join(present))

    uses = WORKFLOW_USES.findall(text)
    generator_uses = [(action, ref) for action, ref in uses if action == SLSA_GENERATOR]
    require(generator_uses == [(SLSA_GENERATOR, SLSA_GENERATOR_TAG)], "publish workflow must use exactly one SLSA generator tag pin")
    check_uses_pinned(text, "publish workflow")


def check_build_script() -> None:
    text = read("tools/build.sh")
    for marker in [
        "docker buildx build",
        "--output \"type=docker,dest=${image_tar},rewrite-timestamp=true\"",
        "docker load -i \"${image_tar}\"",
        "--provenance=false",
        "--sbom=false",
        "SOURCE_DATE_EPOCH",
        "--target \"${target}\"",
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
        "RUNTIME_RPMDB_PATH = \"/var/lib/rpm\"",
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
    for platform_arch, rpm_arch in expected_arch.items():
        relative_path = f"rpm-lock/runtime.{platform_arch}.txt"
        rows = []
        for raw in read(relative_path).splitlines():
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
            rows.append((package, final_rpmdb, name))
        packages = [row[0] for row in rows]
        require(len(packages) == len(set(packages)), f"{relative_path}: duplicate package rows")
        require(len(packages) == 38, f"{relative_path}: expected 38 transaction RPMs, got {len(packages)}")
        final_names = {name for _, final_rpmdb, name in rows if final_rpmdb == "yes"}
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


def check_docs() -> None:
    readme = read("README.md")
    acceptance = read("docs/acceptance.md")
    fips = read("docs/fips.md")
    docs_index = read("docs/README.md")
    verify = read("docs/reference/verify.md")
    vex_doc = read("docs/vex.md")
    nist_doc = read("docs/nist-800-190.md")
    footprint_doc = read("docs/footprint.md")
    reproducibility_doc = read("docs/reproducibility.md")
    stig_doc = read("docs/stig.md")
    legacy_namespace = "ghcr.io/nwarila-" + "platform/*"
    require(legacy_namespace in acceptance, "acceptance copy should preserve source DoD text")
    require("superseded for this repository" in acceptance, "acceptance.md must flag the legacy platform namespace")
    require("Byte-for-byte reproducible (HARD gate)" in acceptance, "acceptance.md must carry hard F3 wording")
    require("explicitly retracted" not in acceptance, "acceptance.md must not preserve the old F3 retract escape")
    require("#4857" in fips, "docs/fips.md must record the OpenSSL CMVP #4857 ledger")
    require("3.0.7-395c1a240fbfffd8" in fips, "docs/fips.md must record the validated OpenSSL provider version")
    require("approved mode" in fips, "docs/fips.md must scope the OpenSSL claim to approved mode")
    require("fips_enabled" in fips and "= 0" in fips, "docs/fips.md must state the non-FIPS-host caveat")
    require("Per-architecture validation scope" in fips, "docs/fips.md must describe per-architecture validation scope")
    require("TD-3" in fips, "docs/fips.md must reference TD-3")
    require("oe_validated" in fips, "docs/fips.md must document fips-status.json oe_validated")
    require(
        "this aarch64 operational environment is NOT in CMVP #4857's validated or vendor-affirmed list" in fips
        and "this is NOT a CMVP-validated configuration on this architecture" in fips,
        "docs/fips.md missing arm64 disclaimer",
    )
    require("x86_64" in fips and "IBM Z" in fips and "POWER" in fips and "aarch64" in fips, "docs/fips.md must cite tested OE architecture scope")
    require("certificate/4857" in fips and "140sp4857.pdf" in fips, "docs/fips.md must cite NIST #4857 sources")

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
        "tailored STIG ARF",
        "byte-for-byte reproducibility",
        "Rekor-logged",
        "Responsibility boundary",
        "standard hardened floor",
        "rpmdb preserved",
        "Java `jdeps`/`jlink`",
        "stdlib pruning",
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
        require(marker in fips, f"docs/fips.md missing G2/G2a/G3 marker: {marker}")
    require("tailored RHEL9 STIG ARF gate" in readme and "docs/stig.md" in readme, "README.md must describe current STIG gate scope")
    require("reference/verify.md" in docs_index, "docs README must index verify contract")
    require("nist-800-190.md" in docs_index, "docs README must index NIST 800-190 evidence")
    require("footprint.md" in docs_index, "docs README must index footprint evidence")
    require("reproducibility.md" in docs_index, "docs README must index reproducibility evidence")
    require("stig.md" in docs_index, "docs README must index STIG evidence")
    require("vex.md" in docs_index, "docs README must index VEX flow")
    require("CODEOWNERS-gated" in vex_doc and "cosign attest --type openvex" in vex_doc, "docs/vex.md must describe VEX review and attestation flow")
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
    ]:
        require(marker in reproducibility_doc, f"docs/reproducibility.md missing marker: {marker}")
    require(
        "report-mode scope" not in docs_index,
        "docs/README.md must not describe reproducibility as report-mode scope",
    )
    require(
        "build-failing hard gate" in docs_index,
        "docs/README.md must describe reproducibility as a build-failing hard gate",
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
        require(marker in footprint_doc, f"docs/footprint.md missing marker: {marker}")

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
        require(marker in nist_doc, f"docs/nist-800-190.md missing marker: {marker}")

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
        require(marker in stig_doc, f"docs/stig.md missing marker: {marker}")

    for marker in [
        "cosign verify \"${IMAGE_REF}\"",
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
        "cosign download sbom \"${IMAGE_REF}\" | grep -q glibc",
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
        if path.suffix.lower() not in {".cnf", ".json", ".md", ".py", ".sh", ".xml", ".yaml", ".yml", ".dockerignore", ".gitignore", ""}:
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
        check_renovate_config,
        check_dockerfile,
        check_rpm_locks,
        check_workflow,
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
