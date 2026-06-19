#!/usr/bin/env python3
"""Repository contract checks for ubi9-base-micro."""

from __future__ import annotations

import re
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
        ".github/workflows/build.yaml",
        ".github/workflows/publish-image.yaml",
        ".gitignore",
        "Makefile",
        "README.md",
        "VERSION",
        "containers/Dockerfile",
        "containers/fips/openssl.cnf",
        "docs/README.md",
        "docs/acceptance.md",
        "docs/fips.md",
        "docs/reference/verify.md",
        "docs/vex.md",
        "tests/fips.sh",
        "tests/hardening.sh",
        "tools/build.sh",
        "tools/install-syft.sh",
        "tools/install-trivy.sh",
        "tools/install-grype.sh",
        "tools/assert-sbom-rpms.py",
        "tools/assert-vex.py",
        "tools/verify.py",
        "vex/.gitkeep",
        "vex/README.md",
    ]:
        require((ROOT / relative_path).is_file(), f"missing required file: {relative_path}")


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
        "amd64) rpm_arch=\"x86_64\"",
        "arm64) rpm_arch=\"aarch64\"",
        "expected_provider_nevra=\"${OPENSSL_FIPS_PROVIDER_NEVRA}.${rpm_arch}\"",
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
    require(workflows == ["build.yaml", "publish-image.yaml"], "repo must ship exactly build.yaml and publish-image.yaml")

    text = read(".github/workflows/build.yaml")
    for marker in [
        "pull_request:",
        "branches: [main]",
        "tags:",
        "tools/build.sh",
        "tests/hardening.sh",
        "tests/fips.sh",
        "tools/verify.py",
        "tools/assert-sbom-rpms.py --self-test",
        "tools/assert-vex.py --self-test",
        "TRIVY_VERSION: \"0.71.0\"",
        "GRYPE_VERSION: \"0.87.0\"",
        "tools/install-trivy.sh",
        "tools/install-grype.sh",
        "Generate and verify runtime SBOMs",
        "dist/tools/syft scan",
        "json=dist/sbom/base-micro.${sbom_arch}.syft.json",
        "spdx-json=dist/sbom/base-micro.${sbom_arch}.spdx.json",
        "cyclonedx-json=dist/sbom/base-micro.${sbom_arch}.cdx.json",
        "--source \"dist/sbom/base-micro.${sbom_arch}.syft.json\"",
        "Run Trivy fixable vulnerability gate",
        "dist/tools/trivy image",
        "--ignore-unfixed",
        "--severity HIGH,CRITICAL",
        "--exit-code 1",
        "Run Grype fixable vulnerability gate",
        "dist/tools/grype \"${RUNTIME_IMAGE}\" --only-fixed --fail-on high",
        "Run OpenVEX default-deny gate",
        "--format json",
        "--file \"${grype_json}\"",
        "tools/assert-vex.py",
        "ghcr.io/nwarila/ubi9-base-micro",
    ]:
        require(marker in text, f"build workflow missing marker: {marker}")

    forbidden = [
        "NWarila/.github/.github/workflows/",
        "reusable-",
        "--" + "push",
        "docker " + "push",
        "co" + "sign",
        "generator_container_" + "sl" + "sa3",
        "attest-build-" + "provenance",
        "os" + "cap",
        "continue-on-" + "error",
    ]
    present = [marker for marker in forbidden if marker in text]
    require(not present, "build workflow contains out-of-scope marker(s): " + ", ".join(present))
    check_uses_pinned(text, "build workflow")


def check_publish_workflow() -> None:
    text = read(".github/workflows/publish-image.yaml")
    required = [
        "pull_request:",
        "push:",
        "branches: [main]",
        "tags:",
        "ghcr.io/nwarila/ubi9-base-micro",
        "github.event_name == 'push'",
        "--push",
        "--platform linux/amd64,linux/arm64",
        "--target runtime",
        "--provenance=mode=max",
        "--sbom=false",
        "--metadata-file dist/image-metadata.json",
        "OPENSSL_FIPS_MODULE_VERSION",
        "OPENSSL_FIPS_PROVIDER_NEVRA",
        "SYFT_VERSION: \"1.45.1\"",
        "TRIVY_VERSION: \"0.71.0\"",
        "GRYPE_VERSION: \"0.87.0\"",
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
        "attest-build-" + "provenance",
        "gh attestation verify",
        "continue-on-" + "error",
        "os" + "cap",
        "examples/image-manifest.json",
        "tools/build_app.sh",
        "tools/generate_build_args.py",
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
        "--load",
        "--provenance=false",
        "--sbom=false",
        "--target runtime",
        "--target dev",
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

def check_docs() -> None:
    acceptance = read("docs/acceptance.md")
    fips = read("docs/fips.md")
    docs_index = read("docs/README.md")
    verify = read("docs/reference/verify.md")
    vex_doc = read("docs/vex.md")
    legacy_namespace = "ghcr.io/nwarila-" + "platform/*"
    require(legacy_namespace in acceptance, "acceptance copy should preserve source DoD text")
    require("superseded for this repository" in acceptance, "acceptance.md must flag the legacy platform namespace")
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
    require("reference/verify.md" in docs_index, "docs README must index verify contract")
    require("vex.md" in docs_index, "docs README must index VEX flow")
    require("CODEOWNERS-gated" in vex_doc and "cosign attest --type openvex" in vex_doc, "docs/vex.md must describe VEX review and attestation flow")

    for marker in [
        "cosign verify \"${IMAGE_REF}\"",
        "cosign verify-attestation --type spdxjson",
        "cosign verify-attestation --type cyclonedx",
        "cosign verify-attestation --type openvex",
        "cosign download sbom \"${IMAGE_REF}\" | grep -q glibc",
        "Trivy",
        "Grype",
        "OpenVEX default-deny",
        "cosign verify-attestation --type slsaprovenance",
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
        "co-authored" + "-by",
        "generated" + " with",
    ]
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        if path.suffix.lower() not in {".cnf", ".md", ".py", ".sh", ".yaml", ".yml", ".dockerignore", ".gitignore", ""}:
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
        check_dockerfile,
        check_workflow,
        check_publish_workflow,
        check_build_script,
        check_hardening_script,
        check_sbom_assertion_script,
        check_scanner_install_scripts,
        check_fips_config,
        check_fips_script,
        check_vex,
        check_docs,
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
