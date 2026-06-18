#!/usr/bin/env python3
"""Repository contract checks for ubi9-base-micro."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_USES = re.compile(r"uses:\s+([^@\s]+)@([^\s#]+)")
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class VerifyError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerifyError(message)


def read(relative_path: str) -> str:
    path = ROOT / relative_path
    require(path.is_file(), f"missing required file: {relative_path}")
    return path.read_text(encoding="utf-8")


def check_required_files() -> None:
    for relative_path in [
        ".dockerignore",
        ".editorconfig",
        ".github/CODEOWNERS",
        ".github/workflows/build.yaml",
        ".gitignore",
        "Makefile",
        "README.md",
        "VERSION",
        "containers/Dockerfile",
        "docs/README.md",
        "docs/acceptance.md",
        "docs/fips.md",
        "tests/hardening.sh",
        "tools/build.sh",
        "tools/install-syft.sh",
        "tools/verify.py",
    ]:
        require((ROOT / relative_path).is_file(), f"missing required file: {relative_path}")


def check_dockerfile() -> None:
    text = read("containers/Dockerfile")
    required = [
        "# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-minimal",
        "# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-micro",
        "ARG UBI_MINIMAL_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal@sha256:",
        "ARG UBI_MICRO_IMAGE=registry.access.redhat.com/ubi9/ubi-micro@sha256:",
        "microdnf install -y --installroot=/rootfs",
        "--nodocs --setopt=install_weak_deps=0",
        "FROM ${UBI_MICRO_IMAGE} AS runtime",
        "FROM ${UBI_MICRO_IMAGE} AS dev",
        "COPY --from=rpm-rootfs /rootfs/ /",
        "COPY --from=dev-rootfs /rootfs/ /",
        "USER 65532:65532",
        "var/lib/rpm",
        "ca-certificates",
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
    ]
    present = [marker for marker in forbidden if marker in text]
    require(not present, "Dockerfile contains forbidden marker(s): " + ", ".join(present))


def check_workflow() -> None:
    workflows = sorted((ROOT / ".github/workflows").glob("*.y*ml"))
    require(len(workflows) == 1, "STEP014 must ship exactly one workflow")

    text = read(".github/workflows/build.yaml")
    for marker in [
        "pull_request:",
        "branches: [main]",
        "tags:",
        "tools/build.sh",
        "tests/hardening.sh",
        "tools/verify.py",
        "ghcr.io/nwarila/ubi9-base-micro",
    ]:
        require(marker in text, f"workflow missing marker: {marker}")

    forbidden = [
        "NWarila/.github/.github/workflows/",
        "reusable-",
        "--" + "push",
        "docker " + "push",
        "co" + "sign",
        "generator_container_" + "sl" + "sa3",
        "attest-build-" + "provenance",
        "tri" + "vy",
        "gry" + "pe",
        "os" + "cap",
        "continue-on-" + "error",
    ]
    present = [marker for marker in forbidden if marker in text]
    require(not present, "workflow contains out-of-scope marker(s): " + ", ".join(present))

    uses = WORKFLOW_USES.findall(text)
    require(uses, "workflow should pin external actions explicitly")
    bad_refs = [f"{action}@{ref}" for action, ref in uses if not SHA40.fullmatch(ref)]
    require(not bad_refs, "workflow uses entries must be pinned to 40-char SHA: " + ", ".join(bad_refs))




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


def check_docs() -> None:
    acceptance = read("docs/acceptance.md")
    fips = read("docs/fips.md")
    read("docs/README.md")
    legacy_namespace = "ghcr.io/nwarila-" + "platform/*"
    require(legacy_namespace in acceptance, "acceptance copy should preserve source DoD text")
    require("superseded for this repository" in acceptance, "acceptance.md must flag the legacy platform namespace")
    require("P1.3" in fips, "docs/fips.md must state that FIPS is filled by P1.3")
    require("does not claim FIPS" in fips, "docs/fips.md must avoid a present FIPS claim")


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
        if path.suffix.lower() not in {".md", ".py", ".sh", ".yaml", ".yml", ".dockerignore", ".gitignore", ""}:
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
        check_build_script,
        check_hardening_script,
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
