# ADR-0011: Pin GitHub-Hosted Runner Labels

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

The repository already pins third-party workflow actions by commit SHA, pins
container inputs by digest, and verifies the SLSA generator tag with an explicit
commit guard. The remaining hosted-runner alias, `ubuntu-latest`, is a moving
label. GitHub documents `-latest` runner images as the latest stable images it
provides, not necessarily the most recent operating-system release.

For this image, CI runner drift matters because the build workflows install
scanner and build tools, run shell gates, and prove byte-for-byte rootfs
reproducibility for linux/amd64 and linux/arm64.

## Decision

All GitHub-hosted Ubuntu jobs in this repository use `runs-on: ubuntu-24.04`
instead of `runs-on: ubuntu-latest`. The repository verifier rejects the moving
alias and requires the pinned runner label in build, nightly, refresh, and
publish workflows.

This pin controls the workflow host label only. It does not replace digest pins,
RPM lockfiles, SLSA verification, Rekor checks, scanner gates, or rootfs
reproducibility proofs.

## Consequences

- Workflow host upgrades become explicit repository changes instead of ambient
  alias drift.
- Build and reproducibility evidence is easier to compare across runs.
- The repository must deliberately review and update the runner label when
  GitHub deprecates the selected image.

## References

- GitHub-hosted runners reference:
  <https://docs.github.com/en/actions/reference/runners/github-hosted-runners>
- GitHub workflow token permissions:
  <https://docs.github.com/actions/security-for-github-actions/security-guides/automatic-token-authentication>
- Repository workflows: `.github/workflows/build.yaml`,
  `.github/workflows/nightly.yaml`, `.github/workflows/publish-image.yaml`,
  `.github/workflows/rpm-lock-refresh.yaml`