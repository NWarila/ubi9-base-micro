# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Pinned the complete `fips-verify` OpenSSL closure to direct Red Hat UBI CDN
  RPMs, ending live-metadata package resolution in that stage.
- Absorbed the Red Hat `openssl-libs` z-stream update (`3.5.5-4.el9_8` → `3.5.5-5.el9_8`) on
  both architectures; reproducibility baselines re-established from the CI gate.
- Refreshed the digest-pinned Red Hat UBI 9 base images and updated the
  byte-for-byte reproducibility baselines.

## [1.0.0] - 2026-07-12

### Added

- UBI 9 `base-micro` and `base-micro-dev` image build path with digest-pinned
  Red Hat UBI inputs and architecture-specific runtime RPM lockfiles.
- Test-only pull-request gates for repository contract checks, hardening, FIPS,
  footprint, STIG ARF, SBOM derivation, dual-scanner vulnerability checks,
  OpenVEX default-deny coverage, NIST SP 800-190 image-control evidence, and
  both-architecture byte-for-byte rootfs reproducibility.
- Publish workflow for main and `v*` tags that signs the pushed image digest,
  attaches rpmdb-derived SPDX and CycloneDX SBOM attestations, attaches NIST
  SP 800-190 and tailored STIG ARF predicates, invokes the SLSA L3 container
  provenance generator, and verifies the Rekor-logged evidence set.
- Repository documentation for FIPS scope, footprint, reproducibility, VEX,
  STIG, NIST SP 800-190, published digest verification, and repo-scope decision
  records.
- Community health files, issue forms, and a repository-specific pull request
  checklist.

### Security

- Runtime hardening contract for no shell, no package-manager executable,
  preserved rpmdb, CA trust, and non-root `USER 65532:65532`.
- Module-scoped OpenSSL FIPS provider approved-mode evidence, with per-
  architecture scope recorded in the documentation.
- Runtime RPM locks refreshed for the shipped UBI 9 glibc errata, with the
  refreshed byte-for-byte reproducibility baseline recorded in the image
  contract.
- Coordinated vulnerability reporting through GitHub private vulnerability
  reporting.
