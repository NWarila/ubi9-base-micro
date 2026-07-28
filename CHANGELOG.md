# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Absorbed the Red Hat `glibc` z-stream update (`2.34-272.el9_8` → `2.34-274.el9_8`) on both
  architectures, remediating the fixable CVE-2026-5435, CVE-2026-5928, and CVE-2026-6238 findings the
  nightly sentinel flagged; reproducibility baselines re-established from the CI gate.
- The same lock refresh advanced the build-closure package `libacl`
  (`2.3.1-4.el9` → `2.4.0-1.el9_8`) on both architectures. `libacl` is a protected build-time
  dependency (`final_rpmdb=no`) that the rootfs build fully removes with `rpm -e`; neither its payload
  nor its rpmdb record ships (the phantom-package gate asserts its absence), so its version has no
  effect on the shipped image.

### Added

- `images/python/`: the base-python image build — a pinned, signature-verified RPM
  transaction applied to a byte-asserted clone of the published `base-micro`
  parent, producing one truthful combined rpmdb; build-support packages are
  stripped behind ldd-ownership and floor-disjoint guards with intentional
  unsatisfied-Requires committed as a reviewed exception contract; the image
  ships from scratch as a single reproducible layer (non-root, python3.12
  entrypoint) and is gated in CI by tool self-tests, a functional stdlib battery
  with a real loopback TLS handshake, parent-subset invariance on the exported
  image, an OCI config contract, dual CVE scanners reading the combined rpmdb,
  and a both-arch byte-identical double-build. The image is built and gated
  only: it is not published, tagged, or attested yet.

### Changed

- Recorded the reversed base-image family topology in ADR-0010: planned language
  variants will live in this repository as `images/<variant>/` trees with
  per-image path-scoped publish workflows; the root micro image is unchanged.
- Gated micro publication on a publish-scope decision: a push to `main` whose
  entire delta against the currently published `:base-micro` revision lies under
  `images/` skips micro republication; every ambiguity publishes, and the gate
  contract is structurally locked by `tools/verify.py`.
- Seeded the `images/` family tree with its README and allowlist entries.
- Added the base `nonroot:65532` identity and home and set `HOME=/home/nonroot`.
  The base's default command remains a non-functional inherited placeholder on
  this shell-less base, so consumers must set their own exec-form `ENTRYPOINT`.
- Updated the published-image verification reference and how-to to verify
  repository-generated attestations on both platform children and fail closed if either child fails.
- Corrected enforcement, reproducibility, and published-image verification claims
  to match the active ruleset, builder scope, and index-versus-child digest routing.
- Suppressed repeat owner pings for unchanged unresolved nightly drift while preserving alerts for
  new, changed, or recurring incidents.
- Surfaced the failing gate's captured diagnostic line in nightly drift alerts.
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
