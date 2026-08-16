# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Added an exact, expiring accept-and-track disposition for the known-affected
  base-python `CVE-2026-11940` finding on `python3.12` and
  `python3.12-libs` at `3.12.13-3.el9_8.1`. The legacy local-product path is a
  two-key gate requiring both its closed in-tool authorization and the reviewed
  `affected` OpenVEX statement. The statement is now version 2 and also names a
  non-image-matchable policy scope for potential published platform children.
  The production path can derive an eligible digest-addressed child under the
  pinned `ghcr.io/nwarila/ubi9-base-python` repository from exact,
  digest-verified OCI index bytes and bind it to the architecture reported by
  both scanners. Its runnable-platform and descriptor-shape policy requires
  exactly one `linux/amd64` child and one `linux/arm64` child with distinct
  digests, admits only the locked BuildKit attestation shape otherwise,
  requires every descriptor digest to be unique across the index, and
  separately requires child and attestation digests to be disjoint. That path
  combines fixed in-tool constraints, the canonical statement, and registry
  index evidence. The
  publisher fetches those bytes once by the push-reported digest, corroborates
  their SHA-256, protects cross-job transfers, and uses that digest for every
  consumer. Its stricter publish-side resolver additionally requires exactly one
  BuildKit attestation reference per child; TD-11 tracks the VEX-side policy's
  weaker attestation cardinality.
  Both paths refuse valid fix evidence and byte-noncanonical scanner identities,
  expire after `review-by 2026-10-01`, suppress no raw finding, and do not make
  the image unaffected.
- Removed `sqlite-libs`, `libsqlite3`, and Python's optional `sqlite3` surface
  from `images/python/` on both architectures. The component was outside the
  image's declared supported surface and was the source of five unfixed scanner
  findings. Exact retained-payload, RPM verification, ELF dependency, runtime,
  rpmdb, SBOM, phantom-package, raw-scanner, and OpenVEX gates now prove the
  component is absent; consumers needing `sqlite3` must use a fuller Red Hat
  Python base or retain both the matching Python payload and library.
- Absorbed the Red Hat `glibc` z-stream update (`2.34-272.el9_8` → `2.34-274.el9_8`) on both
  architectures, remediating the fixable CVE-2026-5435, CVE-2026-5928, and CVE-2026-6238 findings the
  nightly sentinel flagged; reproducibility baselines re-established from the CI gate.
- The same lock refresh advanced the build-closure package `libacl`
  (`2.3.1-4.el9` → `2.4.0-1.el9_8`) on both architectures. `libacl` is a protected build-time
  dependency (`final_rpmdb=no`) that the rootfs build fully removes with `rpm -e`; neither its payload
  nor its rpmdb record ships (the phantom-package gate asserts its absence), so its version has no
  effect on the shipped image.

### Added

- `images/python/` evidence machinery: a python STIG tailoring and justification
  ledger, forked SBOM, NIST SP 800-190 and rootfs-secret gates, an OpenVEX
  disclosure, and the image contract's record of the identity the production
  publish workflow must use. The evidence chain runs in CI on locally built
  images for both architectures. The image still has no external or project
  publication, public or moving tag, signature, consumer-resolvable attestation,
  or transparency-log evidence; those require a completed production publish
  run.
- `images/python/`: the base-python image build — a pinned, signature-verified RPM
  transaction applied to a byte-asserted clone of the published `base-micro`
  parent, producing one truthful combined rpmdb; build-support packages are
  stripped behind ldd-ownership and floor-disjoint guards with intentional
  unsatisfied-Requires committed as a reviewed exception contract; the image
  ships from scratch as a single reproducible layer (non-root, python3.12
  entrypoint) and is gated in CI by tool self-tests, a functional stdlib battery
  with a real loopback TLS handshake, parent-subset invariance on the exported
  image, an OCI config contract, dual CVE scanners reading the combined rpmdb,
  and a both-arch byte-identical double-build. The image remains unpublished: it
  has no external or project publication, public or moving tag, signature, or
  consumer-resolvable attestation or digest yet.
- Added a registry-capable Python `release` Bake target and a pull-request-only
  preflight that invokes it once for both architectures. The preflight pushes a
  candidate index and unsigned BuildKit provenance to a loopback-bound ephemeral
  registry, reads both children back, and compares their rootfs and rpmdb state
  with the contract and same-commit `ci` builds. It creates no project package,
  external publication, production signature or attestation, SLSA or Rekor
  record, or consumer-resolvable digest.
- Added the guarded `base-python` publication workflow for `main` and
  `python/v*` pushes. It uses an unaliased digest-first candidate, per-child
  evidence and index-only trust/SLSA evidence, credentialed pre-alias
  verification, non-atomic collision detection with post-apply readback, and a
  separate anonymous post-visibility leg. This is publication capability only;
  the publisher is merged and its first production execution is awaited. No
  Python package, public artifact, or consumable image is claimed by this
  change.
- Added a fail-closed Python publish-scope policy. Python release tags always
  publish; a `main` push skips only when every changed path is in the closed
  unrelated allowlist, while Python-tree changes, consumed shared inputs,
  unknown paths, missing published-revision evidence, and empty deltas publish.
- Added the index-only Python trust-contract predicate and exact provenance
  policy. The predicate binds package, `images/python/` tree, workflow, and
  commit to the published index; the SLSA checks additionally bind the verified
  statement and Fulcio extensions to the exact source SHA/ref, Python caller,
  and pinned generator commit.

### Changed

- Expanded the micro publish-scope skip policy to a conservative closed set. A
  `main` push with an available, non-empty diff now skips publication when every
  changed path is under `images/` or `docs/`, or is exactly
  `.github/workflows/python-ci.yaml`, `.github/workflows/publish-python.yaml`,
  `tools/verify.py`, `README.md`, `SUPPORT.md`, `CHANGELOG.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, or `CODE_OF_CONDUCT.md`. Any unlisted path or ambiguity
  still publishes; skipping avoids a new publication and does not remove an
  already-published digest.
- Pinned the unpublished `base-python` builder input chain through one native
  Bake contract used by its CI and double-build paths. Python builders now
  fail before building unless the Buildx version, commit, Linux-amd64 asset
  SHA-256, BuildKit driver image, and derived BuildKit version match; repository
  checks also require the exact `base`/`ci`/`release`/`repro` target set, base-only
  inheritance, no protected-field redeclaration in the committed non-base
  targets, and contract-derived workflow pin inputs. Each named identity step
  must keep strict shell mode, omit `continue-on-error`, and end with the
  identity checker as its final unwrapped command. The verifier does not validate
  Bake command-line overrides or discover and count build callers. The new
  Buildx and BuildKit Renovate surfaces cannot automerge.
- Hardened repository self-verification: the required-file manifest is
  duplicate-free and its rejection fixture checks the exact reason; twelve
  `assert-vex.py` JSON/OpenVEX loader and parser probes, the raw-scanner marker's
  invalid-architecture probe, and all six SQLite absence probes likewise check
  their exact failure reasons.
- Aligned decision-envelope fixability with the OpenVEX classifier. Malformed
  Trivy or Grype fix metadata on HIGH or CRITICAL findings grants no fix and
  stays on the unfixed OpenVEX path. Grype's `fix.available` field remains
  descriptive and is deliberately excluded from fixability; both pull-request
  decisions and nightly drift issues report the resulting classification.
- Corrected the `base-python` raw-scanner gate so a valid zero-finding
  Trivy/Grype report pair passes. Trivy's package inventory now supplies the
  positive `python3.12-libs` marker, with epoch, version, release, and RPM
  architecture derived from `runtime.shipped[arch]`; Grype validates report
  identity, distro, source shape, and every present match while permitting
  `matches: []`. Normal invocations now require `--contract` and `--arch`, and
  the redundant early Grype visibility scan was removed.
- Tightened the same gate to reject malformed runtime-marker identities with
  extra epoch separators or colons in version/release, and to reject
  whitespace-bearing Trivy package names and Grype artifact names before the
  SQLite absence decision.
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
