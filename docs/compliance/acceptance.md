# Acceptance Criteria

This document states the acceptance policy for the image produced by this
repository. Command-level consumer verification is canonical in
[`../how-to/verify-a-published-image.md`](../how-to/verify-a-published-image.md)
and [`../reference/verify.md`](../reference/verify.md); the separation between
pull-request, publish, and post-publish proof is summarized in
[`../reference/verification-contract.md`](../reference/verification-contract.md).

## Scope and enforcement boundaries

The published artifact is the `base-micro` runtime image at
`ghcr.io/nwarila/ubi9-base-micro`. The publish workflow creates one OCI index
with `linux/amd64` and `linux/arm64` children. The `base-micro-dev` target is
built for local and pull-request tests but is not published, signed, attested,
or covered by the post-publish claims below.

Pull-request checks prove only pre-publication properties. Publication evidence
is produced only on pushes to `main` and `v*` tags, and anonymous verification
is a separate post-publish check against immutable digests. The repository runs
the named checks when their workflows are triggered, but required status checks
are not enforced; these checks are not claimed to block merges.

## Criteria and gates

| Criterion | Accepted state | Enforcing gate |
| --- | --- | --- |
| Multi-architecture runtime publication | The runtime target publishes as an OCI index with `linux/amd64` and `linux/arm64` children. The development target remains built-not-published. | `.github/workflows/publish-image.yaml` builds and pushes only the `runtime` target, then resolves both platform child digests. |
| Signed publication, contract assertion, and transparency evidence | The publish workflow signs the index first. It then exports each published child and requires its canonical rootfs digest and rpmdb digest to match `contracts/image-manifest.json` before producing repository attestations, SLSA provenance, and the Rekor roll-up. Known residual: because the signature is written before the published-rootfs assertion, a later assertion failure stops all later evidence but cannot retract the already-written signature. | `publish-image.yaml`; `tools/assert-reproducible.py --expect-from-contract`; `tools/assert-cosign-rekor.py`. |
| Anonymous consumer verification | A clean, unauthenticated consumer resolves one immutable index, verifies the Cosign signature on that index, verifies SPDX, CycloneDX, NIST SP 800-190, tailored STIG ARF, and any published OpenVEX attestations on each platform child, then verifies both the `slsaprovenance` attestation and `slsa-verifier` result on the index against exact identities. | The post-publish procedure in [`../reference/verify.md`](../reference/verify.md), reached through [`../how-to/verify-a-published-image.md`](../how-to/verify-a-published-image.md). The authenticated SBOM content check is summarized below; an attached-BuildKit-SBOM download path is not part of this contract. |
| Byte-for-byte reproducibility | **Byte-for-byte reproducible (HARD gate):** two builds from identical inputs must export byte-identical rootfs archives independently for `linux/amd64` and `linux/arm64`. The rpmdb remains in scope; byte differences are failures, with no normalization or retraction escape. Each published child must also match the per-architecture rootfs and rpmdb contract. | `.github/workflows/build.yaml` and `.github/workflows/nightly.yaml` run `tools/assert-reproducible.py --assert-byte-identical` for both architectures; `publish-image.yaml` runs the published-child `--expect-from-contract` assertion. |
| Runtime hardening | The runtime has no shell or package-manager executable, runs as UID 65532, retains a valid rpmdb, contains the CA bundle, and preserves the declared runtime identity and ownership constraints. | `tests/hardening.sh`, `tools/assert-rootfs-identity.py`, and `tools/assert-no-phantom-packages.py`, orchestrated by `tools/run-test-gates.sh` in `.github/workflows/build.yaml` and `.github/workflows/nightly.yaml`. |
| Fixable vulnerability policy | Trivy and Grype independently reject fixable MEDIUM, HIGH, and CRITICAL findings. The only exception is the repository's `TD-6`: `CVE-2026-31790` on exactly `openssl-fips-provider` and `openssl-fips-provider-so` at exactly `3.0.7-8.el9`, expiring on `2026-10-10`; both scanner configurations and `tools/assert-ignore-scope.py` enforce that two-package, version-pinned boundary. | `tools/run-test-gates.sh`, `security/cve-ignore.trivyignore.yaml`, `security/cve-ignore.grype.yaml`, and the equivalent per-child scanner steps in `publish-image.yaml`. |
| Unfixed vulnerability policy | Separately from the fixable gate, every unfixed HIGH or CRITICAL finding from either scanner is default-denied unless a reviewed OpenVEX statement has an accepted clearing status and matches the product. The live `CVE-2026-31790` statement is `affected`; it is disclosure only and clears nothing. | `tools/assert-vex.py`, the CODEOWNERS-gated `vex/` documents, and the per-child scan and OpenVEX steps in `tools/run-test-gates.sh` and `publish-image.yaml`. |
| Scanner database freshness | Trivy metadata and Grype database status must be parseable, schema-compatible, and no older than the configured maximum age before either scanner result is accepted. | `tools/assert-scanner-db-freshness.py` in `tools/run-test-gates.sh` and `publish-image.yaml`. |
| Child SBOM evidence | Each published child has rpmdb-derived SPDX and CycloneDX attestations. A gate-only Syft inventory and both emitted formats must contain the required RPM floor and a nontrivial package count; phantom-package checks corroborate the inventory against exported runtime content and the rpmdb. | `tools/assert-sbom-rpms.py`, `tools/assert-no-phantom-packages.py`, and the per-child SBOM generation, attestation, and verified-payload checks in `publish-image.yaml`. |
| Rootfs secret exclusion | The exported runtime rootfs must pass the secret scan before NIST evidence is generated. | `tools/assert-no-rootfs-secrets.py` precedes `tools/generate-nist-800-190-predicate.py` in `tools/run-test-gates.sh` and `publish-image.yaml`. |
| Tailored STIG evidence | The pinned RHEL 9 ComplianceAsCode datastream and committed tailoring must produce a parseable ARF with no applicable failures at the configured threshold, no unaccounted mass-N/A omissions, and deterministic coverage for selected identity and ownership rules. Each child receives the tailored STIG ARF attestation. | `tools/assert-stig-tailoring.py`, `tools/assert-stig-arf.py`, `tools/assert-rootfs-identity.py`, `tools/run-stig-arf.sh`, and the per-child attestation steps in `publish-image.yaml`. |
| NIST SP 800-190 evidence | Each child receives the repository's validated NIST SP 800-190 section 4.1 image-control predicate, backed by the rootfs secret report and the other recorded image-control evidence. This is image evidence, not a CIS Docker host claim. | `tools/generate-nist-800-190-predicate.py` in `tools/run-test-gates.sh`; per-child generation, attestation, and verification in `publish-image.yaml`. |
| Per-architecture FIPS scope | Both architectures ship `openssl-fips-provider-so-3.0.7-8.el9`, configure the Red Hat OpenSSL provider in approved mode, run the provider self-test, reject MD5, and record the same module version. Only `linux/amd64` is within certificate #4857's validated operational environments. `linux/arm64` is approved-mode configured and self-test passing but explicitly is not a CMVP-validated configuration. Claims remain module-scoped and approved-mode-scoped as defined in [`fips.md`](fips.md). | The build-stage FIPS verification, `tests/fips.sh`, per-architecture status artifacts and manifest assertions, `tools/run-test-gates.sh`, and `publish-image.yaml`. |
| Runtime footprint | The `linux/amd64` runtime's exported-rootfs regular-file total must not exceed 25 MiB (26,214,400 bytes). No both-architecture footprint ceiling is claimed. | `tools/assert-footprint.py` through the default `linux/amd64` invocation of `tools/run-test-gates.sh`; measurement details are in [`../explanation/footprint.md`](../explanation/footprint.md). |
| Scheduled sentinel capability | A daily scheduled workflow can rerun repository verification, both-architecture byte reproducibility, and the default `linux/amd64` gate harness. It does not publish, prove a historical green streak, promise future currency, or block merges. | `.github/workflows/nightly.yaml`. |

## SBOM content verification

Package content is read only from a successfully verified SPDX attestation:

```sh
cosign verify-attestation --type spdxjson "${CHILD_REF}" \
  --certificate-identity "${CERTIFICATE_IDENTITY}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  | jq -r '.payload | @base64d | fromjson | .predicate.packages[].name' \
  | grep -q glibc
```

Every workflow gate above fails its workflow when the assertion cannot run or
the accepted state is not met. Post-publish signature, attestation, provenance,
transparency-log, and anonymous-pull claims require evidence from an actual
completed publish; pull-request success alone does not prove them.
