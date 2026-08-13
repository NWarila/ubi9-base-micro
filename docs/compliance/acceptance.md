# Acceptance Criteria

This document states the acceptance policy for the published `base-micro`
artifact and the separately scoped pre-publication gates for `base-python`.
Command-level consumer verification of the published artifact is canonical in
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
is a separate post-publish check against immutable digests. The active
`Pull Request Gate` ruleset requires its 11 named status-check contexts, which
block non-bypass merges. Its Repository Admin bypass (`RepositoryRole` 5,
`bypass_mode=always`) can bypass every rule in this ruleset; the solo maintainer
uses that bypass routinely because the approval requirements cannot be
self-satisfied. Required status checks have `strict=false`, so the pull-request
head need not be current with the base branch.

`base-python` is a separate pre-publication image path with an active CI-rootfs
preflight and a pull-request-only release preflight; it remains externally
unpublished. Its build and reproducibility matrices run for both architectures
on every push to `main` and manual dispatch; pull requests keep the existing
Python-tree and shared-gate path selector. The release preflight runs on every
pull request. The Python-only Bake contract fixes the graph-affecting inputs and
the distinct CI, release, and double-build policies. The CI workflow pins and
observes the Buildx executable and BuildKit driver identities; the release
workflow consumes verifier-locked versions and action inputs. The verifier
checks the committed contract for exactly the `base`, `ci`, `release`, and
`repro` targets, requires the three non-base targets to inherit only `base`, and
rejects protected graph-field redeclarations. It also requires contract-derived
setup and identity inputs, with all five builder observations ordered before the
CI builds. Each named identity step must keep `set -euo pipefail` enabled, may
not set `continue-on-error`, and must finish with the identity checker as its
final unwrapped command.

Each build-matrix job builds the `ci` target once, runs the gate battery against
that loaded image, and checks the effective rootfs exported from the same image
against the committed architecture-specific `canonical_rootfs_digest` and
`rpmdb_sha256`. It also binds the revision, source, version, and created labels to
the current commit and committed inputs. The separate reproducibility matrix
continues to compare two `repro` builds and to assert the same contract fields.
These CI-rootfs checks cover effective rootfs entries and the rpmdb file, not an
OCI manifest digest, image-config digest, or exact future release child. The
release preflight separately invokes the registry-capable `release` target once
for both architectures, pushes only to a loopback-bound ephemeral registry,
reads the served index and child digests back, and compares each registry-served
rootfs both with the contract and with a same-commit `ci` build. Its local index,
candidate tag, and unsigned BuildKit provenance are pre-publication test
evidence, not a project publication.

Each Python workflow's `GITHUB_TOKEN` grants `contents: read` only, and the
committed YAML contains no configured registry credential or login surface. The
verifier checks those boundaries and binds each complete workflow to an
expected SHA-256 and byte length, so a YAML-surface change requires a
corresponding visible verifier edit. The locks do not cover separately invoked
scripts or pinned external code. Outside the specifically checked invocations,
the verifier does not interpret arbitrary Bake command-line overrides or
discover and count build callers. The contract has no publisher for external or
project publication, does not pin the micro build path, and does not make the Python reducer a
claimed merge-blocking context. Neither preflight creates a package in the
project namespace, a public or moving alias, a signature, a Cosign or GitHub
artifact attestation, a SLSA or Rekor record, or a consumer-resolvable digest.
The result remains built-and-gated, unpublished: no project or external
publication exists.

## Criteria and gates

| Criterion | Accepted state | Enforcing gate |
| --- | --- | --- |
| Pre-publication base-python build identity | The Bake contract contains exactly `base`, `ci`, `release`, and `repro`; all three non-base targets inherit the shared graph inputs without redeclaring protected fields. Before the CI-rootfs and reproducibility builds start, their builders must match the contracted Buildx version, commit, Linux-amd64 asset SHA-256, digest-qualified BuildKit image, and derived BuildKit version. On every `main` push and manual dispatch, both architecture build jobs build `ci` once, gate that loaded image, and compare its exported effective rootfs and rpmdb with the contract while binding revision, source, version, and created labels; the separate `repro` matrix retains its double-build byte-identity gate. On pull requests, the release preflight invokes `release` once for both architectures against a loopback-bound ephemeral registry, resolves the registry-served children, and checks their rootfs and rpmdb values against both the contract and same-commit `ci` builds. Its local candidate tag and unsigned BuildKit provenance are not an external or project publication. | `.github/workflows/python-ci.yaml`, `.github/workflows/publish-python.yaml`, `images/python/docker-bake.json`, `images/python/tools/assert-reproducible.py`, and `tools/verify.py`. |
| Multi-architecture runtime publication | The runtime target publishes as an OCI index with `linux/amd64` and `linux/arm64` children. The development target remains built-not-published. | `.github/workflows/publish-image.yaml` builds and pushes only the `runtime` target, then resolves both platform child digests. |
| Signed publication, contract assertion, and transparency evidence | The workflow must push the OCI index before it can export and compare the registry-served child rootfs bytes, and it requires each child's canonical rootfs digest and rpmdb digest to match `contracts/image-manifest.json` before this run's signing step and before producing repository attestations, SLSA provenance, and the Rekor roll-up. Until that assertion passes, mutable tags may resolve to a digest for which this run has emitted no signature or downstream attestations. If the assertion fails, the job stops before this run's signing step, but it cannot retract the pushed manifest or tag update. | `publish-image.yaml`; `tools/assert-reproducible.py --expect-from-contract`; `tools/assert-cosign-rekor.py`. |
| Anonymous consumer verification | A clean, unauthenticated consumer resolves one immutable index, verifies the Cosign signature on that index, verifies SPDX, CycloneDX, NIST SP 800-190, tailored STIG ARF, and any published OpenVEX attestations on each platform child, then verifies both the `slsaprovenance` attestation and `slsa-verifier` result on the index against exact identities. | The post-publish procedure in [`../reference/verify.md`](../reference/verify.md), reached through [`../how-to/verify-a-published-image.md`](../how-to/verify-a-published-image.md). The authenticated SBOM content check is summarized below; an attached-BuildKit-SBOM download path is not part of this contract. |
| Byte-for-byte reproducibility | **Byte-for-byte reproducible (HARD gate):** two builds from identical inputs must export byte-identical rootfs archives independently for `linux/amd64` and `linux/arm64`. The rpmdb remains in scope; byte differences are failures, with no normalization or retraction escape. Each published child must also match the per-architecture rootfs and rpmdb contract. | `.github/workflows/build.yaml` and `.github/workflows/nightly.yaml` run `tools/assert-reproducible.py --assert-byte-identical` for both architectures; `publish-image.yaml` runs the published-child `--expect-from-contract` assertion. |
| Runtime hardening | The runtime has no shell or package-manager executable, runs as UID 65532, retains a valid rpmdb, contains the CA bundle, and preserves the declared runtime identity and ownership constraints. | `tests/hardening.sh`, `tools/assert-rootfs-identity.py`, and `tools/assert-no-phantom-packages.py`, orchestrated by `tools/run-test-gates.sh` in `.github/workflows/build.yaml` and `.github/workflows/nightly.yaml`. |
| Fixable vulnerability policy | Trivy and Grype independently reject fixable MEDIUM, HIGH, and CRITICAL findings. The only exception is the repository's `TD-6`: `CVE-2026-31790` on exactly `openssl-fips-provider` and `openssl-fips-provider-so` at exactly `3.0.7-8.el9`, expiring on `2026-10-10`; both scanner configurations and `tools/assert-ignore-scope.py` enforce that two-package, version-pinned boundary. | `tools/run-test-gates.sh`, `security/cve-ignore.trivyignore.yaml`, `security/cve-ignore.grype.yaml`, and the equivalent per-child scanner steps in `publish-image.yaml`. |
| Unfixed vulnerability policy | Separately from the fixable gate, every unfixed HIGH or CRITICAL finding from either scanner is default-denied unless a reviewed OpenVEX statement has an accepted clearing status and matches the product. The live `CVE-2026-31790` statement is `affected`; it is disclosure only and clears nothing. The sole `affected` exception is the exact TD-9 accept-and-track path for known-affected `CVE-2026-11940` on the two base-python CI products, exactly `python3.12` and `python3.12-libs` at `3.12.13-3.el9_8.1`, through `review-by 2026-10-01`; both the in-tool allowlist and canonical reviewed statement must match, raw scanner vulnerability IDs, package names, and installed versions must have no surrounding whitespace, and valid fix evidence refuses it. Padded identity evidence is malformed rather than normalized into authorization. This does not make base-python unaffected. | `tools/assert-vex.py`, the CODEOWNERS-gated `vex/` and `images/python/vex/` documents, `tools/verify.py`, and the OpenVEX steps in `tools/run-test-gates.sh`, `.github/workflows/publish-image.yaml`, and `.github/workflows/python-ci.yaml`. |
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
