# Acceptance Criteria

This document states the acceptance policy for the published `base-micro`
artifact and the separately scoped pre-publication gates and publication
capability for `base-python`.
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
is produced only on pushes to `main`, root-image `v*` tags, and Python
`python/v*` tags, and anonymous verification is a separate post-publish check
against immutable digests. The active
`Pull Request Gate` ruleset requires its 11 named status-check contexts, which
block non-bypass merges. Its Repository Admin bypass (`RepositoryRole` 5,
`bypass_mode=always`) can bypass every rule in this ruleset; the solo maintainer
uses that bypass routinely because the approval requirements cannot be
self-satisfied. Required status checks have `strict=false`, so the pull-request
head need not be current with the base branch.

`base-python` is a separate pre-publication image path and remains externally
visible as a public package after the failed 2026-08-17 production attempt. It
has an active CI-rootfs preflight, a pull-request-only release
preflight, and a guarded production publication workflow. Its build and
reproducibility matrices run for both architectures on every push to `main` and
manual dispatch; pull requests keep the existing Python-tree and shared-gate
path selector. The release preflight runs on every pull request. The Python-only
Bake contract fixes the graph-affecting inputs and the distinct CI, release, and
double-build policies. The CI workflow pins and observes the Buildx executable
and BuildKit driver identities; the production workflow consumes verifier-locked
versions and action inputs. The verifier checks the committed contract for
exactly the `base`, `ci`, `release`, and `repro` targets, requires the three
non-base targets to inherit only `base`, and rejects protected graph-field
redeclarations. It also requires contract-derived setup and identity inputs,
with all five builder observations ordered before the CI builds. Each named
identity step must keep `set -euo pipefail` enabled, may not set
`continue-on-error`, and must finish with the identity checker as its final
unwrapped command.

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

The CI and pull-request preflight jobs grant `contents: read` only and contain no
external registry credential or login surface. In the production workflow,
package-write and OIDC permissions exist only on jobs that push, sign, or attest,
and every independently guarded privileged job requires the exact base
repository. The verifier checks those boundaries, the `main` and `python/v*`
trigger namespace, the digest-only export, complete evidence subject matrix,
exact identities, collision checks, and alias ordering. It also binds each
complete workflow to an expected SHA-256 and byte length. Those locks do not
cover pinned external code or every possible caller spelling. Neither preflight
creates a package in the project namespace, a public or moving alias, a
signature, a Cosign or GitHub artifact attestation, a SLSA or Rekor record, or a
consumer-resolvable digest. The 2026-08-17 production attempt did create the
public package and unaliased, unsigned candidate digests before it failed in
`registry-served gates and evidence` while `Install publication gate tools`
tried to install Syft without Cosign available. The earlier no publisher
limitation is superseded by the production workflow. The artifact is now a
public package serving unaliased, unsigned candidate digests after the gate job
failed. The Python
contract does not pin the micro build path and does not make the Python reducer a
claimed merge-blocking context.

Every privileged Python publication job skips on pull requests. The package's
two BuildKit `mode=max` provenance attestation manifests exist. No production
gate evidence, Cosign signature or attestation, SLSA-generator provenance,
Rekor record, or consumer alias exists. The missing Cosign prerequisite is now
repaired and lock-enforced; production proof remains pending the next `main`
push.

## Criteria and gates

| Criterion | Accepted state | Enforcing gate |
| --- | --- | --- |
| Pre-publication base-python build identity | The Bake contract contains exactly `base`, `ci`, `release`, and `repro`; all three non-base targets inherit the shared graph inputs without redeclaring protected fields. Before the CI-rootfs and reproducibility builds start, their builders must match the contracted Buildx version, commit, Linux-amd64 asset SHA-256, digest-qualified BuildKit image, and derived BuildKit version. On every `main` push and manual dispatch, both architecture build jobs build `ci` once, gate that loaded image, and compare its exported effective rootfs and rpmdb with the contract while binding revision, source, version, and created labels; the separate `repro` matrix retains its double-build byte-identity gate. On pull requests, the release preflight invokes `release` once for both architectures against a loopback-bound ephemeral registry, resolves the registry-served children, and checks their rootfs and rpmdb values against both the contract and same-commit `ci` builds. Its local candidate tag and unsigned BuildKit provenance are not an external or project publication. | `.github/workflows/python-ci.yaml`, `.github/workflows/publish-python.yaml`, `images/python/docker-bake.json`, `images/python/tools/assert-reproducible.py`, and `tools/verify.py`. |
| Base-python publication scope | Python release tags in the disjoint `python/v*` namespace always publish. On `main`, every Python-tree change and every enumerated shared input consumed by the publisher publishes. An unavailable published revision, empty delta, unclassified path, or malformed published config also publishes fail-closed. Only a delta entirely within the closed unrelated allowlist skips. | `.github/workflows/publish-python.yaml`, `tools/decide-python-publish-scope.py`, and its self-test and verifier locks. |
| Base-python publication capability | `main` and `python/v*` pushes in the base repository may push an unaliased candidate by digest. The push-reported digest selects the workflow's single registry index readback; SHA-256 over those exact bytes independently corroborates the push metadata, and checksum verification protects every cross-job transfer before the same digest reaches signing, attestation, VEX, or aliasing. SPDX, CycloneDX, OpenVEX, NIST SP 800-190, and STIG ARF evidence is required and verified on both platform children; the trust contract and SLSA provenance are index-only. A credentialed cache-cold verification completes before aliases. Create-once aliases receive mandatory pre-evidence and pre-apply collision checks plus post-apply readback, but the operation is not atomic against an external writer. A completed publish is distinct from public consumability: only an owner visibility change followed by successful anonymous verification establishes the latter. | `.github/workflows/publish-python.yaml`, `tools/resolve-python-index.py`, `tools/assert-python-alias-policy.py`, `tools/assert-python-attestation.py`, `tools/assert-python-provenance.py`, [`../reference/verification-contract.md`](../reference/verification-contract.md), and [`../TECH-DEBT.md`](../TECH-DEBT.md#td-10-base-python-create-once-alias-external-writer-race). |
| Base-python index trust and provenance identity | The index-only trust contract has one exact subject and binds package, `images/python/` tree, caller workflow, and commit. Successfully authenticated SLSA provenance must name the same sole index subject, source repository, SHA/ref, material, and Python `configSource.entryPoint`. The SLSA certificate must carry exactly one matching Build Signer Digest, source SHA/ref, and Build Config URI/Digest extension, including the pinned generator commit and exact Python caller. | `tools/python-trust-contract.py`, `tools/assert-python-attestation.py`, `tools/assert-python-provenance.py`, `tools/assert-python-slsa-certificate.py`, and `.github/workflows/publish-python.yaml`. |
| Multi-architecture runtime publication | The runtime target publishes as an OCI index with `linux/amd64` and `linux/arm64` children. The development target remains built-not-published. | `.github/workflows/publish-image.yaml` builds and pushes only the `runtime` target, then resolves both platform child digests. |
| Signed publication, contract assertion, and transparency evidence | The workflow must push the OCI index before it can export and compare the registry-served child rootfs bytes, and it requires each child's canonical rootfs digest and rpmdb digest to match `contracts/image-manifest.json` before this run's signing step and before producing repository attestations, SLSA provenance, and the Rekor roll-up. Until that assertion passes, mutable tags may resolve to a digest for which this run has emitted no signature or downstream attestations. If the assertion fails, the job stops before this run's signing step, but it cannot retract the pushed manifest or tag update. | `publish-image.yaml`; `tools/assert-reproducible.py --expect-from-contract`; `tools/assert-cosign-rekor.py`. |
| Anonymous base-micro consumer verification | A clean, unauthenticated consumer resolves one immutable index, verifies the Cosign signature on that index, verifies SPDX, CycloneDX, NIST SP 800-190, tailored STIG ARF, and any published OpenVEX attestations on each platform child, then verifies both the `slsaprovenance` attestation and `slsa-verifier` result on the index against exact identities. | The post-publish procedure in [`../reference/verify.md`](../reference/verify.md), reached through [`../how-to/verify-a-published-image.md`](../how-to/verify-a-published-image.md). Python's distinct private/public boundary is part of the publication-capability row above and its image-specific how-to. |
| Byte-for-byte reproducibility | **Byte-for-byte reproducible (HARD gate):** two builds from identical inputs must export byte-identical rootfs archives independently for `linux/amd64` and `linux/arm64`. The rpmdb remains in scope; byte differences are failures, with no normalization or retraction escape. Each published child must also match the per-architecture rootfs and rpmdb contract. | `.github/workflows/build.yaml` and `.github/workflows/nightly.yaml` run `tools/assert-reproducible.py --assert-byte-identical` for both architectures; `publish-image.yaml` runs the published-child `--expect-from-contract` assertion. |
| Runtime hardening | The runtime has no shell or package-manager executable, runs as UID 65532, retains a valid rpmdb, contains the CA bundle, and preserves the declared runtime identity and ownership constraints. | `tests/hardening.sh`, `tools/assert-rootfs-identity.py`, and `tools/assert-no-phantom-packages.py`, orchestrated by `tools/run-test-gates.sh` in `.github/workflows/build.yaml` and `.github/workflows/nightly.yaml`. |
| Fixable vulnerability policy | Trivy and Grype independently reject fixable MEDIUM, HIGH, and CRITICAL findings. The only exception is the repository's `TD-6`: `CVE-2026-31790` on exactly `openssl-fips-provider` and `openssl-fips-provider-so` at exactly `3.0.7-8.el9`, expiring on `2026-10-10`; both scanner configurations and `tools/assert-ignore-scope.py` enforce that two-package, version-pinned boundary. | `tools/run-test-gates.sh`, `security/cve-ignore.trivyignore.yaml`, `security/cve-ignore.grype.yaml`, and the equivalent per-child scanner steps in `publish-image.yaml`. |
| Unfixed vulnerability policy | Separately from the fixable gate, every unfixed HIGH or CRITICAL finding from either scanner is default-denied unless a reviewed OpenVEX statement has an accepted clearing status and matches the product. The live `CVE-2026-31790` statement is `affected`; it is disclosure only and clears nothing. The only gate-clearing `affected` case is one exact, expiring accept-and-track entry: TD-12 for known-affected `CVE-2026-14456` on exactly `openssl-libs` at `1:3.5.5-5.el9_8` in base-python and base-micro. It expires after `review-by 2026-10-01`. The closed model has two statement surfaces and requires exactly one to match the complete CVE, package/version set, product, repository, and statement path. Local Python CI products and the locally loaded `ghcr.io/nwarila/ubi9-base-micro:base-micro` product use two keys: the exact in-tool disposition surface and its canonical reviewed statement. A digest-addressed published child uses three: those two keys plus repository-correct, digest-verified OCI index evidence under the surface's pinned Python or micro repository. `assert-vex.py` requires exactly one distinct child per supported architecture, locks the BuildKit attestation platform and annotations, requires descriptor-digest uniqueness, and enforces child/attestation disjointness. It does not constrain attestation cardinality or duplicate references, close either descriptor kind's top-level key set, or close the runnable `platform` key set. The Python publisher's stricter resolver rejects those measured shapes before its VEX gate; the micro publisher uses the common VEX-side policy directly, as tracked by TD-11. Both publishers are configured to pass the pushed index digest and exact registry-read index bytes to each child call. Production proof of the new TD-12 published-child paths remains pending the merge-triggered runs. Every path requires byte-canonical raw scanner identities and refuses valid fix evidence. Padded identity evidence is malformed rather than normalized into authorization. This disposition suppresses no raw finding and does not make either image unaffected. | `tools/assert-vex.py`, `tools/resolve-python-index.py`, the CODEOWNERS-gated `vex/` and `images/python/vex/` documents, `tools/verify.py`, `.github/workflows/python-ci.yaml`, `.github/workflows/build.yaml`, `.github/workflows/publish-python.yaml`, and `.github/workflows/publish-image.yaml`. |
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
