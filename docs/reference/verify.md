# Published Digest Verification

The publish workflow publishes `ghcr.io/nwarila/ubi9-base-micro` by digest from `.github/workflows/publish-image.yaml`. It signs the image digest with Cosign keyless from the repository workflow identity, attaches Syft rpmdb-derived SPDX and CycloneDX SBOM attestations to each platform child digest, gates fixable MEDIUM, HIGH, and CRITICAL findings with both Trivy and Grype, applies the OpenVEX default-deny policy to unfixed HIGH and CRITICAL findings, runs the tailored RHEL9 STIG ARF gate, generates and attests the NIST SP 800-190 section 4.1 image predicate and the STIG ARF summary predicate, then passes the index digest to the SLSA container generator reusable workflow. The final push-only roll-up verifies that the full attestation set is Rekor-logged.

This page is the completed-publication contract for `base-micro`. For
`base-python`, use the Python-specific commands in
[`../how-to/verify-a-published-image.md`](../how-to/verify-a-published-image.md#verify-base-python)
and the subject matrix in
[`verification-contract.md`](verification-contract.md#image-family-publication-evidence-contract).

## Prerequisites

- `cosign`
- `crane`
- `jq`
- `slsa-verifier`

## Identities

| Evidence | Exact identity |
| --- | --- |
| Image signature | `https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>` |
| SBOM SPDX and CycloneDX attestations | `https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>` |
| OpenVEX attestations, when `vex/*.json` is present | `https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>` |
| NIST SP 800-190 section 4.1 image attestation | `https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>` |
| STIG ARF attestation | `https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>` |
| SLSA provenance attestation | `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |

The SLSA generator tag `v2.1.0` is allowed only with the workflow tag-integrity guard asserting `refs/tags/v2.1.0 == f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`.

## Contract

Start from the policy-intended create-once per-commit tag for the completed publish. Resolve its image index and then resolve both platform children from that pinned index:

```sh
IMAGE="ghcr.io/nwarila/ubi9-base-micro"
TAG="base-micro-<short_sha>"                 # policy-intended create-once tag
INDEX_DIGEST="$(crane digest "${IMAGE}:${TAG}")"
INDEX_REF="${IMAGE}@${INDEX_DIGEST}"
AMD64_DIGEST="$(crane digest --platform linux/amd64 "${INDEX_REF}")"
AMD64_REF="${IMAGE}@${AMD64_DIGEST}"
ARM64_DIGEST="$(crane digest --platform linux/arm64 "${INDEX_REF}")"
ARM64_REF="${IMAGE}@${ARM64_DIGEST}"
PUBLISH_REF="refs/heads/main"
```

The moving `base-micro` tag may be used for discovery, but resolve it once to `INDEX_REF` and anchor every child lookup to that reference. This prevents a concurrent publish from mixing index and child generations. `crane digest --platform` selects the requested platform and filters the index's `unknown/unknown` attestation descriptors.

This is example output — your digests will differ:

```console
$ printf 'INDEX_REF=%s\nAMD64_REF=%s\nARM64_REF=%s\n' "${INDEX_REF}" "${AMD64_REF}" "${ARM64_REF}"
INDEX_REF=ghcr.io/nwarila/ubi9-base-micro@sha256:be8f76f648fa8d8245892059bda8a119a31c5d45c40b5ec6b64f1b270f050ab2
AMD64_REF=ghcr.io/nwarila/ubi9-base-micro@sha256:8280680a2218fe91cff051974b046b3a9ac61c81457ce61c86f098943b5ccc87
ARM64_REF=ghcr.io/nwarila/ubi9-base-micro@sha256:a98111c433a72b937ef9d34b0f78e56f252e65e7f7b61dd60f596292c8d0aa47
```

Use `INDEX_REF` for the canonical image signature and index-bound SLSA evidence. Use `AMD64_REF` and `ARM64_REF` for repository-generated attestations bound to both platform children.

```sh
cosign verify "${INDEX_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
set -euo pipefail
for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do
  cosign verify-attestation --type spdxjson "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
done
```

```sh
set -euo pipefail
for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do
  cosign verify-attestation --type cyclonedx "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
done
```

```sh
set -euo pipefail
for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do
  cosign verify-attestation --type spdxjson "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    | jq -r '.payload | @base64d | fromjson | .predicate.packages[].name' | grep -q glibc
done
```

When `vex/*.json` exists in the publishing commit, verify the OpenVEX attestation on each per-platform child digest:

```sh
set -euo pipefail
for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do
  cosign verify-attestation --type openvex "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
done
```

Verify the NIST SP 800-190 section 4.1 image-control predicate on each per-platform child digest:

```sh
set -euo pipefail
for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do
  cosign verify-attestation --type https://nwarila.dev/attestations/nist-sp-800-190-image/v1 "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
done
```

Verify the tailored RHEL9 STIG ARF predicate on each per-platform child digest:

```sh
set -euo pipefail
for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do
  cosign verify-attestation --type https://nwarila.dev/attestations/stig-arf/v1 "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
done
```

```sh
cosign verify-attestation --type slsaprovenance "${INDEX_REF}" \
  --certificate-identity "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
slsa-verifier verify-image "${INDEX_REF}" \
  --source-uri github.com/NWarila/ubi9-base-micro \
  --builder-id "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
```

The publish workflow also parses the verified SLSA predicate with `tools/assert-slsa-builder-id.py` and fails unless `builderID` is exactly `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0`.

## Rekor Roll-Up

The push-only `rekor-rollup` job verifies that the full attestation set is Rekor-logged: the Cosign signature, SLSA provenance, SPDX SBOM, CycloneDX SBOM, OpenVEX when `vex/*.json` exists, the NIST SP 800-190 section 4.1 predicate, and the tailored STIG ARF predicate. It uses `cosign verify` and `cosign verify-attestation` with exact identities and the default Rekor behavior; it does not use `--insecure-ignore-tlog`, `--tlog-upload=false`, or a custom Rekor URL. `tools/assert-cosign-rekor.py` checks the `cosign verify` signature JSON for the Rekor bundle fields that signature records carry. Attestation Rekor logging is proven by successful `cosign verify-attestation` with the transparency log enabled; cosign fails if the attestation has no accepted log entry, prints its tlog verification line, and writes DSSE envelopes with `payload` plus `signatures` rather than `optional.Bundle`.

`gh attestation verify` is not part of this contract. It verifies GitHub-native Artifact Attestations, not the cosign OCI attestation written by `generator_container_slsa3.yml` or the repository publish workflow.

## CVE And OpenVEX Policy

OpenSCAP builds ComplianceAsCode/content `0.1.81` from SHA512-pinned source, runs `stig/rhel9-base-micro-tailoring.xml`, and attests the `https://nwarila.dev/attestations/stig-arf/v1` predicate per platform digest. The STIG summary embedded in that predicate includes every per-rule `idref` result and the deterministic rootfs identity assertion report when OpenSCAP reports a selected must-verify identity or ownership rule as `notapplicable`. Trivy and Grype are installed as checksum-verified pinned binaries (`TRIVY_VERSION` and `GRYPE_VERSION`), not as scanner actions. Before scan results are accepted, `tools/assert-scanner-db-freshness.py` fails closed unless Trivy metadata and Grype DB status are fresh, parseable, and within the configured schema and age bounds. Both scanners fail the workflow on fixable MEDIUM, HIGH, and CRITICAL findings, subject only to the version-pinned TD-6 exception for `CVE-2026-31790` covering `openssl-fips-provider` and `openssl-fips-provider-so` at `3.0.7-8.el9`, expiring on `2026-10-10`: Trivy uses `--severity MEDIUM,HIGH,CRITICAL --ignore-unfixed --exit-code 1` with `security/cve-ignore.trivyignore.yaml`, and Grype uses `--only-fixed --fail-on medium` with `security/cve-ignore.grype.yaml`. A separate scanner pass without those fixable-only filters feeds `tools/assert-vex.py`, which fails closed unless every unfixed HIGH or CRITICAL finding has a matching reviewed OpenVEX statement under the CODEOWNERS-gated `vex/` path. If no unfixed HIGH or CRITICAL findings exist and no VEX JSON exists, there is no OpenVEX attestation to verify.

The gate has one exact accept-and-track entry. TD-12 covers the
known-affected unfixed HIGH `CVE-2026-14456` on exactly `openssl-libs` at
`1:3.5.5-5.el9_8` in base-python and base-micro. The entry and both surfaces expire after
`review-by 2026-10-01`.

The closed model has one entry and two statement surfaces: TD-12 Python and TD-12
micro. Local products use a two-key authorization. The exact disposition
surface and its byte-canonical reviewed `affected` statement must match for one
of the two base-python CI products or the locally loaded
`ghcr.io/nwarila/ubi9-base-micro:base-micro` product. Candidate selection must
resolve to exactly one surface; a CVE, statement, product, repository, or policy
IRI from one surface cannot authorize another.

A digest-addressed published child uses a three-key authorization: the exact
surface, its canonical statement, and paired `--index-reference` plus
`--index-manifest` evidence under that surface's pinned Python or micro
repository. The tool recomputes the digest of the exact supplied index bytes,
enforces exactly one `linux/amd64` child and one `linux/arm64` child with
distinct digests, locks the BuildKit attestation platform and annotations,
requires descriptor-digest uniqueness across all roles, and binds the eligible
digest to the architecture reported by both scanners. The index digest and
attestation digests are never eligible, and child/attestation digest aliasing is
rejected.

The VEX-side index policy does not constrain attestation count or per-child
reference cardinality and does not close either descriptor kind's top-level key
set or the runnable `platform` key set. The Python publisher's stricter resolver
rejects those measured shapes before its VEX gate. The micro publisher uses the
common VEX-side policy directly; TD-11 tracks that boundary.

Each merged caller supplies index evidence from the index that run pushed. The
Python publisher fetches the bytes once by the push-reported digest,
corroborates their SHA-256, checksum-protects cross-job transfers, and gives the
same digest to every consumer. The micro publisher supplies the pushed digest
and exact `dist/image-index.json` bytes it already read from the registry to
both child calls in the same job.

Valid fix evidence from either scanner and byte-noncanonical raw scanner
identities refuse authorization. `tools/verify.py` independently expires the
entry even if its scanner finding is absent. Its current summary locks 2 active canonical byte documents plus 1 fixed-history
document, the exact 1-entry/2-surface model, 12 active document mutations, 6
fixed-history mutations, 35 disposition documentation prose mutations across 6
files, and 1/1 dormant expiry; five verifier mutations and five corresponding checker
mutations must also fail. These paths do not make either image unaffected and
are not TD-6 fixable-CVE scanner suppressions.

## SBOM Source

BuildKit SBOM generation is disabled in the publish build with `--sbom=false`. The authoritative C3 evidence is the Syft rpmdb-derived SPDX and CycloneDX predicates emitted after push from the per-platform child digests. A gate-only Syft JSON inventory corroborates the required RPM names before the SPDX and CycloneDX predicates are attested, avoiding two competing SPDX documents with different source semantics.

`cosign download sbom` does not apply because the SBOM is delivered as the `spdxjson` and `cyclonedx` attestations, not as an attached BuildKit SBOM.

## Anonymous Pull Status

The `ghcr.io/nwarila/ubi9-base-micro` package is publicly readable. The complete
pull and verification chain above works from a clean machine without registry
authentication. Current and historical `base-python` service observations are
bound to an immutable digest in the
[canonical publication evidence contract](verification-contract.md#image-family-publication-evidence-contract).
