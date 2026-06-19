# Published Digest Verification

P1.4d publishes `ghcr.io/nwarila/ubi9-base-micro` by digest from `.github/workflows/publish-image.yaml`. The publish workflow signs the image digest with Cosign keyless from the repository workflow identity, attaches Syft rpmdb-derived SPDX and CycloneDX SBOM attestations to each platform child digest, gates fixable HIGH and CRITICAL findings with both Trivy and Grype, applies the OpenVEX default-deny policy to unfixed HIGH and CRITICAL findings, runs the tailored RHEL9 STIG ARF gate, generates and attests the NIST SP 800-190 section 4.1 image predicate and the STIG ARF summary predicate, then passes the index digest to the SLSA container generator reusable workflow. The final push-only roll-up verifies that the full attestation set is Rekor-logged.

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

Set `IMAGE_REF` to the published digest reference being verified, for example `ghcr.io/nwarila/ubi9-base-micro@sha256:<digest>`. For SBOM verification, use the per-platform child digest because the SBOM predicates are bound to `linux/amd64` and `linux/arm64` child manifests. Set `PUBLISH_REF` to the publishing Git ref, such as `refs/heads/main` or `refs/tags/v1.2.3`.

```sh
cosign verify "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign verify-attestation --type spdxjson "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign verify-attestation --type cyclonedx "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign download sbom "${IMAGE_REF}" | grep -q glibc
```

When `vex/*.json` exists in the publishing commit, verify the OpenVEX attestation on each per-platform child digest:

```sh
cosign verify-attestation --type openvex "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify the NIST SP 800-190 section 4.1 image-control predicate on each per-platform child digest:

```sh
cosign verify-attestation --type https://nwarila.dev/attestations/nist-sp-800-190-image/v1 "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify the tailored RHEL9 STIG ARF predicate on each per-platform child digest:

```sh
cosign verify-attestation --type https://nwarila.dev/attestations/stig-arf/v1 "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign verify-attestation --type slsaprovenance "${IMAGE_REF}" \
  --certificate-identity "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
slsa-verifier verify-image "${IMAGE_REF}" \
  --source-uri github.com/NWarila/ubi9-base-micro \
  --builder-id "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
```

The publish workflow also parses the verified SLSA predicate with `tools/assert-slsa-builder-id.py` and fails unless `builderID` is exactly `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0`.

## Rekor Roll-Up

The push-only `rekor-rollup` job verifies that the full attestation set is Rekor-logged: the Cosign signature, SLSA provenance, SPDX SBOM, CycloneDX SBOM, OpenVEX when `vex/*.json` exists, the NIST SP 800-190 section 4.1 predicate, and the tailored STIG ARF predicate. It uses `cosign verify` and `cosign verify-attestation` with exact identities and the default Rekor behavior; it does not use `--insecure-ignore-tlog`, `--tlog-upload=false`, or a custom Rekor URL. `tools/assert-cosign-rekor.py` checks the `cosign verify` signature JSON for the Rekor bundle fields that signature records carry. Attestation Rekor logging is proven by successful `cosign verify-attestation` with the transparency log enabled; cosign fails if the attestation has no accepted log entry, prints its tlog verification line, and writes DSSE envelopes with `payload` plus `signatures` rather than `optional.Bundle`.

`gh attestation verify` is not part of this contract. It verifies GitHub-native Artifact Attestations, not the cosign OCI attestation written by `generator_container_slsa3.yml` or the repository publish workflow.

## CVE And OpenVEX Policy

OpenSCAP builds ComplianceAsCode/content `0.1.81` from SHA512-pinned source, runs `stig/rhel9-base-micro-tailoring.xml`, and attests the `https://nwarila.dev/attestations/stig-arf/v1` predicate per platform digest. Trivy and Grype are installed as checksum-verified pinned binaries (`TRIVY_VERSION` and `GRYPE_VERSION`), not as scanner actions. Both scanners fail the workflow on fixable HIGH or CRITICAL findings: Trivy uses `--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1`, and Grype uses `--only-fixed --fail-on high`. A separate scanner pass without those fixable-only filters feeds `tools/assert-vex.py`, which fails closed unless every unfixed HIGH or CRITICAL finding has a matching reviewed OpenVEX statement under the CODEOWNERS-gated `vex/` path. If no unfixed HIGH or CRITICAL findings exist and no VEX JSON exists, there is no OpenVEX attestation to verify.

## SBOM Source

BuildKit SBOM generation is disabled in the publish build with `--sbom=false`. The authoritative C3 evidence is the Syft rpmdb-derived SPDX and CycloneDX predicates emitted after push from the per-platform child digests. A gate-only Syft JSON inventory corroborates the required RPM names before the SPDX and CycloneDX predicates are attested, avoiding two competing SPDX documents with different source semantics.

## Anonymous Pull Status

The commands above are the normative verification contract for a published digest. The full anonymous-pull run is P1.8 because the GHCR package auto-creates private on first publish and requires a one-time owner visibility change before unauthenticated verification can be proven.
