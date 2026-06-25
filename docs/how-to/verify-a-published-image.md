# Verify a Published Image

Use this task after a publish run has produced a digest. The full command
contract lives in [`../reference/verify.md`](../reference/verify.md).

## Prerequisites

- `cosign`
- `slsa-verifier`
- Anonymous registry access to `ghcr.io/nwarila/ubi9-base-micro`
- A published digest such as `ghcr.io/nwarila/ubi9-base-micro@sha256:<digest>`

## Procedure

Set the digest and publishing ref:

```sh
IMAGE_REF="ghcr.io/nwarila/ubi9-base-micro@sha256:<digest>"
PUBLISH_REF="refs/heads/main"
```

Verify the image signature:

```sh
cosign verify "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify repository-generated attestations on each platform child digest:

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
cosign verify-attestation --type https://nwarila.dev/attestations/nist-sp-800-190-image/v1 "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign verify-attestation --type https://nwarila.dev/attestations/stig-arf/v1 "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

If `vex/*.json` existed in the publishing commit, verify the OpenVEX
attestation too:

```sh
cosign verify-attestation --type openvex "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify SLSA provenance:

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

Do not substitute `gh attestation verify`; this repository's published evidence
uses Cosign OCI attestations.
