# Verify a Published Image

Use this task after a publish run has produced a digest. The full command
contract lives in [`../reference/verify.md`](../reference/verify.md).

## Prerequisites

- `cosign`
- `crane`
- `slsa-verifier`
- Anonymous registry access to `ghcr.io/nwarila/ubi9-base-micro`
- An immutable per-commit tag for a completed publish

## Procedure

Resolve the image index and the `linux/amd64` platform child from the immutable per-commit tag, then set the publishing ref:

```sh
IMAGE="ghcr.io/nwarila/ubi9-base-micro"
TAG="base-micro-<short_sha>"                 # immutable per-commit tag (normative input)
INDEX_DIGEST="$(crane digest "${IMAGE}:${TAG}")"
INDEX_REF="${IMAGE}@${INDEX_DIGEST}"
CHILD_DIGEST="$(crane digest --platform linux/amd64 "${INDEX_REF}")"   # per-arch child
CHILD_REF="${IMAGE}@${CHILD_DIGEST}"
PUBLISH_REF="refs/heads/main"
```

The moving `base-micro` tag can help discover the latest publish. Resolve it once to `INDEX_REF` and anchor the child lookup to that reference so a concurrent publish cannot mix generations. The platform lookup also filters the index's `unknown/unknown` attestation descriptors.

Verify the canonical image signature on the index:

```sh
cosign verify "${INDEX_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify repository-generated attestations on each platform child digest:

```sh
cosign verify-attestation --type spdxjson "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign verify-attestation --type cyclonedx "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign verify-attestation --type https://nwarila.dev/attestations/nist-sp-800-190-image/v1 "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign verify-attestation --type https://nwarila.dev/attestations/stig-arf/v1 "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

If `vex/*.json` existed in the publishing commit, verify the OpenVEX
attestation too:

```sh
cosign verify-attestation --type openvex "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify index-bound SLSA provenance:

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

Do not substitute `gh attestation verify`; this repository's published evidence
uses Cosign OCI attestations.
