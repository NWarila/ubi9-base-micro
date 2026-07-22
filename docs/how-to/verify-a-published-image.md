# Verify a Published Image

Use this task after a publish run has produced a digest. The full command
contract lives in [`../reference/verify.md`](../reference/verify.md).

## Prerequisites

- `cosign`
- `crane`
- Python 3.12
- `slsa-verifier`
- Anonymous registry access to `ghcr.io/nwarila/ubi9-base-micro`
- An immutable per-commit tag for a completed publish
- A repository checkout at the publishing commit

## Procedure

Resolve the image index and both platform children from the immutable per-commit
tag, then set the publishing ref:

```sh
IMAGE="ghcr.io/nwarila/ubi9-base-micro"
TAG="base-micro-<short_sha>"                 # immutable per-commit tag (normative input)
INDEX_DIGEST="$(crane digest "${IMAGE}:${TAG}")"
INDEX_REF="${IMAGE}@${INDEX_DIGEST}"
AMD64_DIGEST="$(crane digest --platform linux/amd64 "${INDEX_REF}")"
AMD64_REF="${IMAGE}@${AMD64_DIGEST}"
ARM64_DIGEST="$(crane digest --platform linux/arm64 "${INDEX_REF}")"
ARM64_REF="${IMAGE}@${ARM64_DIGEST}"
PUBLISH_REF="refs/heads/main"
```

The moving `base-micro` tag can help discover the latest publish. Resolve it
once to `INDEX_REF` and anchor both child lookups to that reference so a
concurrent publish cannot mix generations. Each platform lookup also filters
the index's `unknown/unknown` attestation descriptors.

Export and assert both immutable platform children against the publishing commit's
rootfs contract:

```sh
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

for ARCH in amd64 arm64; do
  case "${ARCH}" in
    amd64) CHILD_REF="${AMD64_REF}" ;;
    arm64) CHILD_REF="${ARM64_REF}" ;;
  esac
  ROOTFS_TAR="${tmp_dir}/base-micro.${ARCH}.tar"
  crane export "${CHILD_REF}" "${ROOTFS_TAR}"
  python3.12 tools/assert-reproducible.py \
    --rootfs-tar "${ROOTFS_TAR}" \
    --arch "${ARCH}" \
    --expect-from-contract contracts/image-manifest.json
done
```

Each assertion fails closed unless both `canonical_rootfs_digest` and
`rpmdb_sha256` match the contract for that architecture.

Verify the canonical image signature on the index:

```sh
cosign verify "${INDEX_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify repository-generated attestations on both platform child digests. The
loop binds `CHILD_REF` to each architecture-specific reference in turn, so each
attestation is verified against the child it describes:

```sh
for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do
  cosign verify-attestation --type spdxjson "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

  cosign verify-attestation --type cyclonedx "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

  cosign verify-attestation --type https://nwarila.dev/attestations/nist-sp-800-190-image/v1 "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

  cosign verify-attestation --type https://nwarila.dev/attestations/stig-arf/v1 "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
done
```

If `vex/*.json` existed in the publishing commit, verify the OpenVEX attestation
on both child digests too:

```sh
for CHILD_REF in "${AMD64_REF}" "${ARM64_REF}"; do
  cosign verify-attestation --type openvex "${CHILD_REF}" \
    --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
done
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
