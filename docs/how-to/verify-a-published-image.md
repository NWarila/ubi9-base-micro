# Verify a Published Image

Use this task after a publish run has produced a digest. The completed
`base-micro` command contract lives in
[`../reference/verify.md`](../reference/verify.md). The Python-specific contract
is summarized in
[`../reference/verification-contract.md`](../reference/verification-contract.md#base-python-publication-evidence-contract);
the Python steps below apply only to a digest reported by a successful
production publish.

## Prerequisites

- `cosign`
- `crane`
- Python 3.12
- `slsa-verifier`
- Anonymous registry access to `ghcr.io/nwarila/ubi9-base-micro`
- A policy-intended create-once per-commit tag for a completed publish
- A repository checkout at the publishing commit

## Procedure

Resolve the image index and both platform children from the policy-intended
create-once per-commit tag, then set the publishing ref:

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

The moving `base-micro` tag can help discover the latest publish. Resolve it
once to `INDEX_REF` and anchor both child lookups to that reference so a
concurrent publish cannot mix generations. Each platform lookup also filters
the index's `unknown/unknown` attestation descriptors.

Export and assert both immutable platform children against the publishing commit's
rootfs contract:

```sh
set -euo pipefail
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
set -euo pipefail
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
set -euo pipefail
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

## Verify base-python

Current and historical Python publication evidence is in the
[canonical publication evidence contract](../reference/verification-contract.md#base-python-publication-evidence-contract).
Use this procedure only after a successful Python publish run reports its
immutable index digest and publishing SHA/ref.

There are two distinct verification states. During publication, a fresh runner
logs in to GHCR and performs the cache-cold `cosign verify-attestation` and
`slsa-verifier` checks against the unaliased digest before the final job applies
consumer aliases. Success of that credentialed leg establishes the production
evidence but not anonymous access. Repeat the checks from a fresh client with no
registry credentials; only success of that genuinely anonymous leg establishes
that the evidenced digest was publicly consumable at the observation time.

The commands below are the anonymous leg. Start with an empty registry-auth
directory; do not log in to GHCR in this shell:

```sh
set -euo pipefail
VERIFY_AUTH_DIR="$(mktemp -d)"
trap 'rm -rf -- "${VERIFY_AUTH_DIR}"' EXIT
export DOCKER_CONFIG="${VERIFY_AUTH_DIR}"
export REGISTRY_AUTH_FILE="${VERIFY_AUTH_DIR}/containers-auth.json"
IMAGE="ghcr.io/nwarila/ubi9-base-python"
TAG="base-python-<first-12-lowercase-hex-of-publishing-sha>"
PUBLISH_SHA="<40-lowercase-hex-publishing-sha>"
PUBLISH_REF="refs/heads/main" # or refs/tags/python/v<version>
INDEX_DIGEST="$(crane digest "${IMAGE}:${TAG}")"
INDEX_REF="${IMAGE}@${INDEX_DIGEST}"
AMD64_DIGEST="$(crane digest --platform linux/amd64 "${INDEX_REF}")"
ARM64_DIGEST="$(crane digest --platform linux/arm64 "${INDEX_REF}")"
AMD64_REF="${IMAGE}@${AMD64_DIGEST}"
ARM64_REF="${IMAGE}@${ARM64_DIGEST}"
PUBLISH_IDENTITY="https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-python.yaml@${PUBLISH_REF}"
SLSA_IDENTITY="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
ISSUER="https://token.actions.githubusercontent.com"
```

Verify the index and both recursively signed children:

```sh
cosign verify "${INDEX_REF}" \
  --certificate-identity "${PUBLISH_IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --certificate-github-workflow-repository NWarila/ubi9-base-micro \
  --certificate-github-workflow-sha "${PUBLISH_SHA}" \
  --certificate-github-workflow-ref "${PUBLISH_REF}"
cosign verify "${AMD64_REF}" \
  --certificate-identity "${PUBLISH_IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --certificate-github-workflow-repository NWarila/ubi9-base-micro \
  --certificate-github-workflow-sha "${PUBLISH_SHA}" \
  --certificate-github-workflow-ref "${PUBLISH_REF}"
cosign verify "${ARM64_REF}" \
  --certificate-identity "${PUBLISH_IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --certificate-github-workflow-repository NWarila/ubi9-base-micro \
  --certificate-github-workflow-sha "${PUBLISH_SHA}" \
  --certificate-github-workflow-ref "${PUBLISH_REF}"
```

Verify the complete per-child predicate matrix:

- SPDX rpmdb SBOM, CycloneDX rpmdb SBOM, OpenVEX, NIST SP 800-190, and STIG ARF
  are each required on both the `linux/amd64` and `linux/arm64` child digests.
- The Python trust contract and SLSA provenance are required on the index only.

```sh
set -euo pipefail
verify_python_child() {
  PYTHON_CHILD_REF="$1"
  cosign verify-attestation --type spdxjson "${PYTHON_CHILD_REF}" \
    --certificate-identity "${PUBLISH_IDENTITY}" \
    --certificate-oidc-issuer "${ISSUER}"
  cosign verify-attestation --type cyclonedx "${PYTHON_CHILD_REF}" \
    --certificate-identity "${PUBLISH_IDENTITY}" \
    --certificate-oidc-issuer "${ISSUER}"
  cosign verify-attestation --type openvex "${PYTHON_CHILD_REF}" \
    --certificate-identity "${PUBLISH_IDENTITY}" \
    --certificate-oidc-issuer "${ISSUER}"
  cosign verify-attestation --type https://nwarila.dev/attestations/nist-sp-800-190-image/v1 "${PYTHON_CHILD_REF}" \
    --certificate-identity "${PUBLISH_IDENTITY}" \
    --certificate-oidc-issuer "${ISSUER}"
  cosign verify-attestation --type https://nwarila.dev/attestations/stig-arf/v1 "${PYTHON_CHILD_REF}" \
    --certificate-identity "${PUBLISH_IDENTITY}" \
    --certificate-oidc-issuer "${ISSUER}"
}
verify_python_child "${AMD64_REF}"
verify_python_child "${ARM64_REF}"
```

Verify the exact index-only trust contract. The checkout at the publishing
commit supplies the expected `images/python/` tree identity:

```sh
PYTHON_TREE="$(git rev-parse "${PUBLISH_SHA}:images/python")"
python3 tools/python-trust-contract.py \
  --digest "${INDEX_DIGEST#sha256:}" \
  --tree "${PYTHON_TREE}" --commit "${PUBLISH_SHA}" \
  --predicate-out "${VERIFY_AUTH_DIR}/expected-trust-contract.predicate.json" \
  --statement-out "${VERIFY_AUTH_DIR}/expected-trust-contract.statement.json"

cosign verify-attestation \
  --type https://nwarila.dev/attestations/python-trust-contract/v1 \
  "${INDEX_REF}" \
  --certificate-identity "${PUBLISH_IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  > "${VERIFY_AUTH_DIR}/verified-trust-contract.jsonl"

python3 tools/assert-python-attestation.py \
  --verified "${VERIFY_AUTH_DIR}/verified-trust-contract.jsonl" \
  --image "${IMAGE}" --digest "${INDEX_DIGEST}" \
  --predicate-type https://nwarila.dev/attestations/python-trust-contract/v1 \
  --expected-statement "${VERIFY_AUTH_DIR}/expected-trust-contract.statement.json"
```

Verify provenance at the generator's exact identity, then bind the authenticated
SLSA layer certificate to the pinned generator commit, publishing SHA/ref, and
Python caller workflow:

```sh
cosign verify-attestation --type slsaprovenance "${INDEX_REF}" \
  --certificate-identity "${SLSA_IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --certificate-github-workflow-repository NWarila/ubi9-base-micro \
  --certificate-github-workflow-sha "${PUBLISH_SHA}" \
  --certificate-github-workflow-ref "${PUBLISH_REF}" \
  > "${VERIFY_AUTH_DIR}/verified-slsa.jsonl"

ATTESTATION_REF="$(cosign triangulate --type attestation "${INDEX_REF}")"
crane manifest "${ATTESTATION_REF}" \
  > "${VERIFY_AUTH_DIR}/attestation-manifest.json"
SLSA_LAYER_DIGEST="$(python3 tools/assert-python-slsa-certificate.py \
  --attestation-manifest "${VERIFY_AUTH_DIR}/attestation-manifest.json" \
  --print-layer-digest)"
crane blob "${IMAGE}@${SLSA_LAYER_DIGEST}" \
  > "${VERIFY_AUTH_DIR}/slsa-envelope.json"
python3 tools/assert-python-slsa-certificate.py \
  --verified "${VERIFY_AUTH_DIR}/verified-slsa.jsonl" \
  --attestation-manifest "${VERIFY_AUTH_DIR}/attestation-manifest.json" \
  --envelope "${VERIFY_AUTH_DIR}/slsa-envelope.json" \
  --sha "${PUBLISH_SHA}" --ref "${PUBLISH_REF}"
```

For a main publish, authenticate the source branch and print the provenance for
the exact-source policy helper. For a release, replace `--source-branch main`
with `--source-tag "${PUBLISH_REF#refs/tags/}"`.

```sh
slsa-verifier verify-image "${INDEX_REF}" \
  --source-uri github.com/NWarila/ubi9-base-micro \
  --source-branch main \
  --builder-id "${SLSA_IDENTITY}" \
  --print-provenance > "${VERIFY_AUTH_DIR}/verified-provenance.json"

python3 tools/assert-python-provenance.py \
  --provenance "${VERIFY_AUTH_DIR}/verified-provenance.json" \
  --image "${IMAGE}" --digest "${INDEX_DIGEST}" \
  --sha "${PUBLISH_SHA}" --ref "${PUBLISH_REF}"
```

These commands verify only the digest and publishing identity supplied above.
They do not claim that any Python image currently exists. For a release, the
publishing ref must be in the `python/v*` namespace; top-level `v*` tags belong
to the root-image publisher.
