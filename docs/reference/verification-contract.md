# Verification Contract Summary

`ubi9-base-micro` has three verification boundaries. Each boundary proves a
different subset of the repository contract.

The consumer-verifiable image contract is declared in
[`../../contracts/image-manifest.json`](../../contracts/image-manifest.json) and
validated by
[`../../contracts/image-manifest.schema.json`](../../contracts/image-manifest.schema.json).
The manifest is the source of truth for the supported architectures, FIPS module
and provider values, per-arch `fips.so` digests, per-arch `oe_validated` scope,
runtime package floor, footprint ceiling, Cosign identity, OIDC issuer, SLSA
builder ID, and repository-generated attestation predicate types. A worked
consumer check lives in
[`../../contracts/examples/README.md`](../../contracts/examples/README.md).

| Boundary | Runs on | Proves | Does not prove |
| --- | --- | --- | --- |
| Pull request | `pull_request` to `main` | Repository contract, lint, local build, hardening, FIPS artifact checks, SBOM and scanner gates, OpenVEX policy, NIST predicate validation, tailored STIG ARF, byte-for-byte rootfs reproducibility, and the Python release exporter exercised against a loopback-bound ephemeral registry. | Project or external publication, published signatures or attestations, SLSA provenance over a consumer-resolvable digest, Rekor roll-up, or anonymous GHCR pull. |
| Publish | `push` to `main`, root-image `v*` tags, and Python `python/v*` tags | Multi-arch publish, Cosign keyless signature, Syft rpmdb-derived SPDX and CycloneDX attestations, NIST SP 800-190 and STIG ARF predicates, OpenVEX attestations when needed, SLSA L3 provenance, and Rekor roll-up. | The one-time public package visibility change required before anonymous GHCR verification can pass. |
| Post-publish audit | Clean unauthenticated verifier | Anonymous pull by digest and the full `cosign` plus `slsa-verifier` contract in [`verify.md`](verify.md). | Future rebuild currency or downstream family-coherence status. |

The Python publish boundary above describes repository capability, not a
completed publication. This revision does not claim that
`ghcr.io/nwarila/ubi9-base-python` has been published, made public, or made
consumable. The image is not publicly consumable at this revision. Those claims
require evidence from the corresponding completed boundary.

The Python CI workflow has an active CI-rootfs preflight for the unpublished
`base-python` image. Its build and reproducibility matrices run for both
architectures on every push to `main` and manual dispatch; pull requests retain
the Python-tree and shared-gate path selector. Both matrices assert five
contracted Buildx/BuildKit identities before building. The reproducibility
matrix compares two `repro` rootfs exports. Separately, each build-matrix job
builds the `ci` target once, exports the effective rootfs from the same loaded
image used by its gate battery, and checks the architecture-specific
`canonical_rootfs_digest` and `rpmdb_sha256` against
`images/python/contracts/image-manifest.json`. That job also binds the loaded
image's revision, source, version, and created labels to the current commit and
committed inputs.

The CI-rootfs preflight does not create a published artifact, signature,
attestation, transparency-log entry, provenance statement, or release-shaped
manifest. Its effective-rootfs assertion does not determine the OCI manifest
digest of a future release child.

A separate Python release preflight runs only on pull requests. It invokes the
registry-exporting `release` target once for both architectures, pushes a
candidate index and unsigned BuildKit provenance to a loopback-bound ephemeral
registry, reads both served child digests back, and checks each exported rootfs
against the contract and a same-commit `ci` build. This is a local registry
write, not an external or project publication: it creates no project package,
public or moving alias, production signature or attestation, SLSA or Rekor
record, or consumer-resolvable digest.

Pull-request preflight jobs grant `contents: read` only and contain no external
registry credential or login surface. Push-only publication jobs receive the
smallest additional package or OIDC permissions needed by their role and carry
an exact base-repository guard. Repository verification checks those boundaries
and binds each complete committed workflow to an expected SHA-256 and byte
length, requiring a corresponding visible verifier edit for any YAML-surface
change. Those byte locks do not extend to the scripts or pinned external code
the workflows invoke. The `python / required` reducer is not a required
repository status context.

The publish path uses exact certificate identities. The repository workflow
identity signs image signatures and repository-generated predicates; the SLSA
generator identity signs provenance:

```text
https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>
https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0
https://token.actions.githubusercontent.com
```

## Base-python published evidence

The Python publisher pushes an unaliased multi-architecture candidate by digest,
reruns every image and evidence gate, signs the index and children, attaches all
five image-evidence predicates to each child, and attaches the trust-contract and
SLSA provenance only to the index. The subject matrix is exact:

| Evidence | `linux/amd64` child | `linux/arm64` child | Index |
| --- | --- | --- | --- |
| SPDX rpmdb SBOM | Required | Required | No |
| CycloneDX rpmdb SBOM | Required | Required | No |
| OpenVEX | Required | Required | No |
| NIST SP 800-190 | Required | Required | No |
| STIG ARF | Required | Required | No |
| Python trust contract | No | No | Required |
| SLSA provenance | No | No | Required |

The tag namespace for Python releases is `python/v*`; a top-level `v*` tag is
reserved for the root-image publisher. On `main`, the final job applies the
moving `base-python` alias and the create-once
`base-python-<first-12-lowercase-hex-of-publishing-sha>` alias. On a Python
release tag, it applies that commit alias and the validated version alias, and
does not move `base-python`.

The create-once mechanism is mandatory collision detection, not a guarantee.
It checks applicable aliases once after the candidate digest is known and before
any signing, attestation, SLSA, or Rekor work, checks again immediately before
applying aliases, and reads every applied alias back afterward. These operations
are not atomic because GHCR exposes no conditional manifest write. An external
writer with package-write authority, including an owner, PAT, or another
workflow, can race the final resolve-then-apply window. This residual race is
explicitly accepted in
[`../TECH-DEBT.md`](../TECH-DEBT.md#td-9-base-python-create-once-alias-external-writer-race).

The first cache-cold verification leg runs on a fresh runner with GHCR
credentials against the candidate digest and completes before aliases are
applied. A successful publish can therefore exist while the new GHCR package is
still private. That is distinct from public consumability. Only after the owner
makes the package public and the separate cache-cold verification succeeds with
no registry credentials may the image be described as publicly consumable.

After setting `INDEX_DIGEST`, `AMD64_DIGEST`, `ARM64_DIGEST`, and the exact
publishing ref, verify the repository-produced evidence with the contract
identity:

```sh
IMAGE="ghcr.io/nwarila/ubi9-base-python"
PUBLISH_REF="refs/heads/main" # or refs/tags/python/v<version>
PUBLISH_SHA="<40-lowercase-hex-publishing-sha>"
PUBLISH_IDENTITY="https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-python.yaml@${PUBLISH_REF}"
ISSUER="https://token.actions.githubusercontent.com"

cosign verify "${IMAGE}@${INDEX_DIGEST}" \
  --certificate-identity "${PUBLISH_IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}"

for DIGEST in "${AMD64_DIGEST}" "${ARM64_DIGEST}"; do
  CHILD="${IMAGE}@${DIGEST}"
  for TYPE in spdxjson cyclonedx openvex \
    https://nwarila.dev/attestations/nist-sp-800-190-image/v1 \
    https://nwarila.dev/attestations/stig-arf/v1; do
    cosign verify-attestation --type "${TYPE}" "${CHILD}" \
      --certificate-identity "${PUBLISH_IDENTITY}" \
      --certificate-oidc-issuer "${ISSUER}"
  done
done

cosign verify-attestation \
  --type https://nwarila.dev/attestations/python-trust-contract/v1 \
  "${IMAGE}@${INDEX_DIGEST}" \
  --certificate-identity "${PUBLISH_IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}"
```

Verify index-only provenance at the generator's exact pinned identity and bind
the authenticated source ref. Use `--source-tag python/v<version>` instead of
`--source-branch main` for a release tag:

```sh
SLSA_IDENTITY="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"

cosign verify-attestation --type slsaprovenance \
  "${IMAGE}@${INDEX_DIGEST}" \
  --certificate-identity "${SLSA_IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --certificate-github-workflow-repository NWarila/ubi9-base-micro \
  --certificate-github-workflow-sha "${PUBLISH_SHA}" \
  --certificate-github-workflow-ref "${PUBLISH_REF}"

slsa-verifier verify-image "${IMAGE}@${INDEX_DIGEST}" \
  --source-uri github.com/NWarila/ubi9-base-micro \
  --source-branch main \
  --builder-id "${SLSA_IDENTITY}" \
  --print-provenance > verified-provenance.json

python3 tools/assert-python-provenance.py \
  --provenance verified-provenance.json \
  --image "${IMAGE}" --digest "${INDEX_DIGEST}" \
  --sha "${PUBLISH_SHA}" --ref "${PUBLISH_REF}"
```

For a Python release, replace `--source-branch main` with
`--source-tag python/v<version>`. Successful commands establish cryptographic and
source-policy verification for the named digest. They do not establish public
consumability unless GHCR visibility is public and the commands also succeed
from an unauthenticated, cache-cold client.

The manifest field `runtime.package_floor` is the final rpmdb package-name
floor. The direct RPM URLs and hashes that build that floor are repository
governance inputs and remain checked by `tools/verify.py`, not duplicated in the
consumer contract.

`gh attestation verify` is intentionally outside this contract because this
repository publishes Cosign OCI attestations, not GitHub-native Artifact
Attestations. Use [`verify.md`](verify.md) for the copy-paste verification
commands.
