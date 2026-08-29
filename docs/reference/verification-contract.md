# Verification Contract Summary

The image family has three verification boundaries. Each boundary proves a
different subset of an image-specific repository contract.

The `base-micro` consumer-verifiable image contract is declared in
[`../../contracts/image-manifest.json`](../../contracts/image-manifest.json) and
validated by
[`../../contracts/image-manifest.schema.json`](../../contracts/image-manifest.schema.json).
The manifest is the source of truth for the supported architectures, FIPS module
and provider values, per-arch `fips.so` digests, per-arch `oe_validated` scope,
runtime package floor, footprint ceiling, Cosign identity, OIDC issuer, SLSA
builder ID, and repository-generated attestation predicate types. A worked
consumer check lives in
[`../../contracts/examples/README.md`](../../contracts/examples/README.md).
The `base-python` image has its distinct contract in
[`../../images/python/contracts/image-manifest.json`](../../images/python/contracts/image-manifest.json),
validated by its adjacent schema. That manifest also declares the Python
workflow identity and its six repository-generated predicate types, including
the index-only trust contract. Publication evidence is recorded below against an
immutable digest rather than inferred from that declarative manifest.

| Boundary | Runs on | Proves | Does not prove |
| --- | --- | --- | --- |
| Pull request | `pull_request` to `main` | Repository contract, lint, local build, hardening, FIPS artifact checks, SBOM and scanner gates, OpenVEX policy, NIST predicate validation, tailored STIG ARF, byte-for-byte rootfs reproducibility, and the Python release exporter exercised against a loopback-bound ephemeral registry. | Project or external publication, published signatures or attestations, SLSA provenance over a consumer-resolvable digest, Rekor roll-up, or anonymous GHCR pull. |
| Publish | `push` to `main`, root-image `v*` tags, and Python `python/v*` tags | After a successful image-specific run: multi-arch publish, Cosign keyless signature, Syft rpmdb-derived SPDX and CycloneDX attestations, NIST SP 800-190 and STIG ARF predicates, OpenVEX attestations when needed, SLSA L3 provenance, and Rekor roll-up. Python additionally requires the index-only trust contract. | A tag's later resolution, later package visibility, later anonymous accessibility, or the continued presence of signatures and attestations. Those mutable service properties require a dated observation bound to an immutable digest. |
| Post-publish audit | Clean unauthenticated verifier | Anonymous pull by digest and the full image-specific `cosign` plus `slsa-verifier` contract in [`verify.md`](verify.md) or [`../how-to/verify-a-published-image.md`](../how-to/verify-a-published-image.md#verify-base-python). | Future rebuild currency or downstream family-coherence status. |

## Micro publish scope

For a push to `main`, the workflow compares the pushed revision with the
revision label on the currently published `base-micro` image. It skips micro
publication only when that diff is available and non-empty and every changed
path matches this closed set:

- the `images/` or `docs/` directory prefix; or
- exactly `.github/workflows/python-ci.yaml`,
  `.github/workflows/publish-python.yaml`, `tools/verify.py`, `README.md`,
  `SUPPORT.md`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, or
  `CODE_OF_CONDUCT.md`.

An unavailable diff base, an empty diff, or any path outside that set publishes
fail-closed. Tag pushes also always publish. The policy applies only to micro
publication; it does not define the Python image's publication scope. A skipped
run creates no new micro publication and does not remove or re-point any
already-published digest or revision-bound attestation.

The Python publish boundary above describes repository capability and the
requirements for a successful publication. Current and historical observations
are maintained in the
[canonical publication evidence contract](#base-python-publication-evidence-contract).

## Python publish scope

The Python publisher uses `tools/decide-python-publish-scope.py`, not the micro
policy. A `python/v*` tag always publishes. On `main`, the workflow reads the
revision label from the `base-python` alias when that alias exists and compares
that commit with the pushed SHA. It publishes when any `images/python/**` path
or any exact shared input consumed by the publisher changed. An absent alias,
absent or malformed published config, unavailable base commit, empty delta, or
unclassified path also publishes fail-closed.

Publication skips only when every changed path belongs to the closed unrelated
set: `docs/**`, `.github/ISSUE_TEMPLATE/**`, or exactly `.editorconfig`,
`.github/pull_request_template.md`, `.github/renovate.json`,
`.github/zizmor.yml`, `.markdownlint-cli2.jsonc`, `.pre-commit-config.yaml`,
`.shellcheckrc`, `.yamllint`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`,
`CONTRIBUTING.md`, `LICENSE`, `README.md`, `SECURITY.md`, `SUPPORT.md`, or
`images/README.md`. This scope decision does not claim that a skipped run
creates or verifies an image; once a prior publication exists, it avoids
replacing that Python digest when all changes are classified as unrelated.

The Python CI workflow has an active CI-rootfs preflight for the `base-python`
image. Its build and reproducibility matrices run for both
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

The surviving `publish-python.yaml` verifier applies 28 named semantic rejection
guards: trigger, job graph, concurrency, exact permission inventory, nine
base-repository guards, fail-closed spellings, Cosign action/version/adjacency,
SLSA generator caller, digest exporter, closed release argv, OCI label binding,
attestation subject matrix, signing, trust contract, provenance, alias ordering,
alias collisions, independent verification, contract identity, publish scope,
gate battery, index dataflow, VEX production caller, SLSA execution-certificate
binding, pre-alias absence, and tag isolation. It also binds the complete file to
an expected SHA-256 and byte length. That surface lock is a drift alarm, not a
semantic replacement. The deleted secret-reference, registry-credential,
OIDC/signing-absence, registry-container, Docker-floor, and BuildKit-network
preflight checks have no live equivalent. The `python / required` reducer is not
a required repository status context.

The publish path uses exact certificate identities. The repository workflow
identity signs image signatures and repository-generated predicates; the SLSA
generator identity signs provenance:

```text
https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>
https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-python.yaml@<ref>
https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0
https://token.actions.githubusercontent.com
```

## Base-python publication evidence contract

Only an `@sha256` image reference is immutable. Every tag or alias resolution,
including a commit or version alias intended to be create-once, is a dated
registry observation. Package visibility, anonymous accessibility, evidence
presence, and workflow conclusions are also dated service observations and do
not become permanent properties of a digest.

### Verified evidence record

Verified evidence record, refreshed 2026-08-29 UTC: the immutable subject
`ghcr.io/nwarila/ubi9-base-python@sha256:1fd3b3659c3fae216fb904ad482e675ba316b96db10637da427eb66b53defe56`
was produced from commit `d83526192b83be0f45c4f9b90da213559c15a334` by
[publishing run attempt 1](https://github.com/NWarila/ubi9-base-micro/actions/runs/33212723050/attempts/1).
For that same digest, a 2026-08-29 anonymous, empty-credential registry read
succeeded; its Cosign signature and Python trust-contract attestation verified
at the repository workflow identity with transparency-log inclusion; and its
SLSA attestation and `slsa-verifier` result verified the named commit,
`refs/heads/main`, and pinned generator. The separate
[anonymous verification job](https://github.com/NWarila/ubi9-base-micro/actions/runs/33219400518/job/99010080494)
for run attempt 1 was observed successful on 2026-08-29 and is bound to that
digest. Alias snapshot at `2026-08-29T02:53:54Z`: both the moving `:base-python`
alias and the policy-intended create-once `:base-python-dff74825297a` alias
resolved to
`sha256:3bed3ce13460449ded0f4c9093603a8eed281eca6886462f173e2d03219e5e45`.
That snapshot is historical; query GHCR for current alias resolution.

### Publication mechanism

On a production attempt, the Python publisher pushes an unaliased
multi-architecture candidate by digest. It fetches the index bytes
from the registry exactly once at the push-reported
digest, requires SHA-256 over those bytes to corroborate that metadata, and
checksums the artifact for every cross-job handoff. The same verified index
digest selects every signing, attestation, VEX, provenance, collision-check, and
alias consumer; no later consumer re-resolves a tag. It then reruns every image
and evidence gate, signs the index and children, attaches all
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
moving `base-python` alias and the policy-intended create-once
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
[`../TECH-DEBT.md`](../TECH-DEBT.md#td-10-base-python-create-once-alias-external-writer-race).

The first cache-cold verification leg runs on a fresh runner with GHCR
credentials against the candidate digest and completes before aliases are
applied. A successful credentialed leg establishes the production evidence on
the candidate but does not by itself establish anonymous access. Public
consumability requires the separate cache-cold verification to succeed without
registry credentials. Any record of that result must name the immutable digest
and observation date.

From a repository checkout at the publishing commit, set `INDEX_DIGEST`,
`AMD64_DIGEST`, `ARM64_DIGEST`, the publishing SHA, and its exact ref. Then
verify the repository-produced evidence with the contract identity:

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

PYTHON_TREE="$(git rev-parse "${PUBLISH_SHA}:images/python")"
python3 tools/python-trust-contract.py \
  --digest "${INDEX_DIGEST#sha256:}" \
  --tree "${PYTHON_TREE}" --commit "${PUBLISH_SHA}" \
  --predicate-out expected-trust-contract.predicate.json \
  --statement-out expected-trust-contract.statement.json

cosign verify-attestation \
  --type https://nwarila.dev/attestations/python-trust-contract/v1 \
  "${IMAGE}@${INDEX_DIGEST}" \
  --certificate-identity "${PUBLISH_IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  > verified-trust-contract.jsonl

python3 tools/assert-python-attestation.py \
  --verified verified-trust-contract.jsonl \
  --image "${IMAGE}" --digest "${INDEX_DIGEST}" \
  --predicate-type https://nwarila.dev/attestations/python-trust-contract/v1 \
  --expected-statement expected-trust-contract.statement.json
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
  --certificate-github-workflow-ref "${PUBLISH_REF}" \
  > verified-slsa.jsonl

ATTESTATION_REF="$(cosign triangulate --type attestation "${IMAGE}@${INDEX_DIGEST}")"
crane manifest "${ATTESTATION_REF}" > attestation-manifest.json
SLSA_LAYER_DIGEST="$(python3 tools/assert-python-slsa-certificate.py \
  --attestation-manifest attestation-manifest.json --print-layer-digest)"
crane blob "${IMAGE}@${SLSA_LAYER_DIGEST}" > slsa-envelope.json
python3 tools/assert-python-slsa-certificate.py \
  --verified verified-slsa.jsonl \
  --attestation-manifest attestation-manifest.json \
  --envelope slsa-envelope.json \
  --sha "${PUBLISH_SHA}" --ref "${PUBLISH_REF}"

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
Attestations. Use [`verify.md`](verify.md) for the published `base-micro`
commands and
[`../how-to/verify-a-published-image.md`](../how-to/verify-a-published-image.md#verify-base-python)
for the post-publication Python procedure.
