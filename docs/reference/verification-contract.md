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
| Publish | Scope-eligible `push` to `main`, and every `v*` tag | Multi-arch publish, Cosign keyless signature, Syft rpmdb-derived SPDX and CycloneDX attestations, NIST SP 800-190 and STIG ARF predicates, OpenVEX attestations when needed, SLSA L3 provenance, and Rekor roll-up. | The one-time public package visibility change required before anonymous GHCR verification can pass. |
| Post-publish audit | Clean unauthenticated verifier | Anonymous pull by digest and the full `cosign` plus `slsa-verifier` contract in [`verify.md`](verify.md). | Future rebuild currency or downstream family-coherence status. |

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

Each workflow's `GITHUB_TOKEN` grants `contents: read` only, and the committed
YAML contains no configured registry credential or login surface. Repository
verification checks those boundaries and binds each complete committed workflow
to an expected SHA-256 and byte length, requiring a corresponding visible
verifier edit for any YAML-surface change. Those byte locks do not extend to the
scripts or pinned external code the workflows invoke. The `python / required`
reducer is not a required repository status context.

The publish path uses exact certificate identities. The repository workflow
identity signs image signatures and repository-generated predicates; the SLSA
generator identity signs provenance:

```text
https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>
https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0
https://token.actions.githubusercontent.com
```

The manifest field `runtime.package_floor` is the final rpmdb package-name
floor. The direct RPM URLs and hashes that build that floor are repository
governance inputs and remain checked by `tools/verify.py`, not duplicated in the
consumer contract.

`gh attestation verify` is intentionally outside this contract because this
repository publishes Cosign OCI attestations, not GitHub-native Artifact
Attestations. Use [`verify.md`](verify.md) for the copy-paste verification
commands.
