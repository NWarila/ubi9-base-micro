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
| Pull request | `pull_request` to `main` | Repository contract, lint, local build, hardening, FIPS artifact checks, SBOM and scanner gates, OpenVEX policy, NIST predicate validation, tailored STIG ARF, and byte-for-byte rootfs reproducibility. | Published signatures, published attestations, SLSA provenance over a pushed digest, Rekor roll-up, or anonymous GHCR pull. |
| Publish | `push` to `main` and `v*` tags | Multi-arch publish, Cosign keyless signature, Syft rpmdb-derived SPDX and CycloneDX attestations, NIST SP 800-190 and STIG ARF predicates, OpenVEX attestations when needed, SLSA L3 provenance, and Rekor roll-up. | The one-time public package visibility change required before anonymous GHCR verification can pass. |
| Post-publish audit | Clean unauthenticated verifier | Anonymous pull by digest and the full `cosign` plus `slsa-verifier` contract in [`verify.md`](verify.md). | Future rebuild currency or downstream family-coherence status. |

The Python workflow adds an active CI-rootfs preflight for the unpublished
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

This preflight does not create a published artifact, signature, attestation,
transparency-log entry, provenance statement, or release-shaped manifest. Its
effective-rootfs assertion does not determine the OCI manifest digest of a
future release child. The workflow's `GITHUB_TOKEN` grants `contents: read` only
and its committed YAML contains no configured registry credential or login
surface. Repository verification checks those boundaries and binds the complete
committed workflow bytes to an expected SHA-256 and byte length, requiring a
corresponding visible verifier edit for any YAML-surface change. That byte lock
does not extend to the scripts or pinned external code the workflow invokes.
The `python / required` reducer is not a required repository status context.

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
