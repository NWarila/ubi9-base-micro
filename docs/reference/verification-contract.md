# Verification Contract Summary

`ubi9-base-micro` has three verification boundaries. Each boundary proves a
different subset of the repository contract.

| Boundary | Runs on | Proves | Does not prove |
| --- | --- | --- | --- |
| Pull request | `pull_request` to `main` | Repository contract, lint, local build, hardening, FIPS artifact checks, SBOM and scanner gates, OpenVEX policy, NIST predicate validation, tailored STIG ARF, and byte-for-byte rootfs reproducibility. | Published signatures, published attestations, SLSA provenance over a pushed digest, Rekor roll-up, or anonymous GHCR pull. |
| Publish | `push` to `main` and `v*` tags | Multi-arch publish, Cosign keyless signature, Syft rpmdb-derived SPDX and CycloneDX attestations, NIST SP 800-190 and STIG ARF predicates, OpenVEX attestations when needed, SLSA L3 provenance, and Rekor roll-up. | The one-time public package visibility change required before anonymous GHCR verification can pass. |
| Post-publish audit | Clean unauthenticated verifier | Anonymous pull by digest and the full `cosign` plus `slsa-verifier` contract in [`verify.md`](verify.md). | Future rebuild currency or downstream family-coherence status. |

The publish path uses exact certificate identities. The repository workflow
identity signs image signatures and repository-generated predicates; the SLSA
generator identity signs provenance:

```text
https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>
https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0
https://token.actions.githubusercontent.com
```

`gh attestation verify` is intentionally outside this contract because this
repository publishes Cosign OCI attestations, not GitHub-native Artifact
Attestations. Use [`verify.md`](verify.md) for the copy-paste verification
commands.
