# ADR-0004: Keep The SLSA Generator Tag-Pinned With An Integrity Guard

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

The repository's publish path needs SLSA Build L3 provenance. Ordinary GitHub
Actions are pinned to full commit SHA values, but the trusted SLSA container
generator's identity and release mechanics depend on the semantic tag reference.
Replacing the tag with a commit SHA would change the Fulcio SAN and break the
exact builder identity used by downstream verification.

## Decision

The `slsa-framework/slsa-github-generator` reusable workflow remains referenced
as `generator_container_slsa3.yml@v2.1.0`. The publish workflow gates that tag by
asserting `refs/tags/v2.1.0` resolves to
`f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`, and all verification uses the exact
tag identity:

`https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0`

Every other `uses:` entry remains SHA-pinned.

## Consequences

- The generator exception is explicit, narrow, and testable.
- Verification stays exact-identity rather than regex or wildcard based.
- A generator tag drift fails before publish work can proceed.
- Renovate rules must preserve this exception while SHA-pinning ordinary
  actions.

## References

- SLSA security levels: <https://slsa.dev/spec/v1.0/levels>
- SLSA GitHub generator: <https://github.com/slsa-framework/slsa-github-generator/tree/v2.1.0>
- Sigstore Cosign verification: <https://docs.sigstore.dev/cosign/verifying/verify/>
- Repository details: `.github/workflows/publish-image.yaml`,
  `docs/reference/verify.md`, `.github/renovate.json`
