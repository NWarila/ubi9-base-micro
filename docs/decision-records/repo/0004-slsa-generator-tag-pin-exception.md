# ADR-0004: Keep The SLSA Generator Tag-Pinned With An Integrity Guard

- Status: Accepted
- Date: 2026-06-21
- Last reviewed: 2026-08-16
- Scope: repo

## Context

The repository's publish path needs SLSA Build L3 provenance. Ordinary GitHub
Actions are pinned to full commit SHA values, but the trusted SLSA container
generator's identity and release mechanics depend on the semantic tag reference.
Replacing the tag with a commit SHA would change the Fulcio SAN and break the
exact builder identity used by downstream verification.

## Decision

The `slsa-framework/slsa-github-generator` reusable workflow remains referenced
as `generator_container_slsa3.yml@v2.1.0`. Both publish workflows gate that tag
before use by asserting `refs/tags/v2.1.0` resolves to
`f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`, and all verification uses the exact
tag identity:

`https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0`

Every other `uses:` entry remains SHA-pinned.

The Python publisher also checks the generator after execution and before any
consumer alias is applied. It authenticates the SLSA envelope, then requires the
Fulcio Build Signer Digest extension `1.3.6.1.4.1.57264.1.10` to equal the same
pinned commit. The source digest/ref extensions and the Build Config URI/Digest
extensions must bind the publishing SHA/ref and
`.github/workflows/publish-python.yaml`. The micro publisher retains only the
pre-execution tag check and exact tag-shaped identity; its remaining movement
window is tracked in TD-1.

## Consequences

- The generator exception is explicit, narrow, and testable.
- Verification stays exact-identity rather than regex or wildcard based.
- A generator tag drift seen by either pre-execution check fails before publish
  work can proceed; the Python path also fails if the executed signer or caller
  bindings do not match after provenance is produced.
- Renovate rules must preserve this exception while SHA-pinning ordinary
  actions.

## References

- SLSA security levels: <https://slsa.dev/spec/v1.0/levels>
- SLSA GitHub generator: <https://github.com/slsa-framework/slsa-github-generator/tree/v2.1.0>
- Sigstore Cosign verification: <https://docs.sigstore.dev/cosign/verifying/verify/>
- Repository details: `.github/workflows/publish-image.yaml`,
  `.github/workflows/publish-python.yaml`,
  `tools/assert-python-slsa-certificate.py`, `docs/reference/verify.md`,
  `.github/renovate.json`
