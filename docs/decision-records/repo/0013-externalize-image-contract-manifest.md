# ADR-0013: Externalize The Image Contract Manifest

- Status: Accepted
- Date: 2026-06-25
- Scope: repo

## Context

The repository verifier asserted consumer-verifiable image properties directly
in Python: supported architectures, the OpenSSL FIPS provider floor, per-arch
`fips.so` digests, per-arch `oe_validated` scope, the runtime package floor, the
footprint ceiling, and published evidence identities.

Those assertions were correct, but downstream consumers had no versioned
machine-readable declaration to validate against. The Python verifier was acting
as both gate and contract.

## Decision

The consumer-verifiable image contract lives in
`contracts/image-manifest.json`, validated by
`contracts/image-manifest.schema.json`. `tools/verify.py` validates the manifest
against the schema before reading expected image-contract values from it.

Build and repository governance values stay in `tools/verify.py`: GitHub Action
SHAs, pre-commit hook revisions, hadolint image digest, direct RPM URLs and
hashes, and repository layout lists. Those values govern how this repository is
built and checked; they are not the declared runtime image contract a consumer
can verify after pulling a digest.

## Consequences

- Consumers can validate a pulled image against a versioned JSON manifest
  without reading the verifier source.
- The verifier stays fail-closed because an invalid or incomplete manifest fails
  before contract assertions run.
- The image bytes remain unchanged because the Dockerfile, RPM lockfiles, build
  scripts, and `.dockerignore` image context are not changed by the manifest.
- Future image-contract changes require an explicit manifest diff instead of a
  hidden Python constant edit.

## References

- `contracts/image-manifest.schema.json`
- `contracts/image-manifest.json`
- `contracts/examples/README.md`
- `docs/reference/verification-contract.md`
