# ADR-0010: Keep The Base-Image Family As Polyrepos Rooted At Base Micro

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

The base-image family has one root image and planned language variants. A
monorepo could centralize files, but it would also couple variant cadence,
evidence, signer identity, and responsibility boundaries. Each variant must own
its incremental runtime, STIG evidence, FIPS scope, vulnerability posture, and
publish identity while consuming the current micro digest.

## Decision

`ubi9-base-micro` remains the root repository. Planned `ubi9-base-python`,
`ubi9-base-node`, and `ubi9-base-java` repositories consume
`base-micro@sha256:<digest>` and publish their own runtime and development
images. Family coherence is enforced through digest pins, Renovate cascade
behavior, and per-variant gates rather than by sharing one repository.

This repository documents only the micro image and the family contract. It does
not claim the planned variants are published here.

## Consequences

- Each image has a frozen per-repository publish identity and evidence set.
- Variant-specific FIPS and STIG scope stays local to the variant repository.
- The micro digest is the explicit dependency boundary for downstream base
  images.
- Documentation must keep planned variants distinct from artifacts this
  repository actually publishes.

## References

- SLSA security levels: <https://slsa.dev/spec/v1.0/levels>
- Sigstore Cosign verification: <https://docs.sigstore.dev/cosign/verifying/verify/>
- Repository details: `README.md`, `docs/reference/verify.md`,
  `.github/renovate.json`
