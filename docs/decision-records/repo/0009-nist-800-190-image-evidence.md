# ADR-0009: Emit NIST SP 800-190 Image-Control Evidence

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

NIST SP 800-190 covers application container security. For this repository, the
useful scope is image-layer evidence: vulnerability gates, hardening, malware
scanner boundaries, rootfs secret scanning, digest-pinned base inputs, signing,
and provenance. CIS Docker host controls are not image evidence and should not
be presented as if they were.

## Decision

The repository emits a custom in-toto predicate for NIST SP 800-190 section 4.1
image controls:

`https://nwarila.dev/attestations/nist-sp-800-190-image/v1`

PR builds generate and validate the predicate. Publish builds generate it per
platform child digest after rootfs secret scanning, attach it with Cosign, and
verify it with the exact repository workflow identity.

## Consequences

- The repository has machine-readable image-control evidence instead of a prose
  compliance claim.
- Host and daemon controls remain explicitly out of scope.
- The predicate is tied to the image reference, platform, source revision, and
  passing secret-scan report.
- Future variants can reuse the shape while keeping their own evidence honest.

## References

- NIST SP 800-190 Application Container Security Guide: <https://csrc.nist.gov/pubs/sp/800/190/final>
- NIST SP 800-218 SSDF: <https://csrc.nist.gov/pubs/sp/800/218/final>
- Repository details: `docs/nist-800-190.md`,
  `tools/generate-nist-800-190-predicate.py`,
  `tools/assert-no-rootfs-secrets.py`
