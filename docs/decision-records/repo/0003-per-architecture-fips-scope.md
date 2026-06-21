# ADR-0003: Publish Multi-Arch Images With Per-Architecture FIPS Scope

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

The image publishes both `linux/amd64` and `linux/arm64`. The RHEL OpenSSL FIPS
Provider can be configured and self-test passing on both architectures, but CMVP
certificate #4857 does not list an aarch64 or arm64 operational environment.
Claiming identical validation scope across both manifests would overstate the
evidence.

## Decision

The repository publishes both architectures with the same approved-mode OpenSSL
configuration and build-time provider gates. The amd64 image is documented and
labeled as within #4857's validated operational-environment scope. The arm64
image is documented and labeled as approved-mode configured and self-test
passing, but not a CMVP-validated configuration for that architecture.

The image carries `/etc/nwarila/fips-status.json`, and the publish workflow adds
per-platform `org.nwarila.fips.cmvp.oe-validated` annotations.
The status file records the architecture boundary with an `oe_validated` field.

## Consequences

- Multi-arch consumers get one coherent image family without a false arm64 FIPS
  validation claim.
- Documentation, labels, and runtime status artifacts must stay aligned.
- Future CMVP coverage changes can upgrade the arm64 scope only after primary
  evidence supports it.

## References

- NIST CMVP certificate #4857: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4857>
- NIST-hosted security policy for #4857: <https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4857.pdf>
- Repository details: `docs/fips.md`, `tests/fips.sh`, `containers/Dockerfile`
