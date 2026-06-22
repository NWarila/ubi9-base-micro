# ADR-0003: Publish Multi-Arch Images With Per-Architecture FIPS Scope

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

The image publishes both `linux/amd64` and `linux/arm64`. The RHEL OpenSSL FIPS
Provider can be configured and self-test passing on both architectures, but CMVP
certificate #4857 does not list an aarch64 or arm64 operational environment.
The current UBI arm64 repository no longer serves the #4857 amd64 baseline
provider build (`openssl-fips-provider-so-3.0.7-8.el9`), while amd64 still does.
Claiming identical validation scope or provider version across both manifests
would overstate the evidence.

## Decision

The repository publishes both architectures with the same approved-mode OpenSSL
configuration and build-time provider gates, but with per-architecture provider
pins. The amd64 image holds `openssl-fips-provider-so-3.0.7-8.el9` and module
version `3.0.7-395c1a240fbfffd8`, documented and labeled as within #4857's
validated operational-environment scope. The arm64 image pins
`openssl-fips-provider-so-3.0.7-11.el9_8` and module version
`3.0.7-cda111b5812c30d4`, documented and labeled as approved-mode configured and
self-test passing, but not a CMVP-validated configuration for that architecture.

The image carries `/etc/nwarila/fips-status.json`, and the publish workflow adds
per-platform `org.nwarila.fips.cmvp.oe-validated`,
`org.nwarila.fips.module-version`, and `org.nwarila.fips.provider-nvr`
annotations. The status file records the architecture boundary with
`oe_validated` on both architectures. The arm64 status file also records
`provider_nvr` and `provider_nevra`; the amd64 status file keeps the
main-compatible JSON shape so the amd64 rootfs remains byte-for-byte identical
with the validated baseline.

## Consequences

- Multi-arch consumers get one coherent image family without a false arm64 FIPS
  validation claim.
- Documentation, labels, annotations, and runtime status artifacts must stay
  aligned with the per-arch provider pins.
- Future CMVP coverage changes can upgrade the arm64 scope only after primary
  evidence supports it.
- A future purge of amd64 `openssl-fips-provider-so-3.0.7-8.el9.x86_64` forces a
  separate amd64 z-stream coverage decision before that pin can move.

## References

- NIST CMVP certificate #4857: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4857>
- NIST-hosted security policy for #4857: <https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4857.pdf>
- Repository details: `docs/fips.md`, `tests/fips.sh`, `containers/Dockerfile`
