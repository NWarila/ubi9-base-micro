# ADR-0003: Publish Multi-Arch Images With Per-Architecture FIPS Scope

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

The image publishes both `linux/amd64` and `linux/arm64`. The RHEL OpenSSL FIPS
Provider can be configured and self-test passing on both architectures, but CMVP
certificate #4857 does not list an aarch64 or arm64 operational environment.
Current UBI repository metadata has purged `openssl-fips-provider-so-3.0.7-8.el9`
for both RPM architectures, but Red Hat still serves the signed `-8.el9` RPMs by
direct CDN URL. Moving arm64 to a newer z-stream would keep approved mode but
would no longer ship the only module version validated by #4857.

## Decision

The repository publishes both architectures with the same approved-mode OpenSSL
configuration and build-time provider gates, and both architectures hold
`openssl-fips-provider-so-3.0.7-8.el9` with module version
`3.0.7-395c1a240fbfffd8`. The Dockerfile and RPM lock generator fetch the
provider metapackage and `-so` RPMs from Red Hat UBI CDN direct URLs, verify the
Red Hat RPM signature and pinned SHA-256 for each architecture, and install the
local RPMs so rpm ownership remains truthful.

The image carries `/etc/nwarila/fips-status.json`, and the publish workflow adds
per-platform `org.nwarila.fips.cmvp.oe-validated`,
`org.nwarila.fips.module-version`, and `org.nwarila.fips.provider-nvr`
annotations. The status file records the architecture boundary with
`oe_validated`, `provider_nvr`, and `provider_nevra` on both architectures.

amd64 is documented and labeled as within #4857's validated
operational-environment scope. arm64 is documented and labeled as the same module
and provider NVR, approved-mode configured and self-test passing, but not a
CMVP-validated configuration for that architecture.

## Consequences

- Multi-arch consumers get one coherent image family without a false arm64 FIPS
  validation claim.
- Documentation, labels, annotations, runtime status artifacts, and RPM locks
  must stay aligned with the single provider/module pin.
- Future CMVP coverage changes can upgrade the arm64 scope only after primary
  evidence supports it.
- A future Red Hat CDN 404, SHA-256 mismatch, or GPG verification failure for the
  direct `-8.el9` RPMs forces a provider bump plus amd64 revalidation decision;
  the image must not silently substitute a rebuild or newer z-stream.

## References

- NIST CMVP certificate #4857: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4857>
- NIST-hosted security policy for #4857: <https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4857.pdf>
- Repository details: `docs/fips.md`, `tests/fips.sh`, `containers/Dockerfile`
