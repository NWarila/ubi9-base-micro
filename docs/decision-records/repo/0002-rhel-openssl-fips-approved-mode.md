# ADR-0002: Use The RHEL OpenSSL FIPS Provider Approved-Mode Config

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

`ubi9-base-micro` ships a shell-free runtime, but it must provide the OpenSSL
FIPS floor for C/OpenSSL-linked consumers. The RHEL OpenSSL build does not use
upstream `openssl fipsinstall` in this image model. The shipped provider must be
bound to the validated module version and to the exact runtime copy, not merely
tested in a parallel build stage.

## Decision

The image ships the RHEL 9 OpenSSL FIPS Provider, CMVP certificate #4857,
through `openssl-fips-provider-so` and `openssl-libs`. Approved mode is enabled
by a self-contained `/etc/pki/tls/openssl-fips.cnf` that activates the `fips`
and `base` providers and sets `default_properties = fips=yes`.

The Dockerfile verifies the provider in a builder stage with the OpenSSL CLI,
then fails closed unless the runtime provider NEVRA, `openssl-libs` NEVRA, and
`fips.so` SHA-256 match the verified stage and the configured pins.

## Consequences

- The runtime keeps no OpenSSL CLI or shell, so runtime tests assert shipped
  artifacts, labels, and environment variables while build-time gates prove
  provider activation and MD5 refusal.
- The FIPS claim remains module-scoped and approved-mode-scoped.
- Any provider, library, or config drift fails the build before publish.

## References

- NIST CMVP certificate #4857: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4857>
- NIST SP 800-218 SSDF: <https://csrc.nist.gov/pubs/sp/800/218/final>
- Repository details: `docs/compliance/fips.md`, `containers/fips/openssl.cnf`,
  `tests/fips.sh`, `containers/Dockerfile`
