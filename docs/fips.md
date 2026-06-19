# FIPS

## OpenSSL module ledger

| Module | Runtime consumer | CMVP cert | Status |
|---|---|---|---|
| Red Hat Enterprise Linux 9 OpenSSL FIPS Provider, `fips.so` v3.0.7-395c1a240fbfffd8 | base-micro C/OpenSSL consumers that link system `libcrypto.so.3` | #4857, FIPS 140-3 Level 1 | ACTIVE; validated 2024-10-29; sunset 2029-10-28; covers RHEL 9.2, 9.4, 9.5, and 9.6 |

#4857 is the authoritative RHEL 9 OpenSSL FIPS-provider certificate for this image and supersedes the stale #4754 reference. The shipped provider package is `openssl-fips-provider-so-3.0.7-8.el9.x86_64`, and the build gate fails if the provider does not report `version: 3.0.7-395c1a240fbfffd8`.

## Runtime mechanism

The runtime image ships the RHEL-validated `fips.so` through the `ca-certificates` and explicit `openssl-fips-provider` RPM closure, alongside system `libcrypto.so.3`. The runtime does not include the `openssl` CLI.

Approved mode is forced with `/etc/pki/tls/openssl-fips.cnf` and image ENV:

```text
OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf
OPENSSL_MODULES=/usr/lib64/ossl-modules
```

The config is self-contained: `fips` and `base` providers are active, the default provider is not activated, and `default_properties = fips=yes` is the approved mode switch. Red Hat disables `openssl fipsinstall` in its OpenSSL build, so this image does not generate or include a `fipsmodule.cnf`. The RHEL provider self-verifies when it loads; `status: active` from `openssl list -providers` is the captured self-test PASS signal for this RHEL model.

The Docker build verifies the exact shipping config in a builder stage that has the OpenSSL CLI. That gate captures the provider NEVRA, the `fips` provider `status: active` and version, confirms `base` is active and `default` is absent, rejects MD5, and confirms SHA-256 plus AES-256-CBC succeed. The runtime test only checks artifacts and ENV because base-micro intentionally has no shell or OpenSSL CLI.

## Scope

This is a module-scoped and approved-mode-scoped claim: base-micro uses the FIPS-validated OpenSSL provider (#4857) in approved mode for processes that dynamically link the shipped system `libcrypto.so.3`. It is not an OS, host, container, or application FIPS validation claim.

The host/runtime kernel remains non-FIPS by platform decision: `fips_enabled = 0`. RHEL distro-wide host FIPS plumbing is not inherited from this image. Go-static leaves ignore this OpenSSL provider and must carry their own validated Go module (#5247).
