# FIPS

## OpenSSL module ledger

| Module | Runtime consumer | CMVP cert | Status |
|---|---|---|---|
| Red Hat Enterprise Linux 9 OpenSSL FIPS Provider, `fips.so` v3.0.7-395c1a240fbfffd8 | base-micro C/OpenSSL consumers that link system `libcrypto.so.3` | #4857, FIPS 140-3 Level 1 | ACTIVE; validated 2024-10-29; sunset 2029-10-28; covers RHEL 9.2, 9.4, 9.5, and 9.6 |

#4857 is the authoritative RHEL 9 OpenSSL FIPS-provider certificate for this image and corrects the earlier/stale #4754 reference. The shipped provider package NVR is `openssl-fips-provider-so-3.0.7-8.el9`; the Docker build derives the exact NEVRA from the build platform (`x86_64` for `amd64`, `aarch64` for `arm64`) and fails if the provider does not report `version: 3.0.7-395c1a240fbfffd8`.

## Runtime mechanism

The runtime image ships the RHEL-validated `fips.so` through the `ca-certificates` and explicit `openssl-fips-provider` RPM closure, alongside system `libcrypto.so.3`. The runtime does not include the `openssl` CLI.

Approved mode is forced with `/etc/pki/tls/openssl-fips.cnf` and image ENV:

```text
OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf
OPENSSL_MODULES=/usr/lib64/ossl-modules
```

The config is self-contained: `fips` and `base` providers are active, the default provider is not activated, and `default_properties = fips=yes` is the approved mode switch. Red Hat disables `openssl fipsinstall` in its OpenSSL build, so this image does not generate or include a `fipsmodule.cnf`. The RHEL provider self-verifies when it loads; `status: active` from `openssl list -providers` is the captured self-test PASS signal for this RHEL model.

The Docker build verifies the exact shipping config in a builder stage that has the OpenSSL CLI. That gate captures the provider NEVRA, `openssl-libs` NEVRA, `fips.so` SHA-256, the `fips` provider `status: active` and version, confirms `base` is active and `default` is absent, rejects MD5, and confirms SHA-256 plus AES-256-CBC succeed. The runtime rootfs stage then fails closed unless the provider NEVRA matches the pin, the shipped `fips.so` SHA-256 equals the verified-stage `fips.so`, and the shipped `openssl-libs` NEVRA equals the verified-stage loader boundary. The runtime test only checks artifacts, labels, and ENV because base-micro intentionally has no shell or OpenSSL CLI.

## Per-architecture validation scope

This image publishes `linux/amd64` and `linux/arm64` runtime manifests with the Red Hat OpenSSL FIPS provider enabled on both architectures. Both platforms run the same build-time FIPS gate: the provider must load in approved mode, report module version `3.0.7-395c1a240fbfffd8`, refuse MD5, and match the shipped runtime `fips.so` by NEVRA and SHA-256.

The CMVP validation scope is per operational environment:

| Platform | OE validation scope | Runtime status artifact |
| --- | --- | --- |
| `linux/amd64` | CMVP #4857-validated approved-mode configuration. | `/etc/nwarila/fips-status.json` has `"oe_validated": true`. |
| `linux/arm64` | Approved-mode configured and self-test passing, but not a CMVP-validated configuration on this architecture. | `/etc/nwarila/fips-status.json` has `"oe_validated": false`. |

The arm64 disclaimer is part of the runtime image. The publish manifest carries the per-architecture `org.nwarila.fips.cmvp.oe-validated` annotation.

```text
The Red Hat OpenSSL FIPS provider (module #4857, v3.0.7-395c1a240fbfffd8) is present, approved-mode-configured, and self-test-passing, but this aarch64 operational environment is NOT in CMVP #4857's validated or vendor-affirmed list — this is NOT a CMVP-validated configuration on this architecture.
```

NIST CMVP certificate #4857 and its security policy list tested operational environments on x86_64, IBM Z, and POWER platforms; they do not list an aarch64 operational environment. The owner-ratified TD-3 posture is therefore multi-arch with honest per-arch scope: amd64 is #4857-validated approved mode, while arm64 is approved-mode configured and explicitly non-validated.

References:

- NIST CMVP certificate #4857: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4857>
- NIST-hosted security policy for #4857: <https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4857.pdf>
- TD-3: arm64 OpenSSL FIPS is not CMVP-cert-validated; per-arch FIPS scope.

## Scope

This is a module-scoped and approved-mode-scoped claim: base-micro uses the FIPS-validated OpenSSL provider (#4857) in approved mode for processes that dynamically link the shipped system `libcrypto.so.3`. It is not an OS, host, container, or application FIPS validation claim.

The host/runtime kernel remains non-FIPS by platform decision: `fips_enabled = 0`. RHEL distro-wide host FIPS plumbing is not inherited from this image. Go-static leaves ignore this OpenSSL provider and must carry their own validated Go module (#5247).
