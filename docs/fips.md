# FIPS

## OpenSSL module ledger

| Module | Runtime consumer | CMVP cert | Status |
|---|---|---|---|
| Red Hat Enterprise Linux 9 OpenSSL FIPS Provider, `fips.so` v3.0.7-395c1a240fbfffd8 | `linux/amd64` base-micro C/OpenSSL consumers that link system `libcrypto.so.3` | #4857, FIPS 140-3 Level 1 | ACTIVE; validated 2024-10-29; sunset 2029-10-28; covers RHEL 9.2, 9.4, 9.5, and 9.6 tested OEs listed by the certificate |
| Red Hat Enterprise Linux 9 OpenSSL FIPS Provider, `fips.so` v3.0.7-cda111b5812c30d4 | `linux/arm64` base-micro C/OpenSSL consumers that link system `libcrypto.so.3` | No arm64 OE under #4857 | Approved mode configured and self-test passing; disclaimed because #4857 lists no aarch64 or arm64 OE |

#4857 is the authoritative RHEL 9 OpenSSL FIPS-provider certificate for the amd64 image and corrects the earlier/stale #4754 reference. The amd64 provider package NVR is `openssl-fips-provider-so-3.0.7-8.el9`, and the module reports `3.0.7-395c1a240fbfffd8`. The arm64 provider package NVR is `openssl-fips-provider-so-3.0.7-11.el9_8`, and the module reports `3.0.7-cda111b5812c30d4`.

`base-micro` ships only the OpenSSL provider above. It does not ship Go, Node.js, Python, Java, BC-FJA jars, or a language runtime. Family certificates are listed below only to keep the platform ledger coherent; they are not claims about this image.

## Family CMVP context

| Module or runtime | Family use | CMVP status | base-micro scope |
| --- | --- | --- | --- |
| RHEL 9 OpenSSL FIPS Provider, `fips.so` v3.0.7-395c1a240fbfffd8 | `base-micro` amd64, future `base-python` OpenSSL-backed paths, future `base-node` when dynamically linked to system OpenSSL | #4857 ACTIVE | Shipped on amd64 |
| RHEL 9 OpenSSL FIPS Provider, `fips.so` v3.0.7-cda111b5812c30d4 | `base-micro` arm64 | Not CMVP validated for arm64 OE | Shipped on arm64, approved-mode configured and self-test passing only |
| Go Cryptographic Module v1.0.0 | Go-static leaves built with `GOFIPS140=v1.0.0` | #5247 ACTIVE | Not shipped here |
| BC-FJA v2.0.0 | Future Java/Keycloak leaves configured for BCFIPS approved-only mode | #4743 ACTIVE | Not shipped here |
| Node.js | Future `base-node` consumer of linked OpenSSL | No independent CMVP certificate; FIPS derives from OpenSSL #4857 when linkage gates pass | Not shipped here |

Python-specific `hashlib` bypass limitations belong to the planned Python variant. This image does not ship Python and does not make a Python interpreter-wide FIPS claim.

## Out-of-scope certificates

Do not claim these certificates for this repository unless the exact covered module version is actually shipped and gated:

- RHEL 9.0 OpenSSL #4746 is older and narrower than the RHEL 9 OpenSSL provider #4857 shipped on amd64.
- BC-FJA 2.1.0 interim #4943 applies only to that BC-FJA 2.1.0 line, which `base-micro` does not ship.
- Go module v1.26.0 is Pending Review and is not the ACTIVE Go #5247 module.

## Runtime mechanism

The runtime image ships the Red Hat OpenSSL provider through the `ca-certificates` and explicit `openssl-fips-provider` RPM closure, alongside system `libcrypto.so.3`. The runtime does not include the `openssl` CLI.

Approved mode is forced with `/etc/pki/tls/openssl-fips.cnf` and image ENV:

```text
OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf
OPENSSL_MODULES=/usr/lib64/ossl-modules
```

The config is self-contained: `fips` and `base` providers are active, the default provider is not activated, and `default_properties = fips=yes` is the approved mode switch. Red Hat disables `openssl fipsinstall` in its OpenSSL build, so this image does not run `openssl fipsinstall`, generate `fipsmodule.cnf`, or include `fipsmodule.cnf`. The RHEL provider self-verifies when it loads; `status: active` from `openssl list -providers` is the captured self-test PASS signal for this RHEL model.

The Docker build verifies the exact shipping config in a builder stage that has the OpenSSL CLI. That gate captures the per-arch provider NEVRA, `openssl-libs` NEVRA, `fips.so` SHA-256, the `fips` provider `status: active` and version, confirms `base` is active and `default` is absent, rejects MD5, and confirms SHA-256 plus AES-256-CBC succeed. The runtime rootfs stage then fails closed unless the provider NEVRA matches the per-arch pin, the shipped `fips.so` SHA-256 equals the verified-stage `fips.so`, and the shipped `openssl-libs` NEVRA equals the verified-stage loader boundary. The runtime test only checks artifacts, labels, and ENV because base-micro intentionally has no shell or OpenSSL CLI.

## Per-architecture validation scope

This image publishes `linux/amd64` and `linux/arm64` runtime manifests with the Red Hat OpenSSL FIPS provider enabled on both architectures. Both platforms run the same build-time FIPS gate: the provider must load in approved mode, refuse MD5, match the shipped runtime `fips.so` by NEVRA and SHA-256, and report the module version selected for that architecture.

The CMVP validation scope is per operational environment. NIST CMVP certificate #4857 and its security policy list tested operational environments on x86_64, IBM Z, and POWER platforms; they do not list an aarch64 or arm64 operational environment.

| Platform | Provider NVR | Module version | OE validation scope | Runtime status artifact |
| --- | --- | --- | --- | --- |
| `linux/amd64` | `openssl-fips-provider-so-3.0.7-8.el9` | `3.0.7-395c1a240fbfffd8` | CMVP #4857-validated approved-mode configuration. | `/etc/nwarila/fips-status.json` keeps the main-compatible amd64 status shape with `"oe_validated": true` and the amd64 module version; provider NVR is surfaced in OCI labels and publish annotations to preserve rootfs byte identity. |
| `linux/arm64` | `openssl-fips-provider-so-3.0.7-11.el9_8` | `3.0.7-cda111b5812c30d4` | Approved-mode configured and self-test passing, but not a CMVP-validated configuration on this architecture. | `/etc/nwarila/fips-status.json` has `"oe_validated": false`, `"provider_nvr": "openssl-fips-provider-so-3.0.7-11.el9_8"`, and the arm64 module version. |

The arm64 disclaimer is part of the runtime image. The publish manifest carries per-architecture `org.nwarila.fips.cmvp.oe-validated`, `org.nwarila.fips.module-version`, and `org.nwarila.fips.provider-nvr` annotations.

```text
The Red Hat OpenSSL FIPS provider is present, approved-mode-configured, and self-test-passing, but this aarch64 operational environment is NOT in CMVP #4857's validated or vendor-affirmed list - this is NOT a CMVP-validated configuration on this architecture.
```

The owner-ratified TD-3 posture is therefore multi-arch with honest per-arch scope: amd64 is #4857-validated approved mode, while arm64 is approved-mode configured and explicitly non-validated.

References:

- NIST CMVP certificate #4857: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4857>
- NIST-hosted security policy for #4857: <https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp4857.pdf>
- TD-3: arm64 OpenSSL FIPS is not CMVP-cert-validated; per-arch FIPS scope.

## Scope

This is a module-scoped and approved-mode-scoped claim: base-micro uses the FIPS-validated OpenSSL provider (#4857) in approved mode on amd64, and uses an approved-mode configured, self-test-passing but not CMVP-validated OpenSSL provider on arm64. It is never an OS-scoped, host-scoped, container-scoped, image-scoped, or application-scoped FIPS validation claim. Say "uses a FIPS-validated module in approved mode" only for amd64. For arm64, say "uses the Red Hat OpenSSL FIPS provider in approved mode with self-tests passing, but the OE is not CMVP validated". Do not say "FIPS-compliant system", "FIPS-validated container", or "container in FIPS mode".

The host/runtime kernel remains non-FIPS by platform decision: `fips_enabled = 0`. That value is a host/kernel property and is not inherited from this image. RHEL distro-wide host FIPS plumbing, including `fips-mode-setup` and kernel-triggered crypto-policy auto-FIPS behavior, is not enabled by this container image.

Go-static leaves ignore this OpenSSL provider and must carry their own validated Go module (#5247). Planned Node and Python variants must document their own consumer boundaries; `base-micro` only provides the OpenSSL module and the approved-mode OpenSSL configuration.
