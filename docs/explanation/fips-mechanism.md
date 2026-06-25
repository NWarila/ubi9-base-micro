# FIPS Mechanism

`base-micro` enables the Red Hat Enterprise Linux 9 OpenSSL FIPS Provider with
a config-only approved-mode mechanism. The runtime image ships
`openssl-fips-provider-so-3.0.7-8.el9`; the module reports
`3.0.7-395c1a240fbfffd8`.

The runtime image does not run `openssl fipsinstall`, generate
`fipsmodule.cnf`, or ship the `openssl` CLI. Red Hat disables upstream
`openssl fipsinstall` in this OpenSSL build. Instead, the image ships
`/etc/pki/tls/openssl-fips.cnf` and sets:

```text
OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf
OPENSSL_MODULES=/usr/lib64/ossl-modules
```

The config activates the `fips` and `base` providers, does not activate the
default provider, and sets `default_properties = fips=yes`. The provider
self-verifies when it loads. The build-stage OpenSSL CLI gate records the
provider `status: active`, rejects MD5, and confirms approved algorithms such as
SHA-256 and AES-256-CBC succeed.

The validation claim is architecture-scoped:

| Platform | Scope |
| --- | --- |
| `linux/amd64` | CMVP #4857-validated approved-mode configuration for the shipped provider module. |
| `linux/arm64` | Same module, same provider NVR, approved-mode configured and self-test passing, but not a CMVP-validated operational environment because #4857 lists no aarch64 or arm64 OE. |

This is a module-scoped and approved-mode-scoped statement. It is not an
OS-scoped, host-scoped, image-scoped, container-scoped, or application-scoped
FIPS validation claim. The platform host remains non-FIPS with `fips_enabled =
0`; that kernel property is not inherited from this image.

The full evidence ledger is in [`../compliance/fips.md`](../compliance/fips.md).
