# ubi9-base-micro

`ubi9-base-micro` builds the root UBI 9 micro base for the NWarila base-image
family. This scaffold produces two local-test image tags from one Dockerfile:

- `base-micro`: glibc plus RHEL CA trust, no shell, no package-manager
  executable, RPM database preserved at `/var/lib/rpm`, and `USER 65532:65532`.
- `base-micro-dev`: the same UBI 9 floor with a shell and a minimal native
  build toolchain for leaf build-time stages.

This step is intentionally test-only. P1.3 delivers the module-scoped OpenSSL
FIPS provider floor for C/OpenSSL consumers: the runtime ships Red Hat CMVP
#4857 `fips.so` in approved mode through `/etc/pki/tls/openssl-fips.cnf` and
`OPENSSL_CONF`/`OPENSSL_MODULES`. This is not a host, OS, container, or
application FIPS validation claim; the platform host remains non-FIPS. Publishing,
signing, SLSA provenance, SBOM attestations, vulnerability scanners, STIG ARF,
and 800-190 evidence remain out of scope for this test-only PR.

## Local Build

Build both local tags:

```sh
make build
```

Run the runtime hardening gate against `base-micro`:

```sh
make test
```

The repository namespace for future publish work is:

```text
ghcr.io/nwarila/ubi9-base-micro
```
