# ubi9-base-micro

`ubi9-base-micro` builds the root UBI 9 micro base for the NWarila base-image
family. This scaffold produces two local-test image tags from one Dockerfile:

- `base-micro`: glibc plus RHEL CA trust, no shell, no package-manager
  executable, RPM database preserved at `/var/lib/rpm`, and `USER 65532:65532`.
- `base-micro-dev`: the same UBI 9 floor with a shell and a minimal native
  build toolchain for leaf build-time stages.

The local build workflow stays test-only. The publish workflow runs only on
`push` to `main` or `v*` tags, building the `base-micro` runtime for
`linux/amd64` and `linux/arm64`, signing the pushed digest, attaching
rpmdb-derived SBOMs, and invoking the SLSA L3 container provenance generator.

The runtime ships Red Hat CMVP #4857 `fips.so` in approved mode through
`/etc/pki/tls/openssl-fips.cnf` and `OPENSSL_CONF`/`OPENSSL_MODULES`. This is
not a host, OS, container, or application FIPS validation claim; the platform
host remains non-FIPS. The amd64 image is in #4857's validated OE scope; the
arm64 image is approved-mode configured and self-test passing but explicitly not
a CMVP-validated configuration on that architecture. See `docs/fips.md`.

The authoritative SBOM evidence is Syft rpmdb-derived SPDX and CycloneDX,
attested per published platform child digest. BuildKit SBOM output is disabled
so the published SPDX evidence has a single source. Vulnerability scanners,
STIG ARF, and 800-190 evidence remain out of scope for this slice.

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
