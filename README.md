# ubi9-base-micro

`ubi9-base-micro` builds the root UBI 9 micro base for the NWarila base-image
family. This scaffold produces two local-test image tags from one Dockerfile:

- `base-micro`: glibc plus RHEL CA trust, no shell, no package-manager
  executable, RPM database preserved at `/var/lib/rpm`, and `USER 65532:65532`.
- `base-micro-dev`: the same UBI 9 floor with a shell and a minimal native
  build toolchain for leaf build-time stages.

This step is intentionally test-only. FIPS configuration, publishing, signing,
SLSA provenance, SBOM attestations, vulnerability scanners, STIG ARF, and
800-190 evidence are later phase work.

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
