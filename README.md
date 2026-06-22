# ubi9-base-micro

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/NWarila/ubi9-base-micro/badge)](https://scorecard.dev/viewer/?uri=github.com/NWarila/ubi9-base-micro)
[![CodeQL](https://github.com/NWarila/ubi9-base-micro/actions/workflows/codeql.yml/badge.svg)](https://github.com/NWarila/ubi9-base-micro/actions/workflows/codeql.yml)

`ubi9-base-micro` builds the root UBI 9 micro base for the NWarila base-image
family. This repository produces two local-test image tags from one Dockerfile:

- `base-micro`: glibc plus RHEL CA trust, no shell, no package-manager
  executable, RPM database preserved at `/var/lib/rpm`, and `USER 65532:65532`.
- `base-micro-dev`: the same UBI 9 floor with a shell and a minimal native
  build toolchain for leaf build-time stages.

## Image family

The platform base family is a four-repo family. Only `ubi9-base-micro` exists in
this repository today; the language variants below are planned and must not be
read as published artifacts from this repo.

| Image | Status | Base relationship | Runtime scope |
| --- | --- | --- | --- |
| `base-micro` | Current repository | Root image | glibc, CA trust, rpmdb, OpenSSL #4857 provider |
| `base-python` | Planned | `FROM base-micro@sha256:<digest>` | CPython runtime on the micro floor |
| `base-node` | Planned | `FROM base-micro@sha256:<digest>` | Node.js runtime on the micro floor |
| `base-java` | Planned | `FROM base-micro@sha256:<digest>` | OpenJDK runtime on the micro floor |

The evidence contract for each image in the family is the same: cosign keyless
signature, SLSA L3 provenance, rpmdb-derived SPDX and CycloneDX SBOMs, Trivy and
Grype fixable-CVE gates, OpenVEX default-deny coverage for unfixed HIGH/CRITICAL
findings, NIST SP 800-190 section 4.1 image evidence, tailored STIG ARF, and
byte-for-byte reproducibility. Published signatures and attestations are
Rekor-logged. `base-micro` implements that contract here; planned variants must
carry the same evidence set in their own repositories before publication.

Responsibility boundary: the base family owns a standard hardened floor through
RPM hygiene (`install_weak_deps=0`, `--nodocs`, locale/man stripping, shell
removal, discarded builders) with the rpmdb preserved for truthful scanning. The
leaf/user owns app-specific minimization such as Java `jdeps`/`jlink`, Python
stdlib pruning, and application dependency trimming.

## Workflows

The local build workflow stays test-only. The nightly sentinel runs on a
schedule and by `workflow_dispatch`; it rebuilds the pinned runtime, runs the
same test-only gate set as PR CI, and runs the byte-for-byte reproducibility hard
gate for both `linux/amd64` and `linux/arm64`. It does not publish, sign, or
attest. A new fixable HIGH/CRITICAL finding against a pinned RPM or a
reproducibility break turns the sentinel red so the next RPM-lockfile bump can
absorb the change deliberately.

The publish workflow runs only on `push` to `main` or `v*` tags, building the
`base-micro` runtime for `linux/amd64` and `linux/arm64`, signing the pushed
digest, attaching rpmdb-derived SBOMs and image-control evidence, and invoking
the SLSA L3 container provenance generator.

The runtime uses the Red Hat Enterprise Linux 9 OpenSSL FIPS Provider in
approved mode through `/etc/pki/tls/openssl-fips.cnf` and
`OPENSSL_CONF`/`OPENSSL_MODULES`. The amd64 image keeps the CMVP #4857
`openssl-fips-provider-so-3.0.7-8.el9` baseline with `fips.so` version
`3.0.7-395c1a240fbfffd8`. The arm64 image uses
`openssl-fips-provider-so-3.0.7-11.el9_8` with `fips.so` version
`3.0.7-cda111b5812c30d4`, approved-mode configured and self-test passing but
explicitly not a CMVP-validated configuration on that architecture. These are
module-scoped and approved-mode-scoped statements, not host, OS, container, or
application FIPS validation claims. The platform host remains non-FIPS. See
`docs/fips.md`.

The authoritative SBOM evidence is Syft rpmdb-derived SPDX and CycloneDX,
attested per published platform child digest. BuildKit SBOM output is disabled
so the published SPDX evidence has a single source. Vulnerability scanners,
OpenVEX default-deny, NIST SP 800-190 section 4.1 image evidence, and the
tailored RHEL9 STIG ARF gate are gated in CI; publish attaches the STIG ARF
summary predicate per platform digest. See `docs/stig.md`.

Runtime footprint is gated by `tools/assert-footprint.py` using
exported-rootfs-regular-file-bytes. The current amd64 runtime measures
23,840,723 bytes / 22.7363 MiB against the 25 MiB H2 gate; local OCI compressed
layer sum is 12,095,601 bytes / 11.5353 MiB. See `docs/footprint.md`.

Repository-specific decisions are recorded under `docs/decision-records/repo/`.
They cover the byte-for-byte reproducibility gate, FIPS scope, SLSA generator
identity model, runtime strip posture, RPM refresh loop, scanner/VEX policy,
STIG and NIST evidence, CI runner determinism, and base-family topology.

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

## License

This repository is licensed under the terms in [LICENSE](LICENSE).
