# ubi9-base-micro

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/NWarila/ubi9-base-micro/badge)](https://scorecard.dev/viewer/?uri=github.com/NWarila/ubi9-base-micro)
[![CodeQL](https://github.com/NWarila/ubi9-base-micro/actions/workflows/codeql.yml/badge.svg)](https://github.com/NWarila/ubi9-base-micro/actions/workflows/codeql.yml)

`ubi9-base-micro` builds the root UBI 9 micro base for the NWarila base-image
family. It produces two local-test image tags from one Dockerfile:

- `base-micro`: glibc plus RHEL CA trust, no shell, no package-manager
  executable, RPM database preserved at `/var/lib/rpm`, and `USER 65532:65532`.
- `base-micro-dev`: the same UBI 9 floor with a shell and a minimal native
  build toolchain for leaf build-time stages.

## Why It Exists

The image is the smallest hardened floor in the platform base family. It keeps
the rpmdb for truthful scanners, installs all runtime RPMs from direct Red Hat
UBI CDN pins with raw `rpm -Uvh`, configures the Red Hat OpenSSL FIPS provider
in approved mode, and removes runtime shell/package-manager entry points. The
leaf image or application still owns app-specific minimization such as Java
`jdeps`/`jlink`, Python stdlib pruning, and application dependency trimming.

## Image Family

Only `ubi9-base-micro` exists in this repository today; the language variants
below are planned and must not be read as published artifacts from this repo.

| Image | Status | Base relationship | Runtime scope |
| --- | --- | --- | --- |
| `base-micro` | Current repository | Root image | glibc, CA trust, rpmdb, OpenSSL #4857 provider |
| `base-python` | Planned | `FROM base-micro@sha256:<digest>` | CPython runtime on the micro floor |
| `base-node` | Planned | `FROM base-micro@sha256:<digest>` | Node.js runtime on the micro floor |
| `base-java` | Planned | `FROM base-micro@sha256:<digest>` | OpenJDK runtime on the micro floor |

The evidence contract for each image in the family is the same: cosign keyless
signature, SLSA L3 provenance, rpmdb-derived SPDX and CycloneDX SBOMs, Trivy and
Grype fixable-CVE gates, OpenVEX default-deny coverage for unfixed HIGH/CRITICAL
findings, NIST SP 800-190 section 4.1 image evidence, tailored RHEL9 STIG ARF,
and byte-for-byte reproducibility. Published signatures and attestations are
Rekor-logged. `base-micro` implements that contract here; planned variants must
carry the same evidence set in their own repositories before publication.

Responsibility boundary: the base family owns a standard hardened floor through
RPM hygiene (`install_weak_deps=0`, `--nodocs`, locale/man stripping, shell
removal, discarded builders) with the rpmdb preserved for truthful scanning. The
leaf/user owns app-specific minimization such as Java `jdeps`/`jlink`, Python
stdlib pruning, and application dependency trimming.

## Quickstart

Build both local tags:

```sh
make build
```

Run the runtime hardening gate against `base-micro`:

```sh
make test
```

Run the repository contract verifier:

```sh
python tools/verify.py
```

The repository namespace for publish work is:

```text
ghcr.io/nwarila/ubi9-base-micro
```

## Verify a Published Digest

Published digest verification uses `cosign verify`, `cosign verify-attestation`,
and `slsa-verifier verify-image` against exact GitHub Actions OIDC identities.
Use [`docs/reference/verify.md`](docs/reference/verify.md) for the copy-paste
contract and [`docs/how-to/verify-a-published-image.md`](docs/how-to/verify-a-published-image.md)
for the task flow. `gh attestation verify` is not part of this repository's
published-image contract.

## Security and Compliance Posture

The runtime uses the Red Hat Enterprise Linux 9 OpenSSL FIPS Provider in
approved mode through `/etc/pki/tls/openssl-fips.cnf` and
`OPENSSL_CONF`/`OPENSSL_MODULES`. Both amd64 and arm64 hold
`openssl-fips-provider-so-3.0.7-8.el9` with `fips.so` version
`3.0.7-395c1a240fbfffd8`; the provider RPMs are fetched from Red Hat UBI CDN
direct URLs, verified with Red Hat RPM signatures and pinned SHA-256 values, and
installed locally to preserve rpm ownership. The amd64 image is the CMVP #4857
validated approved-mode configuration. The arm64 image ships the same module and
passes approved-mode self-tests, but it is explicitly not a CMVP-validated
configuration on that architecture because #4857 lists no arm64 OE. These are
module-scoped and approved-mode-scoped statements, not host, OS, container, or
application FIPS validation claims. The platform host remains non-FIPS. See
[`docs/compliance/fips.md`](docs/compliance/fips.md) and
[`docs/explanation/fips-mechanism.md`](docs/explanation/fips-mechanism.md).

The authoritative SBOM evidence is Syft rpmdb-derived SPDX and CycloneDX,
attested per published platform child digest. BuildKit SBOM output is disabled
so the published SPDX evidence has a single source. Vulnerability scanners,
OpenVEX default-deny, NIST SP 800-190 section 4.1 image evidence, and the
tailored RHEL9 STIG ARF gate are gated in CI; publish attaches the STIG ARF
summary predicate per platform digest. See
[`docs/compliance/stig.md`](docs/compliance/stig.md),
[`docs/compliance/nist-800-190.md`](docs/compliance/nist-800-190.md), and
[`docs/compliance/vex.md`](docs/compliance/vex.md).

Runtime footprint is gated by `tools/assert-footprint.py` using
exported-rootfs-regular-file-bytes. The current amd64 runtime measures
23,840,723 bytes / 22.7363 MiB against the 25 MiB H2 gate; local OCI compressed
layer sum is 12,095,601 bytes / 11.5353 MiB. See
[`docs/explanation/footprint.md`](docs/explanation/footprint.md).

Repository-specific decisions are recorded under `docs/decision-records/repo/`.
They cover the byte-for-byte reproducibility gate, FIPS scope, SLSA generator
identity model, runtime strip posture, RPM refresh loop, scanner/VEX policy,
STIG and NIST evidence, CI runner determinism, direct-CDN runtime RPM sourcing,
and base-family topology.

## Documentation

The docs follow the org-standard Diataxis layout:

- [Tutorials](docs/tutorials/) for learning walkthroughs.
- [How-to guides](docs/how-to/) for task procedures.
- [Reference](docs/reference/) for contracts and gate inventories.
- [Explanation](docs/explanation/) for design rationale.
- [Compliance](docs/compliance/) for scoped evidence notes.
- [Decision records](docs/decision-records/) for repository ADRs.

Start with [`docs/README.md`](docs/README.md) for the full index.

## License

This repository is licensed under the terms in [LICENSE](LICENSE).
