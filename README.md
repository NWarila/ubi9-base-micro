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

## Verify From a Clean Machine (No Auth)

Anyone can cryptographically verify the published
`ghcr.io/nwarila/ubi9-base-micro:base-micro` image with no registry
authentication. The prerequisites are `cosign`, `crane`, `jq`, and
`slsa-verifier`.

Resolve the moving `base-micro` tag once, then anchor every child lookup to the
resolved index so a concurrent publish cannot mix index and child generations:

```sh
IMAGE="ghcr.io/nwarila/ubi9-base-micro"
TAG="base-micro"
INDEX_DIGEST="$(crane digest "${IMAGE}:${TAG}")"
INDEX_REF="${IMAGE}@${INDEX_DIGEST}"
CHILD_DIGEST="$(crane digest --platform linux/amd64 "${INDEX_REF}")"
CHILD_REF="${IMAGE}@${CHILD_DIGEST}"
PUBLISH_REF="refs/heads/main"
```

Verify the index signature:

```sh
cosign verify "${INDEX_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify the SPDX and CycloneDX attestations on the selected platform child:

```sh
cosign verify-attestation --type spdxjson "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign verify-attestation --type cyclonedx "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Check the verified SPDX predicate for the required glibc package:

```sh
cosign verify-attestation --type spdxjson "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  | jq -r '.payload | @base64d | fromjson | .predicate.packages[].name' | grep -q glibc
```

When a `vex/*.json` file exists in the publishing commit, verify the OpenVEX
attestation on the selected platform child:

```sh
cosign verify-attestation --type openvex "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify the NIST SP 800-190 section 4.1 image-control predicate:

```sh
cosign verify-attestation --type https://nwarila.dev/attestations/nist-sp-800-190-image/v1 "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Verify the tailored RHEL9 STIG ARF predicate:

```sh
cosign verify-attestation --type https://nwarila.dev/attestations/stig-arf/v1 "${CHILD_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Finally, verify the index-bound SLSA provenance with both verifiers:

```sh
cosign verify-attestation --type slsaprovenance "${INDEX_REF}" \
  --certificate-identity "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
slsa-verifier verify-image "${INDEX_REF}" \
  --source-uri github.com/NWarila/ubi9-base-micro \
  --builder-id "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
```

[`docs/reference/verify.md`](docs/reference/verify.md) is the authoritative full
contract, including rationale and edge cases. See also the
[`docs/how-to/verify-a-published-image.md`](docs/how-to/verify-a-published-image.md)
task flow. `gh attestation verify` is not part of this repository's
published-image contract.

## Supply Chain Pipeline

```mermaid
flowchart TB
  subgraph dockerfile["Dockerfile stage DAG"]
    FIPS["fips-verify"] -->|"proof + binaries"| RPM["rpm-rootfs"]
    FIPS -->|"proof"| COMMON["runtime-common"]
    RPM -->|"/rootfs"| COMMON
    COMMON --> AMD["runtime-amd64"]
    COMMON --> ARM["runtime-arm64"]
    AMD --> TARGET["runtime-${TARGETARCH}"]
    ARM --> TARGET
    DEVROOT["dev-rootfs"] --> DEV["dev<br/>defined but NOT published<br/>(build target = runtime)"]
  end

  subgraph publish["publish — push to main/tag only"]
    BUILD["build + push by digest<br/>recursive cosign sign"] --> EVIDENCE["resolve children<br/>tailored STIG ARF + rpmdb SBOMs<br/>scanner freshness + Trivy + Grype + OpenVEX<br/>secret scan + NIST"]
    EVIDENCE --> ATTEST["attest evidence per child"]
  end

  TARGET --> BUILD
  TAG["slsa-generator-tag-integrity"] --> BUILD
  ATTEST --> SLSA["slsa-provenance<br/>SLSA L3 on index<br/>push to main/tag only"]
  ATTEST --> REKOR["rekor-rollup<br/>full split evidence set<br/>push to main/tag only"]
  SLSA --> REKOR
```

Pull requests exercise the tag-integrity job but do not publish, attest, or run
the Rekor roll-up.

## Comparison at a Glance

| Dimension | `ubi9-base-micro` | Stock `ubi9/ubi-micro` | Chainguard | Canonical rocks |
| --- | --- | --- | --- | --- |
| Package/scanner truth | Retained RPM rpmdb, rpmdb-derived SPDX/CycloneDX, and a no-phantom-payload guard (`containers/Dockerfile:159-164,215-230,294-295,387`; `.github/workflows/publish-image.yaml:321-356`) | **Parity on rpmdb presence**, not a differentiator: exporting the exact pinned base from `containers/Dockerfile:10-13` produced `var/lib/rpm/rpmdb.sqlite` | Not RPM-based; Wolfi/APK inventory and signed SBOMs. Say “APK ecosystem / no RPM rpmdb,” never “untruthful” or “SBOM-only” | Not RPM-based; Chisel records package, slice, and file metadata in `manifest.wall` specifically for SBOM generators and scanners. Say “dpkg/Chisel ecosystem / no RPM rpmdb,” never “untruthful” |
| Signing, SBOM, provenance / SLSA | Cosign keyless signature, per-child SPDX+CycloneDX, and index-bound trusted-generator SLSA L3 (`.github/workflows/publish-image.yaml:196-220,470-545,809-823`) | Do not assert absence without digest-specific vendor evidence | **Parity capability:** all images have signed SPDX and SLSA provenance; Chainguard states SLSA 3 and signs images/attestations | **No negative:** Canonical's public OCI factory generates SBOMs and provenance; exact signing and SLSA level vary by rock/channel and must be verified for a named artifact. Do not show “no SLSA,” “unsigned,” or “no SBOM” |
| STIG evidence | Committed, tailored RHEL9 profile; fail-closed ARF; signed per-child predicate (`.github/workflows/publish-image.yaml:262-319,689-739`; `docs/compliance/stig.md:15-56`) | Do not claim a stock-image-specific signed ARF without evidence | Not a lack: Chainguard has a GPOS-SRG STIG profile and STIG-hardened FIPS images. The honest distinction is **this repo's tailored RHEL9 ARF attestation**, not “Chainguard lacks STIG” | Ubuntu has DISA-STIG material; rock evidence varies. RHEL9 tailoring is inapplicable, so compare exact evidence only and do not claim Canonical lacks STIG |
| CMVP FIPS | Exact RHEL OpenSSL provider #4857 in approved mode **on amd64 only**; arm64 ships the same provider/self-tests but is not a validated OE (`containers/Dockerfile:304-335,391-410`; `docs/compliance/fips.md:59-84`) | Do not infer this held provider/config from stock UBI Micro | Not a lack: Chainguard markets FIPS containers using other validated modules (including OpenSSL #4282) and approved-only mode. #4857 plus this repo's architecture-scoped evidence is the distinction | Canonical offers Ubuntu FIPS modules/containers under its own certificates and host/runtime conditions. Do not claim general FIPS absence; only say the compared rock does not establish this exact #4857 mechanism unless verified |
| Byte reproducibility | Fail-closed, two-build, both-architecture exported-rootfs identity plus contract digest/rpmdb assertions (`docs/explanation/reproducibility.md:3-29,39-52`) | No product-wide negative; mark “not evaluated” unless a digest-specific source is supplied | **Parity capability:** Chainguard documents bit-for-bit reproduction from signed apko configuration. The local differentiator is the explicit canonical-rootfs/rpmdb CI gate, not reproducibility itself | Mark “varies/not established for the named rock”; do not assert non-reproducibility |
| Footprint | amd64 regular-file rootfs: 23,840,723 B / 22.7363 MiB, gated at 25 MiB (`README.md:198-202`; `docs/explanation/footprint.md:3-24`) | Same-method export of the Dockerfile-pinned stock digest measured 22,995,384 B / 21.9301 MiB; therefore this repo is about 0.81 MiB larger and must not claim it is smaller | Varies by image and package set; no generic number or winner claim | Varies by rock and slices; no generic number or winner claim |

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
