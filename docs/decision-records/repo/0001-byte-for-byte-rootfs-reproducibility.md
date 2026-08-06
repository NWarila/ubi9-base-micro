# ADR-0001: Enforce Byte-For-Byte Rootfs Reproducibility

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

This image is a base artifact. Downstream consumers rely on it as a stable
floor, so a rebuild from the same inputs must not silently change file content,
metadata, or the scanner-visible RPM database. Normalizing away the rpmdb would
make the image easier to compare but would also remove the evidence source used
by SBOM and vulnerability scanners.

The builder is also an image input. A moving Buildx executable or BuildKit
driver image can change exported rootfs bytes even when the Dockerfile and RPM
inputs do not change, so action-SHA pinning alone is not a complete input
contract.

## Decision

`ubi9-base-micro` enforces a build-failing, per-architecture exported-rootfs
byte-identity gate with `tools/assert-reproducible.py --assert-byte-identical`.
The comparison includes file content, metadata, ownership, type, presence, and
`/var/lib/rpm`. The runtime RPM lockfiles pin NEVRA plus `%{SHA256HEADER}` and
`%{SIGMD5}` so same-NEVRA content drift fails before the strip stage.

`linux/amd64` is checked natively. `linux/arm64` is checked through the publish
workflow's QEMU/binfmt path, with both the setup action SHA and the binfmt index
digest immutably pinned, so its current proof is emulator-relative to those
pinned inputs.

The built-and-gated, unpublished `base-python` path additionally defines its
build graph in `images/python/docker-bake.json`. That native Bake contract owns
the context, Dockerfile, runtime target, platforms, fixed timestamp arguments,
and the distinct CI, release, and double-build exporter policies. It pins
Buildx by version, expected commit, and independently verified Linux-amd64 release-asset
SHA-256, and pins the BuildKit driver by a versioned digest-qualified image
reference. Both Python builder jobs assert those identities before building.
`tools/verify.py` requires exactly the `base`, `ci`, `release`, and `repro`
targets; the three non-base targets must inherit the shared target without
redeclaring protected graph inputs. It also requires both builder jobs to derive
their setup and identity inputs from that file. Each named identity step must keep strict shell
mode enabled, omit `continue-on-error`, and finish with the identity checker as
its final unwrapped command. The both-architecture byte gates retain the
committed rootfs and rpmdb values. The workflow and double-build harness use the
contract, but repository verification does not analyze arbitrary Bake
command-line overrides or discover and count build callers. The registry-capable
`release` target is exercised on pull requests against a loopback-bound
ephemeral registry, including unsigned BuildKit provenance and registry-served
rootfs checks. It creates no external or project publication, and the contract
contains no production publisher. The non-Python Buildx and BuildKit paths remain
outside this decision's new pin and are not made reproducible by the Python
contract.

## Consequences

- The rpmdb remains present and valid for SBOM and scanner truthfulness.
- A timestamp, rpmdb, ownership, or content drift breaks CI instead of being
  documented away.
- Cross-host and native-arm64 reproduction can strengthen the proof later, but
  they do not replace the current fail-closed gate.
- Any image-input change must preserve the both-architecture byte-identity proof
  or be treated as an image change requiring a fresh proof.
- Renovate tracks the Python Buildx release version and the BuildKit
  version-plus-digest reference through separate, non-automerge managers. A
  Buildx version update cannot pass until its expected commit and asset SHA-256
  are updated to the same release identity.
- A Python Buildx or BuildKit update fails closed until its executable or image
  identity and both-architecture byte gates pass together.

## References

- Reproducible Builds documentation: <https://reproducible-builds.org/docs/>
- SLSA security levels: <https://slsa.dev/spec/v1.0/levels>
- Repository details: `docs/explanation/reproducibility.md`, `tools/assert-reproducible.py`,
  `images/python/docker-bake.json`, `images/python/tools/assert-reproducible.py`,
  `rpm-lock/runtime.amd64.txt`, `rpm-lock/runtime.arm64.txt`
