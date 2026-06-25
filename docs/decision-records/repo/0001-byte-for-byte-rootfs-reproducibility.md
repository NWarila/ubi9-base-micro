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

## Decision

`ubi9-base-micro` enforces a build-failing, per-architecture exported-rootfs
byte-identity gate with `tools/assert-reproducible.py --assert-byte-identical`.
The comparison includes file content, metadata, ownership, type, presence, and
`/var/lib/rpm`. The runtime RPM lockfiles pin NEVRA plus `%{SHA256HEADER}` and
`%{SIGMD5}` so same-NEVRA content drift fails before the strip stage.

`linux/amd64` is checked natively. `linux/arm64` is checked through the pinned
QEMU/binfmt path used by the publish workflow, so its current proof is
emulator-relative to that pinned input.

## Consequences

- The rpmdb remains present and valid for SBOM and scanner truthfulness.
- A timestamp, rpmdb, ownership, or content drift breaks CI instead of being
  documented away.
- Cross-host and native-arm64 reproduction can strengthen the proof later, but
  they do not replace the current fail-closed gate.
- Any image-input change must preserve the both-architecture byte-identity proof
  or be treated as an image change requiring a fresh proof.

## References

- Reproducible Builds documentation: <https://reproducible-builds.org/docs/>
- SLSA security levels: <https://slsa.dev/spec/v1.0/levels>
- Repository details: `docs/explanation/reproducibility.md`, `tools/assert-reproducible.py`,
  `rpm-lock/runtime.amd64.txt`, `rpm-lock/runtime.arm64.txt`
