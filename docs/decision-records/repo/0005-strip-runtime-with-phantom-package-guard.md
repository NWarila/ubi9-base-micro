# ADR-0005: Strip Runtime Payload Only Behind Rpmdb And Ownership Guards

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

The runtime needs to be small and shell-free, but it also needs truthful RPM
metadata for scanners, SBOM generation, and vulnerability accountability.
Removing files after RPM install can create phantom packages if the rpmdb still
claims payload that no longer exists. Removing the rpmdb would hide that problem
from scanners.

## Decision

The Dockerfile strips only after installing a locked RPM transaction and proving
that protected FIPS and glibc dependencies are not owned by strip candidates.
The runtime keeps the rpmdb. `tools/assert-no-phantom-packages.py` compares the
runtime rpmdb and exported rootfs, rejects missing shippable payload, and checks
that remaining ELF files are owned by runtime RPMs.

The footprint gate measures exported-rootfs regular-file bytes and enforces the
25 MiB uncompressed H2 target for the runtime image.

## Consequences

- The image stays small without sacrificing scanner truthfulness.
- A strip that removes package-owned runtime payload fails CI.
- The retained rpmdb is a deliberate part of the security evidence, not bloat.
- Future strip changes must be evaluated against footprint, rpmdb, SBOM, and
  phantom-package gates together.

## References

- OpenSSF Best Practices criteria: <https://www.bestpractices.dev/en/criteria/0>
- NIST SP 800-190 Application Container Security Guide: <https://csrc.nist.gov/pubs/sp/800/190/final>
- Repository details: `docs/explanation/footprint.md`, `tools/assert-footprint.py`,
  `tools/assert-no-phantom-packages.py`, `containers/Dockerfile`
