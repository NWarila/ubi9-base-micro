# OpenVEX Absence Proofs

This directory contains the reviewed OpenVEX documents backed by independent
absence gates for `base-python`. It is not a vulnerability allowlist: unfixed
findings are report-only, and these statements do not suppress scanner output.

The production publisher attests every JSON document here, byte-unmodified, to
both platform children and verifies the resulting OpenVEX attestations. An empty
document set is fatal. Files remain review-gated through `.github/CODEOWNERS`.

`sqlite-component-not-present.openvex.json` records five
`component_not_present` statements. Build-time ELF/filesystem checks, runtime
import/library/extension/package-directory/build-ID checks, rpmdb/SBOM checks,
the `sqlite-libs` phantom-package assertion, and the raw-scanner assertion all
independently prove that SQLite is absent.

`cve-2026-53613.openvex.json` records `vulnerable_code_not_present` for the
Grype finding on `libuuid` `0:2.37.4-25.el9`. The vulnerable `mount(8)` payload
belongs to `util-linux-core`; CI and publication invoke the generic
phantom-package assertion with both `util-linux` and `util-linux-core` expected
absent on each architecture.

The complete Trivy and Grype JSON and SARIF reports remain available as sealed
evidence regardless of these statements.
