# OpenVEX Absence Evidence

OpenVEX is retained only for the two `base-python` absence proofs under
`images/python/vex/`. It is not used to clear or block scanner findings.
Unfixed vendor CVEs are report-only; fixable MEDIUM, HIGH, and CRITICAL findings
still fail through the native Trivy and Grype gates.

The retained documents cover:

- `images/python/vex/sqlite-component-not-present.openvex.json`, covering five
  SQLite CVEs whose `sqlite-libs`, native library, CPython extension,
  standard-library directory, and build-ID link are independently proven absent;
- `images/python/vex/cve-2026-53613.openvex.json` on `libuuid`, whose vulnerable
  `mount(8)` code is absent because both `util-linux` and `util-linux-core` are
  independently proven absent.

The Python production publisher requires a non-empty document set, attests every
document to both platform children, verifies the OpenVEX attestations, and checks
their Rekor presence during independent verification. The exact documents and
their proof wiring are locked by `tools/verify.py`; complete scanner JSON and
SARIF remain sealed evidence. OpenVEX does not suppress scanner findings.
