# ADR-0016: Remove Vulnerable Components Only Outside Declared Supported Surfaces

- Status: Accepted
- Date: 2026-07-29
- Last reviewed: 2026-07-31
- Scope: repo

## Context

Language-runtime images contain packaged features that may be optional from the
runtime's perspective but visible to consumers as standard APIs. Calling a
library "unused" merely because an empty base image does not invoke it would
silently narrow that consumer surface. Conversely, retaining an unused,
vulnerable engine expands the attack surface and can leave the image exposed
when no vendor remediation is available.

The Red Hat Python 3.12 package makes `sqlite-libs` a hard dependency solely for
the optional `_sqlite3` extension and `sqlite3` standard-library package.
`base-python` does not include SQLite in its declared supported surface. No
other shipped ELF object needs `libsqlite3.so.0`, so retaining the engine would
serve no supported consumer.

## Decision

Vulnerable components may be removed from an image only after an image-specific
review proves they are outside that image's declared supported runtime and API
surface. Every consumer removed with the component must be named, and gates
must prove package metadata, remaining ELF dependencies, payload ownership,
SBOMs, scanner reports, and runtime behavior remain truthful.

For `base-python`, remove the packaged `sqlite3` directory, `_sqlite3` extension,
and its build-id link from the retained `python3.12-libs` payload before
computing the protected ELF closure. Then erase `sqlite-libs` as a
`final_rpmdb=no` transaction package. The exact 20-path per-architecture
deviation is materialized from the semantic policy committed in
`images/python/rpm-lock/retained-payload-trim.json`. The native extension's
single GNU build ID derives its canonical link, and installed RPM ownership,
file/link metadata, and the link's actual resolved target must all agree before
the trim. The `rpm -V --nodeps python3.12-libs` result must then report exactly
the materialized set and no other retained-package payload deviation.

The raw-scanner proof uses `python3.12-libs` as a policy selector, not as a
hardcoded package identity. With required `--contract` and `--arch` inputs,
`images/python/tools/assert-raw-scanners-no-sqlite.py` selects exactly one
matching NEVRA from `runtime.shipped[arch]` and compares its complete epoch,
version, release, and RPM architecture with Trivy's package inventory. Trivy
therefore supplies the positive content evidence. Grype exposes findings rather
than a package inventory, so `matches: []` is a legitimate clean result; every
present match is still schema-checked, and both reports are still searched for
`sqlite-libs` and the five associated CVEs. Malformed marker NEVRAs, colons in
the compared version or release, and whitespace-bearing Trivy package or Grype
artifact names fail as malformed evidence. The adjacent `tools/assert-vex.py`
gate, not this raw absence gate, binds the two reports to each other and to the
scanned product.

This decision does not authorize mechanical stripping from other language
images. Node and Java require independent dependency and API review. Standard
runtime features are presumed supported unless the image prominently declares
their omission and gives consumers a viable alternative.

## Consequences

- `base-python` intentionally does not support `import sqlite3`.
- Adding `sqlite-libs` to a derived image is insufficient because the matching
  Python package and native extension payload are absent; consumers need a
  fuller Red Hat Python base or a derivative retaining both parts.
- The final rpmdb and all three SBOM formats omit `sqlite-libs`; raw Trivy and
  Grype reports must contain neither that package nor the five associated
  findings before OpenVEX is evaluated. A correctly formed pair with zero
  vulnerability findings is a successful proof, not a gate failure.
- The retained `python3.12-libs` RPM has a deliberate, exact payload deviation
  instead of an implied claim of complete RPM payload fidelity.
- Future removals require the same supported-surface analysis and evidence; this
  record creates no automatic inheritance across the image family.

## References

- `images/README.md`
- `images/python/README.md`
- `images/python/rpm-lock/retained-payload-trim.json`
- `images/python/tools/build-python-rootfs.py`
- `images/python/tools/run-python-gates.sh`
- `images/python/tools/assert-raw-scanners-no-sqlite.py`
- `tools/assert-vex.py`
- `tools/assert-no-phantom-packages.py`
- `docs/decision-records/repo/0005-strip-runtime-with-phantom-package-guard.md`
