# OpenVEX Dispositions

This directory is the reviewed source for OpenVEX dispositions used by the base-python CVE gate. The gate is default-deny: every unfixed HIGH or CRITICAL finding reported by either Trivy or Grype must match an accepted statement here, or the workflow fails.

Accepted statements must be OpenVEX JSON files with:

- `@context` and a non-empty `statements` array.
- `vulnerability.name` or an equivalent vulnerability id matching the scanner finding.
- `products[].@id` matching the exact image reference scanned, or the same reference prefixed with `pkg:oci/`.
- `status: "fixed"` or `status: "not_affected"` with one of the standard OpenVEX justifications, except for the exact accept-and-track path below.

`affected` satisfies the gate only for the exact, expiring CVE-2026-11940
accept-and-track authorization implemented in `tools/assert-vex.py` and matched
by `cve-2026-11940.openvex.json`. Every other `affected` statement, and every
`under_investigation` statement, remains documentary and does not satisfy the
gate. Files under `vex/` require review through `.github/CODEOWNERS`. The
pull-request release preflight does not attest OpenVEX; a future production
publisher will attest each JSON file to the per-architecture image digests with
`cosign attest --type openvex`.

The image inherits the deliberately held FIPS provider packages from its parent, so the same
disclosure applies here with a base-python product identity.

`cve-2026-31790.openvex.json` discloses that the deliberately held FIPS provider
packages are affected and gives downstream consumers mitigation guidance. This
statement is documentary: it does not suppress the finding or satisfy the
default-deny gate. The exact, expiring scanner suppression is maintained
separately under `security/` and tracked as TD-6 in `docs/TECH-DEBT.md`.

`cve-2026-11940.openvex.json` discloses that both base-python CI products ship
the affected `python3.12` and `python3.12-libs` packages at
`3.12.13-3.el9_8.1`. The gate accepts that known-affected finding only when the
document and the in-tool allowlist match every canonical product, package,
version, status, TD-9, and `review-by 2026-10-01` field. The authorization is
refused if either scanner supplies valid fix evidence. Gate expiry is scoped to
a present matching candidate; `tools/verify.py` independently expires a dormant
repository entry after the review date.

`sqlite-component-not-present.openvex.json` records five distinct
`not_affected` / `component_not_present` dispositions for CVE-2026-51296,
CVE-2026-51297, CVE-2026-51302, CVE-2026-51303, and CVE-2026-51304. The
statements bind the image products, not an included SQLite subcomponent:
`sqlite-libs`, `libsqlite3`, the CPython `_sqlite3` extension, the `sqlite3`
stdlib package directory, and the matching build-id link are all absent from
the final image. Build, runtime, rpmdb, SBOM, phantom-package, and raw-scanner
gates independently prove that absence before OpenVEX is applied. The raw
scanner gate treats a correctly formed zero-finding pair as a pass: Trivy's
inventory provides the contract-derived runtime-package marker, while Grype's
findings-only `matches` list may be empty. `tools/assert-vex.py` then separately
binds the report identities to each other and to the scanned product before it
evaluates findings and dispositions.
