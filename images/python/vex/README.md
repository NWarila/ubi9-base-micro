# OpenVEX Dispositions

This directory is the reviewed source for OpenVEX dispositions used by the base-python CVE gate. The gate is default-deny: every unfixed HIGH or CRITICAL finding reported by either Trivy or Grype must match an accepted statement here, or the workflow fails.

Accepted statements must be OpenVEX JSON files with:

- `@context` and a non-empty `statements` array.
- `vulnerability.name` or an equivalent vulnerability id matching the scanner finding.
- `products[].@id` matching the exact image reference scanned, or the same reference prefixed with `pkg:oci/`.
- `status: "fixed"` or `status: "not_affected"` with one of the standard OpenVEX justifications.

`affected` and `under_investigation` are valid OpenVEX statuses, but they do not satisfy this gate. Files under `vex/` require review through `.github/CODEOWNERS`; the publish workflow introduced by a later change will attest each JSON file to the per-architecture image digests with `cosign attest --type openvex`.

The image inherits the deliberately held FIPS provider packages from its parent, so the same
disclosure applies here with a base-python product identity.

`cve-2026-31790.openvex.json` discloses that the deliberately held FIPS provider
packages are affected and gives downstream consumers mitigation guidance. This
statement is documentary: it does not suppress the finding or satisfy the
default-deny gate. The exact, expiring scanner suppression is maintained
separately under `security/` and tracked as TD-6 in `docs/TECH-DEBT.md`.

`sqlite-under-investigation.openvex.json` records five distinct
`under_investigation` dispositions for CVE-2026-51296, CVE-2026-51297,
CVE-2026-51302, CVE-2026-51303, and CVE-2026-51304. The image ships
`sqlite-libs` 3.34.1-10.el9_8, but the available CVE records do not establish
affected versions or fixes, and no Red Hat product assessment or exact
shipped-SRPM source comparison supports a stronger disposition. These honest
statements deliberately do not satisfy the default-deny gate. They bind both CI
product references and the stable base-python family identifier.
