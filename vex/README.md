# OpenVEX Dispositions

This directory is the reviewed source for OpenVEX dispositions used by the C4 CVE gate. The gate is default-deny: every unfixed HIGH or CRITICAL finding reported by either Trivy or Grype must match an accepted statement here, or the workflow fails.

Accepted statements must be OpenVEX JSON files with:

- `@context` and a non-empty `statements` array.
- `vulnerability.name` or an equivalent vulnerability id matching the scanner finding.
- `products[].@id` matching the exact image reference scanned, or the same reference prefixed with `pkg:oci/`.
- `status: "fixed"` or `status: "not_affected"` with one of the standard OpenVEX justifications.

`affected` and `under_investigation` are valid OpenVEX statuses, but they do not satisfy this gate. Files under `vex/` require review through `.github/CODEOWNERS`; publish runs attest each JSON file to the per-architecture image digests with `cosign attest --type openvex`.
