# OpenVEX Dispositions

This directory is the reviewed source for OpenVEX dispositions used by the C4 CVE gate. The gate is default-deny: every unfixed HIGH or CRITICAL finding reported by either Trivy or Grype must match an accepted statement here, or the workflow fails.

Accepted statements must be OpenVEX JSON files with:

- `@context` and a non-empty `statements` array.
- `vulnerability.name` or an equivalent vulnerability id matching the scanner finding.
- `products[].@id` matching the exact image reference scanned, or the same reference prefixed with `pkg:oci/`.
- `status: "fixed"` or `status: "not_affected"` with one of the standard OpenVEX justifications, except for the exact accept-and-track path below.

`affected` satisfies the gate here only for the exact, expiring
`CVE-2026-14456` accept-and-track authorization implemented in
`tools/assert-vex.py` and matched by `cve-2026-14456.openvex.json`. Every other
`affected` statement, and every `under_investigation` statement, remains
documentary. Files under `vex/` require review through `.github/CODEOWNERS`;
publish runs attest each JSON file to the per-architecture image digests with
`cosign attest --type openvex`.

`cve-2026-31790.openvex.json` discloses that the deliberately held FIPS provider
packages are affected and gives downstream consumers mitigation guidance. This
statement is documentary: it does not suppress the finding or satisfy the
default-deny gate. The exact, expiring scanner suppression is maintained
separately under `security/` and tracked as TD-6 in `docs/TECH-DEBT.md`.

`cve-2026-14456.openvex.json` records that the locally built
`ghcr.io/nwarila/ubi9-base-micro:base-micro` product ships `openssl-libs` at
exactly `1:3.5.5-5.el9_8`. Red Hat listed RHEL 9 `openssl` as Affected with no
fixed RPM as of 2026-08-18; RHEL 9.8 and later ship the affected OpenSSL 3.5.x
QUIC server, and exploitation requires an application to explicitly enable a
QUIC server listener. The micro image has no default command and removes
runtime executables. The statement tracks the acceptance as TD-12 through
`review-by 2026-10-01`; it does not claim that the package or image is
unaffected and does not suppress either scanner's report.

For the local product, the gate requires two keys: the exact in-tool
disposition entry and this byte-canonical reviewed statement. For a
digest-addressed child of the pinned `ghcr.io/nwarila/ubi9-base-micro`
repository, it requires three: the same entry, this statement, and paired
`--index-reference` plus `--index-manifest` evidence whose bytes verify the
index digest and bind the child to the scanner-reported architecture. The
micro publish workflow is configured to supply the index bytes it already
reads from the registry. Production evidence for this path is in the
[canonical publication evidence contract](../docs/reference/verification-contract.md#image-family-publication-evidence-contract).
Valid fix evidence from either scanner
refuses the disposition, and `tools/verify.py` expires the repository entry even
when the finding is dormant.
