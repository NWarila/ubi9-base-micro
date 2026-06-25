# ADR-0008: Gate The Image With A Tailored RHEL 9 STIG ARF

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

The DISA RHEL 9 STIG includes host, service, account, kernel, and runtime
controls that do not all apply to a shell-free container image rootfs. Treating
host-only controls as image passes would overclaim. Marking broad rule sets not
applicable without a reviewed scope ledger would be theater.

## Decision

The repository commits a tailored RHEL 9 STIG profile and a reviewed JSON scope
ledger. The workflow builds the ComplianceAsCode datastream from a pinned
release tarball, runs OpenSCAP against the image rootfs, fails on applicable
findings at the configured threshold, and emits a structured ARF summary. Helper
scripts derive omitted-control coverage from the pinned source tree and require
deterministic rootfs assertions for selected identity and ownership rules that
OpenSCAP reports as not applicable.

Publish runs attach the STIG ARF predicate per platform digest and verify it
with exact repository workflow identity.

## Consequences

- Image-applicable STIG controls are gated instead of merely documented.
- Host-only controls remain out of scope with reviewed justification.
- The tailoring cannot silently become mass-not-applicable without the helper
  checks failing.
- The signed ARF summary becomes part of the published evidence set.

## References

- OpenSCAP documentation: <https://www.open-scap.org/resources/documentation/>
- NIST SP 800-190 Application Container Security Guide: <https://csrc.nist.gov/pubs/sp/800/190/final>
- Repository details: `docs/compliance/stig.md`, `stig/rhel9-base-micro-tailoring.xml`,
  `stig/tailoring-justifications.json`, `tools/assert-stig-tailoring.py`,
  `tools/assert-stig-arf.py`
