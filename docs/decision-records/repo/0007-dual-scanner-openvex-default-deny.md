# ADR-0007: Use Dual Scanners And Default-Deny OpenVEX

- Status: Superseded
- Date: 2026-06-21
- Scope: repo

## Context

The repository originally blocked unfixed HIGH and CRITICAL findings unless a
reviewed OpenVEX disposition cleared each finding. That bespoke policy grew a
large parser, mutation suite, calendar model, duplicated report binding, and
publisher-specific authority plumbing.

## Decision

Historically, Trivy and Grype supplied independent reports to a default-deny
OpenVEX gate. This decision is now superseded: unfixed vendor CVEs are
report-only, while native fixable-CVE gates remain blocking.

OpenVEX publication remains only for independently proven `base-python` SQLite
and `libuuid` absence statements. It no longer authorizes scanner findings.

## Consequences

Complete Trivy and Grype JSON and SARIF evidence is published without suppressing
unfixed findings. Scanner execution, freshness, and canary failures remain fatal.
Fixable MEDIUM, HIGH, and CRITICAL findings still block, subject only to the
native TD-6 FIPS exception.

## References

- `docs/compliance/vex.md`
- `docs/compliance/acceptance.md`
- `images/python/vex/README.md`
- `.github/workflows/publish-image.yaml`
- `.github/workflows/publish-python.yaml`
