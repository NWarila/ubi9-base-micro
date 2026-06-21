# ADR-0007: Use Dual Scanners And Default-Deny OpenVEX

- Status: Accepted
- Date: 2026-06-21
- Scope: repo

## Context

No single vulnerability scanner is a complete source of truth. Container scanner
coverage, feeds, and matching logic differ, and unfixed findings need reviewed
product-specific status rather than an informal ignore list.

## Decision

The publish and test gate paths run both Trivy and Grype. Fixable HIGH and
CRITICAL findings fail closed in either scanner. A second pass collects unfixed
HIGH and CRITICAL findings, and `tools/assert-vex.py` requires each one to have
a matching reviewed OpenVEX statement under the CODEOWNERS-gated `vex/` path.
Publish runs attach VEX documents with Cosign when present and verify the
attestations with the repository workflow identity.

## Consequences

- Scanner disagreement is handled conservatively: either fixable finding blocks
  the image.
- Unfixed findings require explicit reviewed status and justification.
- Empty VEX is not manufactured when there are no unfixed HIGH or CRITICAL
  findings.
- VEX documents become signed supply-chain evidence, not comments in a workflow.

## References

- OpenVEX specification: <https://github.com/openvex/spec>
- Trivy image command documentation: <https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/>
- Grype project: <https://github.com/anchore/grype>
- Repository details: `docs/vex.md`, `vex/README.md`, `tools/assert-vex.py`,
  `.github/workflows/publish-image.yaml`
