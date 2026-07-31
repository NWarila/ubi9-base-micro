# ADR-0007: Use Dual Scanners And Default-Deny OpenVEX

- Status: Accepted
- Date: 2026-06-21
- Last reviewed: 2026-07-31
- Scope: repo

## Context

No single vulnerability scanner is a complete source of truth. Container scanner
coverage, feeds, and matching logic differ, and unfixed findings need reviewed
product-specific status rather than an informal ignore list.

## Decision

The publish and test gate paths run both Trivy and Grype. Fixable MEDIUM, HIGH,
and CRITICAL findings fail closed in either scanner. A second pass collects unfixed
HIGH and CRITICAL findings, and `tools/assert-vex.py` requires each one to have
a matching reviewed OpenVEX statement under the CODEOWNERS-gated `vex/` path.
Publish runs attach VEX documents with Cosign when present and verify the
attestations with the repository workflow identity.

The OpenVEX classifier and the hardening decision-envelope generator apply the
same fixability truth table. Trivy fix metadata grants a fix only when every
present field has the accepted type and vocabulary and either `FixedVersion` is
a non-empty string or `Status` is exactly `fixed`. Grype requires `fix` to be an
object containing a list of non-empty string `versions` and a recognized
`state`; a non-empty version list or the exact `fixed` state establishes a fix.
Grype's separate `fix.available` field is descriptive and is not consulted.
Malformed fix metadata grants no fix rather than creating a second parser gate.
For HIGH and CRITICAL findings, that keeps the finding in the default-deny
OpenVEX set; the reporting envelope remains complete and exposes the same
classification to the pull-request decision and nightly drift issue.

## Consequences

- Scanner disagreement is handled conservatively: either fixable finding blocks
  the image.
- Scanner summaries cannot upgrade malformed fix metadata into an actionable
  fix or remove it from the unfixed OpenVEX set.
- Unfixed findings require explicit reviewed status and justification.
- Empty VEX is not manufactured when there are no unfixed HIGH or CRITICAL
  findings.
- VEX documents become signed supply-chain evidence, not comments in a workflow.

## References

- OpenVEX specification: <https://github.com/openvex/spec>
- Trivy image command documentation: <https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/>
- Grype project: <https://github.com/anchore/grype>
- Repository details: `docs/compliance/vex.md`, `vex/README.md`, `tools/assert-vex.py`,
  `tools/summarize-gates.py`, `tools/render-pr-decision.py`,
  `tools/render-drift-issue.py`, `.github/workflows/publish-image.yaml`
