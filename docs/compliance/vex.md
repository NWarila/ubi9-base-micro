# OpenVEX Gate

The C4 vulnerability policy uses two scanners across two distinct axes. Trivy
and Grype fail the build on fixable MEDIUM, HIGH, or CRITICAL findings, subject
only to the exact, expiring TD-6 exception for `CVE-2026-31790` on the two held
FIPS provider packages at `3.0.7-8.el9`, with review date 2026-10-10. A separate,
unfiltered report pass feeds the default-deny check for unfixed HIGH and CRITICAL
findings; that scope does not expand to Medium.

On the current image, the MEDIUM threshold catches two findings and TD-6 excuses
those same two findings, so the immediate enforcement delta is zero. The change
is forward-looking: a future fixable Medium outside that exact exception fails.

The `vex/` path is CODEOWNERS-gated. Use `not_affected` only when the stronger posture is inapplicable and the statement carries a standard OpenVEX justification; use `fixed` only when the published image reference is actually fixed. Publish runs attach every JSON document in `vex/` to each per-architecture image digest with `cosign attest --type openvex`.

The `affected` statement for `CVE-2026-31790` is the disclosure side of this
policy. It records the held `3.0.7-8.el9` FIPS provider packages and directs
consumers away from the vulnerable call path through the TD-6 review date,
2026-10-10. It cannot clear an unfixed HIGH or CRITICAL finding because
`affected` is not an accepted default-deny disposition. The separate
package-, version-, CVE-, and date-scoped files under `security/` are the only
scanner suppressors.
