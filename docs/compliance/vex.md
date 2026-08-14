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

Base-python has a distinct TD-9 accept-and-track disposition for the
known-affected unfixed HIGH `CVE-2026-11940`. Red Hat lists RHEL 9
`python3.12` as Affected with no fixed RPM as of 2026-08-13. It is limited to
exactly `python3.12` and `python3.12-libs` at `3.12.13-3.el9_8.1`, and
`review-by 2026-10-01`.

For the legacy local-product path, the two-key authorization requires both the
closed allowlist in `tools/assert-vex.py` and the canonical reviewed `affected`
statement in `images/python/vex/cve-2026-11940.openvex.json`, and applies only
to `local/ubi9-base-python:ci-amd64` and
`local/ubi9-base-python:ci-arm64`.

The tool also implements a dormant path for a digest-addressed child under the
pinned `ghcr.io/nwarila/ubi9-base-python` repository. Its authorization is the
conjunction of fixed in-tool constraints, the canonical reviewed statement, and
index evidence supplied through paired `--index-reference` and
`--index-manifest` inputs. The tool verifies the exact bytes against the
reference digest, enforces the OCI image-index shape and the locked BuildKit
attestation-descriptor convention, derives exactly one distinct `linux/amd64`
and `linux/arm64` child, and requires the product digest to match the child for
the architecture reported by both scanners. The index digest and attestation
digests are never eligible. Version 2 of the canonical statement names this
scope with a non-image-matchable policy IRI, so it is not a bare repository
wildcard.

This index evidence is a dynamic authorization input, not a trusted origin.
Digest verification proves what index bytes were supplied, but not that a
publisher actually pushed those bytes. No production workflow supplies the new
inputs, no production gate battery uses this path, and the base-python image
remains externally unpublished. Production use requires a verifier-locked
dataflow that obtains the exact registry-served bytes for the index just pushed
and binds that index digest to signing, attestation, and alias operations. Until
then the primitive is dormant and does not close the child-binding defect
end-to-end.

A mismatch, a duplicate statement, or valid fix evidence from either scanner
leaves the finding un-vexed. The raw scanner vulnerability ID, package name, and
installed version must each have no leading or trailing whitespace on either
path; padded identity evidence is malformed and is rejected rather than
normalized into an exact match. Candidate evaluations fail after the review
date, and `tools/verify.py` expires the entry even when no matching finding
remains.

This is the sole path on which `affected` satisfies the gate. All other
`affected` statements remain documentary. TD-9 does not suppress raw scanner
reports, does not alter the HIGH/CRITICAL threshold, and does not claim that the
base-python image is unaffected. Consumers must not rely on
`tarfile.extractall()` `data` or `tar` filters to contain untrusted archives
until a fixed RPM is absorbed.
