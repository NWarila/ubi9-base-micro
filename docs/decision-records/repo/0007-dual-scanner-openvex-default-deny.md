# ADR-0007: Use Dual Scanners And Default-Deny OpenVEX

- Status: Accepted
- Date: 2026-06-21
- Last reviewed: 2026-08-14
- Scope: repo

## Context

No single vulnerability scanner is a complete source of truth. Container scanner
coverage, feeds, and matching logic differ, and unfixed findings need reviewed
product-specific status rather than an informal ignore list.

## Decision

The publish and test gate paths run both Trivy and Grype. Fixable MEDIUM, HIGH,
and CRITICAL findings fail closed in either scanner. A second pass collects unfixed
HIGH and CRITICAL findings, and `tools/assert-vex.py` requires each one to have
a matching reviewed OpenVEX statement under the image's CODEOWNERS-gated VEX
directory. Micro publish runs attach `vex/` documents with Cosign when present
and verify the attestations with the repository workflow identity. Base-python
remains externally unpublished, so its `images/python/vex/` documents are
pre-publication gate evidence rather than published attestations.

The only `affected` statement that satisfies the gate is the exact, expiring
TD-9 accept-and-track disposition for known-affected `CVE-2026-11940`, with the
complete `python3.12` and `python3.12-libs` package set at
`3.12.13-3.el9_8.1` and `review-by 2026-10-01`. The legacy local-product path
is a two-key authorization: an exact in-tool allowlist for the two base-python
CI products and the canonical reviewed statement must both match.

The decision also permits a second, dormant product-eligibility path for a
digest-addressed child under the in-tool pinned
`ghcr.io/nwarila/ubi9-base-python` repository. That path is authorized only by
the conjunction of the fixed in-tool constraints, the canonical reviewed
statement, and index evidence supplied through paired `--index-reference` and
`--index-manifest` inputs. The tool verifies the exact index bytes against the
reference digest, requires the closed OCI descriptor shape of one distinct
`linux/amd64` and `linux/arm64` image manifest plus only the locked BuildKit
attestation convention, and binds the product digest to the child for the
architecture reported by both scanners. The index digest, attestations, nested
indexes, additional or duplicate runnable platforms, and architecture swaps are
not eligible.

The descriptor classification locks a producer convention; index metadata
alone does not prove that an `unknown/unknown` image-manifest descriptor is
non-runnable. More importantly, digest verification authenticates the supplied
bytes only relative to the supplied digest. The caller-selected index is a
dynamic authorization input and is not yet trusted. No production workflow
calls this path, and base-python remains externally unpublished. Activation
requires a verifier-locked publisher dataflow that obtains the exact
registry-served bytes for the index it pushed and uses the same index digest for
signing, attestation, and aliases. Until then the primitive is dormant and does
not close the binding defect end-to-end.

Valid fix evidence from either scanner refuses either product path. Raw scanner
vulnerability IDs, package names, and installed versions must also be
byte-canonical: surrounding whitespace is malformed evidence and is rejected
rather than normalized into an exact match. Every other `affected` statement
remains documentary, and this path does not make the base-python image
unaffected or suppress a raw scanner finding.

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
- A known-affected finding can pass only through one of the exact, expiring
  product paths above. The two-key description applies only to legacy local
  products; the dormant child path additionally depends on caller-supplied
  index evidence that is not trusted for production.
- Empty VEX is not manufactured when there are no unfixed HIGH or CRITICAL
  findings.
- Published VEX documents become signed supply-chain evidence, not comments in
  a workflow; reviewed documents for an unpublished image remain pre-publication
  gate evidence.

## References

- OpenVEX specification: <https://github.com/openvex/spec>
- Trivy image command documentation: <https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/>
- Grype project: <https://github.com/anchore/grype>
- Repository details: `docs/compliance/vex.md`, `vex/README.md`,
  `images/python/vex/README.md`, `docs/TECH-DEBT.md`, `tools/assert-vex.py`,
  `tools/summarize-gates.py`, `tools/render-pr-decision.py`,
  `tools/render-drift-issue.py`, `.github/workflows/publish-image.yaml`
