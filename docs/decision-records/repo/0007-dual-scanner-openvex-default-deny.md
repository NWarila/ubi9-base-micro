# ADR-0007: Use Dual Scanners And Default-Deny OpenVEX

- Status: Accepted
- Date: 2026-06-21
- Last reviewed: 2026-08-28
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
and verify the attestations with the repository workflow identity. The
base-python publisher gates and attaches the byte-unmodified
`images/python/vex/` documents to both platform children.

An `affected` statement satisfies the gate only through an exact, expiring
accept-and-track disposition. The tool models a closed set of N disposition
entries. Each entry binds one CVE, its complete package/version set, a debt ID,
a review date, and one or more statement surfaces. Each surface binds its
canonical statement path and contents, action text, local products,
non-image-matchable policy IRI, and pinned published repository. The current
entry is:

- TD-12 for known-affected `CVE-2026-14456`, with `openssl-libs` at exactly
  `1:3.5.5-5.el9_8` on separate base-python and base-micro surfaces.

The former TD-9 disposition for `CVE-2026-11940` was retired on 2026-08-28 after
the fixed `python3.12` and `python3.12-libs` `3.12.14-1.el9_8` RPMs were
absorbed. Its version-3 OpenVEX history statement names only the fixed,
architecture-qualified RPM products and therefore cannot authorize an image
finding.

The entry has `review-by 2026-10-01`. A local product uses a two-key
authorization: the exact in-tool disposition surface and its byte-canonical
reviewed statement must both match. This covers the two base-python CI products
and the locally loaded `ghcr.io/nwarila/ubi9-base-micro:base-micro` product.

A digest-addressed published child uses a three-key authorization: the exact
in-tool disposition surface, its byte-canonical reviewed statement, and index
evidence supplied through paired `--index-reference` and `--index-manifest`
inputs must all match. Each surface pins its own repository,
`ghcr.io/nwarila/ubi9-base-python` or
`ghcr.io/nwarila/ubi9-base-micro`. The tool verifies the exact index bytes
against the reference digest, requires exactly one `linux/amd64` image manifest
and one `linux/arm64` image manifest with distinct digests, locks the BuildKit
attestation platform and annotations, requires index-wide descriptor-digest
uniqueness across all roles, and binds the product digest to the child for the
architecture reported by both scanners. Candidate selection must resolve to
exactly one disposition surface; zero matches confer no authorization and
multiple matches fail closed. A statement, product, policy IRI, repository, or
index from one surface cannot authorize another. The
duplicate-or-contradictory descriptor diagnostic names the first and repeated
positions; the child/attestation digest-disjointness guard remains separate with
its own diagnostic. The index digest is never eligible, and a distinct
attestation-descriptor digest is rejected when submitted as the product. Nested
indexes, additional or duplicate runnable platforms, and architecture swaps are
also rejected. This policy does not constrain attestation count or per-child
reference cardinality, and it does not exact-check either descriptor kind's
top-level keys: measured `urls`, `data`, and `artifactType` additions are
accepted on runnable and attestation descriptors. It also accepts an invented
key on a runnable `platform` object. Before any consumer runs, the base-python
publish resolver requires exactly `digest`, `mediaType`, `platform`, and `size`
on runnable descriptors, those four keys plus `annotations` on attestation
descriptors, exact `architecture` and `os` platform objects, and exactly one
attestation reference per child.

The descriptor classification locks a producer convention; index metadata
alone does not prove that an `unknown/unknown` image-manifest descriptor is
non-runnable. More importantly, digest verification authenticates the supplied
bytes only relative to the supplied digest. Each merged production caller binds
that dynamic authorization input to the index the same run pushed. The Python
publisher performs one digest-addressed registry readback, corroborates its
SHA-256 against push metadata, checksum-verifies every cross-job transfer, and
gives the same digest to signing, attestation, VEX, provenance, collision, and
alias consumers. The micro publisher passes the pushed digest and the exact
`dist/image-index.json` bytes it already read from the registry to both child
gate calls in the same job. Production proof of the new TD-12 published-child
paths remains pending the merge-triggered runs. These bindings are limited to
the index each run pushed and read back, and the Python binding does not close
the external-writer alias race. TD-11 tracks the remaining VEX-side descriptor,
runnable-platform, and attestation-cardinality asymmetries.

Valid fix evidence from either scanner refuses every accept-and-track path. Raw scanner
vulnerability IDs, package names, and installed versions must also be
byte-canonical: surrounding whitespace is malformed evidence and is rejected
rather than normalized into an exact match. Every other `affected` statement
remains documentary, and these paths do not make either image unaffected or
suppress a raw scanner finding.

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
- A known-affected finding can pass only through one exact, expiring surface.
  Local products use two keys; published children use three and additionally
  depend on the production workflow's repository-correct, digest-verified index
  evidence.
- Empty VEX is not manufactured when there are no unfixed HIGH or CRITICAL
  findings.
- Published VEX documents become signed supply-chain evidence, not comments in
  a workflow; reviewed documents remain pre-publication gate evidence until a
  publish succeeds.

## References

- OpenVEX specification: <https://github.com/openvex/spec>
- Trivy image command documentation: <https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/>
- Grype project: <https://github.com/anchore/grype>
- Repository details: `docs/compliance/vex.md`, `vex/README.md`,
  `images/python/vex/README.md`, `docs/TECH-DEBT.md`, `tools/assert-vex.py`,
  `tools/summarize-gates.py`, `tools/render-pr-decision.py`,
  `tools/render-drift-issue.py`, `.github/workflows/publish-image.yaml`,
  `.github/workflows/publish-python.yaml`
