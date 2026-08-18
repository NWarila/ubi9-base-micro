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

The gate has two exact, expiring accept-and-track dispositions:

- TD-9 covers known-affected unfixed HIGH `CVE-2026-11940` on exactly
  `python3.12` and `python3.12-libs` at `3.12.13-3.el9_8.1` in base-python. Red
  Hat listed RHEL 9 `python3.12` as Affected with no fixed RPM as of 2026-08-13.
- TD-12 covers known-affected unfixed HIGH `CVE-2026-14456` on exactly
  `openssl-libs` at `1:3.5.5-5.el9_8` in both base-python and base-micro. Red
  Hat listed RHEL 9 `openssl` as Affected with no fixed RPM as of 2026-08-18;
  RHEL 9.8 and later ship the affected OpenSSL 3.5.x QUIC server, and risk
  requires an application to explicitly enable a QUIC server listener.

Both entries have `review-by 2026-10-01`. The in-tool model is a closed set of
dispositions, each with one or more exact statement surfaces. A surface binds
its canonical statement path and contents, action text, local products,
non-image-matchable policy IRI, and pinned published repository. Candidate
selection must resolve to exactly one surface; zero matches confer no
authorization, and multiple matches fail closed. Authority from one CVE,
statement, product, repository, or policy IRI cannot satisfy another surface.

Local products use a two-key authorization: the exact disposition surface and
its canonical reviewed `affected` statement must both match. The local products
are `local/ubi9-base-python:ci-amd64`,
`local/ubi9-base-python:ci-arm64`, and
`ghcr.io/nwarila/ubi9-base-micro:base-micro`. TD-9 uses
`images/python/vex/cve-2026-11940.openvex.json`; TD-12 uses
`images/python/vex/cve-2026-14456.openvex.json` for Python and
`vex/cve-2026-14456.openvex.json` for micro.

Digest-addressed published children use a three-key authorization: the exact
disposition surface, its canonical statement, and paired `--index-reference`
plus `--index-manifest` evidence must all match. The Python surfaces pin
`ghcr.io/nwarila/ubi9-base-python`; the micro surface pins
`ghcr.io/nwarila/ubi9-base-micro`. The tool verifies the supplied bytes against
the reference digest, derives exactly one `linux/amd64` child and one
`linux/arm64` child with distinct digests, locks the BuildKit attestation
platform and annotations, requires every descriptor digest in `manifests` to be
unique across all roles, and requires the product digest to match the child for
the architecture reported by both scanners. The index digest and attestation
digests are never eligible, and child/attestation digest aliasing is rejected.

The VEX-side index policy does not constrain attestation count or per-child
reference cardinality and does not close the top-level key set of either
descriptor kind or the runnable `platform` key set. It accepts the measured
additional-field cases tracked in TD-11. The Python publisher's stricter index
resolver rejects those shapes before its VEX gate. The micro publisher uses the
common VEX-side policy directly, so those exact asymmetries remain part of its
tracked production boundary.

Each merged publisher binds the dynamic evidence to the index that run pushed.
The Python publisher reads the index once by the push-reported digest,
corroborates its SHA-256, checksum-protects cross-job transfers, and gives the
same digest to every consumer. The micro publisher passes the pushed digest and
the exact `dist/image-index.json` bytes it already read from the registry to
both child gate calls in the same job. Production proof of the new TD-12
published-child paths remains pending the merge-triggered runs. The earlier
Python production attempt remains incomplete: its public package serves only
unaliased, unsigned candidate digests, with no production gate evidence,
Cosign signature or attestation, SLSA-generator provenance, Rekor record, or
consumer alias.

A mismatch, duplicate statement, byte-noncanonical scanner identity, or valid
fix evidence from either scanner leaves the finding un-vexed. Candidate
evaluations fail after the review date, and `tools/verify.py` expires both
entries even when their findings are dormant. These exact paths are the only
ones on which `affected` satisfies the gate; all other `affected` statements
remain documentary. They suppress no scanner report, do not alter the
HIGH/CRITICAL threshold, and do not claim that either image is unaffected.
Consumers must not rely on `tarfile.extractall()` `data` or `tar` filters to
contain untrusted archives until TD-9 is remediated. Consumers that enable an
OpenSSL QUIC server listener must mitigate at the application boundary until
TD-12 is remediated.
