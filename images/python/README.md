# ubi9-base-python (unpublished)

CPython 3.12 on the untouched `base-micro` floor: the build clones the published
parent rootfs, applies a pinned, signature-verified RPM transaction with one
truthful combined rpmdb, strips build-support packages behind ldd-ownership
guards, and ships as a single reproducible layer running as `nonroot` (65532)
with `/usr/bin/python3.12` as the entrypoint.

## SQLite is intentionally unavailable

This image omits the Python `sqlite3` standard-library package, the native
`_sqlite3` extension, and `libsqlite3`. SQLite is outside this image's declared
supported runtime surface, and removing the otherwise unused engine eliminates
the component that produced five unfixed CVE findings instead of carrying
vulnerable code no supported feature needs. CI requires
`importlib.util.find_spec("sqlite3")` to return `None` and proves the RPM,
library, extension, package directory, and build-id link are absent on both
architectures.

Installing `sqlite-libs` alone does **not** restore Python SQLite support because
the matching Python payload is also absent. Consumers that need `sqlite3` should
use a fuller Red Hat Python base image or build a derivative that deliberately
retains both the matching `python3.12-libs` SQLite payload and `sqlite-libs`.

## Raw scanner evidence

A valid clean scan is a successful result. The SQLite-absence gate accepts a
Trivy report with no vulnerabilities and a Grype report with `matches: []`; it
does not require the image to retain a vulnerability finding. Positive content
evidence comes from Trivy's `--list-all-pkgs` inventory. The gate selects
`python3.12-libs` as the runtime marker and derives its expected epoch, version,
release, and RPM architecture from the exactly one matching entry in
`runtime.shipped[arch]` in the image contract.

Grype does not expose a complete package inventory in this report. Its side of
the gate therefore validates the Grype descriptor, Red Hat distro, recognized
image-or-directory source shape, list-valued `matches`, and every present
match's RPM artifact and vulnerability fields. Both scanner documents are still
searched for `sqlite-libs` and the five SQLite CVEs. Marker identities with an
extra epoch separator or a colon in version/release, and whitespace-bearing
Trivy package or Grype artifact names, are rejected as malformed evidence.

Normal execution requires `--trivy-json`, `--grype-json`, `--contract`, and
`--arch` (`amd64` or `arm64`); `--self-test` remains standalone. This raw gate
does not bind the two reports to each other. The adjacent `tools/assert-vex.py`
invocation owns product, image, architecture, distro, and repository-digest
binding before findings are evaluated against OpenVEX.

**Status: built and gated in CI, unpublished.** The evidence machinery is in
place and exercised on every change — a tailored RHEL9 STIG profile evaluated
fail-closed, rpmdb-derived SPDX and CycloneDX SBOMs, dual CVE scanners with
OpenVEX default-deny, a rootfs secret gate, and a NIST SP 800-190 image-control
predicate — but it runs against locally built images. Nothing is signed,
attested, or pushed. No registry package, tag, or
publish workflow exists for this image yet; publication requires the full
`base-micro` evidence-parity set (signature, SPDX and CycloneDX SBOMs, OpenVEX,
NIST SP 800-190 evidence, tailored STIG ARF, SLSA provenance) and will arrive
as its own change. Consumption instructions are deliberately absent until then.

The shipped package set is derived, not hand-picked: the lock refresh harness
resolves the python3.12 closure against a clone of the pinned parent, records
shipped versus build-support rows in `rpm-lock/`, and CI gates the result with a
functional standard-library battery (including TLS against the parent CA store
and an explicit assertion that `sqlite3` is unavailable),
parent-invariance comparisons at both build boundaries, and dual CVE scanners
reading the combined rpmdb. `python3.12-pip-wheel` ships as an RPM-closure
requirement; the image has no `pip` entrypoint.
