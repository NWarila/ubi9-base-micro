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
