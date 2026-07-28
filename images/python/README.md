# ubi9-base-python (unpublished)

CPython 3.12 on the untouched `base-micro` floor: the build clones the published
parent rootfs, applies a pinned, signature-verified RPM transaction with one
truthful combined rpmdb, strips build-support packages behind ldd-ownership
guards, and ships as a single reproducible layer running as `nonroot` (65532)
with `/usr/bin/python3.12` as the entrypoint.

**Status: built and gated in CI, unpublished.** No registry package, tag, or
publish workflow exists for this image yet; publication requires the full
`base-micro` evidence-parity set (signature, SPDX and CycloneDX SBOMs, OpenVEX,
NIST SP 800-190 evidence, tailored STIG ARF, SLSA provenance) and will arrive
as its own change. Consumption instructions are deliberately absent until then.

The shipped package set is derived, not hand-picked: the lock refresh harness
resolves the python3.12 closure against a clone of the pinned parent, records
shipped versus build-support rows in `rpm-lock/`, and CI gates the result with a
functional standard-library battery (including TLS against the parent CA store),
parent-invariance comparisons at both build boundaries, and dual CVE scanners
reading the combined rpmdb. `python3.12-pip-wheel` ships as an RPM-closure
requirement; the image has no `pip` entrypoint.
