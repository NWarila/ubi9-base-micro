# ADR-0014: Pin The Builder Python Closure

- Status: Accepted
- Date: 2026-07-10
- Scope: repo

## Context

The discarded `rpm-rootfs` and `fips-verify` stages need Python 3.12 for build
helpers. The UBI 9 default Python is 3.9 and cannot import the repository's
canonical RPM lock parser, which uses Python 3.10-or-later dataclass features.
Installing Python with microdnf would resolve against moving repository
metadata and, in `rpm-rootfs`, could upgrade the rpm, sqlite, or glibc stack
that serializes `/rootfs/var/lib/rpm/rpmdb.sqlite`. That would undermine the
byte-for-byte runtime rootfs contract even though the interpreter itself
belongs only to discarded stages.

The builder lock has different semantics from the runtime lock. Builder
packages never enter the final rpmdb, so a `final_rpmdb` column, the 15-package
runtime floor, and the FIPS-provider pin would be false invariants. A separate
validator would duplicate the canonical URL, hash, architecture, and RPM-header
checks.

## Decision

Maintain `rpm-lock/builder.amd64.txt` and `rpm-lock/builder.arm64.txt` with a
distinct eight-column builder grammar implemented as a builder mode in
`tools/rpmlock.py`. The mode shares the canonical direct-CDN and RPM identity
validation but does not inherit runtime-only floor or FIPS rules.

Install the complete seven-RPM Python 3.12 closure into the own roots of the
`rpm-rootfs` and `fips-verify` stages. In `rpm-rootfs`, install it before any
`/rootfs` operation; in `fips-verify`, install it before microdnf. Fetch every
RPM from its locked `https://cdn-ubi.redhat.com/` URL, verify its whole-RPM
SHA-256, require `rpm -K` to report `digests signatures OK`, cross-check the
locked NEVRA and RPM header fields, and install the local paths with raw
`rpm -Uvh`. No microdnf or repository metadata participates in either Python
transaction.

Keep `python3.12-libs` and `python3.12-pip-wheel` even though this stage does not
invoke pip. The `python3.12` RPM requires the exact-version libraries package,
and the libraries RPM requires `python3.12-pip-wheel >= 23.1.2`; removing either
would require bypassing RPM dependency enforcement. The full resolved closure
is safer than a hand-trimmed, `--nodeps` installation.

In `rpm-rootfs`, capture the installed NEVRA for `rpm`, `rpm-libs`,
`sqlite-libs`, `glibc`, and `glibc-common` immediately before and after the
Python transaction. Any change, missing row, duplicate row, or malformed
snapshot fails the build and names the affected package. This floor guard is
not repeated in `fips-verify`, which writes no shipped rpmdb. Only `/rootfs` is
copied into `runtime-common`; Python is never installed into that tree,
`dev-rootfs`, or a stage that becomes a published image.

Keep the bootstrap inline in both discarded stages. A shared parent stage would
change `rpm-rootfs` ancestry, while replacing both loops with a copied script
would edit the stage that creates every shipped byte. The small duplicate is
preferable because it leaves that ratified shipped-byte assembly text unchanged
and confines the additional interpreter to the discarded verifier that uses it.

## Consequences

- The builder interpreter is reproducible and cannot drift with live metadata.
- Builder Python updates are intentional reviewed lock changes. This is a real
  maintenance obligation, but it is preferable to an unpinned executable build
  input.
- Runtime Trivy and Grype scans do not cover discarded builder packages. The
  builder lock therefore does not claim runtime scanner coverage; a builder
  refresh must review applicable Red Hat security errata as a build-toolchain
  change.
- The seven downloaded RPMs and installed interpreter increase only discarded
  stage storage in the two named stages. They are never installed beneath
  `/rootfs`, add no runtime path, and must not change either contracted
  `canonical_rootfs_digest`.
- A separate Python-bearing stage with bind-mounted `PYTHONHOME` and loader
  paths was rejected because it adds dynamic-loader and standard-library path
  coupling without improving the existing discarded-stage boundary.

## References

- `rpm-lock/builder.amd64.txt`
- `rpm-lock/builder.arm64.txt`
- `tools/fetch-builder-rpms.sh`
- `tools/assert-builder-toolchain-floor.sh`
- `tools/rpmlock.py`
- `containers/Dockerfile`
