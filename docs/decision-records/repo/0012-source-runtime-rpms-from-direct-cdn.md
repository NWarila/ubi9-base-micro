# ADR-0012: Source Runtime RPMs From Pinned Direct CDN Blobs

- Status: Accepted
- Date: 2026-06-25
- Scope: repo

## Context

The runtime RPM lock pins exact NEVRAs so the rootfs, including the sqlite rpmdb,
can remain byte-for-byte reproducible across rebuilds. The discarded
`fips-verify` stage must also use an OpenSSL CLI and libraries whose versions
match the runtime lock. Red Hat UBI repository metadata can remove older fixed
NEVRAs while the signed RPM blobs remain served from the Red Hat UBI CDN. When
metadata no longer lists a pinned NEVRA, metadata-driven
`microdnf install <nevra>` fails even though the authentic RPM blob is still
available.

The OpenSSL FIPS provider already needed this treatment for the held
`openssl-fips-provider-so-3.0.7-8.el9` package. The same metadata-purge failure
now applies to ordinary runtime transaction RPMs such as `coreutils`,
`coreutils-common`, and `libtasn1` while the current NEVRAs must remain held.

## Decision

Every runtime lock row carries a `# direct_rpm:` entry with the exact package row,
a `https://cdn-ubi.redhat.com/` URL, and the whole-RPM SHA-256. The build fetches
the complete per-architecture runtime transaction from those URLs with `curl -f`,
verifies the whole-RPM SHA-256, verifies the Red Hat RPM signature with `rpm -K`,
and fails closed on any missing URL, hash mismatch, signature failure, or lock row
without a direct pin.

The per-architecture `fips-verify` lock applies the same direct-CDN policy to its
one build-only addition: the `openssl` CLI with `final_rpmdb=no`. The stage reuses
the runtime lock pins for `openssl-libs`, `crypto-policies`, and the two held FIPS
provider RPMs, then installs those five local RPM paths in one raw-rpm
transaction. It never resolves this closure through live repository metadata.
This follows the direct-CDN builder-closure precedent in ADR-0014 while keeping
the FIPS CLI out of the shipped runtime transaction.

The runtime rootfs is assembled with a raw rpm transaction over the fetched local
RPM paths — `rpm --root=/rootfs --initdb` then
`rpm --root=/rootfs -Uvh --oldpackage --replacepkgs --excludedocs <paths>` — with
no microdnf/libdnf and no install-time dependency resolution. The lockfile is a
complete, pre-resolved, deterministically (LC_ALL=C) ordered transaction closure
and the paths are installed in that order; because `rpm -Uvh` runs without
`--nodeps`, any unsatisfied dependency aborts the whole transaction, so a
successful build proves the locked closure is complete. This makes live metadata
fallback impossible and needs no repository-metadata generator (createrepo_c is
unavailable in the UBI build context). The FIPS provider packages are installed in
the same fetched-local-RPM transaction, holding the validated provider bytes. This
raw-rpm path re-serializes the sqlite rpmdb to a new but deterministic baseline
versus the prior microdnf-metadata builds; with no tagged release depending on the
old rpmdb, this one-time re-baseline was accepted.

`tools/generate-rpm-lock.sh` remains the controlled CVE-absorption path: it uses
current UBI metadata only when intentionally refreshing the lock, then resolves
and records the direct CDN URL and whole-RPM SHA-256 for every generated runtime
row. The generated runtime lock and manually maintained `fips-verify` lock have a
deliberate co-refresh obligation: a future `openssl-libs` refresh is blocked until
the matching `openssl` CLI NEVRA, URL, and hashes are updated in the FIPS lock.
Repository verification enforces equality of their epoch, version, and release.

## Consequences

- Runtime and FIPS-verification rebuilds no longer depend on old NEVRAs remaining
  present in repository metadata.
- Runtime RPM bytes are pinned by Red Hat signature, whole-RPM SHA-256,
  `%{SHA256HEADER}`, and `%{SIGMD5}` checks.
- A CDN blob 404, SHA mismatch, or signature failure is a hard stop requiring an
  explicit vendor or version-bump decision.
- CVE absorption still happens through reviewed lock refresh pull requests that
  update the NEVRA, URL, and SHA-256 together.
- An `openssl-libs` refresh cannot pass until both architecture-specific
  `fips-verify` locks are co-refreshed to the matching OpenSSL CLI version.
- The Red Hat CDN blob lifetime is not guaranteed forever; nightly rebuilds act
  as the purge sentinel.

## References

- `rpm-lock/runtime.amd64.txt`
- `rpm-lock/runtime.arm64.txt`
- `rpm-lock/fips-verify.amd64.txt`
- `rpm-lock/fips-verify.arm64.txt`
- `tools/fetch-runtime-rpms.sh`
- `tools/assert-rpm-lock-hashes.py`
- `tools/generate-rpm-lock.sh`
- `.github/workflows/rpm-lock-refresh.yaml`
- `0014-pin-builder-python-closure.md`
