# Reproducibility

`base-micro` enforces the F3 byte-for-byte rootfs gate in CI. The
`reproducibility-gate` job builds the runtime target twice from identical inputs
for both `linux/amd64` and `linux/arm64`, exports each image rootfs, and runs
`tools/assert-reproducible.py --assert-byte-identical --expect-from-contract
contracts/image-manifest.json`. Any content, metadata, mtime, ownership, type,
or presence difference in the exported rootfs fails the build. The same gate
also asserts the per-architecture `canonical_rootfs_digest` and `rpmdb_sha256`
recorded in `contracts/image-manifest.json` on every pull request, push to
`main`, and nightly run.

The canonical rootfs digest is not a tarball hash. The helper flattens the image
layers into normalized rootfs entries, sorts those entries by path, then hashes
the UTF-8 text made from one line per entry:
`path|type|mode|uid|gid|uname|gname|mtime|size|linkname|sha256`. The `mode`
field is octal, and the final field is empty for entries without file or link
content. This keeps the digest tied to rootfs content and metadata rather than
Python `tarfile` archive encoding.

`canonical_rootfs_digest` is asserted at the scope of this repository's Docker
Buildx path with `rewrite-timestamp=true`. The setup action is SHA-pinned, but it
installs Buildx `latest`, so the Buildx version itself is not pinned. Because
the line format includes entry metadata (`uname`, `gname`, and `mtime`) along
with file content, a different builder such as buildah or kaniko can export
byte-identical file contents while producing a different
`canonical_rootfs_digest`. The builder-portable checks available today are the
per-file content digests recorded in the contract, specifically `rpmdb_sha256`
for `/var/lib/rpm/rpmdb.sqlite` and `fips_so_sha256` for
`/usr/lib64/ossl-modules/fips.so`.

The arm64 proof intentionally uses QEMU on the GitHub-hosted amd64 runner because
that is the same architecture path used by the publish workflow. Native arm64
hosted runners would be a cleaner fallback if QEMU ever produces a byte diff, but
QEMU is currently in scope and hard-gated because arm64 is a published artifact.

The setup-action code is pinned by
`docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8`.
Its binfmt emulator image is immutably pinned to
`docker.io/tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0`,
with `cache-image: true` persisting the selected image to the GitHub Actions
cache across runs.

The `linux/amd64` byte-identity claim is native: no emulator participates in
that build path. It remains scoped to this repository's Docker Buildx and
`rewrite-timestamp=true` path and is not portable across arbitrary builders or
toolchain versions. The `linux/arm64` byte-identity claim is emulator-relative:
it is reproducible relative to that pinned binfmt emulator image. The
build-twice CI gate proves determinism for arm64 with the immutable emulator
input. A third-party arm64 reproducer uses the same pinned action SHA and
emulator digest unless they are deliberately testing a different emulator or
native arm64 path. That boundary is intrinsic to cross-architecture
reproducible builds.

The two-builds-in-one-CI-run gate is necessary for the F3 claim because any rootfs
difference fails the build, but it is not sufficient by itself for a broad
"anyone-anywhere" reproducibility claim. Future cross-host and native-arm64
confirmation would strengthen the evidence without changing the current hard gate
scope.

## Determinism Controls

- `SOURCE_DATE_EPOCH=1704067200` is the committed timestamp input.
- Buildx uses `rewrite-timestamp=true` on local, CI, and publish image exporters.
- `docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8` pins
  the setup-action code for the cross-architecture `linux/arm64` build path on
  GitHub-hosted amd64 runners. Its emulator image is immutably pinned to
  `docker.io/tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0`
  and persisted to the GitHub Actions cache across runs.
- Runtime RPM inputs are locked by per-architecture transaction files in
  `rpm-lock/`. Every lock row has a `# direct_rpm:` entry with a
  `https://cdn-ubi.redhat.com/` URL and whole-RPM SHA-256. The build fetches
  the complete runtime transaction from those pinned URLs with `curl -f`,
  verifies Red Hat RPM signatures with `rpm -K`, verifies the whole-RPM SHA-256,
  installs the complete locked transaction with a raw rpm command
  (`rpm --root=/rootfs --initdb` then
  `rpm --root=/rootfs -Uvh --oldpackage --replacepkgs --excludedocs <paths>`) over
  the fetched local RPM paths in lockfile (LC_ALL=C-sorted) order - no microdnf,
  no install-time dependency resolution, and no repository metadata. Because
  `rpm -Uvh` runs without `--nodeps`, an unsatisfied dependency aborts the build,
  so the locked set must be a complete pre-resolved closure. The held OpenSSL
  FIPS provider RPMs are part of the same fetched-local-RPM transaction.
- Every locked RPM is verified immediately after install with
  `rpm --root=/rootfs -q --qf '%{SHA256HEADER}|%{SIGMD5}\n' <locked-nevra>`.
  `SHA256HEADER` is the rpmdb-exposed tag that matches the lockfile
  `sha256_header` column; `SIGMD5` matches the `sigmd5` column. A mismatch fails
  the build before any strip step runs.
- The Dockerfile verifies that the final runtime rpmdb still contains exactly
  the 15-package scanner-visible floor after strip. The reproducibility gate
  also asserts the per-architecture rpmdb serialization SHA-256 recorded in
  `contracts/image-manifest.json`.
- Generated rootfs files such as `/etc/nwarila/fips-status.json` use the same
  deterministic timestamp path.

The rpmdb remains present and valid because SBOM and scanner truthfulness depend
on it. Differences in `/var/lib/rpm/rpmdb.sqlite` are gate failures; the rpmdb is
not deleted, normalized away, or excluded from the rootfs comparison.

## Vulnerability Database Freshness

The vulnerability scanner databases are deliberately non-hermetic. Trivy and
Grype are pinned scanner binaries, but their vulnerability data must move as
vendors publish new CVEs and fixes. Pinning a scanner database would make a
single scan reproducible while making the nightly sentinel blind to newly
published vulnerabilities against the same frozen image.

The invariant is DB freshness, not DB pinning. `tools/run-test-gates.sh` and the
publish workflow explicitly download the scanner databases, run
`tools/assert-scanner-db-freshness.py`, and only then accept Trivy or Grype scan
results. The helper fails closed when metadata is missing, unreadable,
malformed, stale, expired, or when Grype reports a schema below the required
floor. Grype's native DB age validation is also enabled for the later Grype scan
invocations. A changed scanner finding on tomorrow's nightly run is expected
behavior: the image may be byte-identical while the vulnerability knowledge base
has legitimately changed.

## RPM Lock Refresh Loop

The lockfiles deliberately pin RPM NEVRAs and content hashes, so patched Red Hat
RPMs are not absorbed automatically. The nightly sentinel detects when a pinned
runtime RPM has a fixable CVE and turns the gate red. The weekly and manually
runnable `.github/workflows/rpm-lock-refresh.yaml` workflow runs
`tools/generate-rpm-lock.sh` for `linux/amd64` and `linux/arm64`; the generator
uses current UBI metadata only during the intentional refresh, resolves direct CDN RPM URLs for every runtime row, and emits the
`rpm-lock/runtime.<arch>.txt` format consumed by the build.

A no-change refresh is expected to be byte-identical. Maintainers can reproduce
that proof locally with `tools/generate-rpm-lock.sh --check`, which regenerates
both lockfiles in a temporary directory and fails with a unified diff if either
file drifts. When Red Hat has published patched RPMs, the refresh workflow opens
a normal pull request titled `Refresh runtime RPM lockfiles`. That PR is not a
publish path and is not auto-merged; the repository PR gates must pass first,
including the fixable-CVE gates, both-architecture byte-for-byte reproducibility
gates, whole-RPM direct-CDN SHA-256 and `rpm -K` verification, and
`%{SHA256HEADER}`/`%{SIGMD5}` RPM content-hash enforcement. Merging the gated PR
re-establishes the reproducible floor at the new NEVRA, URL, and SHA-256 pins.

The Red Hat UBI CDN blob lifetime is not guaranteed forever. A direct RPM 404,
whole-RPM SHA mismatch, or signature failure is a hard failure: the nightly
rebuild is the purge sentinel, and recovery requires an explicit vendor or
controlled URL/NEVRA bump decision rather than metadata fallback or package
substitution.

F3 scope is the exported rootfs for each architecture. Published manifest
digests, provenance metadata, and labels that intentionally vary outside the
rootfs are not part of this rootfs byte-identity gate.
