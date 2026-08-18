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

`canonical_rootfs_digest` is asserted at the scope of each image's reviewed
Docker Buildx profile. The non-Python workflows pin the setup action SHA but
still let it select Buildx `latest` and the default moving BuildKit driver image.
The production-attempted `base-python` path instead pins Buildx by
version, expected commit, and Linux-amd64 asset SHA-256 and pins its BuildKit
driver with a versioned digest-qualified reference in
`images/python/docker-bake.json`. Micro's Buildx and BuildKit remain unpinned by
that Python-only contract. Because the line format includes entry metadata
(`uname`, `gname`, and `mtime`) along with file content, a different builder such
as buildah or kaniko can export byte-identical file contents while producing a
different `canonical_rootfs_digest`. The builder-portable checks available today
are the per-file content digests recorded in the contract, specifically
`rpmdb_sha256` for `/var/lib/rpm/rpmdb.sqlite` and `fips_so_sha256` for
`/usr/lib64/ossl-modules/fips.so`.

The 2026-08-17 production attempt failed in `registry-served gates and evidence`
while `Install publication gate tools` tried to install Syft without Cosign
available. That prerequisite is now repaired and lock-enforced; production proof
remains pending the next `main` push. The package exists publicly and serves only
unaliased, unsigned candidate digests. Its two BuildKit `mode=max` provenance
attestation manifests exist; no production gate evidence, Cosign signature or
attestation, SLSA-generator provenance, Rekor record, or consumer alias exists.

The Python reproducibility matrix runs the `repro` target twice with no cache
for each architecture, compares both exported rootfs trees, and asserts the
image-specific `canonical_rootfs_digest` and `rpmdb_sha256` baselines. Each side
is represented by one immutable Bake invocation descriptor; the same file,
target, variable environment, and overrides drive both `bake --print`
and the build that the report describes. Repository verification fails closed
unless the exact `base`/`ci`/`release`/`repro` target set is present and the
three non-base targets inherit the base without redeclaring a protected graph
field. It also
requires the two CI workflow builder setups and their five-observation identity
steps to derive the pins from the contract before building. Each named identity
step must keep `set -euo pipefail` enabled, omit `continue-on-error`, and end in
the identity checker as its final unwrapped command. These static shape checks
catch accidental changes such as disabling strict mode, wrapping the assertion,
or following it with another command; they are not exhaustive analysis of the
free-form shell body. Function shadowing, an `ERR` trap, and a job-level shell
wrapper can still swallow status while passing the text checks. The live
assertion compares the Buildx version, commit, installed plugin SHA-256, BuildKit
container image, and BuildKit node version, and any mismatch fails the CI job
before building. [TD-8](../TECH-DEBT.md#td-8-python-builder-identity-workflow-static-analysis-boundary)
records why this is an accepted trust boundary and the compensating controls.
The verifier does not interpret arbitrary caller command-line overrides or
discover and count every possible build caller. It does, however, lock the
production publisher's exact `release` invocation and resolved destination,
output attributes, protected OCI arguments, cache policy, platforms, and
attestation settings. The current per-side descriptor remains behavior of the
reproducibility harness, not a repository-wide invocation guarantee.

The Python build matrix is also an active CI-rootfs preflight. On pushes to
`main` and manual dispatches it runs for both architectures independently of the
pull-request path selector; pull requests retain that selector. Each matrix job
builds the `ci` target once and exports a flattened rootfs from the loaded
`local/ubi9-base-python:ci-${ARCH}` image. The contract step consumes that same
rootfs before the remaining image gates and asserts its architecture-specific
`canonical_rootfs_digest` and `rpmdb_sha256` against
`images/python/contracts/image-manifest.json`. It also checks that the loaded
image labels bind revision to `GITHUB_SHA`, source to the repository URL, version
to the committed `images/python/VERSION`, and created time to the fixed Bake
contract value.

The CI-rootfs preflight is scoped to the effective rootfs entry set and the
rpmdb file.
The canonical digest is produced from normalized, sorted entries; it is not an
OCI manifest, image-config, compressed-layer, or tar-encoding digest. The
ephemeral `ci` image is not a release-shaped artifact, and its successful check
does not establish the manifest digest of a later release child. The CI
workflow's `GITHUB_TOKEN` grants `contents: read` only and that workflow contains
no configured registry credential or login surface. The separate production
workflow grants package-write and OIDC permissions only where its publish,
signing, or attestation roles require them. Repository verification binds every
committed byte of both workflows to an expected SHA-256 and byte length, so
changing either YAML surface requires a corresponding visible verifier edit;
those locks do not cover external code.

The separate pull-request release preflight exercises the registry-exporting
`release` target once for both architectures against a loopback-bound ephemeral
registry. It resolves the registry-served Linux child digests, exports each
child rootfs, checks `canonical_rootfs_digest` and `rpmdb_sha256` against the
contract, and compares the entries with a same-commit `ci` rootfs. The local
candidate index and unsigned BuildKit provenance establish the release
exporter's behavior without creating an external or project publication,
signature, SLSA or Rekor record, or consumer-resolvable digest.

Renovate has two non-automerge Python builder surfaces. The Buildx manager
updates the release version only; the independently owned expected commit and
Linux-amd64 asset SHA-256 must be paired with that version before the pre-build
identity gate can pass. The BuildKit manager updates the version-plus-digest
driver reference together, and the expected BuildKit version is derived from
that reference. Either update still has to pass all five live identity
observations and the both-architecture byte gates. These managers update only
the pinned builder inputs; they do not configure the release destination or
production publication.

The arm64 proof intentionally uses QEMU on the GitHub-hosted amd64 runner because
that is the same architecture path used by the publish workflow. Native arm64
hosted runners would be a cleaner fallback if QEMU ever produces a byte diff, but
QEMU is currently in scope and hard-gated because the publication contract
includes an arm64 child.

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
- The base-micro local, CI, and publish exporter paths use
  `rewrite-timestamp=true`. Base-python's `repro` target uses the same policy for
  its docker-tar double-build gate, and its `release` target uses it for the
  registry exporter with `push-by-digest=true` and `name-canonical=true`; `ci`
  uses a local Docker exporter without claiming that policy. The pull-request
  preflight remains confined to its loopback registry. The production workflow
  is capable of exporting an unaliased candidate to GHCR by digest.
  Base-python has a failed publish result at this revision: the workflow exported
  public, unaliased candidate digests before its registry-served gate job failed.
- `images/python/docker-bake.json` is the base-python build definition. Its
  shared target owns the graph inputs, while the `ci`, `release`, and `repro`
  targets own distinct exporter, cache, provenance, and SBOM policies.
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
