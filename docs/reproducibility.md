# Reproducibility

`base-micro` enforces the F3 byte-for-byte rootfs gate in CI. The
`reproducibility-gate` job builds the runtime target twice from identical inputs
for both `linux/amd64` and `linux/arm64`, exports each image rootfs, and runs
`tools/assert-reproducible.py --assert-byte-identical`. Any content, metadata,
mtime, ownership, type, or presence difference in the exported rootfs fails the
build.

The arm64 proof intentionally uses QEMU on the GitHub-hosted amd64 runner because
that is the same architecture path used by the publish workflow. Native arm64
hosted runners would be a cleaner fallback if QEMU ever produces a byte diff, but
QEMU is currently in scope and hard-gated because arm64 is a published artifact.

The QEMU input is pinned by
`docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130`.

The `linux/amd64` byte-identity claim is native and toolchain-independent: no
emulator participates in that build path. The `linux/arm64` byte-identity claim
is emulator-relative: it is reproducible relative to the pinned QEMU/binfmt
emulator above. The build-twice CI gate proves same-environment determinism for
arm64 with that pinned QEMU; it does not claim byte-identity across arbitrary
QEMU versions. A third-party arm64 reproducer needs the same pinned QEMU
input unless they are deliberately testing a different emulator or native arm64
path. That boundary is intrinsic to cross-architecture reproducible builds.

The two-builds-in-one-CI-run gate is necessary for the F3 claim because any rootfs
difference fails the build, but it is not sufficient by itself for a broad
"anyone-anywhere" reproducibility claim. Future cross-host and native-arm64
confirmation would strengthen the evidence without changing the current hard gate
scope.

Determinism controls:

- `SOURCE_DATE_EPOCH=1704067200` is the committed timestamp input.
- Buildx uses `rewrite-timestamp=true` on local, CI, and publish image exporters.
- `docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130` pins
  the QEMU/binfmt emulator used for the cross-architecture `linux/arm64` build
  path on GitHub-hosted amd64 runners.
- Runtime RPM inputs are locked by per-architecture transaction files in
  `rpm-lock/`. Every lock row has a `# direct_rpm:` entry with a
  `https://cdn-ubi.redhat.com/` URL and whole-RPM SHA-256. The build fetches
  the complete runtime transaction from those pinned URLs with `curl -f`,
  verifies Red Hat RPM signatures with `rpm -K`, verifies the whole-RPM SHA-256,
  installs the complete locked transaction with a raw rpm command
  (`rpm --root=/rootfs --initdb` then
  `rpm --root=/rootfs -Uvh --oldpackage --replacepkgs --excludedocs <paths>`) over
  the fetched local RPM paths in lockfile (LC_ALL=C-sorted) order — no microdnf, no
  install-time dependency resolution, and no repository metadata. Because
  `rpm -Uvh` runs without `--nodeps`, an unsatisfied dependency aborts the build, so
  the locked set must be a complete pre-resolved closure. The held OpenSSL FIPS
  provider RPMs are part of the same fetched-local-RPM transaction.
- Every locked RPM is verified immediately after install with
  `rpm --root=/rootfs -q --qf '%{SHA256HEADER}|%{SIGMD5}\n' <locked-nevra>`.
  `SHA256HEADER` is the rpmdb-exposed tag that matches the lockfile
  `sha256_header` column; `SIGMD5` matches the `sigmd5` column. A mismatch fails
  the build before any strip step runs.
- The Dockerfile verifies that the final runtime rpmdb still contains exactly
  the 15-package scanner-visible floor after strip.
- Generated rootfs files such as `/etc/nwarila/fips-status.json` use the same
  deterministic timestamp path.

The rpmdb remains present and valid because SBOM and scanner truthfulness depend
on it. Differences in `/var/lib/rpm/rpmdb.sqlite` are gate failures; the rpmdb is
not deleted, normalized away, or excluded from the rootfs comparison.

## RPM lock refresh loop

The lockfiles deliberately pin RPM NEVRAs and content hashes, so patched Red Hat
RPMs are not absorbed automatically. The nightly sentinel detects when a pinned
runtime RPM has a fixable CVE and turns the gate red. The weekly and manually
runnable `.github/workflows/rpm-lock-refresh.yaml` workflow runs
`tools/generate-rpm-lock.sh` for `linux/amd64` and `linux/arm64`; the generator
uses the same microdnf installroot transaction shape as the Dockerfile and emits
the `rpm-lock/runtime.<arch>.txt` format consumed by the build.

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
