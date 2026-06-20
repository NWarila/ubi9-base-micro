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

Determinism controls:

- `SOURCE_DATE_EPOCH=1704067200` is the committed timestamp input.
- Buildx uses `rewrite-timestamp=true` on local, CI, and publish image exporters.
- Runtime RPM inputs are locked by per-architecture transaction files in
  `rpm-lock/`.
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

F3 scope is the exported rootfs for each architecture. Published manifest
digests, provenance metadata, and labels that intentionally vary outside the
rootfs are not part of this rootfs byte-identity gate.
