# Reproducibility

`base-micro` is moving toward the F3 byte-for-byte gate: two rebuilds from the
same inputs must export byte-identical runtime rootfs archives for each
architecture. This repository does not claim that result until
`tools/assert-reproducible.py --assert-byte-identical` passes.

The current harness runs in report mode for `linux/amd64` in PR CI. It builds
the runtime target twice with cache disabled, exports both rootfs archives, and
classifies each path as identical, content-different, mtime-different,
mode/owner-different, or present in only one export. The JSON report is written
to `dist/reproducibility/base-micro.amd64.reproducibility.json`; the text
summary is printed in CI.

Determinism controls landed for this pass:

- `SOURCE_DATE_EPOCH=1704067200` is the committed timestamp input.
- Buildx uses `rewrite-timestamp=true` on local and publish image exporters.
- Runtime RPM inputs are locked by per-architecture transaction NEVRA files in
  `rpm-lock/`, including RPM header hashes where the rpmdb exposes them.
- The Dockerfile verifies that the final runtime rpmdb still contains exactly
  the 15-package scanner-visible floor after strip.
- Generated rootfs files such as `/etc/nwarila/fips-status.json` use the same
  deterministic timestamp path.

The rpmdb remains present and valid because SBOM and scanner truthfulness depend
on it. If byte differences remain in `/var/lib/rpm/rpmdb.sqlite`, they must be
made deterministic without deleting or corrupting the rpmdb.
