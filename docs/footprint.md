# Runtime Footprint

`base-micro` is measured as a single-arch `linux/amd64` runtime artifact. The
build gate measures the exported rootfs regular-file total, not Docker's local
cache size or a multi-arch index aggregate.

The gate is:

```text
exported-rootfs-regular-file-bytes <= 25 * 1024 * 1024 bytes
```

Current STEP024 local evidence:

| Metric | Value |
| --- | ---: |
| Uncompressed exported-rootfs-regular-file-bytes | 24,035,076 bytes / 22.9216 MiB |
| Limit | 26,214,400 bytes / 25 MiB |
| Local OCI compressed layer sum | 12,111,841 bytes / 11.5508 MiB |
| Local Docker image `.Size` | 12,125,924 bytes |

The uncompressed number is produced by `tools/assert-footprint.py`, which
exports the final image rootfs and sums regular files from the tar stream. The
same script runs in CI and writes `dist/footprint/base-micro.${arch}.json`.

The compressed number above is a local OCI-layout layer-size sum for the same
runtime target. The authoritative compressed registry-layer sum is recorded
after publish from the registry manifest; STEP024 is a PR-time strip and gate,
not the post-merge publish proof.

The H2 target was renegotiated from 16 MiB to 25 MiB after the STEP022/STEP023
file sweep. The floor is dominated by the ldd-verified FIPS library closure
plus the retained rpmdb. Keeping rpmdb is intentional because native scanner
truthfulness is part of the acceptance contract.

The strip removes accidental runtime tooling and auxiliary formats while keeping
the FIPS floor:

- RPM removals are performed against the installroot rpmdb after checking that
  candidate packages own no ldd-protected FIPS or glibc runtime dependency.
- `ld.so.cache` is prebuilt before removing `ldconfig`.
- The runtime keeps only the extracted TLS PEM CA bundle and verifies it during
  the build with OpenSSL from the verification stage.
- Locale and timezone data are trimmed to the required runtime floor.
