# Runtime Footprint

`base-micro` is measured as a single-arch `linux/amd64` runtime artifact. The
build gate measures the exported rootfs regular-file total, not Docker's local
cache size or a multi-arch index aggregate.

The gate is:

```text
exported-rootfs-regular-file-bytes <= 25 * 1024 * 1024 bytes
```

Current local amd64 evidence:

| Metric | Value |
| --- | ---: |
| Uncompressed exported-rootfs-regular-file-bytes | 23,840,723 bytes / 22.7363 MiB |
| Limit | 26,214,400 bytes / 25 MiB |
| Local OCI compressed layer sum | 12,095,601 bytes / 11.5353 MiB |
| Local Docker image `.Size` | 12,102,195 bytes |

The uncompressed number is produced by `tools/assert-footprint.py`, which
exports the final image rootfs and sums regular files from the tar stream. The
same script runs in CI and writes `dist/footprint/base-micro.${arch}.json`.
`tools/assert-no-phantom-packages.py` then queries the runtime rpmdb with
`rpm -ql --dump` and checks it against the exported rootfs. An rpmdb-listed
package that declares shippable regular payload cannot pass after that payload
has been stripped. Structural or metadata-only packages with only directories,
symlinks, docs, licenses, manpages, build-id residue, or mountpoint/debug
pseudo paths are reported as non-payload RPMs instead of phantoms. Every
non-excluded shared object or executable ELF file must be owned by a runtime
rpmdb package.

The compressed number above is a local OCI-layout layer-size sum for the same
runtime target. The authoritative compressed registry-layer sum is recorded
after publish; the strip-and-footprint check is a pull-request-time gate, not
post-publish proof.

The ceiling was raised from 16 MiB to 25 MiB after a file-level sweep showed
that the ldd-verified FIPS library closure plus retained rpmdb could not meet
the smaller target. Keeping rpmdb is intentional because native scanner
truthfulness is part of the acceptance contract.

The strip removes accidental runtime tooling and auxiliary formats while keeping
the FIPS floor:

- RPM removals are performed against the installroot rpmdb after checking that
  candidate packages own no ldd-protected FIPS or glibc runtime dependency.
- `ld.so.cache` is prebuilt before removing `ldconfig`.
- The runtime keeps only the extracted TLS PEM CA bundle and verifies it during
  the build with OpenSSL from the verification stage.
- Locale and timezone data are trimmed to the required runtime floor.
