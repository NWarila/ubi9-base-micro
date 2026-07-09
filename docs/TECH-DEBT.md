# Technical Debt

## TD-4: Red Hat UBI direct-CDN blob availability

Red Hat UBI repository metadata can purge older z-stream RPM builds while this
image still needs exact NEVRA pins for byte-for-byte reproducibility and FIPS
scope. The runtime lock therefore records a direct `https://cdn-ubi.redhat.com/`
URL plus whole-RPM SHA-256 for every runtime RPM, including the held
`openssl-fips-provider` / `openssl-fips-provider-so` `3.0.7-8.el9` packages and
ordinary transaction RPMs such as `coreutils`, `coreutils-common`, and
`libtasn1`.

This removes the known metadata-purge failure mode, but it does not make CDN blob
retention a permanent guarantee. The nightly rebuild is the purge sentinel: a
404, whole-RPM SHA mismatch, or `rpm -K` failure is a hard stop. Recovery requires
an explicit vendor decision or a controlled lock refresh that bumps the NEVRA,
URL, and SHA-256 together. Do not substitute a rebuild, EPEL package, rpmrebuild
output, metadata fallback, or newer z-stream just to keep the build green.

## TD-5: Builder-scoped canonical rootfs digest

`canonical_rootfs_digest` currently binds to the rootfs as exported by this
repository's CI builder path: Docker Buildx with `rewrite-timestamp=true`. It
includes entry metadata (`uname`, `gname`, and `mtime`) as well as content. A
different builder, such as buildah or kaniko, can produce byte-identical file
contents and still produce a different aggregate digest because exported layer
metadata differs. Today the builder-portable independent checks are the per-file
content digests in the contract: `rpmdb_sha256` and `fips_so_sha256`.

The workflows pin `docker/setup-buildx-action` by SHA, but that action installs
buildx `latest`. A future buildx release that changes layer-tar metadata can
move `canonical_rootfs_digest` and make CI red without a real baseline content
move. That is a fail-safe false red, not a release-quality baseline change.
Treat that event as a reviewed step: inspect the toolchain change, re-derive the
contract under the chosen builder, and update the recorded baseline only through
the normal review path. A builder-independent rebuild proof belongs to the F3/v1
anonymous-verify work.
