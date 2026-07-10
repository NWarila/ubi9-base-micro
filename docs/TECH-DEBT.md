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

## TD-6: CMVP-held FIPS provider fixable vulnerability

Red Hat rates `CVE-2026-31790` Medium with a CVSS 3.1 base score of 5.9
(`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`). Red Hat fixes it in
`openssl-fips-provider{,-so}` `3.0.7-11.el9_8`, but this image deliberately holds
`3.0.7-8.el9`: the provider build tied to CMVP certificate #4857. The repository
contract forbids the fixed build until its validation status is reconciled.

The temporary exception is limited to `CVE-2026-31790` on exactly
`openssl-fips-provider` and `openssl-fips-provider-so` at exactly `3.0.7-8.el9`.
Both scanner configurations pin that version. Trivy also enforces
`expired_at: 2026-10-10`; `tools/assert-ignore-scope.py` enforces the same review
date for both scanners because Grype has no native expiry. On review, re-check the
certificate #4857 hold and remove the exception when a validated fixed provider
is available.

The two vulnerability-policy axes remain distinct. The fixable gate rejects
MEDIUM, HIGH, and CRITICAL findings except for the exact exception above. The
OpenVEX default-deny gate remains limited to unfixed HIGH and CRITICAL findings.
The following 12 unfixed Medium package findings were reviewed and are tolerated
by that policy; they are not additions to the fixable-CVE exception:

| CVE | Packages |
| --- | --- |
| `CVE-2026-2673` | `openssl-fips-provider`, `openssl-fips-provider-so`, `openssl-libs` |
| `CVE-2026-5435` | `glibc`, `glibc-common`, `glibc-minimal-langpack` |
| `CVE-2026-5928` | `glibc`, `glibc-common`, `glibc-minimal-langpack` |
| `CVE-2026-6238` | `glibc`, `glibc-common`, `glibc-minimal-langpack` |

On the current image, tightening the fixable threshold catches two findings and
the exact exception excuses those same two findings, so the immediate enforcement
delta is zero. The tightening is forward-looking: any future fixable Medium on a
different CVE, package, or version fails the gate.
