# Technical Debt

Numbering is shared and is not necessarily contiguous; only debt affecting this
repository is recorded here.

## TD-1: SLSA container-generator tag-pin exception

This repository pins every GitHub Actions `uses:` reference to a 40-character
commit SHA. The SLSA container-generator reusable workflow is the one documented,
reviewed exception: it is pinned to the `@v2.1.0` semantic-version tag because
the reusable must be referenced by a version tag for both its release-binary
download and its Fulcio provenance identity to resolve. A raw-SHA pin would not
satisfy that current release-binary plus exact-tag-identity contract and would
change the observed identity; this does not rule out a redesigned SHA-based
generator configuration with a different build and identity contract.

The [publish workflow](../.github/workflows/publish-image.yaml) reduces the
mutable-tag risk with a separate tag-to-SHA integrity job that asserts
`refs/tags/v2.1.0` resolves to
`f7dd8c54c2067bafc12ca7a55595d5ee9b75204a` before publish. Provenance is
verified only against the exact Fulcio identity
`https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0`,
never a regular expression. The disabled Renovate rule keeps generator tag,
SHA-guard, and identity updates manual and reviewed, never an automatic
dependency pull request.

This guard reduces but does not eliminate the mutable-tag window. It runs as a
separate job before publish; `slsa-provenance` runs after publish and independently
resolves `@v2.1.0`, so the tag can move between the check and the reusable
invocation. The exact Fulcio identity proves that the tag reference was used,
not that the tag still named the audited commit at invocation time.

## TD-3: Per-architecture FIPS scope

On `linux/amd64`, the Red Hat OpenSSL FIPS provider operates in the approved-mode
configuration validated under CMVP certificate #4857 (`oe_validated=true`). On
`linux/arm64`, the image ships the same module #4857 and provider NVR,
approved-mode-configured and self-test-passing, but certificate #4857 does not
list arm64 in its validated or vendor-affirmed operational environments; the
contract therefore records `oe_validated=false`. This is the distinction between
module validation and validation of a specific operational environment.

Claims remain module-scoped and approved-mode-scoped, never an image, OS, host,
or application validation. The per-architecture evidence and disclaimer are in
[the FIPS documentation](compliance/fips.md) and the
[image contract](../contracts/image-manifest.json). Remove this entry or upgrade
the provider when a validated arm64 provider becomes available.

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
