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

The [micro publish workflow](../.github/workflows/publish-image.yaml) reduces
the mutable-tag risk with a separate tag-to-SHA integrity job that asserts
`refs/tags/v2.1.0` resolves to
`f7dd8c54c2067bafc12ca7a55595d5ee9b75204a` before publish. Provenance is
verified only against the exact Fulcio identity
`https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0`,
never a regular expression. The disabled Renovate rule keeps generator tag,
SHA-guard, and identity updates manual and reviewed, never an automatic
dependency pull request.

For micro, this guard reduces but does not eliminate the mutable-tag window. It
runs as a separate job before publish; `slsa-provenance` runs after publish and
independently resolves `@v2.1.0`, so the tag can move between the check and the
reusable invocation. The exact Fulcio identity proves that the tag reference was
used, not that the tag still named the audited commit at invocation time.

The Python publisher retains the same pre-execution guard and adds a
post-execution binding before aliases: after successful Cosign and
`slsa-verifier` authentication, `tools/assert-python-slsa-certificate.py`
requires the Fulcio Build Signer Digest extension to equal the pinned generator
commit. It also binds the source SHA/ref and Python caller workflow through the
source and build-config extensions. That closes this tag-movement ambiguity for
the Python publication path at its implemented scope. Its first production
execution is post-merge and has not yet produced Python evidence; the residual
in this entry remains the micro publisher's weaker binding.

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
`libtasn1`. The discarded `fips-verify` stage uses the same direct-CDN path for
its build-only `openssl` CLI pin and reuses the runtime pins for `openssl-libs`,
`crypto-policies`, and the provider pair, with no live metadata resolution.

This removes the known metadata-purge failure mode, but it does not make CDN blob
retention a permanent guarantee. The nightly rebuild is the purge sentinel: a
404, whole-RPM SHA mismatch, or `rpm -K` failure is a hard stop. Recovery requires
an explicit vendor decision or a controlled lock refresh that bumps the NEVRA,
URL, and SHA-256 together. Do not substitute a rebuild, EPEL package, rpmrebuild
output, metadata fallback, or newer z-stream just to keep the build green.
Because repository verification requires the FIPS CLI epoch, version, and
release to equal the runtime `openssl-libs` values, an `openssl-libs` refresh is
blocked until both FIPS locks are deliberately co-refreshed. This coupling keeps
the verification CLI and shipped libraries aligned; it is not optional fallback
behavior.

## TD-5: Builder-scoped canonical rootfs digest

`canonical_rootfs_digest` is profile- and image-specific. For `base-micro`, it
binds to the rootfs exported by the local, CI, and publish Docker Buildx paths,
which set `rewrite-timestamp=true`. For `base-python`, it binds to both the
`repro` target's docker-tar export and the registry-served child exported by the
`release` target; both set `rewrite-timestamp=true`. The pull-request release
preflight checks each served child against that baseline and compares its
entries with a same-commit `ci` rootfs. The Python `ci` target uses a local
Docker exporter without the timestamp-rewrite policy. The digest
includes entry metadata (`uname`, `gname`, and `mtime`) as well as content. A
different builder, such as buildah or kaniko, can produce byte-identical file
contents and still produce a different aggregate digest because exported layer
metadata differs. The builder-portable independent checks are the per-file
content digests recorded in each image contract, including `rpmdb_sha256` and
`fips_so_sha256`.

The Python build path now pins Buildx, its expected commit and Linux-amd64 asset
SHA-256, and a versioned digest-qualified BuildKit driver image in
`images/python/docker-bake.json`. Eight non-Python setup sites remain unpinned:
two each in `.github/workflows/build.yaml`, `publish-image.yaml`, `nightly.yaml`,
and `rpm-lock-refresh.yaml`. Those sites still allow the setup action to select
Buildx `latest` and the moving default BuildKit driver image. A future toolchain
change at a build-serving site can move `canonical_rootfs_digest` and make its
gate red without a real baseline content move. The later setup site in
`publish-image.yaml` serves imagetools rather than a rootfs build; it remains an
unpinned toolchain surface but cannot directly change the built rootfs. A
builder-driven digest failure is a fail-safe false red, not a release-quality
baseline change. Treat that event as a reviewed step: inspect the toolchain
change, re-derive the contract under the chosen builder, and update the recorded
baseline only through the normal review path. A builder-independent rebuild
proof belongs to the F3/v1 anonymous-verify work.

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
The following 3 unfixed Medium package findings were reviewed and are tolerated
by that policy; they are not additions to the fixable-CVE exception:

| CVE | Packages |
| --- | --- |
| `CVE-2026-2673` | `openssl-fips-provider`, `openssl-fips-provider-so`, `openssl-libs` |

The remediated `glibc`, `glibc-common`, and `glibc-minimal-langpack` findings are
no longer part of this tolerated set.

On the current image, tightening the fixable threshold catches two findings and
the exact exception excuses those same two findings, so the immediate enforcement
delta is zero. The tightening is forward-looking: any future fixable Medium on a
different CVE, package, or version fails the gate.

## TD-7: RPM verification is limited to payload-trim packages

`assert_exact_rpm_verify_deviations` runs `rpm -V` only for packages named by the
retained-payload-trim contract. It therefore detects undeclared verification
deviations in those deliberately trimmed packages, but it does not detect a
missing-payload deviation in a different retained package. The trim contract and
the associated decision record remain correctly scoped to the contracted
packages; they do not claim repository-wide RPM payload verification.

Widening this check requires a separate security-gate change with positive and
negative oracles across every retained package. Until then, do not describe the
current assertion as complete verification of all retained RPM payloads.

## TD-8: Python builder identity workflow static-analysis boundary

The `Assert python builder identity` steps in the Python build and
reproducibility jobs run the identity assertion before building. Repository
verification statically requires each step to contain only its environment and
multiline run body, start with the exact `set -euo pipefail` preamble, contain no
later `set +...`, omit step-level `continue-on-error`, and place
`python3 tools/verify.py --check-python-builder-identity` as the final unwrapped
command. In CI, that assertion compares the contracted Buildx version, commit,
installed plugin SHA-256, BuildKit driver image, and BuildKit node version with
the five live observations. A mismatch returns failure and, under the current
workflow configuration, fails the job before its build.

Static analysis of a free-form `run:` block cannot detect every
status-swallowing construct. Function shadowing (`python3() { return 0; }`), an
`ERR` trap (`trap 'exit 0' ERR`), and job-level shell wrappers are known examples
that pass the text checks. Enumerating more shell spellings would not close this
open-ended class and would give the workflow checker a misleading security
scope.

This is an accepted trust boundary. A committer able to insert one of those
constructs can, in the same change, alter the verifier or remove the identity
step. The workflow checks are therefore defence-in-depth against accidental
regression, not an adversarial control over a hostile committer. Code review,
CODEOWNERS, and required status checks are the controls for that threat.

## TD-9: Expiring acceptance of CVE-2026-11940 in base-python

The base-python CI products `local/ubi9-base-python:ci-amd64` and
`local/ubi9-base-python:ci-arm64` are known affected by `CVE-2026-11940` in
`python3.12` and `python3.12-libs` at exactly `3.12.13-3.el9_8.1`. As of
2026-08-13, Red Hat lists RHEL 9 `python3.12` as Affected with no fixed RPM;
RHEL 9 `python3.9` is fixed via RHSA-2026:54268, and the upstream CPython 3.12
branch is fixed. Consumers must not rely on `tarfile.extractall()` `data` or
`tar` filters to contain untrusted archives until a fixed RPM is absorbed.

The legacy local-product path is a two-key authorization: the closed allowlist
in `tools/assert-vex.py` and the reviewed disclosure in
`images/python/vex/cve-2026-11940.openvex.json`. Both must match the CVE, the two
CI products, the complete two-package set, the installed version, this debt id,
and `review-by 2026-10-01`.

The same tool contains a second product-eligibility path for
a digest-addressed `ghcr.io/nwarila/ubi9-base-python` platform child. The
canonical OpenVEX document was reissued as version 2 and names that policy scope
with the non-image-matchable
`https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-python/published-platform-children`
IRI; it does not enumerate or prove the existence of a published image. For this
path the authorization is the conjunction of fixed in-tool constraints (the
pinned repository, CVE, package/version pair, and expiry), that canonical
reviewed statement, and supplied index evidence. The tool requires paired
`--index-reference` and `--index-manifest` inputs, recomputes the digest of the
exact index bytes, accepts exactly one `linux/amd64` child and one
`linux/arm64` child with distinct digests, locks the BuildKit attestation
platform and annotation maps, requires every descriptor digest in `manifests`
to be unique across all roles, and binds the gated product digest to the child
for the architecture reported by both scanners. It does not constrain the
number of attestation descriptors or their per-child reference cardinality, and
it does not close the top-level key set of either descriptor kind or the key
set of a runnable child's `platform` object.
The duplicate-or-contradictory descriptor diagnostic names the first and
repeated positions; the child/attestation digest-disjointness guard remains
separate with its own diagnostic. The index digest is never eligible, and a
distinct attestation-descriptor digest is rejected when submitted as the
product. An extra or duplicate runnable platform, a nested index, a wrong
repository, and an architecture swap are also rejected.

Those checks prove that a digest is a child of the supplied, digest-verified
index. The merged production caller supplies the previously missing origin
binding on each run: it fetches the index bytes once from the registry by the
push-reported digest, independently corroborates their SHA-256, protects
cross-job transfers with a checksum manifest, and requires the same digest for
signing, attestation, VEX, provenance, collision checks, and aliases. The
published-child path is therefore wired to a production caller rather than
dormant; its first production execution remains post-merge. This binding is
only to the index that run pushed and read back. It does not close the
external-writer alias race described in TD-10 or the VEX-side
descriptor-policy differences described in TD-11.

On both product paths, valid fix evidence from either scanner refuses the
disposition. Each raw scanner vulnerability ID, package name, and installed
version must already be byte-canonical: leading or trailing whitespace is
malformed evidence and is rejected rather than normalized into an exact match.
The image is not unaffected, and no scanner input or raw finding is suppressed.

Review this entry by 2026-10-01 and monitor Red Hat for a fixed RHEL 9
`python3.12` RPM. When Red Hat ships a fixed `python3.12` RPM, the rpm-lock
refresh absorbs it and the same pull request removes the in-tool allowlist entry
and flips the OpenVEX statement to `fixed`; that change also removes the
published-child authorization.

## TD-10: Base-python create-once alias external-writer race

The `base-python-<first-12-lowercase-hex-of-publishing-sha>` commit alias and the
Python version alias are checked for absence or the candidate index digest as
soon as that digest is known, before any signing, attestation, SLSA, or Rekor
work. They are checked again immediately before application and resolved after
application to require the expected digest. Only the moving `base-python` alias
may replace an existing digest under repository policy.

GHCR does not expose a conditional manifest write for this operation. An owner,
PAT, or other workflow with package-write authority can therefore race the final
resolve-then-apply window. The owner accepts this residual external-writer risk;
the checks are mandatory collision detection, not an atomic create-once
guarantee. Closing the window requires package settings or another owner-managed
serialization mechanism outside repository code.

## TD-11: Published-child VEX descriptor-cardinality asymmetry

The publish-side resolver requires the pinned exporter shape exactly: one
runnable `linux/amd64` child, one runnable `linux/arm64` child, and one unique
BuildKit attestation descriptor referring to each child. It rejects a third
otherwise valid attestation descriptor and a second reference to either child.

`tools/assert-vex.py` deliberately remains unchanged by the publisher work. Its
published-child index policy accepts three unique, correctly shaped attestation
descriptors referring to `amd64`, `arm64`, and `amd64`, and likewise accepts two
unique descriptors referring to the same child. It still excludes every
attestation descriptor from `eligible_child_digests`, rejects an attestation
digest used as the product, requires descriptor-digest uniqueness and
child/attestation disjointness, and verifies the supplied bytes against the
index digest. An added descriptor therefore cannot become an authorized product
and cannot appear without moving the index digest bound to the push metadata.

The policies also differ on descriptor top-level closure. The publish-side
resolver requires runnable descriptors to contain exactly `digest`,
`mediaType`, `platform`, and `size`, and attestation descriptors to contain
exactly those four keys plus `annotations`. The VEX-side policy accepts an
additional `urls`, `data`, or `artifactType` field on either descriptor kind.
In particular, `urls` can direct a client to an external location for the
descriptor content, so the publish-side policy rejects all six cases before
the index can be signed, scanned, attested, or aliased.

They also differ on runnable-platform closure. The publish-side resolver
requires both runnable and attestation `platform` objects to contain exactly
`architecture` and `os`. The VEX-side policy applies that exact check only to
the attestation platform. It accepts a runnable platform carrying `variant`,
`os.version`, `os.features`, or an invented key. `variant` can alter platform
matching, so the publish-side resolver rejects these shapes before any child is
selected for signing, scanning, attestation, or aliasing.

The stronger resolver runs before signing, scanning, attestation, or aliasing,
so production rejects both cardinality classes, every descriptor
additional-field case, and every runnable-platform additional-key case despite
the weaker secondary policy. Tightening `tools/assert-vex.py` to require exact
descriptor and runnable-platform key sets and one attestation reference per
child remains separate follow-up work. Until then, future callers must not use
the VEX-side validator alone as an exact exporter-shape or cardinality oracle.
