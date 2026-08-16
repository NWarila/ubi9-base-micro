# ubi9-base-python (unpublished)

CPython 3.12 on the untouched `base-micro` floor: the build clones the published
parent rootfs, applies a pinned, signature-verified RPM transaction with one
truthful combined rpmdb, strips build-support packages behind ldd-ownership
guards, and ships as a single reproducible layer running as `nonroot` (65532)
with `/usr/bin/python3.12` as the entrypoint.

## SQLite is intentionally unavailable

This image omits the Python `sqlite3` standard-library package, the native
`_sqlite3` extension, and `libsqlite3`. SQLite is outside this image's declared
supported runtime surface, and removing the otherwise unused engine eliminates
the component that produced five unfixed CVE findings instead of carrying
vulnerable code no supported feature needs. CI requires
`importlib.util.find_spec("sqlite3")` to return `None` and proves the RPM,
library, extension, package directory, and build-id link are absent on both
architectures.

Installing `sqlite-libs` alone does **not** restore Python SQLite support because
the matching Python payload is also absent. Consumers that need `sqlite3` should
use a fuller Red Hat Python base image or build a derivative that deliberately
retains both the matching `python3.12-libs` SQLite payload and `sqlite-libs`.

## Raw scanner evidence

A valid clean scan is a successful result. The SQLite-absence gate accepts a
Trivy report with no vulnerabilities and a Grype report with `matches: []`; it
does not require the image to retain a vulnerability finding. Positive content
evidence comes from Trivy's `--list-all-pkgs` inventory. The gate selects
`python3.12-libs` as the runtime marker and derives its expected epoch, version,
release, and RPM architecture from the exactly one matching entry in
`runtime.shipped[arch]` in the image contract.

Grype does not expose a complete package inventory in this report. Its side of
the gate therefore validates the Grype descriptor, Red Hat distro, recognized
image-or-directory source shape, list-valued `matches`, and every present
match's RPM artifact and vulnerability fields. Both scanner documents are still
searched for `sqlite-libs` and the five SQLite CVEs. Marker identities with an
extra epoch separator or a colon in version/release, and whitespace-bearing
Trivy package or Grype artifact names, are rejected as malformed evidence.

Normal execution requires `--trivy-json`, `--grype-json`, `--contract`, and
`--arch` (`amd64` or `arm64`); `--self-test` remains standalone. This raw gate
does not bind the two reports to each other. The adjacent `tools/assert-vex.py`
invocation owns product, image, architecture, distro, and repository-digest
binding before findings are evaluated against OpenVEX.

## Build input contract

`docker-bake.json` is the one native build definition used by the Python image
build sites. Its shared target owns the context, Dockerfile, runtime build
target, two supported platforms, `SOURCE_DATE_EPOCH`, and `OCI_CREATED`. The
`ci` target selects the local Docker exporter. The registry-exporting `release`
target takes its repository destination from the fail-closed `RELEASE_REF`,
binds the protected OCI revision, source, and version arguments, emits
maximum-mode BuildKit provenance, disables exporter SBOM, and uses
`rewrite-timestamp=true`, `push-by-digest=true`, and `name-canonical=true`. The
`repro` target selects no-cache double builds, disables BuildKit provenance and
SBOM, and applies the same timestamp-rewrite policy to its docker-tar exporter.

The same file carries the Buildx version, expected commit, Linux-amd64 release
asset SHA-256, and version-plus-digest BuildKit driver reference. Before either
CI profile builds, the workflow checks the installed Buildx version and commit,
hashes the selected plugin binary, checks the builder container's
`Config.Image`, and checks the BuildKit version reported by the setup action.
Any missing or mismatched observation stops the job; there is no fallback to a
moving tag or nearby version.

Repository verification enforces the four-target contract shape and fails
closed if a committed non-base target redeclares a protected graph field. It
also locks the `release` target's exact registry exporter and attestation
settings. Both CI workflow builder setups and their five-observation identity
steps must derive the pins from this file before building. Each named identity
step must keep `set -euo pipefail` enabled, omit `continue-on-error`, and end
with the identity checker as its final unwrapped command.

The build matrix is an active CI-rootfs preflight. On pushes to `main` and manual
dispatches it runs for both architectures independently of the pull-request path
selector; pull requests retain that selector. Each architecture builds the `ci`
target once. The workflow exports the effective rootfs from the same loaded image
used by the build-job gate battery, asserts its `canonical_rootfs_digest` and
`rpmdb_sha256` against `contracts/image-manifest.json`, and checks that the
image's revision, source, version, and created labels match the current commit
and committed inputs. This is an effective-rootfs and rpmdb assertion, not an OCI
manifest or image-config identity check, and it does not determine the digest of
a future release child.

A separate pull-request-only release preflight invokes `release` once for both
architectures against a loopback-bound ephemeral registry. It reads back the
registry-served index and children, checks each exported rootfs and rpmdb against
the committed contract, and compares each rootfs with a same-commit `ci` build.
The preflight pushes a candidate tag and unsigned BuildKit provenance only to
that local registry; it does not create an external or project publication.

The Python CI and pull-request preflight jobs grant `contents: read` only and
contain no external registry credential or login surface. The production
publisher grants package-write or OIDC authority only to jobs that need it,
guards every independently executable privileged job to the base repository,
and accepts only `main` or `python/v*` pushes. Repository verification binds each
complete workflow to an expected SHA-256 and byte length and also locks the
publisher's closed Bake invocation, digest-only export, subject matrix, identity,
two-phase alias ordering, and fail-closed guards. Those locks do not cover
pinned external code.

Renovate tracks the Buildx release version and the BuildKit
version-plus-digest reference through separate managers with automerge disabled.
A Buildx version update deliberately leaves the independently established
commit and asset SHA-256 untouched, so it fails the identity gate until all
three values identify the same release. Builder-pin changes remain
image-affecting and must preserve both architectures' rootfs and rpmdb
baselines. See
[`../../docs/explanation/reproducibility.md`](../../docs/explanation/reproducibility.md)
for the complete scope.

## Publication contract

The merged publisher runs only for base-repository pushes to `main` or
`python/v*`; pull requests run the unprivileged release preflight instead. Its
Python-specific scope policy publishes for every `images/python/**` change,
every enumerated shared input it consumes, and every missing or ambiguous diff.
It skips only a delta entirely within its closed unrelated allowlist.

A production run pushes one unaliased candidate by digest and reads its index
bytes back from GHCR exactly once at the digest reported by Buildx metadata. It
independently hashes those bytes, checksum-protects each cross-job handoff, and
passes that same digest to signing, attestation, VEX, provenance, collision, and
alias consumers. The publish resolver requires one runnable child and one
BuildKit attestation reference for each of `linux/amd64` and `linux/arm64`, and
exact-checks the runnable descriptor's four top-level keys and the attestation
descriptor's five. It rejects `urls`, `data`, and `artifactType` additions on
both descriptor kinds. The VEX-side policy independently verifies runnable
children, the attestation platform and annotations, and digest relationships,
but it neither closes the descriptor top-level key sets nor constrains
attestation count or duplicate per-child references. TD-11 tracks both measured
differences, and the stricter publish resolver runs first.

The index and both children are signed recursively. SPDX, CycloneDX, OpenVEX,
NIST SP 800-190, and STIG ARF attestations are required on each child. The exact
Python trust contract and SLSA provenance are index-only. A fresh credentialed
verification completes before aliases. Alias collision checks run before
evidence, immediately before apply, and after apply, but they cannot make the
resolve-then-write window atomic against an external package writer; TD-10
records that residual.

**Status: publisher merged; awaiting first successful publication.** The evidence
machinery is exercised by the CI-rootfs preflight on every push to `main` and
manual dispatch, and for Python-tree or shared-gate changes selected on pull
requests — a tailored RHEL9 STIG profile evaluated fail-closed, rpmdb-derived
SPDX and CycloneDX SBOMs, dual CVE scanners with OpenVEX default-deny, a rootfs
secret gate, and a NIST SP 800-190 image-control predicate. The pull-request
release preflight additionally pushes a candidate tag and unsigned BuildKit
provenance to its ephemeral loopback registry. A guarded two-phase production
publisher is merged, but this change adds capability only. No completed
run, project package, public or moving alias, production signature, Cosign
attestation, SLSA or Rekor record, or consumer-resolvable digest exists for this
image at this revision. Publication requires a successful publish run; public
consumability additionally requires the owner to change GHCR
visibility and a successful anonymous verification. See
[`../../docs/how-to/verify-a-published-image.md`](../../docs/how-to/verify-a-published-image.md)
for the post-publication procedure.

The shipped package set is derived, not hand-picked: the lock refresh harness
resolves the python3.12 closure against a clone of the pinned parent, records
shipped versus build-support rows in `rpm-lock/`, and CI gates the result with a
functional standard-library battery (including TLS against the parent CA store
and an explicit assertion that `sqlite3` is unavailable),
parent-invariance comparisons at both build boundaries, and dual CVE scanners
reading the combined rpmdb. `python3.12-pip-wheel` ships as an RPM-closure
requirement; the image has no `pip` entrypoint.
