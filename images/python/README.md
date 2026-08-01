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

`docker-bake.json` is the one native build definition used by both existing
Python image build sites. Its shared target owns the context, Dockerfile,
runtime build target, two supported platforms, `SOURCE_DATE_EPOCH`, and
`OCI_CREATED`. The `ci` target selects the local Docker exporter; the `repro`
target selects no-cache double builds, disables BuildKit provenance and SBOM,
and keeps `rewrite-timestamp=true` on its docker-tar exporter. There is no
release target.

The same file carries the Buildx version, expected commit, Linux-amd64 release
asset SHA-256, and version-plus-digest BuildKit driver reference. Before either
CI profile builds, the workflow checks the installed Buildx version and commit,
hashes the selected plugin binary, checks the builder container's
`Config.Image`, and checks the BuildKit version reported by the setup action.
Any missing or mismatched observation stops the job; there is no fallback to a
moving tag or nearby version.

Repository verification enforces the contract shape and fails closed if a
`ci` or `repro` target redeclares a protected graph field, the CI command adds a
non-static or undeclared `--set` field, selects a builder, changes output with
push/load/output options, or includes another token, or the double-build report
and execution stop sharing the AST-locked per-side Bake descriptor. Discovery
parses tracked-file shell command segments and Python literal list or tuple
commands, rejecting direct builds whose literal tokens statically select this
image's Dockerfile or context and requiring exactly the two recognized existing
consumers. Those guarantees do not cover arbitrary dynamic command construction
or a future publisher.

Renovate tracks the Buildx release version and the BuildKit
version-plus-digest reference through separate managers with automerge disabled.
A Buildx version update deliberately leaves the independently established
commit and asset SHA-256 untouched, so it fails the identity gate until all
three values identify the same release. Builder-pin changes remain
image-affecting and must preserve both architectures' rootfs and rpmdb
baselines. See
[`../../docs/explanation/reproducibility.md`](../../docs/explanation/reproducibility.md)
for the complete scope.

**Status: built and gated in CI, unpublished.** The evidence machinery is in
place and exercised for every Python-tree or shared-gate change selected by the
Python workflow — a tailored RHEL9 STIG profile evaluated fail-closed,
rpmdb-derived SPDX and CycloneDX SBOMs, dual CVE scanners with OpenVEX
default-deny, a rootfs secret gate, and a NIST SP 800-190 image-control predicate
— but it runs against locally built images. Nothing is signed, attested, or
pushed. No registry package, tag, or
publish workflow exists for this image yet; publication requires the full
`base-micro` evidence-parity set (signature, SPDX and CycloneDX SBOMs, OpenVEX,
NIST SP 800-190 evidence, tailored STIG ARF, SLSA provenance) and will arrive
as its own change. Consumption instructions are deliberately absent until then.

The shipped package set is derived, not hand-picked: the lock refresh harness
resolves the python3.12 closure against a clone of the pinned parent, records
shipped versus build-support rows in `rpm-lock/`, and CI gates the result with a
functional standard-library battery (including TLS against the parent CA store
and an explicit assertion that `sqlite3` is unavailable),
parent-invariance comparisons at both build boundaries, and dual CVE scanners
reading the combined rpmdb. `python3.12-pip-wheel` ships as an RPM-closure
requirement; the image has no `pip` entrypoint.
