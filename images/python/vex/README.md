# OpenVEX Dispositions

This directory is the reviewed source for OpenVEX dispositions used by the base-python CVE gate. The gate is default-deny: every unfixed HIGH or CRITICAL finding reported by either Trivy or Grype must match an accepted statement here, or the workflow fails.

Accepted statements must be OpenVEX JSON files with:

- `@context` and a non-empty `statements` array.
- `vulnerability.name` or an equivalent vulnerability id matching the scanner finding.
- `products[].@id` matching the exact image reference scanned, or the same reference prefixed with `pkg:oci/`.
- `status: "fixed"` or `status: "not_affected"` with one of the standard OpenVEX justifications, except for the exact accept-and-track path below.

`affected` satisfies the gate only for the exact, expiring accept-and-track
authorizations implemented in `tools/assert-vex.py`: CVE-2026-11940 matched by
`cve-2026-11940.openvex.json`, and CVE-2026-14456 matched by
`cve-2026-14456.openvex.json`. Every other `affected` statement, and every
`under_investigation` statement, remains documentary and does not satisfy the
gate. Files under `vex/` require review through `.github/CODEOWNERS`. The
pull-request release preflight does not attest OpenVEX. The production publisher
attests each JSON file, byte-unmodified, to both per-architecture image digests
with `cosign attest --type openvex` after the same-child gate succeeds.

The image inherits the deliberately held FIPS provider packages from its parent, so the same
disclosure applies here with a base-python product identity.

`cve-2026-31790.openvex.json` discloses that the deliberately held FIPS provider
packages are affected and gives downstream consumers mitigation guidance. This
statement is documentary: it does not suppress the finding or satisfy the
default-deny gate. The exact, expiring scanner suppression is maintained
separately under `security/` and tracked as TD-6 in `docs/TECH-DEBT.md`.

`cve-2026-11940.openvex.json` version 2 discloses that both base-python CI
products ship the affected `python3.12` and `python3.12-libs` packages at
`3.12.13-3.el9_8.1`. It also names the potential
`ghcr.io/nwarila/ubi9-base-python` platform-child scope with the
non-image-matchable policy IRI
`https://github.com/NWarila/ubi9-base-micro/policy/ubi9-base-python/published-platform-children`.
The IRI documents policy scope without becoming a bare repository wildcard and
does not assert that any such image or index has been published. The statement
tracks acceptance as TD-9 through `review-by 2026-10-01`; it does not claim
that the package or image is unaffected.

`cve-2026-14456.openvex.json` records that both base-python CI products ship
`openssl-libs` at exactly `1:3.5.5-5.el9_8`. It names the same pinned published
repository through the non-image-matchable Python policy IRI. Red Hat listed
RHEL 9 `openssl` as Affected with no fixed RPM as of 2026-08-18; RHEL 9.8 and
later ship the affected OpenSSL 3.5.x QUIC server, and exploitation requires an
application to explicitly enable a QUIC server listener. The image runs no
server process by default and starts the Python interpreter. The statement
tracks acceptance as TD-12 through `review-by 2026-10-01`; it does not claim
that the package or image is unaffected.

For either accepted finding on the two local CI products, the gate requires two
keys: the exact in-tool disposition entry and the matching byte-canonical
reviewed statement. The complete CVE, package/version set, product surface,
statement path, and action text must match. For a digest-addressed child under
the pinned `ghcr.io/nwarila/ubi9-base-python` repository, the production path
requires three keys: the same disposition entry, the surface's canonical
statement, and paired index evidence. `--index-reference` identifies an index
digest and `--index-manifest` supplies its exact bytes. The tool recomputes the
byte digest, enforces an OCI index with exactly one `linux/amd64` child and one `linux/arm64`
child with distinct digests, locks the BuildKit attestation platform and
annotations, requires a unique digest for every descriptor in `manifests`
across all roles, and binds the product to the child matching the
scanner-reported architecture. It does not constrain attestation count or
per-child reference cardinality, and it accepts measured `urls`, `data`, and
`artifactType` additions on both descriptor kinds because it does not close
their top-level key sets. It also accepts an invented member in a runnable
child's `platform` object. Before any consumer runs, the production publish
resolver requires exactly the four-key runnable and five-key attestation
descriptor shapes, exact `architecture` and `os` platform objects, and exactly
one attestation descriptor referring to each child.
The duplicate-or-contradictory descriptor diagnostic names the first and
repeated positions. The index digest is never eligible, and a distinct
attestation-descriptor digest is rejected when submitted as the product. The
separate child/attestation digest-disjointness guard makes an alias malformed
and rejects it before child-product eligibility is decided. Extra or duplicate
runnable platforms, nested indexes, and architecture swaps are also rejected.

The production caller obtains the index bytes from the registry exactly once at
the digest reported by its push metadata. It requires SHA-256 over those exact
bytes to equal that independently reported digest, seals the artifact for every
cross-job handoff, and re-verifies it before use. The same index digest selects
the publish resolver, both child VEX calls, recursive signing, attestations,
SLSA provenance, collision checks, and final aliases. This binds the dynamic
authorization input to the index this run pushed and read back; it does not make
the later resolve-then-apply alias operation atomic against an external writer.
All three VEX-side descriptor-policy differences are tracked as TD-11. The
2026-08-17 production attempt failed in `registry-served gates and evidence`
while `Install publication gate tools` tried to install Syft without Cosign
available. That prerequisite is now repaired and lock-enforced; production proof
remains pending the next `main` push. The package exists publicly and serves only
unaliased, unsigned candidate digests. Its two BuildKit `mode=max` provenance
attestation manifests exist; no production gate evidence, Cosign signature or
attestation, SLSA-generator provenance, Rekor record, or consumer alias exists.

An authorization on one disposition or image surface cannot satisfy another.
The authorization is refused if either scanner supplies valid fix evidence. The
raw scanner vulnerability ID, package name, and installed version must also be
byte-canonical on both paths: surrounding whitespace is malformed evidence and
is rejected rather than normalized into an exact match. Gate expiry is scoped
to a present matching candidate; `tools/verify.py` independently expires the
repository entries after the review date, including while a finding is dormant.

`sqlite-component-not-present.openvex.json` records five distinct
`not_affected` / `component_not_present` dispositions for CVE-2026-51296,
CVE-2026-51297, CVE-2026-51302, CVE-2026-51303, and CVE-2026-51304. The
statements bind the image products, not an included SQLite subcomponent:
`sqlite-libs`, `libsqlite3`, the CPython `_sqlite3` extension, the `sqlite3`
stdlib package directory, and the matching build-id link are all absent from
the final image. Build, runtime, rpmdb, SBOM, phantom-package, and raw-scanner
gates independently prove that absence before OpenVEX is applied. The raw
scanner gate treats a correctly formed zero-finding pair as a pass: Trivy's
inventory provides the contract-derived runtime-package marker, while Grype's
findings-only `matches` list may be empty. `tools/assert-vex.py` then separately
binds the report identities to each other and to the scanned product before it
evaluates findings and dispositions.

`cve-2026-53613.openvex.json` records a `not_affected` /
`vulnerable_code_not_present` disposition for the Grype finding on `libuuid` at
exactly `0:2.37.4-25.el9`. Red Hat identifies the vulnerable code as `mount(8)`;
the `/usr/bin/mount` payload belongs to `util-linux-core`, while `libuuid` is a
separate binary package from the same `util-linux` source RPM. Neither
`util-linux` nor `util-linux-core` is installed in the base-python image on
either architecture, so the vulnerable code is absent. The document binds both
local CI products and the published-platform-children policy product to the
same exact `libuuid` subcomponent. The gate requires the canonical statement
and package/version pair for local products; a published child additionally
requires repository-correct, digest-verified OCI index evidence. This permanent
not-affected disposition is not tracked technical debt.
