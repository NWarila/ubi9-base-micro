# Local Gate Reference

This page summarizes what each repository helper enforces. The source of truth
for implementation details remains the helper itself and the workflow that calls
it.

| Path | Enforces |
| --- | --- |
| `tools/verify.py` | Repository contract checks: a duplicate-free required-file manifest; pinned workflow inputs; the exact `base`/`ci`/`release`/`repro` Python Bake shape; one shared base; base-only inheritance; rejection of protected fields redeclared in a committed non-base target; and the `release` target's fail-closed reference, exact registry exporter, cache policy, and BuildKit provenance/SBOM settings. It requires contract-derived setup and identity inputs in both Python CI builder jobs, ordered as setup, identity assertion, then build. Each named identity step must contain only its environment and multiline run body, start with the exact `set -euo pipefail` preamble, contain no later `set +...`, omit step-level `continue-on-error`, and end with the identity checker as its final unwrapped command. For the active Python CI-rootfs preflight it locks the pull-request selector, requires push and dispatch jobs to run independently of that selector, exercises both event directions against repository history, and requires the contract step to consume the rootfs exported from the loaded `ci` image after that rootfs exists. It exact-checks the revision, source, version, and created label bindings. For the pull-request-only Python release preflight it locks the trigger, permissions and action inputs; the loopback registry image, complete container argv, inspected publication, Docker version floor, and host-networked BuildKit node; the immutable `RELEASE_REF`, exact Bake invocations and resolved exporter objects; registry index platform resolution; and the independent registry-served and same-commit `ci` rootfs checks. Host networking is confined to this preflight builder and is not a security boundary. The `release` target is registry-export capable, but this checked caller's registry export and tag are confined to its loopback-bound ephemeral registry; it has no project publication, registry credential, OIDC or signing path. Each committed Python workflow is bound to an expected SHA-256 and byte length. These workflow-text checks are defence-in-depth against accidental regression. Static analysis of a free-form `run:` block cannot detect every status-swallowing construct; function shadowing (`python3() { return 0; }`), an `ERR` trap (`trap 'exit 0' ERR`), and job-level shell wrappers are known examples that pass these checks. A committer able to insert such a construct could instead change `tools/verify.py` or remove the identity step, so the controls for a hostile tracked-file edit are code review, CODEOWNERS, and required status checks. Outside the specifically checked invocations, the verifier does not interpret arbitrary Bake command-line overrides or discover and count build callers. It also checks the two non-automerge Python builder Renovate managers, deny-all ignore allowlists, documentation markers, Diataxis layout, ADR inventory, lint setup, helper self-tests, attribution-residue denial, and internal-process-residue denial limited to `README.md`, `docs/**/*.md`, and `images/**/*.md` in the current checkout. Its Python build-input self-test exercises seven fail-closed classes through 67 negative cases. The workflow-only `--check-python-builder-identity` mode compares the Buildx version, commit, installed plugin SHA-256, BuildKit container image, and BuildKit node version supplied by the setup step. A mismatch in any observation returns failure; under the current workflow configuration, that fails the CI job before the build. |
| `tools/run-test-gates.sh` | Local orchestration for the image gate set: build, hardening, FIPS, footprint, STIG, SBOM, fixable MEDIUM+ scanners, OpenVEX, rootfs secret scan, NIST SP 800-190 predicate validation, SLSA builder assertion, and Rekor assertion helpers. |
| `tools/assert-reproducible.py` | Builds the same runtime twice for a platform, exports both rootfs tar streams, reports canonical rootfs and rpmdb digests, fails on any byte, metadata, ownership, type, mtime, or presence difference when `--assert-byte-identical` is set, and fails when `--expect-from-contract` values from `contracts/image-manifest.json` do not match. |
| `images/python/tools/assert-reproducible.py` | Builds the Python runtime twice through the `repro` target in `images/python/docker-bake.json`, using one immutable Bake invocation descriptor per side for both `bake --print` and execution. It compares exported rootfs trees and fails when byte identity or the architecture-specific rootfs and rpmdb values in `images/python/contracts/image-manifest.json` do not match. Its single-rootfs mode checks both the effective rootfs exported from the loaded `ci` image in the build job and each registry-served `release` child in the pull-request release preflight. The same preflight uses its two-rootfs mode to compare each served child with a same-commit `ci` rootfs. Builder installation and live identity observations are owned by the workflows, not this helper. |
| `tools/assert-footprint.py` | Exports the runtime rootfs and fails when regular-file bytes exceed the configured H2 limit. |
| `tools/assert-no-phantom-packages.py` | Compares rpmdb-declared payloads with the exported rootfs so stripped files cannot leave scanner-visible packages with missing shippable payload. |
| `tools/assert-rpm-lock-hashes.py` | Confirms installed RPMs match the lockfile `%{SHA256HEADER}` and `%{SIGMD5}` values after local RPM installation. |
| `tools/generate-rpm-lock.sh` | Regenerates per-architecture runtime lockfiles with exact NEVRA, direct-CDN URL, whole-RPM SHA-256, `%{SHA256HEADER}`, and `%{SIGMD5}` records; `--check` fails on drift. |
| `tools/fetch-runtime-rpms.sh` | Fetches locked runtime RPMs from pinned Red Hat UBI CDN URLs, verifies whole-RPM SHA-256 values, and verifies Red Hat RPM signatures before installation. |
| `tools/assert-sbom-rpms.py` | Confirms Syft rpmdb-derived SBOM output enumerates required runtime RPMs before SPDX and CycloneDX evidence is attested. |
| `tools/assert-scanner-db-freshness.py` | Parses Grype DB status and Trivy DB metadata, then fails if either scanner database is missing, malformed, stale, expired, or below the required Grype schema floor. |
| `tools/assert-scanner-canary.py` | Parses independent Grype and Trivy reports for a committed vulnerable SBOM and fails unless both databases and matchers detect the expected Log4Shell record; this probes content validity, not image cataloging. |
| `tools/assert-ignore-scope.py` | Rejects missing, malformed, widened, version-unpinned, or expired fixable-CVE ignores and requires Grype gate evidence to contain exactly the two approved runtime suppressions. |
| `images/python/tools/assert-raw-scanners-no-sqlite.py` | Requires `--trivy-json`, `--grype-json`, `--contract`, and `--arch` for normal execution. It rejects `sqlite-libs` or any of the five SQLite CVEs on either scanner surface. Trivy's `--list-all-pkgs` inventory must contain the policy-selected `python3.12-libs` package at the exact epoch, version, release, and RPM architecture derived from `runtime.shipped[arch]`. Grype must have valid identity, Red Hat distro, source shape, and per-match schema, but `matches: []` is a legal clean result. Malformed marker identities and whitespace-bearing package names fail before the absence decision. |
| `tools/assert-vex.py` | Binds the Trivy and Grype product, image, architecture, distro, and repository-digest evidence, then fails unless every unfixed HIGH or CRITICAL scanner finding has a matching reviewed OpenVEX statement under the image's CODEOWNERS-gated VEX directory. The only gate-clearing `affected` cases are the exact, expiring TD-9 disposition for CVE-2026-11940 on `python3.12` and `python3.12-libs` at `3.12.13-3.el9_8.1`, and TD-12 for CVE-2026-14456 on `openssl-libs` at `1:3.5.5-5.el9_8` in Python and micro, both through `review-by 2026-10-01`. The closed two-entry model has three statement surfaces. Local products require two keys: the exact in-tool disposition surface and its byte-canonical statement. Published children require three: those keys plus paired `--index-reference` and `--index-manifest` evidence under the surface's pinned Python or micro repository. The tool requires exactly one candidate surface, verifies the index byte digest, requires one child for each supported platform with distinct child digests, locks the BuildKit attestation platform and annotations, requires descriptor-digest uniqueness, and enforces child/attestation disjointness. It does not constrain attestation count or per-child reference cardinality and does not close the descriptor top-level or runnable-platform key sets. Valid fix evidence and byte-noncanonical scanner identities refuse authorization; malformed fix metadata does not establish a fix, so the finding remains on the default-deny path. |
| `tools/resolve-python-index.py` | Enforces the publish-side closed descriptor matrix: exactly one runnable `linux/amd64` child, one runnable `linux/arm64` child, and exactly one BuildKit attestation descriptor referring to each child. Runnable descriptors must contain exactly `digest`, `mediaType`, `platform`, and `size`; attestation descriptors must contain exactly those keys plus `annotations`; both platform objects must contain exactly `architecture` and `os`. It rejects additional `urls`, `data`, and `artifactType` fields on both descriptor kinds and invented keys on every inspected object. It corroborates the push-reported digest against the exact registry readback bytes, locks the same index digest into signing, attestation, VEX, and alias consumers, and verifies checksummed cross-job artifacts before use. Its agreement self-test records all three intentional differences from `tools/assert-vex.py`: top-level key-set closure, runnable-platform key-set closure, and attestation cardinality. |
| `tools/decide-python-publish-scope.py` | Decides Python publication independently of the micro policy. A `python/v*` release tag always publishes. On `main`, every `images/python/**` path and every enumerated shared publisher input publishes; an unavailable prior revision, empty delta, unclassified path, or malformed published config also publishes fail-closed. Only a delta entirely within the closed unrelated allowlist skips. |
| `tools/assert-python-alias-policy.py` | Derives the exact main or release alias set, requires create-once aliases to be absent or already point to the candidate index before evidence and immediately before apply, and requires all aliases to resolve to that digest afterward. These checks detect collisions but are not atomic against an external package writer. |
| `tools/python-trust-contract.py` | Generates and validates the exact index-only in-toto trust-contract statement. It binds the `ghcr.io/nwarila/ubi9-base-python` package and index digest to the `images/python/` Git tree, publishing workflow, and commit with no extra fields or subjects. |
| `tools/assert-python-attestation.py` | Semantically validates successfully Cosign-verified DSSE records. It requires one exact subject and predicate type, a signature, and either the expected predicate set, the exact trust-contract statement, or the explicitly selected envelope-only policy. |
| `tools/assert-python-provenance.py` | Consumes only successful, pinned `slsa-verifier --print-provenance` output and binds its sole index subject, builder, source repository, SHA, ref, material, and `configSource.entryPoint` to the Python publisher. |
| `tools/assert-python-slsa-certificate.py` | Binds the registry SLSA envelope to the authenticated Cosign record and requires exactly one Fulcio Build Signer Digest, source SHA/ref, and Build Config URI/Digest extension. The values must name the pinned generator commit, publishing SHA/ref, and Python caller workflow. |
| `tools/assert-no-rootfs-secrets.py` | Scans the exported runtime rootfs for high-confidence clear-text credential patterns before NIST SP 800-190 evidence can be generated. |
| `tools/generate-nist-800-190-predicate.py` | Generates and validates the NIST SP 800-190 section 4.1 image-control predicate. |
| `tools/assert-cosign-rekor.py` | Checks Cosign signature verification JSON for Rekor bundle fields and self-tests DSSE attestation-envelope parsing. |
| `tools/assert-slsa-builder-id.py` | Parses SLSA provenance and fails unless `builderID` equals the exact trusted generator identity. |
| `tools/assert-stig-tailoring.py` | Derives the full RHEL9 STIG control set from pinned ComplianceAsCode content and fails unless every omitted control is justified. |
| `tools/assert-rootfs-identity.py` | Checks the exported runtime rootfs for UID 0 uniqueness and unknown file UID/GID ownership. |
| `tools/assert-stig-arf.py` | Fails closed on ARF parse errors, `error`/`unknown` rule results, threshold failures, or selected must-verify rules returning `notapplicable` without deterministic equivalent evidence. |
| `tools/generate-stig-arf-predicate.py` | Converts the tailored STIG ARF summary into the signed predicate payload used by publish. |
| `tools/summarize-gates.py` | Converts hardening and reproducibility reports into decision envelopes for the pull-request comment and nightly drift issue. Its Trivy and Grype fixability classification matches `tools/assert-vex.py`: malformed fix metadata grants no fix and remains on the unfixed OpenVEX path. Malformed report inputs produce an incomplete, attention-bearing envelope instead of a new enforcement path. |
| `tools/install-syft.sh` | Installs the pinned Syft binary used for rpmdb-derived SBOM generation. |
| `tools/install-trivy.sh` | Installs the pinned Trivy binary used for the fixable-vulnerability gate. |
| `tools/install-grype.sh` | Installs the pinned Grype binary used as the second fixable-vulnerability scanner. |
| `tools/install-openscap.sh` | Installs the pinned OpenSCAP tooling used by the tailored STIG ARF gate. |
| `tools/build-stig-datastream.sh` | Builds the pinned ComplianceAsCode RHEL9 datastream used for image-scoped STIG scanning. |
| `tools/run-stig-arf.sh` | Runs OpenSCAP with the committed tailoring and emits ARF plus summary evidence. |

The enforcing local gates are intentionally fail-closed: a helper failure,
parse failure, missing input, or unhandled evidence shape is treated as a
failing gate rather than a skipped or advisory result. Decision-envelope
generation is reporting, not enforcement; an incomplete envelope carries an
attention reason while the upstream gate result remains authoritative.

The Python production caller and its registry-origin binding are implemented,
but their privileged jobs do not execute on pull requests. The 2026-08-17
production attempt failed in `registry-served gates and evidence` while
`Install publication gate tools` tried to install Syft without Cosign available.
That prerequisite is now repaired and lock-enforced; production proof remains
pending the next `main` push. The package exists publicly and serves only
unaliased, unsigned candidate digests. Its two BuildKit `mode=max` provenance
attestation manifests exist; no production gate evidence, Cosign signature or
attestation, SLSA-generator provenance, Rekor record, or consumer alias exists.
The binding described above is to the index that a run pushed and read back; it
does not close the external-writer alias race.

The internal-process-residue check reads only the three Markdown path sets named
above. Other paths are outside this check.

The fixable scanner gate rejects MEDIUM, HIGH, and CRITICAL findings. TD-6
temporarily excuses only `CVE-2026-31790` on the two held FIPS provider packages
at `3.0.7-8.el9`, with a review date of 2026-10-10. The scanner report pass is
unfiltered and the separate unfixed OpenVEX default-deny scope remains HIGH and
CRITICAL. On the current image, the threshold catches two findings and TD-6
excuses the same two, so the immediate enforcement delta is zero; the
forward-looking change blocks any other fixable Medium.

TD-9 and TD-12 are separate from the TD-6 fixable-CVE exception. TD-9 accepts
and tracks known-affected `CVE-2026-11940` with the complete `python3.12` and
`python3.12-libs` set at `3.12.13-3.el9_8.1`. TD-12 accepts and tracks
known-affected `CVE-2026-14456` on `openssl-libs` at
`1:3.5.5-5.el9_8` in both images. Neither suppresses scanner input.

The model contains two entries and three exact surfaces: TD-9 Python, TD-12
Python, and TD-12 micro. Local Python CI products and the locally loaded micro
tag require the two-key conjunction of their exact entry and surface statement.
A published child additionally requires repository-correct, digest-verified OCI
index evidence, making that path three-key. Surface selection must be unique;
authority from one CVE, statement, product, repository, or policy IRI cannot
satisfy another.

The index digest itself is never eligible, a BuildKit attestation-descriptor
digest is rejected as a product, and a child for the other scanner-reported
architecture is not eligible. The separate child/attestation
digest-disjointness guard rejects an alias before child-product eligibility is
decided. The Python caller reads the index once by the push-reported digest,
corroborates and checksum-protects those bytes, and carries the same digest to
every consumer. The micro caller passes its pushed digest and existing
registry-read `dist/image-index.json` bytes to both child calls in the same job.
Production proof of the new TD-12 published-child paths remains pending the
merge-triggered runs.

`assert-vex.py` remains weaker on descriptor top-level closure, runnable-platform
key-set closure, attestation count, and duplicate references. The Python
publish-side resolver rejects those measured shapes before its VEX gate. The
micro caller uses the VEX-side policy directly, as tracked in TD-11. Raw scanner
identities must be byte-canonical, valid fix evidence refuses authorization, and
both repository entries expire after 2026-10-01 even if their findings become
dormant. Every other unfixed HIGH or CRITICAL finding remains default-denied.

Repository verification reports 3 canonical byte documents, the exact
2-entry/3-surface model, 18 document mutations, 50 disposition documentation
prose mutations across 6 files, and 2/2 dormant expiries locked. It exact-locks
the published-child source through seven literal constants and nine current
function ASTs. Its four
accept-and-track verifier mutations and four corresponding checker mutations
are also required to fail. These counts describe repository self-tests, not
production executions.
