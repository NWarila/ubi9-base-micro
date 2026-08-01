# Local Gate Reference

This page summarizes what each repository helper enforces. The source of truth
for implementation details remains the helper itself and the workflow that calls
it.

| Path | Enforces |
| --- | --- |
| `tools/verify.py` | Repository contract checks: a duplicate-free required-file manifest; pinned workflow inputs; the exact `base`/`ci`/`repro` Python Bake shape; an exact CI shell-command token allowlist and an AST-locked double-build descriptor for the two declared consumers; rejection of non-static or undeclared CI `--set` fields, builder selection, push/load/output options, and other CI command tokens; and the exact two-consumer invariant. Direct-build discovery examines tracked files other than `tools/verify.py`, parses shell command segments and Python literal list or tuple commands, and rejects a Buildx build whose literal tokens statically select the Python Dockerfile or context. The verifier also checks the two non-automerge Python builder Renovate managers, deny-all ignore allowlists, documentation markers, Diataxis layout, ADR inventory, lint setup, helper self-tests, attribution-residue denial, and internal-process-residue denial limited to `README.md`, `docs/**/*.md`, and `images/**/*.md` in the current checkout. Its Python build-input self-test exercises eight fail-closed classes through 19 negative cases. The workflow-only `--check-python-builder-identity` mode compares the Buildx version, commit, installed plugin SHA-256, BuildKit container image, and BuildKit node version supplied by the setup step. |
| `tools/run-test-gates.sh` | Local orchestration for the image gate set: build, hardening, FIPS, footprint, STIG, SBOM, fixable MEDIUM+ scanners, OpenVEX, rootfs secret scan, NIST SP 800-190 predicate validation, SLSA builder assertion, and Rekor assertion helpers. |
| `tools/assert-reproducible.py` | Builds the same runtime twice for a platform, exports both rootfs tar streams, reports canonical rootfs and rpmdb digests, fails on any byte, metadata, ownership, type, mtime, or presence difference when `--assert-byte-identical` is set, and fails when `--expect-from-contract` values from `contracts/image-manifest.json` do not match. |
| `images/python/tools/assert-reproducible.py` | Builds the unpublished Python runtime twice through the `repro` target in `images/python/docker-bake.json`, using one immutable Bake invocation descriptor per side for both `bake --print` and execution. It compares exported rootfs trees and fails when byte identity or the architecture-specific rootfs and rpmdb values in `images/python/contracts/image-manifest.json` do not match. Builder installation and the five live identity observations are owned by `.github/workflows/python-ci.yaml`, not this helper. |
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
| `tools/assert-vex.py` | Binds the Trivy and Grype product, image, architecture, distro, and repository-digest evidence, then fails unless every unfixed HIGH or CRITICAL scanner finding has a matching reviewed OpenVEX statement under the CODEOWNERS-gated `vex/` path. Malformed fix metadata does not establish a fix, so the finding remains on the default-deny path. |
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

The internal-process-residue check reads only the three Markdown path sets named
above. Other paths are outside this check.

The fixable scanner gate rejects MEDIUM, HIGH, and CRITICAL findings. TD-6
temporarily excuses only `CVE-2026-31790` on the two held FIPS provider packages
at `3.0.7-8.el9`, with a review date of 2026-10-10. The scanner report pass is
unfiltered and the separate unfixed OpenVEX default-deny scope remains HIGH and
CRITICAL. On the current image, the threshold catches two findings and TD-6
excuses the same two, so the immediate enforcement delta is zero; the
forward-looking change blocks any other fixable Medium.
