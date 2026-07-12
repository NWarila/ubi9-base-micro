# Local Gate Reference

This page summarizes what each repository helper enforces. The source of truth
for implementation details remains the helper itself and the workflow that calls
it.

| Path | Enforces |
| --- | --- |
| `tools/verify.py` | Repository contract checks: required files, pinned workflow inputs, deny-all ignore allowlists, documentation markers, Diataxis layout, ADR inventory, lint setup, helper self-tests, and attribution-residue denial. |
| `tools/run-test-gates.sh` | Local orchestration for the image gate set: build, hardening, FIPS, footprint, STIG, SBOM, fixable MEDIUM+ scanners, OpenVEX, rootfs secret scan, NIST SP 800-190 predicate validation, SLSA builder assertion, and Rekor assertion helpers. |
| `tools/assert-reproducible.py` | Builds the same runtime twice for a platform, exports both rootfs tar streams, reports canonical rootfs and rpmdb digests, fails on any byte, metadata, ownership, type, mtime, or presence difference when `--assert-byte-identical` is set, and fails when `--expect-from-contract` values from `contracts/image-manifest.json` do not match. |
| `tools/assert-footprint.py` | Exports the runtime rootfs and fails when regular-file bytes exceed the configured H2 limit. |
| `tools/assert-no-phantom-packages.py` | Compares rpmdb-declared payloads with the exported rootfs so stripped files cannot leave scanner-visible packages with missing shippable payload. |
| `tools/assert-rpm-lock-hashes.py` | Confirms installed RPMs match the lockfile `%{SHA256HEADER}` and `%{SIGMD5}` values after local RPM installation. |
| `tools/generate-rpm-lock.sh` | Regenerates per-architecture runtime lockfiles with exact NEVRA, direct-CDN URL, whole-RPM SHA-256, `%{SHA256HEADER}`, and `%{SIGMD5}` records; `--check` fails on drift. |
| `tools/fetch-runtime-rpms.sh` | Fetches locked runtime RPMs from pinned Red Hat UBI CDN URLs, verifies whole-RPM SHA-256 values, and verifies Red Hat RPM signatures before installation. |
| `tools/assert-sbom-rpms.py` | Confirms Syft rpmdb-derived SBOM output enumerates required runtime RPMs before SPDX and CycloneDX evidence is attested. |
| `tools/assert-scanner-db-freshness.py` | Parses Grype DB status and Trivy DB metadata, then fails if either scanner database is missing, malformed, stale, expired, or below the required Grype schema floor. |
| `tools/assert-scanner-canary.py` | Parses independent Grype and Trivy reports for a committed vulnerable SBOM and fails unless both databases and matchers detect the expected Log4Shell record; this probes content validity, not image cataloging. |
| `tools/assert-ignore-scope.py` | Rejects missing, malformed, widened, version-unpinned, or expired fixable-CVE ignores and requires Grype gate evidence to contain exactly the two approved runtime suppressions. |
| `tools/assert-vex.py` | Fails unless every unfixed HIGH or CRITICAL scanner finding has a matching reviewed OpenVEX statement under the CODEOWNERS-gated `vex/` path. |
| `tools/assert-no-rootfs-secrets.py` | Scans the exported runtime rootfs for high-confidence clear-text credential patterns before NIST SP 800-190 evidence can be generated. |
| `tools/generate-nist-800-190-predicate.py` | Generates and validates the NIST SP 800-190 section 4.1 image-control predicate. |
| `tools/assert-cosign-rekor.py` | Checks Cosign signature verification JSON for Rekor bundle fields and self-tests DSSE attestation-envelope parsing. |
| `tools/assert-slsa-builder-id.py` | Parses SLSA provenance and fails unless `builderID` equals the exact trusted generator identity. |
| `tools/assert-stig-tailoring.py` | Derives the full RHEL9 STIG control set from pinned ComplianceAsCode content and fails unless every omitted control is justified. |
| `tools/assert-rootfs-identity.py` | Checks the exported runtime rootfs for UID 0 uniqueness and unknown file UID/GID ownership. |
| `tools/assert-stig-arf.py` | Fails closed on ARF parse errors, `error`/`unknown` rule results, threshold failures, or selected must-verify rules returning `notapplicable` without deterministic equivalent evidence. |
| `tools/generate-stig-arf-predicate.py` | Converts the tailored STIG ARF summary into the signed predicate payload used by publish. |
| `tools/install-syft.sh` | Installs the pinned Syft binary used for rpmdb-derived SBOM generation. |
| `tools/install-trivy.sh` | Installs the pinned Trivy binary used for the fixable-vulnerability gate. |
| `tools/install-grype.sh` | Installs the pinned Grype binary used as the second fixable-vulnerability scanner. |
| `tools/install-openscap.sh` | Installs the pinned OpenSCAP tooling used by the tailored STIG ARF gate. |
| `tools/build-stig-datastream.sh` | Builds the pinned ComplianceAsCode RHEL9 datastream used for image-scoped STIG scanning. |
| `tools/run-stig-arf.sh` | Runs OpenSCAP with the committed tailoring and emits ARF plus summary evidence. |

The local gates are intentionally fail-closed: a helper failure, parse failure,
missing input, or unhandled evidence shape is treated as a failing gate rather
than a skipped or advisory result.

The fixable scanner gate rejects MEDIUM, HIGH, and CRITICAL findings. TD-6
temporarily excuses only `CVE-2026-31790` on the two held FIPS provider packages
at `3.0.7-8.el9`, with a review date of 2026-10-10. The scanner report pass is
unfiltered and the separate unfixed OpenVEX default-deny scope remains HIGH and
CRITICAL. On the current image, the threshold catches two findings and TD-6
excuses the same two, so the immediate enforcement delta is zero; the
forward-looking change blocks any other fixable Medium.
