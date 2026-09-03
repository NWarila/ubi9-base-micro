# Local Gate Reference

This page summarizes what each repository helper enforces. The source of truth
for implementation details remains the helper itself and the workflow that calls
it.

| Path | Enforces |
| --- | --- |
| `tools/verify.py` | Repository contract checks include required files, action pins, exact workflow permissions and evidence ordering, Python build/publish semantic guards with whole-file SHA-256 and byte-length fallbacks, native TD-6 scope, SQLite and libuuid absence-proof wiring, signing, provenance, SBOM, NIST/STIG, secret gates, scanner freshness/canaries, and retained Python OpenVEX documents. Static workflow checks are defence-in-depth against accidental regression, not exhaustive interpretation of arbitrary shell or Bake overrides. |
| `tools/run-test-gates.sh` | Local orchestration for build, hardening, FIPS, footprint, STIG, SBOM, native fixable MEDIUM+ scanner gates, rootfs secret scanning, and NIST SP 800-190 predicate validation. |
| `tools/assert-reproducible.py` | Builds the same runtime twice for a platform, exports both rootfs tar streams, reports canonical rootfs and rpmdb digests, fails on any byte, metadata, ownership, type, mtime, or presence difference when `--assert-byte-identical` is set, and fails when `--expect-from-contract` values from `contracts/image-manifest.json` do not match. |
| `images/python/tools/assert-reproducible.py` | Builds the Python runtime twice through the `repro` target in `images/python/docker-bake.json`, using one immutable Bake invocation descriptor per side for both `bake --print` and execution. It compares exported rootfs trees and fails when byte identity or the architecture-specific rootfs and rpmdb values in `images/python/contracts/image-manifest.json` do not match. Its single-rootfs mode checks both the effective rootfs exported from the loaded `ci` image in the build job and each registry-served `release` child in the pull-request release preflight. The same preflight uses its two-rootfs mode to compare each served child with a same-commit `ci` rootfs. Builder installation and live identity observations are owned by the workflows, not this helper. |
| `tools/assert-footprint.py` | Exports the runtime rootfs and fails when regular-file bytes exceed the configured H2 limit. |
| `tools/assert-no-phantom-packages.py` | Compares rpmdb-declared payloads with the exported rootfs so stripped files cannot leave scanner-visible packages with missing shippable payload. |
| `tools/assert-rpm-lock-hashes.py` | Confirms installed RPMs match the lockfile `%{SHA256HEADER}` and `%{SIGMD5}` values after local RPM installation. |
| `tools/generate-rpm-lock.sh` | Regenerates each runtime lock and its one-row FIPS-verification companion atomically with exact NEVRA, direct-CDN URL, whole-RPM SHA-256, `%{SHA256HEADER}`, and `%{SIGMD5}` records; the CLI identity is derived from the unique `openssl-libs` row and `--check` fails on drift in either file. |
| `tools/fetch-runtime-rpms.sh` | Fetches locked runtime RPMs from pinned Red Hat UBI CDN URLs, verifies whole-RPM SHA-256 values, and verifies Red Hat RPM signatures before installation. |
| `tools/assert-sbom-rpms.py` | Confirms Syft rpmdb-derived SBOM output enumerates required runtime RPMs before SPDX and CycloneDX evidence is attested. |
| `tools/assert-scanner-db-freshness.py` | Parses Grype DB status and Trivy DB metadata, then fails if either scanner database is missing, malformed, stale, expired, or below the required Grype schema floor. |
| `tools/assert-scanner-canary.py` | Parses independent Grype and Trivy reports for a committed vulnerable SBOM and fails unless both databases and matchers detect the expected Log4Shell record; this probes content validity, not image cataloging. |
| `images/python/tools/assert-raw-scanners-no-sqlite.py` | Requires `--trivy-json`, `--grype-json`, `--contract`, and `--arch` for normal execution. It rejects `sqlite-libs` or any of the five SQLite CVEs on either scanner surface. Trivy's `--list-all-pkgs` inventory must contain the policy-selected `python3.12-libs` package at the exact epoch, version, release, and RPM architecture derived from `runtime.shipped[arch]`. Grype must have valid identity, Red Hat distro, source shape, and per-match schema, but `matches: []` is a legal clean result. Malformed marker identities and whitespace-bearing package names fail before the absence decision. |
| `tools/resolve-python-index.py` | Enforces the publish-side closed descriptor matrix: exactly one runnable `linux/amd64` child, one runnable `linux/arm64` child, and one BuildKit attestation descriptor referring to each child. It closes descriptor and platform key sets, corroborates the push-reported digest against exact registry bytes, binds that digest to signing, attestation, and alias consumers, and verifies checksummed cross-job artifacts. |
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
| `tools/summarize-gates.py` | Converts hardening and reproducibility reports into decision envelopes. Malformed report inputs produce an incomplete, attention-bearing envelope instead of a new enforcement path. |
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
but their privileged jobs do not execute on pull requests. Current and
historical production evidence is in the
[canonical publication evidence contract](verification-contract.md#image-family-publication-evidence-contract).
The binding described above is to the index that a run pushed and read back; it
does not close the external-writer alias race.

The internal-process-residue check reads only the three Markdown path sets named
above. Other paths are outside this check.

The fixable scanner gate rejects MEDIUM, HIGH, and CRITICAL findings. TD-6 excuses only `CVE-2026-31790` on the two held FIPS provider packages at exactly `3.0.7-8.el9`; both native scanner files pin the scope and `tools/verify.py` exact-checks it. Unfixed vendor findings are report-only. Complete Trivy and Grype JSON and SARIF evidence is sealed and retained by both publication workflows, while scanner, database freshness, and canary failures remain fatal.

The Python SQLite and libuuid OpenVEX documents are absence evidence, not scanner authorizations. Their independent build, runtime, SBOM, raw-scanner, and phantom-package gates remain blocking, and the production publisher still requires, attests, verifies, and Rekor-checks the non-empty document set.
