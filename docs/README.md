# Documentation

Documentation for this repository follows the Diataxis framework.

| Quadrant | Path | Purpose |
| --- | --- | --- |
| Tutorials | [`tutorials/`](tutorials/) | Learning-oriented walkthroughs for building and verifying `base-micro` locally |
| How-to | [`how-to/`](how-to/) | Task guides for verification, reproduction, RPM-lock refreshes, local gates, and downstream consumption |
| Reference | [`reference/`](reference/) | Published verification contract, gate inventory, and contract summary |
| Explanation | [`explanation/`](explanation/) | Reproducibility, footprint, and FIPS mechanism rationale |
| Compliance | [`compliance/`](compliance/) | Acceptance, FIPS, NIST SP 800-190, STIG, and OpenVEX evidence notes |
| Decisions | [`decision-records/`](decision-records/) | Repository-scope ADRs for the image contract, evidence model, workflow host determinism, and base-family topology |

## Tutorials

- [`getting-started-build-and-verify.md`](tutorials/getting-started-build-and-verify.md) - build the local runtime and run the repository verifier.

## How-to

- [`verify-a-published-image.md`](how-to/verify-a-published-image.md) - verify signatures, attestations, SBOMs, and provenance for a published digest.
- [`reproduce-a-build-byte-for-byte.md`](how-to/reproduce-a-build-byte-for-byte.md) - run the rootfs reproducibility gate locally.
- [`refresh-the-rpm-lock.md`](how-to/refresh-the-rpm-lock.md) - regenerate locked direct-CDN RPM inputs for controlled CVE absorption.
- [`run-a-gate-locally.md`](how-to/run-a-gate-locally.md) - choose and run the local verifier, hardening gate, or full gate harness.
- [`consume-base-micro-as-from-base.md`](how-to/consume-base-micro-as-from-base.md) - consume a published digest as a downstream `FROM` base.

## Reference

- [`verify.md`](reference/verify.md) - published digest verification contract.
- [`gates.md`](reference/gates.md) - what each local assertion and generation helper enforces.
- [`verification-contract.md`](reference/verification-contract.md) - summary of PR, publish, and post-publish verification boundaries.

## Explanation

- [`reproducibility.md`](explanation/reproducibility.md) - F3 byte-for-byte harness, deterministic epoch, direct-CDN runtime RPM sourcing, rpmdb determinism, refresh loop, and build-failing hard gate.
- [`footprint.md`](explanation/footprint.md) - runtime footprint measurement contract, STEP024 H2 rationale, and current amd64 evidence.
- [`fips-mechanism.md`](explanation/fips-mechanism.md) - config-only approved-mode mechanism and per-architecture #4857 scope.

## Compliance

- [`README.md`](compliance/README.md) - compliance documentation index.
- [`acceptance.md`](compliance/acceptance.md) - copied base-image Definition of Done with this repository's namespace note and current FIPS mechanism corrections.
- [`fips.md`](compliance/fips.md) - OpenSSL FIPS-provider ledger, family CMVP context, out-of-scope certificates, approved-mode mechanism, per-architecture validation scope, and non-FIPS-host scope.
- [`nist-800-190.md`](compliance/nist-800-190.md) - section 4.1 image-control predicate URI, control mapping, and not-CIS-Docker scope.
- [`stig.md`](compliance/stig.md) - image-scoped RHEL9 STIG tailoring, mass-N/A guard, ARF predicate type, and scan scope.
- [`vex.md`](compliance/vex.md) - CODEOWNERS-gated VEX authoring flow for the default-deny unfixed HIGH/CRITICAL gate.

## Maintenance Ledgers

- [`TECH-DEBT.md`](TECH-DEBT.md) - tracked repository debt for provider z-stream availability and future revalidation decisions.
