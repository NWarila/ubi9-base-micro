# Documentation

This repository keeps the current acceptance contract and phase-specific notes
close to the image scaffold.

| Area | Path | Purpose |
| --- | --- | --- |
| Acceptance | [`acceptance.md`](acceptance.md) | Copied base-image Definition of Done with this repository's namespace note |
| FIPS | [`fips.md`](fips.md) | OpenSSL #4857 FIPS-provider ledger, family CMVP context, out-of-scope certificates, approved-mode mechanism, per-architecture validation scope, and non-FIPS-host scope |
| Footprint | [`footprint.md`](footprint.md) | Runtime footprint measurement contract, STEP024 H2 rationale, and current amd64 evidence |
| Reproducibility | [`reproducibility.md`](reproducibility.md) | F3 byte-for-byte harness, deterministic epoch, RPM lockfiles, refresh loop, and build-failing hard gate |
| OpenVEX | [`vex.md`](vex.md) | CODEOWNERS-gated VEX authoring flow for the default-deny unfixed HIGH/CRITICAL gate |
| NIST 800-190 | [`nist-800-190.md`](nist-800-190.md) | Section 4.1 image-control predicate URI, control mapping, and not-CIS-Docker scope |
| Tailored STIG | [`stig.md`](stig.md) | Image-scoped RHEL9 STIG tailoring, mass-N/A guard, ARF predicate type, and scan scope |
| Verify | [`reference/verify.md`](reference/verify.md) | Published digest signature, SBOM, OpenVEX, NIST 800-190, STIG ARF, SLSA L3 provenance, and Rekor verification contract |
| Decisions | [`decision-records/`](decision-records/) | Repository-scope ADRs for the image contract, evidence model, and base-family topology |
