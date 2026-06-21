## Summary

<!-- What changed, and why? -->

## Scope

<!-- Note whether this changes docs only, repository health files, image inputs, gates, release evidence, or workflows. -->

## Verification

<!-- Paste exact commands and results. Use "not run" only with a reason. -->

## Checklist

- [ ] Commits are signed.
- [ ] `python tools/verify.py` passes.
- [ ] New tracked files are allowlisted in the deny-all `.gitignore`.
- [ ] Documentation and repo ADRs are updated when behavior, gates, evidence, or policy changed.
- [ ] No workflow permission, secret, or publish-path change is included without explicit review.
- [ ] No image-affecting change is included without a fresh amd64 and arm64 byte-for-byte reproducibility proof.
- [ ] For image, gate, RPM lock, or release-evidence changes, `bash tools/run-test-gates.sh` passes for the affected platform.
- [ ] For image or release-evidence changes, FIPS, STIG, footprint, SBOM, VEX, Trivy, Grype, NIST SP 800-190, SLSA, and Rekor evidence remain covered by the documented gates.
- [ ] `docs/reference/verify.md` still matches the published digest verification contract.

