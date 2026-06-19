# OpenVEX Gate

The C4 vulnerability policy uses two scanners. Trivy and Grype both fail the build on fixable HIGH or CRITICAL findings. A separate default-deny pass records unfixed HIGH and CRITICAL findings from both scanners and requires each one to have a reviewed OpenVEX JSON statement under `vex/`.

The `vex/` path is CODEOWNERS-gated. Use `not_affected` only when the stronger posture is inapplicable and the statement carries a standard OpenVEX justification; use `fixed` only when the published image reference is actually fixed. Publish runs attach every JSON document in `vex/` to each per-architecture image digest with `cosign attest --type openvex`.
