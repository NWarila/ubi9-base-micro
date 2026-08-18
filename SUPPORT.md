# Support

## Where to get help

| Need | Use |
| --- | --- |
| Bug in the source, docs, local gates, or release-verification instructions | [Bug report](https://github.com/NWarila/ubi9-base-micro/issues/new?template=bug_report.yml) |
| Feature or repository-contract change | [Feature request](https://github.com/NWarila/ubi9-base-micro/issues/new?template=feature_request.yml) |
| General question | [Issues](https://github.com/NWarila/ubi9-base-micro/issues) |
| Vulnerability | [Security policy](SECURITY.md) |

GitHub Discussions are not enabled for this repository. Use issues for public
support unless the question is security-sensitive.

## Supported topics

- Building and testing the `base-micro` and `base-micro-dev` images from this
  repository.
- Running `make build`, `make test`, `make verify`, `make clean`,
  `tools/run-test-gates.sh`, and the byte-for-byte reproducibility harness.
- Understanding published digest verification through
  `docs/reference/verify.md`.
- Repository documentation, decision records, and health files.

## Not supported here

- Vulnerability reports filed publicly.
- Support for `base-python` before its first successful publication completes with its required
  evidence. The current public package serves only unaliased, unsigned candidate
  digests from the failed 2026-08-17 production attempt. Its two BuildKit
  `mode=max` provenance attestation manifests exist, but no production gate
  evidence, Cosign signature or attestation, SLSA-generator provenance, Rekor
  record, or consumer alias exists. The missing Cosign prerequisite is repaired
  and lock-enforced; production proof remains pending the next `main` push.
  `base-node` and `base-java` remain planned.
- Third-party dependency vulnerabilities that need to be reported upstream.
- Private consulting or production operations outside this repository.

Responses may take time. Include commands, outputs, commit SHAs, image digests,
and environment details where they help reproduce the issue.
