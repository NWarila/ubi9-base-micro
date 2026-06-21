# Security Policy

## Reporting a vulnerability

Do not file public issues for vulnerabilities.

Use GitHub private vulnerability reporting from this repository's Security tab:

<https://github.com/NWarila/ubi9-base-micro/security/advisories/new>

If private reporting is unavailable, contact the maintainer through GitHub:

<https://github.com/NWarila>

Include:

- Affected commit, branch, tag, or image digest.
- Steps to reproduce or a proof of concept.
- Expected impact.
- Whether the finding affects source, workflow permissions, published image
  verification, SBOM/VEX evidence, STIG evidence, or release provenance.

## Supported versions

This repository currently has no git tags and no GitHub releases. The supported
line is the latest default branch and any published digest built from it. When
versioned `v*` releases exist, this section must be updated with a supported
versions table before the release is announced as supported.

## Coordinated disclosure

The maintainer will coordinate investigation and remediation through the private
reporting thread. Public disclosure should wait until a fix or mitigation is
available, or until a mutually agreed disclosure date.

Target response windows:

| Stage | Target |
| --- | --- |
| Initial acknowledgement | 7 business days |
| Validation | 14 business days |
| Fix, mitigation, or documented non-applicability | 90 days when reasonable |

These are targets, not guarantees.

## Verifying a release

The verification contract is maintained in
[`docs/reference/verify.md`](docs/reference/verify.md). Use that document as the
source of truth for published digest verification.

At a high level, verification requires:

- `cosign verify` for the published digest signature.
- `cosign verify-attestation` for SPDX, CycloneDX, OpenVEX when present, NIST
  SP 800-190, tailored STIG ARF, and SLSA provenance predicates.
- `slsa-verifier verify-image` for the SLSA L3 provenance.
- Exact certificate identities and the GitHub Actions OIDC issuer documented in
  the verification contract.

Do not substitute `gh attestation verify` for this repository's release
contract; the repository uses cosign OCI attestations for the published image
evidence.

