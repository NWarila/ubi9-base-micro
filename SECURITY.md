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

The supported line is the latest `v*` release and any published image digest
built from it.

| Version | Supported |
| --- | --- |
| `1.0.0` | Yes |

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

The merged `base-python` publisher also requires its index-only trust-contract
predicate. Its first successful publication is still awaited. The 2026-08-17
production attempt failed in `registry-served gates and evidence` while
`Install publication gate tools` tried to install Syft without Cosign available;
that prerequisite is now repaired and lock-enforced, with production proof
pending the next `main` push. The package exists publicly and serves only
unaliased, unsigned candidate digests. Its two BuildKit `mode=max` provenance
attestation manifests exist; no production gate evidence, Cosign signature or
attestation, SLSA-generator provenance, Rekor record, or consumer alias exists.
Use the image-specific commands in
[`docs/how-to/verify-a-published-image.md`](docs/how-to/verify-a-published-image.md)
only for a digest from a successful production publication.

Do not substitute `gh attestation verify` for this repository's release
contract; the repository uses cosign OCI attestations for the published image
evidence.
