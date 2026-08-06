# Image Family Trees

Base-image variants live here, one tree per variant under `images/<variant>/`.
`base-python` is publication-enabled through
`.github/workflows/publish-python.yaml`; its first package is private by default
and is not publicly consumable until the owner changes GHCR visibility and the
anonymous verification succeeds. Node and Java variants remain planned. Each
variant must publish through its own path-scoped workflow and carry the full
`base-micro` evidence parity set — cosign signature, SPDX and CycloneDX SBOMs,
OpenVEX, NIST SP 800-190 evidence, a tailored STIG ARF, and SLSA provenance —
before a digest is described as publicly consumable.

Changes confined to this tree remain eligible to skip root micro publication.
The micro publisher now applies a larger conservative closed skip set, so it
skips only when every changed path is one of the enumerated non-micro-affecting
surfaces. The complete policy, including the `images/` and `docs/` prefixes and
the exact-file entries, is documented in the
[verification contract](../docs/reference/verification-contract.md#micro-publish-scope).
Any unlisted path or ambiguity still publishes.

## Vulnerable-component removal policy

Each image declares a supported runtime and API surface. A vulnerable library
may be removed only when dependency analysis proves it is unused by that
declared surface, all of its consumers are deliberately removed with it, and
build plus runtime evidence proves the resulting image remains internally
honest. This is an image-specific product decision, not a mechanical
size-reduction rule.

Standard runtime features are presumed supported unless an image prominently
documents otherwise. Node and Java images, for example, require their own
dependency and API review before any component is stripped; a removal decision
for Python does not transfer to them. Shells, package managers, and installer
frontends also have different support semantics from user-visible language APIs
and are not precedents for silently removing standard-library features.
