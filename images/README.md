# Image Family Trees

Planned base-image variants will live here, one tree per variant under
`images/<variant>/`. Each variant must publish through its own path-scoped
workflow and must carry the full `base-micro` evidence parity set — cosign
signature, SPDX and CycloneDX SBOMs, OpenVEX, NIST SP 800-190 evidence, a
tailored STIG ARF, and SLSA provenance — before any digest becomes public.

Changes confined to this tree do not republish the root micro image: the
publish workflow skips micro publication when the entire delta against the
currently published revision lies under `images/`.

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
