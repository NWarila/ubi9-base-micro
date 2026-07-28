# Image Family Trees

Planned base-image variants will live here, one tree per variant under
`images/<variant>/`. Each variant must publish through its own path-scoped
workflow and must carry the full `base-micro` evidence parity set — cosign
signature, SPDX and CycloneDX SBOMs, OpenVEX, NIST SP 800-190 evidence, a
tailored STIG ARF, and SLSA provenance — before any digest becomes public.
