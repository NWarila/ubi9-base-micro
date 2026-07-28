# ADR-0010: Keep The Base-Image Family In One Repository With Per-Image Publish Workflows

- Status: Accepted
- Date: 2026-06-21
- Last reviewed: 2026-07-28
- Scope: repo

## Context

The base-image family has one root image and planned language variants. An
earlier revision of this record split the family across repositories, one per
variant, on three load-bearing assumptions: that signer identity requires a
repository boundary, that the dependency-update cascade requires a
cross-repository digest edge, and that hosting several images in one repository
requires a central build engine. Each assumption fails against the mechanisms
this repository actually uses.

Cosign keyless identity binds to the workflow-file path, and SLSA provenance
binds its certificate identity to the shared generator reference. Per-image
workflows inside one repository therefore give every image a distinct, exact
certificate identity with no organization-wide regex. Renovate digest-pin
updates are blind to repository location: `.github/renovate.json` already
groups docker-digest pins inside this tree, so a variant's parent pin is a
first-class update edge wherever the variant lives. And publication coupling,
not file co-location, is what makes a build engine: workflows that never
exchange digests in-run are not a factory.

## Decision

The base-image family lives in this repository. `ubi9-base-micro` remains at
the repository root; relocating it under a variant-style tree was rejected as
cosmetic churn against a shipped, digest-locked v1.0.0 image. Planned variants
will live under `images/<variant>/` trees, each with one self-owned,
path-scoped publish workflow and its own evidence set.

Variants consume the published parent strictly by pinned digest: a committed
`base-micro@sha256:<digest>` reference updated through ordinary
dependency-update pull requests. Publication orchestration remains banned:
no cross-image in-run digest hand-off, no image build matrix, and no publish
step that derives one image's input from another image's output inside the
same run.

## Consequences

- Each image keeps a distinct, exact cosign certificate identity (its own
  workflow-file path) and its own provenance subject.
- The provenance `--source-uri` is shared N:1 across images until a per-image
  trust-contract predicate binds digest, package, tree, workflow, and commit;
  that predicate is planned before the family grows past its first variant.
- GHCR write authority is shared at the repository boundary and is mitigated
  by scoped per-job workflow permissions.
- The layout is heterogeneous: the root image lives at the repository root and
  variants will live under `images/<variant>/`. This asymmetry is accepted.
- A variant whose compliance tooling diverges structurally (for example a Java
  variant carrying its own validated cryptographic module) splits out with
  history via `git subtree`.
- Documentation must keep planned variants distinct from artifacts this
  repository actually publishes.

## References

- SLSA security levels: <https://slsa.dev/spec/v1.0/levels>
- Sigstore Cosign verification: <https://docs.sigstore.dev/cosign/verifying/verify/>
- Repository details: `README.md`, `docs/reference/verify.md`,
  `.github/renovate.json`
