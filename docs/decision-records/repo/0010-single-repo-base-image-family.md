# ADR-0010: Keep The Base-Image Family In One Repository With Per-Image Publish Workflows

- Status: Accepted
- Date: 2026-06-21
- Last reviewed: 2026-08-13
- Scope: repo

## Context

The base-image family has one published root image, one built-and-gated but
unpublished Python variant, and other planned language variants. An earlier
revision of this record split the family across repositories, one per variant,
on three load-bearing assumptions: that signer identity requires a repository
boundary, that the dependency-update cascade requires a cross-repository digest
edge, and that hosting several images in one repository requires a central build
engine. Each assumption fails against the mechanisms this repository actually
uses.

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
cosmetic churn against a shipped, digest-locked v1.0.0 image. The built-and-gated,
unpublished `base-python` variant lives under `images/python/` and has no
production publisher, signature, or published digest. Its pull-request
preflight writes an unsigned candidate and BuildKit provenance only to a
loopback-bound ephemeral registry; this is neither an external or project
publication nor a consumer-resolvable digest. Future variants use
`images/<variant>/` trees. Each variant needs its own path-scoped publish
workflow and evidence set before publication.

The root micro publisher has its own conservative, closed scope decision. On a
`main` push with an available, non-empty diff against the currently published
revision, it skips micro publication only when every changed path is under
`images/` or `docs/`, or is exactly `.github/workflows/python-ci.yaml`,
`.github/workflows/publish-python.yaml`, `tools/verify.py`, `README.md`,
`SUPPORT.md`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, or
`CODE_OF_CONDUCT.md`. Every unlisted path and every ambiguity publishes. This
micro-specific set is not a template for a variant's publish scope.

Variants consume the published parent strictly by pinned digest: a committed
`base-micro@sha256:<digest>` reference updated through ordinary
dependency-update pull requests. Publication orchestration remains banned:
no cross-image in-run digest hand-off, no image build matrix, and no publish
step that derives one image's input from another image's output inside the
same run.

## Consequences

- Each image keeps a distinct, exact cosign certificate identity (its own
  workflow-file path) and its own provenance subject.
- The provenance `--source-uri` is shared N:1 across published images until a
  per-image trust-contract predicate binds digest, package, tree, workflow, and
  commit; that predicate is required before any variant publishes.
- GHCR write authority is shared at the repository boundary and is mitigated
  by scoped per-job workflow permissions.
- The layout is heterogeneous: the root image lives at the repository root and
  variants live under `images/<variant>/`. This asymmetry is accepted.
- Changes confined to the root micro publisher's closed skip set do not mint a
  new micro digest. The policy does not retract or alter previously published
  digests or their revision-bound attestations.
- A variant whose compliance tooling diverges structurally (for example a Java
  variant carrying its own validated cryptographic module) splits out with
  history via `git subtree`.
- Documentation must distinguish built-but-unpublished and planned variants from
  artifacts this repository actually publishes.

## References

- SLSA security levels: <https://slsa.dev/spec/v1.0/levels>
- Sigstore Cosign verification: <https://docs.sigstore.dev/cosign/verifying/verify/>
- Repository details: `README.md`, `docs/reference/verify.md`,
  `.github/renovate.json`
