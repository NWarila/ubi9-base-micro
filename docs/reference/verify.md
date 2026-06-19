# Published Digest Verification

P1.4a publishes `ghcr.io/nwarila/ubi9-base-micro` by digest from `.github/workflows/publish-image.yaml`. The publish workflow signs the image digest with Cosign keyless from the repository workflow identity, then passes the same digest to the SLSA container generator reusable workflow.

## Identities

| Evidence | Exact identity |
| --- | --- |
| Image signature | `https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@<ref>` |
| SLSA provenance attestation | `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |

The SLSA generator tag `v2.1.0` is allowed only with the workflow tag-integrity guard asserting `refs/tags/v2.1.0 == f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`.

## Contract

Set `IMAGE_REF` to the published digest reference, for example `ghcr.io/nwarila/ubi9-base-micro@sha256:<digest>`. Set `PUBLISH_REF` to the publishing Git ref, such as `refs/heads/main` or `refs/tags/v1.2.3`.

```sh
cosign verify "${IMAGE_REF}" \
  --certificate-identity "https://github.com/NWarila/ubi9-base-micro/.github/workflows/publish-image.yaml@${PUBLISH_REF}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
cosign verify-attestation --type slsaprovenance "${IMAGE_REF}" \
  --certificate-identity "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

```sh
slsa-verifier verify-image "${IMAGE_REF}" \
  --source-uri github.com/NWarila/ubi9-base-micro \
  --builder-id "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
```

`gh attestation verify` is not part of this contract. It verifies GitHub-native Artifact Attestations, not the cosign OCI attestation written by `generator_container_slsa3.yml`.

## Anonymous Pull Status

The commands above are the normative verification contract for a published digest. The full anonymous-pull run is P1.8 because the GHCR package auto-creates private on first publish and requires a one-time owner visibility change before unauthenticated verification can be proven.
