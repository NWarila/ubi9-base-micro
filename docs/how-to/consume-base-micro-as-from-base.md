# Consume Base Micro as a FROM Base

Use this task in a downstream image repository that needs the hardened micro
floor.

## Procedure

Pin the published digest, not a tag:

```Dockerfile
FROM ghcr.io/nwarila/ubi9-base-micro@sha256:<digest>
```

Keep the digest current through the shared Renovate preset rather than by hand.
A downstream repository should verify the digest using
[`verify-a-published-image.md`](verify-a-published-image.md) before adopting it.

The base owns the standard hardened floor: glibc, RHEL CA trust, rpmdb,
OpenSSL #4857 provider configuration, no shell, no package-manager executable,
and a `nonroot:65532` identity with `/home/nonroot`, `HOME=/home/nonroot`, and
`USER 65532:65532`. Consumers no longer need to add their own passwd or group
entry for UID/GID 65532. The downstream image still owns application-specific
trimming and runtime behavior, including an exec-form `ENTRYPOINT`, Java
`jdeps`/`jlink`, Python stdlib pruning, and application dependency minimization.

The base's default command is a non-functional inherited placeholder on this
shell-less base. Consumers **MUST** set their own exec-form `ENTRYPOINT`; do not
rely on the inherited command for runtime behavior.

This digest-pinned multi-stage example builds a static Go application and sets
the consumer-owned entrypoint. It was validated with the application running as
UID 65532 and receiving an HTTPS 200 response through the base CA bundle:

```dockerfile
FROM docker.io/library/golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/app ./cmd/app
FROM ghcr.io/nwarila/ubi9-base-micro@sha256:d94acde23a7060ca35c2f2fac3782d1fbdd89ffde6455e8b39b4ecd01e1a5be5
COPY --from=build /out/app /usr/local/bin/app
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/app"]
```

Downstream images must keep their own evidence honest. A `FROM` pin to
`base-micro` does not automatically provide downstream SBOMs, signatures,
scanner results, STIG ARF, NIST SP 800-190 evidence, or SLSA provenance.
