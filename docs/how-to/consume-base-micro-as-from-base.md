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
and `USER 65532:65532`. The downstream image owns application-specific trimming
and runtime behavior, including Java `jdeps`/`jlink`, Python stdlib pruning, and
application dependency minimization.

Downstream images must keep their own evidence honest. A `FROM` pin to
`base-micro` does not automatically provide downstream SBOMs, signatures,
scanner results, STIG ARF, NIST SP 800-190 evidence, or SLSA provenance.
