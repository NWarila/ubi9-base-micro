# Decision Records

This directory stores repository-scope Architecture Decision Records for
`ubi9-base-micro`.

The records here document decisions owned by this repository. They deliberately
do not mirror shared organization or template ADRs; cross-repository governance
belongs in its source repository and should be adopted here only from a coherent
canonical source.

| ADR | Status | Decision |
| --- | --- | --- |
| [ADR-0001](repo/0001-byte-for-byte-rootfs-reproducibility.md) | Accepted | Enforce byte-for-byte rootfs reproducibility, including the rpmdb. |
| [ADR-0002](repo/0002-rhel-openssl-fips-approved-mode.md) | Accepted | Use the RHEL OpenSSL FIPS provider through a self-contained approved-mode config. |
| [ADR-0003](repo/0003-per-architecture-fips-scope.md) | Accepted | Publish multi-arch images with per-architecture FIPS scope. |
| [ADR-0004](repo/0004-slsa-generator-tag-pin-exception.md) | Accepted | Keep the SLSA generator tag-pinned with an integrity guard and exact identity. |
| [ADR-0005](repo/0005-strip-runtime-with-phantom-package-guard.md) | Accepted | Strip runtime payload only behind rpmdb and ownership guards. |
| [ADR-0006](repo/0006-rpm-lock-cve-absorption-loop.md) | Accepted | Absorb patched RPMs through a gated lockfile refresh loop. |
| [ADR-0007](repo/0007-dual-scanner-openvex-default-deny.md) | Accepted | Use dual scanners and default-deny OpenVEX for unfixed HIGH and CRITICAL findings. |
| [ADR-0008](repo/0008-tailored-stig-arf-gate.md) | Accepted | Gate the image with a tailored RHEL 9 STIG ARF and reviewed omissions. |
| [ADR-0009](repo/0009-nist-800-190-image-evidence.md) | Accepted | Emit NIST SP 800-190 section 4.1 image-control evidence. |
| [ADR-0010](repo/0010-base-image-polyrepo-topology.md) | Accepted | Keep the base-image family as polyrepos rooted at `ubi9-base-micro`. |
| [ADR-0011](repo/0011-pin-github-hosted-runner-labels.md) | Accepted | Pin GitHub-hosted Ubuntu runner labels for workflow determinism. |
