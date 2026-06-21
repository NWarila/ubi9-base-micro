# Contributing

This repository builds the root UBI 9 micro image for the NWarila base-image
family. Contributions are welcome when they preserve the repository contract:
image changes must stay reproducible, evidence must remain verifiable, and
documentation must describe the workflow that actually exists here.

## Prerequisites

Use a workstation with:

- Git with commit signing configured.
- Python 3.12 or a compatible Python 3 runtime.
- Bash.
- Docker with Buildx.
- QEMU support when running the arm64 reproducibility gate locally.
- Network access to download the pinned tool releases used by
  `tools/run-test-gates.sh`.

The gate harness installs its own pinned Syft, Trivy, Grype, and OpenSCAP
tooling under `dist/tools/`. Do not replace those installers with ambient host
tools when proving a pull request.

## Make targets

The Makefile intentionally stays small:

| Target | Command | Purpose |
| --- | --- | --- |
| `build` | `make build` | Build the local `base-micro` and `base-micro-dev` tags through `tools/build.sh`. |
| `test` | `make test` | Run the runtime hardening gate against `base-micro`. |
| `verify` | `make verify` | Run `python tools/verify.py`. |
| `clean` | `make clean` | Remove generated `dist/` output and `tools/__pycache__/`. |

## Local verification

For documentation-only or repository-health changes, run the repository
contract verifier:

```sh
python tools/verify.py
```

For image, gate, RPM lock, or security-evidence changes, run the full local gate
harness for the affected platform:

```sh
bash tools/run-test-gates.sh
```

That harness builds the runtime image, runs the hardening and FIPS probes,
checks the footprint gate, runs the tailored STIG ARF scan, derives and checks
SBOM output, runs Trivy and Grype fixable-vulnerability gates, applies the
OpenVEX default-deny check, scans the exported rootfs for secrets, and validates
the NIST SP 800-190 image-control predicate.

For any image-affecting change, also prove byte-for-byte rootfs
reproducibility for both supported platforms:

```sh
python tools/assert-reproducible.py \
  --platform linux/amd64 \
  --assert-byte-identical \
  --report dist/reproducibility/base-micro.amd64.reproducibility.json \
  --summary dist/reproducibility/base-micro.amd64.reproducibility.txt \
  --workdir dist/reproducibility/work.amd64
```

```sh
python tools/assert-reproducible.py \
  --platform linux/arm64 \
  --assert-byte-identical \
  --report dist/reproducibility/base-micro.arm64.reproducibility.json \
  --summary dist/reproducibility/base-micro.arm64.reproducibility.txt \
  --workdir dist/reproducibility/work.arm64
```

The CI pull-request path runs `repo contract`, `actionlint`, `build and
hardening`, and the amd64 and arm64 reproducibility gates. The publish-only
signature, SBOM attestation, SLSA provenance, and Rekor roll-up jobs run only on
`push` to `main` or `v*` tags.

## Pull requests

Before opening a pull request:

1. Keep the change focused.
2. Sign every commit.
3. Run the applicable gates above and include the command results in the pull
   request.
4. Update `docs/` and `docs/decision-records/repo/` when behavior, evidence, or
   policy changes.
5. Confirm `.gitignore` allowlists every new tracked path.

Do not file public issues or pull requests for vulnerabilities. Follow
[SECURITY.md](SECURITY.md) instead.

## Deny-all ignore convention

This repository uses a deny-all `.gitignore`: `**` ignores everything until a
path is explicitly allowlisted. When adding a tracked file or directory, add the
narrowest allowlist entry that covers it. Generated outputs stay under ignored
paths such as `dist/`.

