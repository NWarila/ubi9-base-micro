# Getting Started: Build and Verify

This walkthrough builds the local runtime tags and runs the repository verifier.

## Prerequisites

- Git with commit signing configured
- Python 3.12 or a compatible Python 3 runtime
- Bash
- Docker with Buildx

## Build the Local Images

From the repository root, build the runtime and dev tags:

```sh
make build
```

This produces local `base-micro` and `base-micro-dev` tags from
`containers/Dockerfile`.

## Run the Runtime Hardening Gate

Check the local `base-micro` tag:

```sh
make test
```

The hardening test verifies the no-shell, no-package-manager, non-root, rpmdb,
and CA-bundle runtime expectations.

## Run the Repository Verifier

Run the repository contract checks:

```sh
python tools/verify.py
```

For image-affecting changes, continue with the full local gates in
[`../how-to/run-a-gate-locally.md`](../how-to/run-a-gate-locally.md) and the
byte-for-byte reproduction guide in
[`../how-to/reproduce-a-build-byte-for-byte.md`](../how-to/reproduce-a-build-byte-for-byte.md).
