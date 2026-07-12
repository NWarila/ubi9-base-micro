# Run a Gate Locally

Use the narrowest gate that proves the change.

## Repository Contract

Run this for documentation-only, metadata, and repository-health changes:

```sh
python tools/verify.py
```

The verifier checks required files, pinned workflow inputs, deny-all ignore
allowlists, documentation markers, Diataxis layout, ADR inventory, lint setup,
helper self-tests, and attribution-residue denial.

## Runtime Hardening

Build and check the local runtime tag:

```sh
make build
make test
```

## Full Local Gate Harness

Run this for image, RPM lock, scanner, FIPS, STIG, SBOM, VEX, NIST, or
publish-evidence changes:

Cosign v2.5.2 is a required local prerequisite because the harness installs
Syft, Trivy, and Grype only after verifying their signed release checksums.
Confirm `cosign version` succeeds before running the harness.

```sh
bash tools/run-test-gates.sh
```

The harness installs pinned gate tools under `dist/tools/`. Do not replace those
with ambient host binaries when proving a pull request.

The scanner gates download Trivy and Grype vulnerability databases before
scanning and fail if the DB metadata is stale or missing. Set
`TRIVY_CACHE_DIR` and `GRYPE_DB_CACHE_DIR` to a roomy scratch location when the
default home cache is too small. The default freshness ceiling is seven days and
can be tightened with `SCANNER_DB_MAX_AGE_DAYS`.

## Reproducibility

For any image-affecting change, run both rootfs byte-identity gates from
[`reproduce-a-build-byte-for-byte.md`](reproduce-a-build-byte-for-byte.md).
