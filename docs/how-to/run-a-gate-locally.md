# Run a Gate Locally

Use the narrowest gate that proves the change.

## Repository Contract

Run this for documentation-only, metadata, and repository-health changes:

```sh
pre-commit run --all-files
```

The hooks run formatting, static analysis, workflow linting, Markdown linting,
and the focused repository test suites defined in `.pre-commit-config.yaml`.

## Base-Python Publication Policies

The repository verifier runs the publication helper self-tests. They can also be
replayed individually without a registry write:

```sh
python3 tools/decide-python-publish-scope.py --self-test
python3 tools/resolve-python-index.py --self-test
python3 tools/assert-python-alias-policy.py --self-test
python3 tools/python-trust-contract.py --self-test
python3 tools/assert-python-attestation.py --self-test
python3 tools/assert-python-provenance.py --self-test
python3 tools/assert-python-slsa-certificate.py --self-test
```

These are policy and mutation tests, not evidence of a production publication.
The registry-origin readback, signature, attestation, provenance, Rekor, and
alias gates first execute together on a privileged post-merge publish run.

## Runtime Hardening

Build and check the local runtime tag:

```sh
make build
make test
```

## Full Local Gate Harness

Run this for image, RPM lock, scanner, FIPS, STIG, SBOM, NIST, or
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

## Base-Python Raw Scanner Evidence

To replay the SQLite-absence assertion against the reports produced by the
Python CI workflow, select the matching architecture and pass all four normal
inputs:

```sh
ARCH=amd64
python3 images/python/tools/assert-raw-scanners-no-sqlite.py \
  --trivy-json "dist/python-evidence/vuln/base-python.${ARCH}.trivy.all.json" \
  --grype-json "dist/python-evidence/vuln/base-python.${ARCH}.grype.all.json" \
  --contract images/python/contracts/image-manifest.json \
  --arch "${ARCH}"
```

Use `arm64` only with the corresponding arm64 reports. The Trivy input must be
the inventory-bearing report produced with `--list-all-pkgs`; the Grype report
may legitimately contain `"matches": []`. The raw gate validates the required
identity and schema fields plus SQLite absence in each complete report.

The offline self-test remains standalone:

```sh
python3 images/python/tools/assert-raw-scanners-no-sqlite.py --self-test
```

## Reproducibility

For any image-affecting change, run both rootfs byte-identity gates from
[`reproduce-a-build-byte-for-byte.md`](reproduce-a-build-byte-for-byte.md).
