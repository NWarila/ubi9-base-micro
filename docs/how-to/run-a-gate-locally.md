# Run a Gate Locally

Use the narrowest gate that proves the change.

## Repository Contract

Run this for documentation-only, metadata, and repository-health changes:

```sh
python tools/verify.py
```

The verifier checks a duplicate-free required-file manifest, pinned workflow
inputs, the committed Python Bake target shape, contract-derived Python builder
pin inputs, and the statically checked shape of each named identity step: the
run body starts with `set -euo pipefail`, contains no later `set +...`, omits
step-level `continue-on-error`, and ends with the checker as its final unwrapped
command. It also checks Renovate managers, deny-all ignore
allowlists, documentation markers, Diataxis layout, ADR inventory, lint setup,
helper self-tests, attribution-residue denial, and a separate
internal-process-residue denial. The Python build-input self-test runs the
unmodified positive control and demonstrates seven classes through sixty
non-no-op negative cases: BuildKit digest qualification, repro output policy,
workflow-pin derivation, committed target protection and shape, five identity
observations, two Renovate managers and their non-automerge rules, and the
harness CLI.

The internal-process check reads only Markdown in the current checkout at
`README.md`, `docs/**/*.md`, and `images/**/*.md`. Paths outside that set are
outside this check.

For a Python builder-pin or Bake-contract change, the normal verifier proves
the static contract, including the checked identity-step shape, and runs
the seven-class/sixty-case mutation inventory, but does not create a live
Buildx builder. The live five-observation identity assertion runs in the Python
workflow after setup and before either build. Require non-skipped `python build
and gates` and `python reproducibility` results for both architectures; these
are pre-publication gates and do not publish the image.

The shell-text check is defence-in-depth against accidental regression, not an
exhaustive defence against a hostile workflow edit. See
[TD-8](../TECH-DEBT.md#td-8-python-builder-identity-workflow-static-analysis-boundary)
for the free-form shell limitation and the repository controls that govern that
threat.

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
identity and schema fields plus SQLite absence in each report, but it does not
bind the report identities to each other. The following `tools/assert-vex.py`
invocation in the workflow owns that binding.

The offline self-test remains standalone:

```sh
python3 images/python/tools/assert-raw-scanners-no-sqlite.py --self-test
```

## Reproducibility

For any image-affecting change, run both rootfs byte-identity gates from
[`reproduce-a-build-byte-for-byte.md`](reproduce-a-build-byte-for-byte.md).
