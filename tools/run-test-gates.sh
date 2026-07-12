#!/usr/bin/env bash
# Purpose: Top-level gate pipeline — install scanners + STIG datastream, build images, then run hardening/FIPS tests,
# footprint, STIG ARF, SBOM gen+assertions, phantom-package check, Trivy/Grype + VEX, rootfs secret scan, and NIST
# 800-190 predicate gen/validate.
# Role: workflow
# Python-convertible: partial — thin linear orchestration; all substance is in the called .py/.sh gates, conversion
# mainly relocates the call list.
# Micro-container candidate: yes — this is the gate workflow to collapse into pinned gate micro-container(s), dropping
# the install-on-runner preamble.
# Relocate: no — workflow/gate driver, not a build-process artifact script.

set -euo pipefail

runtime_image="${RUNTIME_IMAGE:-ghcr.io/nwarila/ubi9-base-micro:base-micro}"
platform="${PLATFORM:-linux/amd64}"
arch="${platform#linux/}"
ubi_micro_image="${UBI_MICRO_IMAGE:-registry.access.redhat.com/ubi9/ubi-micro@sha256:35de56a9413112f1474e392ebc35e0cf6f0fb484c8e8877bbae59b513694b41f}"
source_uri="github.com/${GITHUB_REPOSITORY:-NWarila/ubi9-base-micro}"
revision="${GITHUB_SHA:-$(git rev-parse HEAD 2> /dev/null)}"
revision="${revision:-local}"

case "${arch}" in
  amd64 | arm64) ;;
  *)
    echo "unsupported gate architecture: ${arch}" >&2
    exit 1
    ;;
esac

python tools/assert-ignore-scope.py

bash tools/install-syft.sh
bash tools/install-trivy.sh
bash tools/install-grype.sh

scanner_db_max_age_days="${SCANNER_DB_MAX_AGE_DAYS:-7}"
case "${scanner_db_max_age_days}" in
  "" | *[!0-9]*)
    echo "SCANNER_DB_MAX_AGE_DAYS must be a positive integer, got: ${scanner_db_max_age_days}" >&2
    exit 1
    ;;
  *) ;;
esac
if ((scanner_db_max_age_days < 1)); then
  echo "SCANNER_DB_MAX_AGE_DAYS must be at least 1" >&2
  exit 1
fi

dist/tools/trivy image --download-db-only
dist/tools/grype db update
python tools/assert-scanner-db-freshness.py --max-age-days "${scanner_db_max_age_days}"

scanner_canary_fixture="tests/fixtures/scanner-canary/log4shell.cdx.json"
grype_canary_json="dist/vuln/scanner-canary.grype.json"
trivy_canary_json="dist/vuln/scanner-canary.trivy.json"
mkdir -p dist/vuln
: > "${grype_canary_json}"
: > "${trivy_canary_json}"
GRYPE_DB_AUTO_UPDATE=false dist/tools/grype "sbom:${scanner_canary_fixture}" -o json -q > "${grype_canary_json}"
dist/tools/trivy sbom "${scanner_canary_fixture}" \
  --format json \
  --output "${trivy_canary_json}" \
  --skip-db-update \
  --skip-java-db-update \
  --offline-scan \
  -q
python tools/assert-scanner-canary.py \
  --grype-json "${grype_canary_json}" \
  --trivy-json "${trivy_canary_json}" \
  --expect-cve CVE-2021-44228

export GRYPE_DB_VALIDATE_AGE=true
export GRYPE_DB_MAX_ALLOWED_BUILT_AGE="$((scanner_db_max_age_days * 24))h"

bash tools/install-openscap.sh
bash tools/build-stig-datastream.sh

bash tools/build.sh

bash tests/hardening.sh "${runtime_image}"
bash tests/fips.sh "${runtime_image}"

mkdir -p dist/footprint
python tools/assert-footprint.py \
  --image "${runtime_image}" \
  --platform "${platform}" \
  --output "dist/footprint/base-micro.${arch}.json"

bash tools/run-stig-arf.sh "${runtime_image}" "${arch}" "${platform}" "dist/stig/${arch}"

mkdir -p dist/sbom
dist/tools/syft scan "${runtime_image}" \
  --platform "${platform}" \
  -o "json=dist/sbom/base-micro.${arch}.syft.json" \
  -o "spdx-json=dist/sbom/base-micro.${arch}.spdx.json" \
  -o "cyclonedx-json=dist/sbom/base-micro.${arch}.cdx.json"

python tools/assert-sbom-rpms.py \
  --source "dist/sbom/base-micro.${arch}.syft.json" \
  "dist/sbom/base-micro.${arch}.spdx.json" \
  "dist/sbom/base-micro.${arch}.cdx.json"

python tools/assert-no-phantom-packages.py \
  --image "${runtime_image}" \
  --platform "${platform}" \
  --syft-json "dist/sbom/base-micro.${arch}.syft.json" \
  --output "dist/sbom/base-micro.${arch}.phantom-packages.json" \
  --expect-absent libacl \
  --expect-absent libattr \
  --expect-absent libcap \
  --expect-absent coreutils-common \
  --expect-absent pcre2-syntax \
  --expect-absent alternatives

mkdir -p dist/vuln

dist/tools/trivy image \
  --vuln-type os,library \
  --ignore-unfixed \
  --severity MEDIUM,HIGH,CRITICAL \
  --ignorefile security/cve-ignore.trivyignore.yaml \
  --exit-code 1 \
  "${runtime_image}"

grype_gate_json="dist/vuln/base-micro.${arch}.grype.gate.json"
dist/tools/grype "${runtime_image}" \
  --only-fixed \
  --fail-on medium \
  -c security/cve-ignore.grype.yaml \
  --show-suppressed \
  -o json \
  --file "${grype_gate_json}"
python tools/assert-ignore-scope.py --grype-report "${grype_gate_json}"

trivy_json="dist/vuln/base-micro.${arch}.trivy.all.json"
grype_json="dist/vuln/base-micro.${arch}.grype.all.json"

dist/tools/trivy image \
  --vuln-type os,library \
  --severity HIGH,CRITICAL \
  --format json \
  --output "${trivy_json}" \
  "${runtime_image}"

dist/tools/grype "${runtime_image}" -o json --file "${grype_json}"

python tools/assert-vex.py \
  --product "${runtime_image}" \
  --trivy-json "${trivy_json}" \
  --grype-json "${grype_json}"

rootfs_dir="dist/rootfs-secret-scan/rootfs.${arch}"
report="dist/rootfs-secret-scan/base-micro.${arch}.secret-scan.json"
rm -rf "${rootfs_dir}"
mkdir -p "${rootfs_dir}"

container_id="$(docker create "${runtime_image}" /secret-scan-export)"
cleanup() {
  docker rm "${container_id}" > /dev/null
}
trap cleanup EXIT

docker export "${container_id}" | tar --no-same-owner --no-same-permissions -x -C "${rootfs_dir}"
chmod -R u+rwX "${rootfs_dir}"
python tools/assert-no-rootfs-secrets.py \
  --rootfs "${rootfs_dir}" \
  --report "${report}"

predicate="dist/attestations/nist-800-190.base-micro.${arch}.json"
mkdir -p dist/attestations
python tools/generate-nist-800-190-predicate.py \
  --image-ref "${runtime_image}" \
  --platform "${platform}" \
  --arch "${arch}" \
  --base-image "${ubi_micro_image}" \
  --source-uri "${source_uri}" \
  --revision "${revision}" \
  --secret-scan-report "dist/rootfs-secret-scan/base-micro.${arch}.secret-scan.json" \
  --output "${predicate}"

python tools/generate-nist-800-190-predicate.py --validate "${predicate}"
