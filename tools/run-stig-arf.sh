#!/usr/bin/env bash
# Purpose: Run the image-scoped RHEL9 STIG gate — assert the tailoring, export the rootfs, evaluate it with oscap to
# ARF+HTML, then chain assert-rootfs-identity / assert-stig-arf (fail-closed) / generate-stig-arf-predicate.
# Role: gate
# Python-convertible: partial — orchestrator; every assertion/predicate already lives in assert-stig-*.py, only the
# Podman transfer/export, oscap invocation, and exit-code/trap handling are shell.
# Micro-container candidate: yes — STIG ARF gate; pin the oscap/podman toolchain + ARF parse in a micro-container.
# Relocate: no — verification gate, not a build-process script.

set -euo pipefail

usage() {
  cat << 'USAGE'
Usage: tools/run-stig-arf.sh <image-ref> <arch> <platform> <output-dir>

Runs the image-scoped RHEL9 STIG tailoring against an exported image rootfs with oscap,
then parses the ARF fail-closed and emits a structured attestation predicate.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

image_ref="${1:-}"
arch="${2:-}"
platform="${3:-}"
out_dir="${4:-}"
if [[ -z "${image_ref}" || -z "${arch}" || -z "${platform}" || -z "${out_dir}" ]]; then
  usage >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
datastream="${STIG_DATASTREAM:-dist/openscap/ssg-rhel9-ds.xml}"
controls="${STIG_CONTROLS:-dist/openscap/stig_rhel9.yml}"
tailoring="${STIG_TAILORING_FILE:-stig/rhel9-base-micro-tailoring.xml}"
justifications="${STIG_JUSTIFICATIONS_FILE:-stig/tailoring-justifications.json}"
profile="${STIG_PROFILE:-xccdf_org.nwarila.content_profile_ubi9_base_micro_stig}"
fail_on="${STIG_FAIL_ON:-low}"
ssg_version="${SSG_VERSION:-0.1.81}"
ssg_sha512="${SSG_TARBALL_SHA512:-}"

for required in "${datastream}" "${controls}" "${tailoring}" "${justifications}"; do
  if [[ ! -s "${required}" ]]; then
    echo "required STIG input missing or empty: ${required}" >&2
    exit 1
  fi
done
if [[ -z "${ssg_sha512}" ]]; then
  echo "SSG_TARBALL_SHA512 must be set" >&2
  exit 2
fi

mkdir -p "${out_dir}"

python "${repo_root}/tools/assert-stig-tailoring.py" \
  --tailoring "${tailoring}" \
  --justifications "${justifications}" \
  --controls-yaml "${controls}" \
  --datastream "${datastream}" < /dev/null

echo "STIG PHASE: resolve image in Podman"
podman_target="${image_ref}"
if ! sudo podman image exists "${image_ref}" < /dev/null > /dev/null 2>&1; then
  if [[ "${image_ref}" == *@sha256:* ]]; then
    sudo podman pull --arch "${arch}" "${image_ref}" < /dev/null
  elif docker image inspect "${image_ref}" < /dev/null > /dev/null 2>&1; then
    docker save "${image_ref}" < /dev/null | sudo podman load
  else
    sudo podman pull --arch "${arch}" "${image_ref}" < /dev/null
  fi
fi
if ! sudo podman image exists "${podman_target}" < /dev/null > /dev/null 2>&1; then
  echo "Podman scan target could not be resolved for ${image_ref}" >&2
  exit 1
fi
inspect_status=0
inspect_observation="$(sudo podman image inspect --format '{{.Id}} {{.Architecture}} {{.Os}}' \
  "${podman_target}" < /dev/null 2> /dev/null)" || inspect_status=$?
if ((inspect_status != 0)); then
  echo "Podman scan target inspection failed for ${image_ref} with status ${inspect_status}" >&2
  exit "${inspect_status}"
fi
read -r resolved_image_id resolved_arch resolved_os inspect_extra <<< "${inspect_observation}"
if [[ ! "${resolved_image_id:-}" =~ ^(sha256:)?[0-9a-f]{64}$ || -n "${inspect_extra:-}" || "${inspect_observation}" == *$'\n'* ]]; then
  echo "Podman scan target has an invalid image ID for ${image_ref}: ${resolved_image_id:-<unknown>}" >&2
  exit 1
fi
if [[ "${resolved_arch}" != "${arch}" || "${resolved_os}" != "linux" ]]; then
  echo "Podman scan target platform mismatch for ${image_ref}: expected linux/${arch}, observed ${resolved_os:-<unknown>}/${resolved_arch:-<unknown>}" >&2
  exit 1
fi
podman_target="${resolved_image_id}"

arf="${out_dir}/base-micro.${arch}.stig.arf.xml"
report="${out_dir}/base-micro.${arch}.stig.report.html"
summary="${out_dir}/base-micro.${arch}.stig.summary.json"
predicate="${out_dir}/stig-arf.base-micro.${arch}.json"
rootfs_tar="${out_dir}/base-micro.${arch}.rootfs.tar"
identity_summary="${out_dir}/base-micro.${arch}.rootfs-identity.json"
scan_rootfs="$(mktemp -d)"
rootfs_container_id=""

cleanup_scan_resources() {
  if [[ -n "${rootfs_container_id}" ]]; then
    sudo podman rm "${rootfs_container_id}" < /dev/null > /dev/null 2>&1
  fi
  sudo rm -rf -- "${scan_rootfs}" < /dev/null
}
trap cleanup_scan_resources EXIT

echo "STIG PHASE: export Podman rootfs for OpenSCAP"
rootfs_container_id="$(sudo podman create "${podman_target}" /stig-rootfs-export < /dev/null)"
oscap_container_vars="$(sudo podman inspect --format '{{join .Config.Env "\n"}}' \
  "${rootfs_container_id}" < /dev/null)"
sudo podman export --output "${rootfs_tar}" "${rootfs_container_id}" < /dev/null
sudo podman rm "${rootfs_container_id}" < /dev/null > /dev/null
rootfs_container_id=""

# oscap-podman initializes and mounts a container only to populate these three
# environment variables before invoking oscap. The mount has wedged repeatedly
# in CI. Scan the same merged rootfs from the already-required export instead.
# Root extraction preserves numeric ownership because the tailored rules assert it.
sudo tar --numeric-owner --same-owner -xf "${rootfs_tar}" -C "${scan_rootfs}" < /dev/null
sudo mkdir -p "${scan_rootfs}/run" < /dev/null
sudo touch "${scan_rootfs}/run/.containerenv" < /dev/null

echo "STIG PHASE: evaluate exported rootfs with OpenSCAP"
oscap_status=0
if sudo env \
  "OSCAP_CONTAINER_VARS=${oscap_container_vars}" \
  "OSCAP_EVALUATION_TARGET=podman-image://${podman_target}" \
  "OSCAP_PROBE_ROOT=${scan_rootfs}" \
  oscap xccdf eval \
  --tailoring-file "${tailoring}" \
  --profile "${profile}" \
  --results-arf "${arf}" \
  --report "${report}" \
  "${datastream}" < /dev/null; then
  oscap_status=0
else
  oscap_status=$?
fi

if [[ "${oscap_status}" != "0" && "${oscap_status}" != "2" ]]; then
  echo "OpenSCAP rootfs evaluation failed with unexpected status ${oscap_status}" >&2
  exit "${oscap_status}"
fi

python "${repo_root}/tools/assert-rootfs-identity.py" \
  --rootfs-tar "${rootfs_tar}" \
  --report "${identity_summary}" < /dev/null

python "${repo_root}/tools/assert-stig-arf.py" \
  --arf "${arf}" \
  --fail-on "${fail_on}" \
  --equivalent-assertions "${identity_summary}" \
  --summary "${summary}" < /dev/null

python "${repo_root}/tools/generate-stig-arf-predicate.py" \
  --arf "${arf}" \
  --summary "${summary}" \
  --tailoring "${tailoring}" \
  --justifications "${justifications}" \
  --image-ref "${image_ref}" \
  --platform "${platform}" \
  --arch "${arch}" \
  --profile "${profile}" \
  --fail-on "${fail_on}" \
  --ssg-version "${ssg_version}" \
  --ssg-tarball-sha512 "${ssg_sha512}" \
  --output "${predicate}" < /dev/null

echo "STIG ARF gate passed for ${image_ref} (${platform})"
echo "ARF: ${arf}"
echo "HTML report: ${report}"
echo "Predicate: ${predicate}"
