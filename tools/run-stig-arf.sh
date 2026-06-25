#!/usr/bin/env bash
# Purpose: Run the image-scoped RHEL9 STIG gate — assert the tailoring, oscap-podman xccdf eval to ARF+HTML, export
# the rootfs, then chain assert-rootfs-identity / assert-stig-arf (fail-closed) / generate-stig-arf-predicate.
# Role: gate
# Python-convertible: partial — orchestrator; every assertion/predicate already lives in assert-stig-*.py, only
# oscap-podman invocation + exit-code/trap handling are shell.
# Micro-container candidate: yes — STIG ARF gate; pin the oscap/podman toolchain + ARF parse in a micro-container.
# Relocate: no — verification gate, not a build-process script.

set -euo pipefail

usage() {
  cat << 'USAGE'
Usage: tools/run-stig-arf.sh <image-ref> <arch> <platform> <output-dir>

Runs the image-scoped RHEL9 STIG tailoring against an image with oscap-podman,
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
  --datastream "${datastream}"

if ! sudo podman image exists "${image_ref}" > /dev/null 2>&1; then
  if docker image inspect "${image_ref}" > /dev/null 2>&1; then
    docker save "${image_ref}" | sudo podman load
  else
    sudo podman pull --arch "${arch}" "${image_ref}"
  fi
fi

arf="${out_dir}/base-micro.${arch}.stig.arf.xml"
report="${out_dir}/base-micro.${arch}.stig.report.html"
summary="${out_dir}/base-micro.${arch}.stig.summary.json"
predicate="${out_dir}/stig-arf.base-micro.${arch}.json"
rootfs_tar="${out_dir}/base-micro.${arch}.rootfs.tar"
identity_summary="${out_dir}/base-micro.${arch}.rootfs-identity.json"
identity_container_id=""

cleanup_identity_container() {
  if [[ -n "${identity_container_id}" ]]; then
    sudo podman rm "${identity_container_id}" > /dev/null 2>&1
  fi
}
trap cleanup_identity_container EXIT

oscap_status=0
if sudo oscap-podman "${image_ref}" xccdf eval \
  --tailoring-file "${tailoring}" \
  --profile "${profile}" \
  --results-arf "${arf}" \
  --report "${report}" \
  "${datastream}"; then
  oscap_status=0
else
  oscap_status=$?
fi

if [[ "${oscap_status}" != "0" && "${oscap_status}" != "2" ]]; then
  echo "oscap-podman failed with unexpected status ${oscap_status}" >&2
  exit "${oscap_status}"
fi

identity_container_id="$(sudo podman create "${image_ref}" /stig-rootfs-export)"
sudo podman export --output "${rootfs_tar}" "${identity_container_id}"
sudo podman rm "${identity_container_id}" > /dev/null
identity_container_id=""

python "${repo_root}/tools/assert-rootfs-identity.py" \
  --rootfs-tar "${rootfs_tar}" \
  --report "${identity_summary}"

python "${repo_root}/tools/assert-stig-arf.py" \
  --arf "${arf}" \
  --fail-on "${fail_on}" \
  --equivalent-assertions "${identity_summary}" \
  --summary "${summary}"

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
  --output "${predicate}"

echo "STIG ARF gate passed for ${image_ref} (${platform})"
echo "ARF: ${arf}"
echo "HTML report: ${report}"
echo "Predicate: ${predicate}"
