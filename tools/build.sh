#!/usr/bin/env bash
# Purpose: Build the runtime + dev images with docker buildx — derive OCI labels from VERSION/git, enforce
# digest-pinned UBI bases, emit reproducible (rewrite-timestamp) tars, and docker load them.
# Role: container-build
# Python-convertible: no — thin docker buildx orchestration; only the digest-pin regex is logic.
# Relocate: yes — core build-process script; move under containers/scripts/.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

image_repository="${IMAGE_REPOSITORY:-ghcr.io/nwarila/ubi9-base-micro}"
runtime_image="${RUNTIME_IMAGE:-${image_repository}:base-micro}"
dev_image="${DEV_IMAGE:-${image_repository}:base-micro-dev}"
platform="${PLATFORM:-linux/amd64}"
ubi_minimal_image="${UBI_MINIMAL_IMAGE:-registry.access.redhat.com/ubi9/ubi-minimal@sha256:2e8edce823a48e51858f1fad3ff4cbf6875ce8a3f86b9eecf298bc2050c8652a}"
ubi_micro_image="${UBI_MICRO_IMAGE:-registry.access.redhat.com/ubi9/ubi-micro@sha256:b1e86b97028b8fcfb6d85f997c39e6b6b67496163ef8d80d243220a4918e8bef}"
source_date_epoch="${SOURCE_DATE_EPOCH:-1704067200}"
oci_version="${OCI_VERSION:-$(tr -d '[:space:]' < "${repo_root}/VERSION")}"
oci_revision="${OCI_REVISION:-$(git -C "${repo_root}" rev-parse --short=12 HEAD 2> /dev/null)}"
oci_revision="${oci_revision:-local}"
oci_created="${OCI_CREATED:-2024-01-01T00:00:00Z}"
image_output_dir="${IMAGE_OUTPUT_DIR:-${repo_root}/dist/images}"

for value in "${ubi_minimal_image}" "${ubi_micro_image}"; do
  if [[ ! "${value}" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "UBI base image must be digest-pinned; got '${value}'" >&2
    exit 1
  fi
done

common_args=(
  --platform "${platform}"
  --provenance=false
  --sbom=false
  --build-arg "UBI_MINIMAL_IMAGE=${ubi_minimal_image}"
  --build-arg "UBI_MICRO_IMAGE=${ubi_micro_image}"
  --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}"
  --build-arg "OCI_CREATED=${oci_created}"
  --build-arg "OCI_REVISION=${oci_revision}"
  --build-arg "OCI_VERSION=${oci_version}"
  --file "${repo_root}/containers/Dockerfile"
)

build_image() {
  local target="$1"
  local tag="$2"
  local tar_name="$3"
  local image_tar="${image_output_dir}/${tar_name}"

  mkdir -p "${image_output_dir}"
  rm -f "${image_tar}"

  docker buildx build \
    "${common_args[@]}" \
    --target "${target}" \
    --tag "${tag}" \
    --output "type=docker,dest=${image_tar},rewrite-timestamp=true" \
    "${repo_root}"

  docker load -i "${image_tar}" > /dev/null
}

build_image runtime "${runtime_image}" base-micro.runtime.docker.tar
build_image dev "${dev_image}" base-micro-dev.docker.tar

echo "built ${runtime_image}"
echo "built ${dev_image}"
