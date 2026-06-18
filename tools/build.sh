#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

image_repository="${IMAGE_REPOSITORY:-ghcr.io/nwarila/ubi9-base-micro}"
runtime_image="${RUNTIME_IMAGE:-${image_repository}:base-micro}"
dev_image="${DEV_IMAGE:-${image_repository}:base-micro-dev}"
platform="${PLATFORM:-linux/amd64}"
ubi_minimal_image="${UBI_MINIMAL_IMAGE:-registry.access.redhat.com/ubi9/ubi-minimal@sha256:ae09ecc3d754bc1726cbda3e2599cc7839e09fe1cc547ce173cf669b645be3cc}"
ubi_micro_image="${UBI_MICRO_IMAGE:-registry.access.redhat.com/ubi9/ubi-micro@sha256:b498b3ea26111ab4b81d65139f2ebd2ef9a2abb7a4588b7fdcc54889f95e9caa}"
oci_version="${OCI_VERSION:-$(tr -d '[:space:]' < "${repo_root}/VERSION")}"
oci_revision="${OCI_REVISION:-$(git -C "${repo_root}" rev-parse --short=12 HEAD 2>/dev/null)}"
oci_revision="${oci_revision:-local}"
oci_created="${OCI_CREATED:-$(git -C "${repo_root}" show -s --format=%cI HEAD 2>/dev/null)}"
oci_created="${oci_created:-1970-01-01T00:00:00Z}"

for value in "${ubi_minimal_image}" "${ubi_micro_image}"; do
  if [[ ! "${value}" =~ @sha256:[0-9a-f]{64}$ ]]; then
    echo "UBI base image must be digest-pinned; got '${value}'" >&2
    exit 1
  fi
done

common_args=(
  --load
  --platform "${platform}"
  --provenance=false
  --sbom=false
  --build-arg "UBI_MINIMAL_IMAGE=${ubi_minimal_image}"
  --build-arg "UBI_MICRO_IMAGE=${ubi_micro_image}"
  --build-arg "OCI_CREATED=${oci_created}"
  --build-arg "OCI_REVISION=${oci_revision}"
  --build-arg "OCI_VERSION=${oci_version}"
  --file "${repo_root}/containers/Dockerfile"
)

docker buildx build \
  "${common_args[@]}" \
  --target runtime \
  --tag "${runtime_image}" \
  "${repo_root}"

docker buildx build \
  "${common_args[@]}" \
  --target dev \
  --tag "${dev_image}" \
  "${repo_root}"

echo "built ${runtime_image}"
echo "built ${dev_image}"
