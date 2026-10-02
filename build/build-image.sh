#!/usr/bin/env bash
#
# build-image.sh - build one image from its lock.
#
# The same command runs on a laptop and in the GitHub workflow, so both
# produce the same image.
#
# HOW TO RUN IT
#   From the repository root:
#
#     build/build-image.sh micro              for this machine's architecture
#     build/build-image.sh micro aarch64      for another architecture
#
#   It needs "docker buildx" with a BuildKit builder selected. The workflow
#   creates one from a pinned BuildKit image before it calls this script.
#
# WHAT IT READS
#   images/<image>/Dockerfile
#   images/<image>/packages.lock.<arch>
#
# WHAT IT WRITES
#   dist/ubi9-<image>.<arch>.tar     the image, as an OCI archive
#   dist/ubi9-<image>.<arch>.json    the build's details, including the image digest
#
# WHY THE SAME LOCK ALWAYS GIVES THE SAME IMAGE
#   The lock fixes every RPM file. The only other thing that could differ
#   between two builds is time: the dates on files the build creates, and the
#   image's "created" date. The lock records one date (source-date-epoch) and
#   this script gives it to the build, which uses it in place of the clock.

set -euo pipefail

image=${1:?"usage: build/build-image.sh <image> [x86_64|aarch64]     example: build/build-image.sh micro"}
arch=${2:-$(uname -m)}

fail() {
  echo "build-image: $*" >&2
  exit 1
}

case "${arch}" in
  x86_64)  platform=linux/amd64 ;;
  aarch64) platform=linux/arm64 ;;
  *) fail "unknown architecture '${arch}' (expected x86_64 or aarch64)" ;;
esac

lock_file="images/${image}/packages.lock.${arch}"
[ -f "${lock_file}" ] || fail "${lock_file} does not exist; run build/generate-lock.sh for this architecture"

# The fixed date for this build, recorded in the lock by build/generate-lock.sh.
source_date_epoch=$(sed --quiet 's/^# source-date-epoch: //p' "${lock_file}")
[ -n "${source_date_epoch}" ] || fail "${lock_file} has no source-date-epoch line; run build/generate-lock.sh again"

mkdir --parents dist

# SOURCE_DATE_EPOCH       the fixed date: used for the image's "created" date and
#                         handed to the Dockerfile's install stage
# rewrite-timestamp=true  give that date to every file the build created; files
#                         that came out of an RPM are older and keep their own date
# --provenance, --sbom    off: they describe this particular run, so they would
#                         differ between two builds of the same lock
SOURCE_DATE_EPOCH="${source_date_epoch}" docker buildx build \
  --file "images/${image}/Dockerfile" \
  --platform "${platform}" \
  --provenance=false \
  --sbom=false \
  --output "type=oci,dest=dist/ubi9-${image}.${arch}.tar,rewrite-timestamp=true" \
  --metadata-file "dist/ubi9-${image}.${arch}.json" \
  .

digest=$(sed --quiet 's/.*"containerimage.digest": *"\([^"]*\)".*/\1/p' "dist/ubi9-${image}.${arch}.json")
echo "Built dist/ubi9-${image}.${arch}.tar"
echo "Image digest: ${digest}"
