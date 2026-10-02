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
# WHAT IT CHECKS
#   images/<image>/digests.txt records the digest each lock is known to produce,
#   one line per architecture. After the build, the new digest must equal the
#   recorded one, or the script stops. When the lock changes on purpose, update
#   the recorded line with the digest this script prints.
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

[[ "${image}" =~ ^[a-z0-9-]+$ ]] \
  || fail "image name '${image}' must contain only lower-case letters, digits, and hyphens"

case "${arch}" in
  x86_64)  platform=linux/amd64 ;;
  aarch64) platform=linux/arm64 ;;
  *) fail "unknown architecture '${arch}' (expected x86_64 or aarch64)" ;;
esac

lock_file="images/${image}/packages.lock.${arch}"
[ -f "${lock_file}" ] || fail "${lock_file} does not exist; run build/generate-lock.sh for this architecture"

# Match the tag broadly first so duplicate or malformed epoch lines cannot hide.
mapfile -t source_date_epoch_lines < <(grep '^# source-date-epoch' "${lock_file}" || true)
[ "${#source_date_epoch_lines[@]}" -eq 1 ] \
  || fail "${lock_file} must contain exactly one source-date-epoch line"

source_date_epoch_line=${source_date_epoch_lines[0]}
case "${source_date_epoch_line}" in
  '# source-date-epoch: '*) source_date_epoch=${source_date_epoch_line#'# source-date-epoch: '} ;;
  *) fail "${lock_file} has a malformed source-date-epoch line" ;;
esac
[[ "${source_date_epoch}" =~ ^[0-9]+$ ]] \
  || fail "${lock_file} source-date-epoch must contain digits only"

mkdir --parents dist
metadata_file="dist/ubi9-${image}.${arch}.json"

# Empty old metadata so a successful docker command cannot leave a stale digest.
: > "${metadata_file}"

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
  --metadata-file "${metadata_file}" \
  .

[ -s "${metadata_file}" ] || fail "the build wrote no image metadata to ${metadata_file}"
digest=$(sed --quiet 's/.*"containerimage.digest": *"\([^"]*\)".*/\1/p' "${metadata_file}")
[ -n "${digest}" ] || fail "${metadata_file} contains no image digest"
echo "Built dist/ubi9-${image}.${arch}.tar"
echo "Image digest: ${digest}"

# Compare with the recorded digest for this architecture.
digests_file="images/${image}/digests.txt"
[ -f "${digests_file}" ] || fail "${digests_file} does not exist; record this line in it:  ${arch} ${digest}"
recorded=$(sed --quiet "s/^${arch} //p" "${digests_file}")
[ -n "${recorded}" ] || fail "${digests_file} has no ${arch} line; record this line in it:  ${arch} ${digest}"
if [ "${digest}" != "${recorded}" ]; then
  echo "build-image: the image differs from the one recorded in ${digests_file}" >&2
  echo "  recorded: ${arch} ${recorded}" >&2
  echo "  built:    ${arch} ${digest}" >&2
  echo "  If the lock changed on purpose, replace the recorded line with the built one." >&2
  exit 1
fi
echo "Digest matches ${digests_file}."
