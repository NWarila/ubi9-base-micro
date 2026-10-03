#!/usr/bin/env bash
#
# build-image.sh - build one image from its lock, and check the result.
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
#   images/<image>/packages.lock.<arch>    the RPM files, and the fixed date
#   images/<image>/digests.txt             the digest this lock is known to give
#
# WHAT IT WRITES
#   dist/ubi9-<image>.<arch>.tar     the image, as an OCI archive
#   dist/ubi9-<image>.<arch>.json    the build's details, including the digest
#
# WHY THE SAME LOCK ALWAYS GIVES THE SAME IMAGE
#   The lock fixes every RPM file. The only other thing that could differ
#   between two builds is time: the dates on files the build creates, and the
#   image's "created" date. The lock records one date (source-date-epoch) and
#   this script gives it to the build, which uses it in place of the clock.
#
# WHAT IT CHECKS
#   After the build, the new digest must equal the one recorded for this
#   architecture in digests.txt, or the script stops. When the lock changes on
#   purpose, replace the recorded line with the one this script prints.

fail() {
  echo "build-image: $*" >&2
  exit 1
}

case $# in
  1) arch=$(uname -m) || fail 'cannot read the architecture of this machine' ;;
  2) arch=$2 ;;
  *) fail 'usage: build/build-image.sh <image> [x86_64|aarch64]' ;;
esac
image=$1

# An image is a plain folder name under images/: no path, no capitals, and
# not an option such as --help.
[[ $image =~ ^[a-z0-9][a-z0-9-]*$ ]] \
  || fail "image name '$image' must be lower-case letters, digits and" \
          'hyphens, starting with a letter or digit'

# macOS calls the 64-bit Arm architecture arm64; the locks use Linux's name.
case $arch in
  x86_64)          platform=linux/amd64 ;;
  aarch64 | arm64) platform=linux/arm64; arch=aarch64 ;;
  *) fail "unknown architecture '$arch' (expected x86_64 or aarch64)" ;;
esac

dockerfile=images/$image/Dockerfile
lock_file=images/$image/packages.lock.$arch
digests_file=images/$image/digests.txt
archive=dist/ubi9-$image.$arch.tar
metadata_file=dist/ubi9-$image.$arch.json

[[ -f $dockerfile ]] \
  || fail "$dockerfile does not exist; run this from the repository root," \
          'naming a folder under images/'
[[ -f $lock_file ]] \
  || fail "$lock_file does not exist;" \
          'run build/generate-lock.sh for this architecture'

# The fixed date, from the lock's one "# source-date-epoch: N" line.
source_date_epoch=''
date_lines=0
# "|| [[ -n $line ]]" keeps a last line that has no newline after it.
while IFS= read -r line || [[ -n $line ]]; do
  case $line in
    '# source-date-epoch: '*)
      source_date_epoch=${line#'# source-date-epoch: '}
      ((date_lines++))
      ;;
  esac
done < "$lock_file"

((date_lines == 1)) \
  || fail "$lock_file must contain exactly one source-date-epoch line"
[[ $source_date_epoch =~ ^[0-9]+$ ]] \
  || fail "$lock_file source-date-epoch must contain digits only"

mkdir -p dist || fail 'cannot create the dist folder'

# Empty the old metadata, so a build that writes nothing cannot leave a
# stale digest behind.
: > "$metadata_file" || fail "cannot write $metadata_file"

# SOURCE_DATE_EPOCH       the fixed date: used for the image's "created" date
#                         and handed to the Dockerfile's install stage
# rewrite-timestamp=true  give that date to every file the build created;
#                         files that came out of an RPM are older and keep
#                         their own date
# --provenance, --sbom    off: they describe this particular run, so they
#                         would differ between two builds of the same lock
SOURCE_DATE_EPOCH=$source_date_epoch docker buildx build \
  --file "$dockerfile" \
  --platform "$platform" \
  --provenance=false \
  --sbom=false \
  --output "type=oci,dest=$archive,rewrite-timestamp=true" \
  --metadata-file "$metadata_file" \
  . \
  || fail "the build of $image for $arch failed"

# The digest is the "containerimage.digest" value in the metadata file:
# cut away everything before that key (searching from the end, which is
# where buildx writes it), then keep what is between the quotes.
digest=$(<"$metadata_file")
digest=${digest##*\"containerimage.digest\":}
[[ $digest =~ ^[[:space:]]*\" ]] \
  || fail "$metadata_file contains no image digest"
digest=${digest#*\"}
digest=${digest%%\"*}
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] \
  || fail "$metadata_file contains no image digest"

echo "Built $archive"
echo "Image digest: $digest"

# Compare with the digest recorded for this architecture: exactly one line
# "<arch> sha256:..." in digests.txt.
[[ -f $digests_file ]] \
  || fail "$digests_file does not exist; create it with this line:" \
          "$arch $digest"
recorded=''
recorded_lines=0
while read -r line_arch line_digest || [[ -n $line_arch ]]; do
  if [[ $line_arch == "$arch" ]]; then
    recorded=$line_digest
    ((recorded_lines++))
  fi
done < "$digests_file"

((recorded_lines == 1)) \
  || fail "$digests_file must contain exactly one $arch line; record" \
          "this line: $arch $digest"
[[ $recorded =~ ^sha256:[0-9a-f]{64}$ ]] \
  || fail "$digests_file: the $arch line is not a digest; record" \
          "this line: $arch $digest"

if [[ $digest != "$recorded" ]]; then
  echo 'build-image: the image differs from the one recorded in' >&2
  echo "  $digests_file" >&2
  echo "  recorded: $arch $recorded" >&2
  echo "  built:    $arch $digest" >&2
  echo '  If the lock changed on purpose, replace the recorded line with' >&2
  echo '  the built one.' >&2
  exit 1
fi
echo "Digest matches $digests_file."
