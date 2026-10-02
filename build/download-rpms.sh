#!/usr/bin/env bash
#
# download-rpms.sh - download the RPM files named in an image's lock, and
#                    refuse any file that is not exactly what the lock records.
#
# Used by stage 1 of every Dockerfile.
#   reads   /lock/packages.lock.<architecture>
#   writes  /rpms/<file>.rpm
#
# Every file must pass three checks, or the build stops:
#   1. its sha256 checksum equals the one in the lock    -> it is the same file that was locked
#   2. rpm reports the package the lock says it is       -> the file is what its line claims
#   3. it carries a valid Red Hat signature              -> Red Hat built it

set -euo pipefail

lock_file="/lock/packages.lock.$(uname -m)"

fail() {
  echo "download-rpms: $*" >&2
  exit 1
}

[ -f "${lock_file}" ] || fail "${lock_file} does not exist; run build/generate-lock.sh for this architecture"

# A lock with no lines is never right. Refuse it here, with a clear message.
grep --quiet --invert-match '^#' "${lock_file}" || fail "${lock_file} lists no RPM files"

mkdir /rpms
cd /rpms

# A lock line looks like:  package|checksum|address|role
while IFS='|' read -r package checksum address role; do
  case "${role}" in
    ship | install) ;;
    *) fail "not a valid lock line (expected package|checksum|address|role): ${package}" ;;
  esac

  file_name=$(basename "${address}")

  curl --fail --silent --show-error --location --retry 5 --retry-all-errors --output "${file_name}" "${address}"

  echo "${checksum}  ${file_name}" | sha256sum --check --quiet \
    || fail "checksum does not match the lock: ${file_name}"

  found=$(rpm --query --package --nosignature --queryformat '%{NEVRA}' "${file_name}")
  [ "${found}" = "${package}" ] \
    || fail "the lock says ${package} but the file is ${found}"

  rpm --checksig "${file_name}" > /dev/null \
    || fail "not signed by Red Hat: ${file_name}"
done < <(grep --invert-match '^#' "${lock_file}")

echo "Downloaded and verified $(find . -name '*.rpm' | wc --lines) RPM files."
