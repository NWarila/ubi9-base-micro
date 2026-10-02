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

machine_arch=$(uname -m)
lock_file="/lock/packages.lock.${machine_arch}"

fail() {
  echo "download-rpms: $*" >&2
  exit 1
}

[ -f "${lock_file}" ] || fail "${lock_file} does not exist; run build/generate-lock.sh for this architecture"

# Without a final newline, read can silently skip the last lock row.
if [ -s "${lock_file}" ] && ! tail --bytes=1 "${lock_file}" | grep --quiet '^$'; then
  fail "${lock_file} does not end with a newline"
fi

declare -a packages=()
declare -a checksums=()
declare -a addresses=()
declare -a file_names=()
declare -A seen_file_names=()
line_number=0

# Validate the complete lock before a malformed later row can cause partial downloads.
while IFS= read -r line; do
  line_number=$((line_number + 1))
  [[ "${line}" == \#* ]] && continue

  IFS='|' read -r package checksum address role extra <<< "${line}"
  if [ "${line}" != "${package}|${checksum}|${address}|${role}" ] || [ -n "${extra}" ]; then
    fail "${lock_file} line ${line_number} must have exactly four fields: package|checksum|address|role"
  fi
  if [ -z "${package}" ] || [ -z "${checksum}" ] || [ -z "${address}" ] || [ -z "${role}" ]; then
    fail "${lock_file} line ${line_number} has an empty field"
  fi
  [[ "${checksum}" =~ ^[[:xdigit:]]{64}$ ]] \
    || fail "${lock_file} line ${line_number} has an invalid sha256 checksum"
  case "${role}" in
    ship | install) ;;
    *) fail "${lock_file} line ${line_number} has invalid role '${role}' (expected ship or install)" ;;
  esac

  case "${package}" in
    -* | *[[:space:]]*) fail "${lock_file} line ${line_number} has an invalid package field '${package}'" ;;
  esac
  package_arch=${package##*.}
  case "${package_arch}" in
    "${machine_arch}" | noarch) ;;
    *) fail "${lock_file} line ${line_number} has package architecture '${package_arch}' (expected ${machine_arch} or noarch)" ;;
  esac

  case "${address}" in
    https://*) ;;
    *) fail "${lock_file} line ${line_number} address is not an https URL: ${address}" ;;
  esac
  if [[ "${address}" == *\?* ]] || [[ "${address}" == *\#* ]] || [[ "${address}" == *[[:space:]]* ]]; then
    fail "${lock_file} line ${line_number} address must not contain whitespace, a query, or a fragment: ${address}"
  fi
  address_without_scheme=${address#https://}
  if [[ "${address_without_scheme}" != */* ]] || [ -z "${address_without_scheme%%/*}" ]; then
    fail "${lock_file} line ${line_number} address has no host or RPM path: ${address}"
  fi
  file_name=${address##*/}
  [[ "${file_name}" =~ ^[[:alnum:]][[:alnum:]_.+~^-]*[.]rpm$ ]] \
    || fail "${lock_file} line ${line_number} address does not end with an RPM file name: ${address}"

  if [ "${seen_file_names["${file_name}"]+present}" = present ]; then
    fail "${lock_file} line ${line_number} reuses RPM file name '${file_name}'"
  fi
  seen_file_names["${file_name}"]=${line_number}

  packages+=("${package}")
  checksums+=("${checksum}")
  addresses+=("${address}")
  file_names+=("${file_name}")
done < "${lock_file}"

lock_row_count=${#packages[@]}
[ "${lock_row_count}" -gt 0 ] || fail "${lock_file} lists no RPM files"

mkdir /rpms
cd /rpms

# Every array index is one validated package|checksum|address|role lock row.
for row_index in "${!packages[@]}"; do
  package=${packages[${row_index}]}
  checksum=${checksums[${row_index}]}
  address=${addresses[${row_index}]}
  file_name=${file_names[${row_index}]}
  curl --fail --silent --show-error --location --retry 5 --retry-all-errors --output "${file_name}" "${address}"

  echo "${checksum}  ${file_name}" | sha256sum --check --quiet \
    || fail "checksum does not match the lock: ${file_name}"

  found=$(rpm --query --package --nosignature --queryformat '%{NEVRA}' "${file_name}")
  [ "${found}" = "${package}" ] \
    || fail "the lock says ${package} but the file is ${found}"

  rpm --checksig "${file_name}" > /dev/null \
    || fail "not signed by Red Hat: ${file_name}"
done

downloaded_count=$(find . -name '*.rpm' | wc --lines)
[ "${downloaded_count}" -eq "${lock_row_count}" ] \
  || fail "downloaded ${downloaded_count} RPM files but ${lock_file} lists ${lock_row_count} rows"
echo "Downloaded and verified ${downloaded_count} RPM files."
