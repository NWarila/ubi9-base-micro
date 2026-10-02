#!/usr/bin/env bash
#
# remove-install-only.sh - remove the packages that were needed only to build
#                          the image.
#
# Used by stage 2 of every Dockerfile.
#   reads    /lock/packages.lock.<architecture>
#   changes  /rootfs
#
# Installing an RPM needs helpers (a shell for its install scripts, the crypto
# policy tool, and so on). The lock marks those packages "install". Once the
# image's files are in place they are removed, so the finished image holds
# only the packages marked "ship".

set -euo pipefail

lock_file="/lock/packages.lock.$(uname -m)"

fail() {
  echo "remove-install-only: $*" >&2
  exit 1
}

[ -f "${lock_file}" ] || fail "${lock_file} does not exist"

declare -a install_only=()
line_number=0

# Parse every row so a malformed role cannot look like there is nothing to remove.
while IFS= read -r line || [ -n "${line}" ]; do
  line_number=$((line_number + 1))
  [[ "${line}" == \#* ]] && continue

  IFS='|' read -r package checksum address role extra <<< "${line}"
  if [ "${line}" != "${package}|${checksum}|${address}|${role}" ] || [ -n "${extra}" ]; then
    fail "${lock_file} line ${line_number} must have exactly four fields: package|checksum|address|role"
  fi
  if [ -z "${package}" ] || [ -z "${checksum}" ] || [ -z "${address}" ] || [ -z "${role}" ]; then
    fail "${lock_file} line ${line_number} has an empty field"
  fi
  case "${role}" in
    ship) ;;
    install) install_only+=("${package}") ;;
    *) fail "${lock_file} line ${line_number} has invalid role '${role}' (expected ship or install)" ;;
  esac

  # A package operand beginning with a dash would be interpreted as an rpm option.
  case "${package}" in
    -*) fail "${lock_file} line ${line_number} package begins with '-': ${package}" ;;
  esac
done < "${lock_file}"

if [ "${#install_only[@]}" -eq 0 ]; then
  echo "Nothing to remove: every installed package ships in this image."
  exit 0
fi

# --nodeps     remove them although shipped packages name them as dependencies;
#              leaving those dependencies out is the purpose of a minimal image
# --noscripts  do not run uninstall scripts; they need the shell being removed
rpm --root=/rootfs --erase --nodeps --noscripts -- "${install_only[@]}"

echo "Removed ${#install_only[@]} install-only packages."
