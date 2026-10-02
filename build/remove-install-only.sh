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

mapfile -t install_only < <(grep '|install$' "${lock_file}" | cut --delimiter='|' --fields=1)

if [ "${#install_only[@]}" -eq 0 ]; then
  echo "Nothing to remove: every installed package ships in this image."
  exit 0
fi

# --nodeps     remove them although shipped packages name them as dependencies;
#              leaving those dependencies out is the purpose of a minimal image
# --noscripts  do not run uninstall scripts; they need the shell being removed
rpm --root=/rootfs --erase --nodeps --noscripts "${install_only[@]}"

echo "Removed ${#install_only[@]} install-only packages."
