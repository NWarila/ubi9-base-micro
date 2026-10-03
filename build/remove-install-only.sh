#!/usr/bin/env bash
#
# remove-install-only.sh - remove the packages that were needed only to build
#                          the image.
#
# Used by stage 2 of every Dockerfile, inside the builder image, after the
# RPMs have been installed into /rootfs.
#   reads    /lock/packages.lock.<architecture>
#   changes  /rootfs
#   checks   every lock line's shape and role, that no package is listed
#            twice, and that rpm removed what it was asked to
#
# Installing an RPM needs helpers (a shell for its install scripts, the crypto
# policy tool, and so on). The lock marks those packages "install". Once the
# image's files are in place they are removed, so the finished image holds
# only the packages marked "ship".

fail() {
  echo "remove-install-only: $*" >&2
  exit 1
}

# The assignment's status is uname's, so a failure is caught here.
lock_file=/lock/packages.lock.$(uname -m) \
  || fail 'cannot read the architecture of this machine'

[[ -f $lock_file ]] || fail "$lock_file does not exist"

# Read every line, so a misspelt role cannot look like "nothing to remove".
# A line is "package|checksum|address|role"; "#" starts a comment.
install_only=()
declare -A seen_packages=()
line_number=0

# "|| [[ -n $line ]]" keeps a last line that has no newline after it.
while IFS= read -r line || [[ -n $line ]]; do
  ((line_number++))
  [[ $line == '#'* ]] && continue
  where="$lock_file line $line_number"

  # Exactly four fields, none empty, and nothing else on the line.
  [[ $line =~ ^[^|]+\|[^|]+\|[^|]+\|[^|]+$ ]] \
    || fail "$where must have exactly four fields:" \
            'package|checksum|address|role'
  IFS='|' read -r package _ _ role <<< "$line"

  # A package may appear once: never both kept and removed, never counted twice.
  [[ -z ${seen_packages[$package]} ]] \
    || fail "$where repeats package '$package'" \
            "(first used on line ${seen_packages[$package]})"
  seen_packages[$package]=$line_number

  case $role in
    ship) ;;
    install) install_only+=("$package") ;;
    *) fail "$where has role '$role' (expected ship or install)" ;;
  esac
done < "$lock_file"

(( ${#seen_packages[@]} > 0 )) || fail "$lock_file lists no packages"

if (( ${#install_only[@]} == 0 )); then
  echo 'Nothing to remove: every installed package ships in this image.'
  exit 0
fi

# --nodeps     remove them although shipped packages name them as
#              dependencies; leaving those out is the point of a minimal image
# --noscripts  do not run uninstall scripts; they need the shell being removed
# --           everything after it is a package name, never an option
rpm --root=/rootfs --erase --nodeps --noscripts -- "${install_only[@]}" \
  || fail 'rpm could not remove the install-only packages'

echo "Removed ${#install_only[@]} install-only packages."
