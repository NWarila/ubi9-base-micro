#!/usr/bin/env bash
#
# download-rpms.sh - download the RPM files named in an image's lock, and
#                    refuse any file that is not exactly what the lock records.
#
# Used by stage 1 of every Dockerfile, inside the builder image.
#   reads   /lock/packages.lock.<architecture>
#   writes  /rpms/<file>.rpm
#
# Every file must pass three checks, or the build stops:
#   1. its sha256 checksum equals the one in the lock -> the same file that
#      was locked
#   2. rpm reports the package the lock says it is    -> the file is what its
#      line claims
#   3. it carries a signature from a key the builder trusts (Red Hat's)
#      -> Red Hat built it
#
# The whole lock is checked before the first download, so a bad line is
# reported at once instead of after a long download.

fail() {
  echo "download-rpms: $*" >&2
  exit 1
}

machine_arch=$(uname -m) || fail 'cannot read the architecture of this machine'
lock_file=/lock/packages.lock.$machine_arch

[[ -f $lock_file ]] \
  || fail "$lock_file does not exist;" \
          'run build/generate-lock.sh for this architecture'

# ---------------------------------------------------------------------------
# Read the lock. A line is "package|checksum|address|role"; "#" starts a
# comment. Every field is checked here, with the line number in any message.
# ---------------------------------------------------------------------------
packages=()
checksums=()
addresses=()
file_names=()
declare -A seen_file_names=()
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
  IFS='|' read -r package checksum address role <<< "$line"

  [[ $checksum =~ ^[[:xdigit:]]{64}$ ]] \
    || fail "$where: '$checksum' is not a sha256 checksum"

  [[ $role == ship || $role == install ]] \
    || fail "$where has role '$role' (expected ship or install)"

  # A package name that starts with "-" would read as an option to rpm.
  [[ $package != -* && $package != *[[:space:]]* ]] \
    || fail "$where has an invalid package field '$package'"

  # Only RPMs built for this machine, or for any machine, may be installed.
  package_arch=${package##*.}
  [[ $package_arch == "$machine_arch" || $package_arch == noarch ]] \
    || fail "$where is for architecture '$package_arch'" \
            "(expected $machine_arch or noarch)"

  # The address must be a plain https URL, with a host, that ends in the
  # RPM's file name.
  [[ $address =~ ^https://[^/]+/ ]] \
    || fail "$where: address is not an https URL: $address"
  [[ $address != *'?'* && $address != *'#'* && $address != *[[:space:]]* ]] \
    || fail "$where: address must not contain a query, a fragment" \
            "or whitespace: $address"
  file_name=${address##*/}
  [[ $file_name =~ ^[[:alnum:]][[:alnum:]_.+~^-]*\.rpm$ ]] \
    || fail "$where: address does not end in an RPM file name: $address"

  # Two lines must never write the same file.
  [[ -z ${seen_file_names[$file_name]} ]] \
    || fail "$where reuses the file name '$file_name'" \
            "(first used on line ${seen_file_names[$file_name]})"
  seen_file_names[$file_name]=$line_number

  packages+=("$package")
  checksums+=("$checksum")
  addresses+=("$address")
  file_names+=("$file_name")
done < "$lock_file"

(( ${#packages[@]} > 0 )) || fail "$lock_file lists no RPM files"

# ---------------------------------------------------------------------------
# Download and verify each file.
# ---------------------------------------------------------------------------
# /rpms must not exist yet: stage 2 installs every file found in it, so it may
# hold nothing but the files checked below.
mkdir /rpms || fail 'cannot create /rpms'
cd /rpms || fail 'cannot enter /rpms'

for i in "${!packages[@]}"; do
  package=${packages[i]}
  checksum=${checksums[i]}
  address=${addresses[i]}
  file_name=${file_names[i]}

  # --proto =https  a redirect may not lead to a plain http address
  # --globoff       curl must not expand "{a,b}" or "[1-3]" in the address
  curl --fail --silent --show-error --location --retry 5 --retry-all-errors \
    --proto =https --globoff --output "$file_name" "$address" \
    || fail "cannot download $address"

  sha256sum --check --quiet <<< "$checksum  $file_name" > /dev/null 2>&1 \
    || fail "checksum does not match the lock: $file_name"

  # --nosignature: read the package name without judging the signature yet;
  # that is the next check's job.
  found=$(rpm --query --package --nosignature --queryformat '%{NEVRA}' \
    "$file_name") \
    || fail "rpm cannot read $file_name"
  [[ $found == "$package" ]] \
    || fail "the lock says $package but the file is $found"

  # By default rpm is satisfied by intact digests and lets an UNSIGNED file
  # through. "_pkgverify_level all" makes a trusted signature a requirement.
  signature=$(rpm --define '_pkgverify_level all' --checksig "$file_name" \
    2>&1) \
    || fail "not signed by a key the builder trusts: $file_name ($signature)"
done

echo "Downloaded and verified ${#packages[@]} RPM files."
