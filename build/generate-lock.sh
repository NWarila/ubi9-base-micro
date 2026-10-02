#!/usr/bin/env bash
#
# generate-lock.sh - write down exactly which RPM files an image is built from.
#
# WHY THIS EXISTS
#   images/<image>/packages.txt names the packages an image ships. A name is not
#   enough to build the same image twice: Red Hat publishes new versions every
#   week. This script asks the package manager which exact files those names
#   mean today, and records each file's version, checksum and download address
#   in images/<image>/packages.lock.<architecture>.
#
#   The Dockerfile installs the files in the lock and nothing else. The lock
#   only changes when someone runs this script, and the change is an ordinary
#   diff that can be reviewed.
#
# HOW TO RUN IT
#   From the repository root, inside the builder image the Dockerfiles use
#   (the BUILDER line at the top of any Dockerfile), once per architecture:
#
#     podman run --rm --platform linux/amd64 --volume "$PWD":/repo --workdir /repo \
#         <builder image> build/generate-lock.sh micro
#
#     podman run --rm --platform linux/arm64 --volume "$PWD":/repo --workdir /repo \
#         <builder image> build/generate-lock.sh micro
#
# WHAT IT READS
#   images/<image>/packages.txt    the packages the image ships
#   images/<image>/modules.txt     optional: module streams to switch on first
#                                  (for example nodejs:24)
#   build/install-tools.txt        packages needed only while an image is built
#   build/held-rpms.<arch>.txt     RPM files kept at a fixed version instead of
#                                  the one Red Hat currently publishes
#
# WHAT IT WRITES
#   images/<image>/packages.lock.<arch>, one line per RPM file:
#
#       package | sha256 checksum | download address | role
#
#   role is "ship"    - the package stays in the finished image, or
#           "install" - the package is needed only while the image is built
#                       and is removed before the image is finished.
#
#   The lock also records one date, "source-date-epoch": the date of the newest
#   file inside those RPM files. The build gives that date to every file it
#   creates itself, so the same lock always produces the same image.
#
# WHICH PACKAGES SHIP
#   A folder ending in -toolset is a build environment: it ships the listed
#   packages and everything they depend on.
#   Every other folder ships the listed packages and nothing else.

set -euo pipefail
export LC_ALL=C    # the same sort order on every machine, so the lock never reorders itself

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

fail() {
  echo "generate-lock: $*" >&2
  exit 1
}

image=${1:?"usage: build/generate-lock.sh <image>     example: build/generate-lock.sh micro"}
[[ "${image}" =~ ^[a-z0-9-]+$ ]] \
  || fail "image name '${image}' must contain only lower-case letters, digits, and hyphens"

arch=$(uname -m)                                  # x86_64 or aarch64
image_dir="images/${image}"
lock_file="${image_dir}/packages.lock.${arch}"

rpm_cache=/var/cache/generate-lock                # the package manager keeps every RPM it downloads here
trial_ship=/trial/ship                            # trial install: the listed packages only
trial_all=/trial/all                              # trial install: the listed packages plus the install tools
notes=$(mktemp --directory)                       # working files for this run

microdnf_options=(
  --assumeyes
  --releasever=9
  --noplugins
  # An empty trial directory has no repository settings; use the builder image's.
  --config=/etc/dnf/dnf.conf
  --setopt=reposdir=/etc/yum.repos.d
  --setopt=varsdir=/etc/dnf/vars
  # Keep every downloaded RPM so its checksum can be recorded.
  --setopt=cachedir="${rpm_cache}"
  --setopt=keepcache=1
  # Required dependencies only, and no documentation.
  --setopt=install_weak_deps=0
  --nodocs
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Print the entries of a list file: no comments, no blank lines, no stray spaces.
entries_of() {
  sed --expression='s/#.*//' --expression='s/^[[:space:]]*//' --expression='s/[[:space:]]*$//' "$1" \
    | grep --invert-match '^$' || true
}

# Print the name of every package installed in a trial directory.
installed_names() {
  rpm --root="$1" --query --all --queryformat '%{NAME}\n' | grep --invert-match '^gpg-pubkey$' | sort --unique
}

# Print the date of the newest file inside an RPM file, in seconds since 1970.
newest_file_date() {
  rpm --query --package --nosignature --queryformat '[%{FILEMTIMES}\n]' "$1" | sort --numeric-sort | tail --lines=1
}

# Print where a Red Hat UBI repository publishes its RPM files.
repository_address() {
  case "$1" in
    ubi-9-baseos-rpms)    echo "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/${arch}/baseos/os" ;;
    ubi-9-appstream-rpms) echo "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/${arch}/appstream/os" ;;
    *) fail "a package came from repository '$1', which this script does not know" ;;
  esac
}

# ---------------------------------------------------------------------------
# Step 1 of 6: read the lists
# ---------------------------------------------------------------------------
echo "Step 1 of 6: reading ${image_dir}/packages.txt"

[ -f "${image_dir}/packages.txt" ] || fail "${image_dir}/packages.txt does not exist"

entries_of "${image_dir}/packages.txt" | sort --unique > "${notes}/listed"
entries_of build/install-tools.txt     | sort --unique > "${notes}/tools"
mapfile -t listed < "${notes}/listed"
mapfile -t tools  < "${notes}/tools"

[ "${#listed[@]}" -gt 0 ] || fail "${image_dir}/packages.txt lists no packages"

# ---------------------------------------------------------------------------
# Step 2 of 6: switch on module streams, if the image uses any
# ---------------------------------------------------------------------------
if [ -f "${image_dir}/modules.txt" ]; then
  mapfile -t modules < <(entries_of "${image_dir}/modules.txt")
  echo "Step 2 of 6: switching on module streams: ${modules[*]}"
  for trial in "${trial_ship}" "${trial_all}"; do
    microdnf "${microdnf_options[@]}" --installroot="${trial}" module enable "${modules[@]}" > "${notes}/modules.log" 2>&1 \
      || { tail --lines=20 "${notes}/modules.log"; fail "could not switch on ${modules[*]}"; }
  done
else
  echo "Step 2 of 6: no module streams for this image"
fi

# ---------------------------------------------------------------------------
# Step 3 of 6: let the package manager choose and download the RPM files
#
# Two trial installs into empty directories. Nothing installed here reaches an
# image; the point is to learn which files the names resolve to.
#   - the first holds only what the image lists
#   - the second also holds the tools needed while building
# ---------------------------------------------------------------------------
echo "Step 3 of 6: resolving ${#listed[@]} listed packages (this downloads the RPM files)"

microdnf "${microdnf_options[@]}" --installroot="${trial_ship}" install "${listed[@]}" > "${notes}/ship.log" 2>&1 \
  || { tail --lines=20 "${notes}/ship.log"; fail "the listed packages could not be installed"; }

microdnf "${microdnf_options[@]}" --installroot="${trial_all}" install "${listed[@]}" "${tools[@]}" > "${notes}/all.log" 2>&1 \
  || { tail --lines=20 "${notes}/all.log"; fail "the listed packages plus the install tools could not be installed"; }

installed_names "${trial_ship}" > "${notes}/installed-ship"
installed_names "${trial_all}"  > "${notes}/installed-all"

# A misspelt name can be satisfied by a different package. Refuse that.
not_installed=$(comm -23 "${notes}/listed" "${notes}/installed-ship")
[ -z "${not_installed}" ] || fail "listed in packages.txt but not installed under that name: ${not_installed//$'\n'/ }"

# ---------------------------------------------------------------------------
# Step 4 of 6: decide which packages ship
# ---------------------------------------------------------------------------
case "${image}" in
  *-toolset)
    echo "Step 4 of 6: a toolset ships the listed packages and everything they depend on"
    cp "${notes}/installed-ship" "${notes}/ship-names"
    ;;
  *)
    echo "Step 4 of 6: this image ships the listed packages and nothing else"
    cp "${notes}/listed" "${notes}/ship-names"
    ;;
esac

# Every package that ships must be among the packages the build will install.
not_available=$(comm -23 "${notes}/ship-names" "${notes}/installed-all")
[ -z "${not_available}" ] || fail "would ship but would not be installed during the build: ${not_available//$'\n'/ }"

# ---------------------------------------------------------------------------
# Step 5 of 6: record every RPM file the build will install
#
# Working row format:  name|package|checksum|address|date of its newest file
# ---------------------------------------------------------------------------
echo "Step 5 of 6: recording each RPM file"

: > "${notes}/rows"
while read -r rpm_file; do
  name=$(rpm --query --package --nosignature --queryformat '%{NAME}' "${rpm_file}")

  # Skip a downloaded file that the build will not install.
  grep --quiet --line-regexp --fixed-strings "${name}" "${notes}/installed-all" || continue

  package=$(rpm --query --package --nosignature --queryformat '%{NEVRA}' "${rpm_file}")
  checksum=$(sha256sum "${rpm_file}" | cut --delimiter=' ' --fields=1)

  # The cache keeps files in <cache>/metadata/<repository>-9-<arch>/packages/<file>.rpm
  cache_folder=$(basename "$(dirname "$(dirname "${rpm_file}")")")
  repository=${cache_folder%"-9-${arch}"}

  # Red Hat publishes each file at <repository>/Packages/<first letter, lower case>/<file>.rpm
  file_name=$(basename "${rpm_file}")
  first_letter=${file_name:0:1}
  address="$(repository_address "${repository}")/Packages/${first_letter,,}/${file_name}"

  echo "${name}|${package}|${checksum}|${address}|$(newest_file_date "${rpm_file}")" >> "${notes}/rows"
done < <(find "${rpm_cache}" -name '*.rpm' | sort)

# ---------------------------------------------------------------------------
# Step 6 of 6: replace held packages with their fixed versions
#
# build/held-rpms.<arch>.txt lists RPM files by checksum and address. Each one
# is downloaded, checked against its checksum, and then takes the place of the
# version the repository currently publishes under the same name.
# ---------------------------------------------------------------------------
echo "Step 6 of 6: applying held packages from build/held-rpms.${arch}.txt"

while read -r checksum address; do
  held_file="${notes}/$(basename "${address}")"
  curl --fail --silent --show-error --location --retry 5 --retry-all-errors --output "${held_file}" "${address}"
  echo "${checksum}  ${held_file}" | sha256sum --check --quiet \
    || fail "held file does not match its recorded checksum: ${address}"

  name=$(rpm --query --package --nosignature --queryformat '%{NAME}' "${held_file}")
  package=$(rpm --query --package --nosignature --queryformat '%{NEVRA}' "${held_file}")

  # Only images that install this package need the held version.
  grep --quiet "^${name}|" "${notes}/rows" || continue

  grep --invert-match "^${name}|" "${notes}/rows" > "${notes}/rows.without-held" || true
  mv "${notes}/rows.without-held" "${notes}/rows"
  echo "${name}|${package}|${checksum}|${address}|$(newest_file_date "${held_file}")" >> "${notes}/rows"
  echo "             held: ${package}"
done < <(entries_of "build/held-rpms.${arch}.txt")

# ---------------------------------------------------------------------------
# Write the lock
# ---------------------------------------------------------------------------

# The newest file date across every RPM file in the lock.
source_date_epoch=$(cut --delimiter='|' --fields=5 "${notes}/rows" | sort --numeric-sort | tail --lines=1)

{
  echo "# GENERATED by build/generate-lock.sh - do not edit."
  echo "#"
  echo "# source-date-epoch: ${source_date_epoch}"
  echo "#   The date of the newest file inside these RPM files, in seconds since 1970."
  echo "#   The build gives this date to every file it creates itself, so the same"
  echo "#   lock always produces the same image. build/build-image.sh reads this line."
  echo "#"
  echo "# One line per RPM file installed while this image is built:"
  echo "#   package | sha256 checksum | download address | role"
  echo "# role: ship    = stays in the finished image"
  echo "#       install = needed only while building; removed before the image is finished"
  # Sorted by package name, so a refresh shows up as a small, readable diff.
  sort --field-separator='|' --key=1,1 "${notes}/rows" | while IFS='|' read -r name package checksum address _newest; do
    if grep --quiet --line-regexp --fixed-strings "${name}" "${notes}/ship-names"; then
      role=ship
    else
      role=install
    fi
    echo "${package}|${checksum}|${address}|${role}"
  done
} > "${lock_file}"

ship_count=$(grep --count '|ship$' "${lock_file}" || true)
install_count=$(grep --count '|install$' "${lock_file}" || true)
echo "Wrote ${lock_file}: ${ship_count} ship, ${install_count} install-only."
