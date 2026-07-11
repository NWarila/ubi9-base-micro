#!/usr/bin/env bash
# Purpose: Regenerate / --check / --self-test rpm-lock/runtime.<arch>.txt via a capture Dockerfile (install runtime
# set, ldd-protected strip of shells/pkg-managers/unneeded deps, resolve direct CDN URLs) plus host-side
# lockfile-grammar validation against committed files and Dockerfile ARG pins.
# Role: tooling
# Python-convertible: conforming boundary — Python owns parse/decide/render logic; shell retains buildx, package/fetch
# command orchestration, frozen snapshots, and file plumbing.
# Micro-container candidate: no — maintainer regeneration tool, not a per-PR gate.
# Relocate: no — dev/regeneration driver and its Python policy helpers remain under tools/.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 << 'EOF'
usage: generate-rpm-lock.sh [--arch amd64|arm64|all] [--output-dir DIR]
       generate-rpm-lock.sh --check [--arch amd64|arm64|all]
       generate-rpm-lock.sh --self-test

Regenerates rpm-lock/runtime.<arch>.txt from the current UBI 9 repositories.
EOF
}

dockerfile_arg_default() {
  local name="$1"
  python3 "${repo_root}/tools/rpmlock.py" arg-default --repo-root "${repo_root}" --name "${name}"
}

source_date_epoch="${SOURCE_DATE_EPOCH:-$(dockerfile_arg_default SOURCE_DATE_EPOCH)}"
ubi_minimal_image="${UBI_MINIMAL_IMAGE:-$(dockerfile_arg_default UBI_MINIMAL_IMAGE)}"
openssl_fips_provider_nevra="${OPENSSL_FIPS_PROVIDER_NEVRA:-$(dockerfile_arg_default OPENSSL_FIPS_PROVIDER_NEVRA)}"
openssl_fips_provider_rpm_base_url="${OPENSSL_FIPS_PROVIDER_RPM_BASE_URL:-$(dockerfile_arg_default OPENSSL_FIPS_PROVIDER_RPM_BASE_URL)}"
openssl_fips_provider_rpm_sha256_x86_64="${OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64:-$(dockerfile_arg_default OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64)}"
openssl_fips_provider_rpm_sha256_aarch64="${OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64:-$(dockerfile_arg_default OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64)}"
openssl_fips_provider_so_rpm_sha256_x86_64="${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64:-$(dockerfile_arg_default OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64)}"
openssl_fips_provider_so_rpm_sha256_aarch64="${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64:-$(dockerfile_arg_default OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64)}"
dnf_repos="${DNF_REPOS:-}"

validate_arch() {
  case "$1" in
    amd64 | arm64 | all) ;;
    *)
      echo "unsupported architecture: $1" >&2
      return 2
      ;;
  esac
}

arches_for() {
  case "$1" in
    all) printf 'amd64\narm64\n' ;;
    amd64 | arm64) printf '%s\n' "$1" ;;
    *) return 2 ;;
  esac
}

write_capture_dockerfile() {
  local dockerfile="$1"
  cat > "${dockerfile}" << 'DOCKERFILE'
# syntax=docker/dockerfile:1.7

ARG UBI_MINIMAL_IMAGE
FROM ${UBI_MINIMAL_IMAGE} AS capture

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TARGETARCH
ARG DNF_REPOS=""
ARG OPENSSL_FIPS_PROVIDER_NEVRA
ARG OPENSSL_FIPS_PROVIDER_RPM_BASE_URL
ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64
ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64
ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64
ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64
ARG SOURCE_DATE_EPOCH

COPY rpm-lock/builder.amd64.txt rpm-lock/builder.arm64.txt /tmp/rpm-lock/
COPY tools/assert-builder-toolchain-floor.sh /tmp/assert-builder-toolchain-floor.sh
COPY tools/build-runtime-rootfs.py /tmp/build-runtime-rootfs.py
COPY tools/fetch-builder-rpms.sh /tmp/fetch-builder-rpms.sh
COPY fetch-openssl-fips-provider-rpms.sh /usr/local/bin/fetch-openssl-fips-provider-rpms.sh
COPY tools/rpmlock.py /tmp/rpmlock.py
COPY tools/generate-runtime-lock.py /tmp/generate-runtime-lock.py

RUN <<'CAPTURE'
set -euo pipefail

case "${TARGETARCH}" in
  amd64) rpm_arch="x86_64" ;;
  arm64) rpm_arch="aarch64" ;;
  *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;;
esac
case "${TARGETARCH}" in
  amd64) builder_lockfile="/tmp/rpm-lock/builder.amd64.txt" ;;
  arm64) builder_lockfile="/tmp/rpm-lock/builder.arm64.txt" ;;
  *) echo "unsupported TARGETARCH for builder RPM lockfile: ${TARGETARCH}" >&2; exit 1 ;;
esac
dnf_repo_args=()
if [[ -n "${DNF_REPOS}" ]]; then
  dnf_repo_args=(--disablerepo='*' "--enablerepo=${DNF_REPOS}")
fi

test -s "${builder_lockfile}" || {
  echo "builder RPM lockfile missing: ${builder_lockfile}" >&2
  exit 1
}
builder_rpm_paths=()
while IFS='|' read -r package name epoch version release arch sha256_header sigmd5; do
  case "${package}" in ""|\#*) continue ;; esac
  test -n "${name}" && test -n "${epoch}" && test -n "${version}" && test -n "${release}" &&
    test -n "${arch}" && test -n "${sha256_header}" && test -n "${sigmd5}"
  case "${arch}" in
    noarch|"${rpm_arch}") ;;
    *) echo "locked builder package ${package} has wrong arch ${arch} for ${TARGETARCH}" >&2; exit 1 ;;
  esac
  builder_rpm_paths+=("/tmp/builder-rpms/${name}-${version}-${release}.${arch}.rpm")
done < "${builder_lockfile}"
test "${#builder_rpm_paths[@]}" -eq 7 || {
  echo "builder RPM lockfile must yield exactly 7 packages" >&2
  exit 1
}
snapshot_builder_toolchain() {
  snapshot="$1"
  : > "${snapshot}"
  for package in rpm rpm-libs sqlite-libs glibc glibc-common; do
    nevra="$(rpm -q --qf '%{NEVRA}\n' "${package}")"
    printf '%s|%s\n' "${package}" "${nevra}" >> "${snapshot}"
  done
}
snapshot_builder_toolchain /tmp/builder-toolchain.before
mkdir -p /tmp/builder-rpms
bash /tmp/fetch-builder-rpms.sh --targetarch "${TARGETARCH}" --lockfile "${builder_lockfile}" --dest /tmp/builder-rpms
echo "installing locked builder Python RPM transaction"
rpm -Uvh --oldpackage --replacepkgs --excludedocs "${builder_rpm_paths[@]}"
snapshot_builder_toolchain /tmp/builder-toolchain.after
bash /tmp/assert-builder-toolchain-floor.sh --before /tmp/builder-toolchain.before --after /tmp/builder-toolchain.after
python3.12 -c 'import sys; print(sys.version)'
rm -rf /tmp/builder-rpms /tmp/builder-toolchain.before /tmp/builder-toolchain.after

openssl_fips_provider_nevra="${OPENSSL_FIPS_PROVIDER_NEVRA}"
fips_provider_nvr="$(
  python3.12 /tmp/generate-runtime-lock.py provider-nvr --nevra "${openssl_fips_provider_nevra}"
)"
python3.12 /tmp/generate-runtime-lock.py package-specs > /tmp/runtime-package-specs
mapfile -t runtime_package_specs < /tmp/runtime-package-specs

mkdir -p /rootfs /out /tmp/fips-provider-rpms
OPENSSL_FIPS_PROVIDER_NEVRA="${OPENSSL_FIPS_PROVIDER_NEVRA}" \
OPENSSL_FIPS_PROVIDER_RPM_BASE_URL="${OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}" \
OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64="${OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64}" \
OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64="${OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64}" \
OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64="${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64}" \
OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64="${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64}" \
  bash /usr/local/bin/fetch-openssl-fips-provider-rpms.sh --targetarch "${TARGETARCH}" --dest /tmp/fips-provider-rpms
microdnf install -y --installroot=/rootfs --releasever=9 \
  --config=/etc/dnf/dnf.conf --noplugins \
  --setopt=reposdir=/etc/yum.repos.d \
  --setopt=varsdir=/etc/dnf/vars \
  --setopt=cachedir=/var/cache/microdnf-installroot \
  --nodocs --setopt=install_weak_deps=0 \
  "${dnf_repo_args[@]}" \
  "${runtime_package_specs[@]}"
microdnf clean all
rm -rf /rootfs/var/cache/* /var/cache/microdnf-installroot \
  /rootfs/var/log/dnf.log /rootfs/var/log/dnf.librepo.log /rootfs/var/log/hawkey.log
rpm --root=/rootfs -Uvh --oldpackage --replacepkgs \
  "/tmp/fips-provider-rpms/openssl-fips-provider-${fips_provider_nvr}.${rpm_arch}.rpm" \
  "/tmp/fips-provider-rpms/${openssl_fips_provider_nevra}.${rpm_arch}.rpm"

rpm --root=/rootfs -qa \
  --qf '%{NEVRA}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SHA256HEADER}|%{SIGMD5}\n' \
  | LC_ALL=C sort > /tmp/runtime.full.tsv

python3.12 /tmp/build-runtime-rootfs.py strip-packages --rootfs /rootfs

rpm --root=/rootfs -qa --qf '%{NEVRA}\n' | LC_ALL=C sort > /tmp/runtime.final.nevras
python3.12 /tmp/generate-runtime-lock.py validate-floor \
  --full-rows /tmp/runtime.full.tsv \
  --final-nevras /tmp/runtime.final.nevras

rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
mkdir -p /tmp/direct-runtime-rpms
: > /tmp/runtime.direct.tsv
python3.12 /tmp/generate-runtime-lock.py candidates \
  --full-rows /tmp/runtime.full.tsv \
  --arch "${TARGETARCH}" \
  --base-url "${OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}" \
  > /tmp/runtime.candidates.tsv

fetch_direct_rpm_for_row() {
  local package="$1"
  local baseos_url="$2"
  local appstream_url="$3"
  local url filename tmp path actual_sha

  for url in "${baseos_url}" "${appstream_url}"; do
    filename="${url##*/}"
    tmp="/tmp/direct-runtime-rpms/${filename}.tmp"
    if curl -fL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2 --output "${tmp}" "${url}"; then
      actual_sha="$(sha256sum "${tmp}" | awk '{print $1}')"
      path="/tmp/direct-runtime-rpms/${filename}"
      mv "${tmp}" "${path}"
      rpm -K "${path}" | tee /tmp/runtime.signature-output
      python3.12 /tmp/generate-runtime-lock.py signature-output --output /tmp/runtime.signature-output
      printf '%s|%s|%s\n' "${package}" "${url}" "${actual_sha}" >> /tmp/runtime.direct.tsv
      return 0
    fi
    rm -f "${tmp}"
  done

  echo "could not resolve direct CDN URL for ${package}" >&2
  exit 1
}

while IFS='|' read -r package baseos_url appstream_url; do
  fetch_direct_rpm_for_row "${package}" "${baseos_url}" "${appstream_url}"
done < /tmp/runtime.candidates.tsv

python3.12 /tmp/generate-runtime-lock.py render \
  --full-rows /tmp/runtime.full.tsv \
  --final-nevras /tmp/runtime.final.nevras \
  --direct-results /tmp/runtime.direct.tsv \
  --arch "${TARGETARCH}" \
  --source-date-epoch "${SOURCE_DATE_EPOCH}" \
  --output "/out/runtime.${TARGETARCH}.txt"
CAPTURE

FROM scratch AS export
COPY --from=capture /out/ /
DOCKERFILE
}

validate_lockfile() {
  local path="$1"
  local platform_arch="$2"

  python3 "${repo_root}/tools/rpmlock.py" validate \
    --lockfile "${path}" \
    --arch "${platform_arch}" \
    --source-date-epoch "${source_date_epoch}" \
    --openssl-fips-provider-nevra "${openssl_fips_provider_nevra}" \
    --openssl-fips-provider-rpm-base-url "${openssl_fips_provider_rpm_base_url}" \
    --openssl-fips-provider-rpm-sha256-x86-64 "${openssl_fips_provider_rpm_sha256_x86_64}" \
    --openssl-fips-provider-rpm-sha256-aarch64 "${openssl_fips_provider_rpm_sha256_aarch64}" \
    --openssl-fips-provider-so-rpm-sha256-x86-64 "${openssl_fips_provider_so_rpm_sha256_x86_64}" \
    --openssl-fips-provider-so-rpm-sha256-aarch64 "${openssl_fips_provider_so_rpm_sha256_aarch64}"
}
generate_one() {
  local platform_arch="$1"
  local output_dir="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir:-}"' RETURN

  write_capture_dockerfile "${tmpdir}/Dockerfile"
  mkdir -p "${tmpdir}/rpm-lock" "${tmpdir}/tools" "${tmpdir}/out"
  cp "${repo_root}/rpm-lock/builder.amd64.txt" "${repo_root}/rpm-lock/builder.arm64.txt" "${tmpdir}/rpm-lock/"
  cp "${repo_root}/tools/assert-builder-toolchain-floor.sh" "${repo_root}/tools/build-runtime-rootfs.py" \
    "${repo_root}/tools/fetch-builder-rpms.sh" "${repo_root}/tools/rpmlock.py" \
    "${repo_root}/tools/generate-runtime-lock.py" "${tmpdir}/tools/"
  cp "${repo_root}/tools/fetch-openssl-fips-provider-rpms.sh" "${tmpdir}/fetch-openssl-fips-provider-rpms.sh"

  docker buildx build \
    --progress plain \
    --platform "linux/${platform_arch}" \
    --target export \
    --build-arg "UBI_MINIMAL_IMAGE=${ubi_minimal_image}" \
    --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
    --build-arg "DNF_REPOS=${dnf_repos}" \
    --build-arg "OPENSSL_FIPS_PROVIDER_NEVRA=${openssl_fips_provider_nevra}" \
    --build-arg "OPENSSL_FIPS_PROVIDER_RPM_BASE_URL=${openssl_fips_provider_rpm_base_url}" \
    --build-arg "OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64=${openssl_fips_provider_rpm_sha256_x86_64}" \
    --build-arg "OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64=${openssl_fips_provider_rpm_sha256_aarch64}" \
    --build-arg "OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64=${openssl_fips_provider_so_rpm_sha256_x86_64}" \
    --build-arg "OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64=${openssl_fips_provider_so_rpm_sha256_aarch64}" \
    --output "type=local,dest=${tmpdir}/out" \
    "${tmpdir}"

  mkdir -p "${output_dir}"
  cp "${tmpdir}/out/runtime.${platform_arch}.txt" "${output_dir}/runtime.${platform_arch}.txt"
  validate_lockfile "${output_dir}/runtime.${platform_arch}.txt" "${platform_arch}"
  echo "generated ${output_dir}/runtime.${platform_arch}.txt"
}

run_check() {
  local arch="$1"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir:-}"' RETURN

  local generated_dir="${tmpdir}/rpm-lock"
  local failed=0
  local platform_arch
  local arch_list
  arch_list="$(arches_for "${arch}")"
  while IFS= read -r platform_arch; do
    generate_one "${platform_arch}" "${generated_dir}"
    local expected="${repo_root}/rpm-lock/runtime.${platform_arch}.txt"
    local generated="${generated_dir}/runtime.${platform_arch}.txt"
    if ! cmp -s "${expected}" "${generated}"; then
      echo "RPM lockfile drift detected for ${platform_arch}: ${expected}" >&2
      diff -u "${expected}" "${generated}" >&2 || true
      failed=1
    fi
  done <<< "${arch_list}"

  [[ "${failed}" -eq 0 ]] || return 1
  echo "RPM lockfile check: ok (generated lockfiles match committed files)"
}

run_self_test() {
  validate_lockfile "${repo_root}/rpm-lock/runtime.amd64.txt" amd64
  validate_lockfile "${repo_root}/rpm-lock/runtime.arm64.txt" arm64
  echo "RPM lock generator self-test: ok"
}
main() {
  local arch="all"
  local output_dir="${repo_root}/rpm-lock"
  local mode="generate"

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --arch)
        arch="${2:-}"
        shift 2
        ;;
      --output-dir)
        output_dir="${2:-}"
        shift 2
        ;;
      --check)
        mode="check"
        shift
        ;;
      --self-test)
        mode="self-test"
        shift
        ;;
      -h | --help)
        usage
        return 0
        ;;
      *)
        usage
        return 2
        ;;
    esac
  done

  validate_arch "${arch}"

  if [[ "${mode}" == "self-test" ]]; then
    run_self_test
    return 0
  fi

  [[ "${ubi_minimal_image}" =~ @sha256:[0-9a-f]{64}$ ]] || {
    echo "UBI_MINIMAL_IMAGE must be digest-pinned; got '${ubi_minimal_image}'" >&2
    return 1
  }
  [[ "${source_date_epoch}" =~ ^[0-9]+$ ]] || {
    echo "SOURCE_DATE_EPOCH must be numeric; got '${source_date_epoch}'" >&2
    return 1
  }

  if [[ "${mode}" == "check" ]]; then
    run_check "${arch}"
    return 0
  fi

  local platform_arch
  local arch_list
  arch_list="$(arches_for "${arch}")"
  while IFS= read -r platform_arch; do
    generate_one "${platform_arch}" "${output_dir}"
  done <<< "${arch_list}"
}

main "$@"
