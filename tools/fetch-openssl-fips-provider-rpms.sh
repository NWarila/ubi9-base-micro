#!/usr/bin/env bash
# Purpose: Fetch the pinned OpenSSL FIPS provider RPMs (provider + -so NEVRA) for the target arch from the Red Hat UBI
# CDN, verify each sha256 + rpm -K signature, and write a direct-rpms.lock manifest.
# Role: container-build
# Python-convertible: partial — fetch/verify glue, but per-arch NEVRA/sha branching would share cleanly with
# fetch-runtime-rpms in Python; runs in-container against rpm so not a strong yes.
# Relocate: yes — build-process fetch script (also COPYed into the capture Dockerfile); move under
# containers/scripts/.

set -euo pipefail

usage() {
  cat >&2 << 'EOF'
usage: fetch-openssl-fips-provider-rpms.sh --targetarch amd64|arm64 --dest DIR
EOF
}

targetarch=""
dest=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --targetarch)
      targetarch="${2:-}"
      shift 2
      ;;
    --dest)
      dest="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${targetarch}" || -z "${dest}" ]]; then
  usage
  exit 2
fi

provider_so_nevra="${OPENSSL_FIPS_PROVIDER_NEVRA:-openssl-fips-provider-so-3.0.7-8.el9}"
provider_nvr="${provider_so_nevra#openssl-fips-provider-so-}"
if [[ "${provider_nvr}" == "${provider_so_nevra}" ]]; then
  echo "invalid FIPS provider NEVRA pin: ${provider_so_nevra}" >&2
  exit 1
fi

case "${targetarch}" in
  amd64)
    basearch="x86_64"
    provider_sha="${OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64:?missing OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64}"
    provider_so_sha="${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64:?missing OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64}"
    ;;
  arm64)
    basearch="aarch64"
    provider_sha="${OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64:?missing OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64}"
    provider_so_sha="${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64:?missing OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64}"
    ;;
  *)
    echo "unsupported TARGETARCH for FIPS provider RPM fetch: ${targetarch}" >&2
    exit 1
    ;;
esac

base_url="${OPENSSL_FIPS_PROVIDER_RPM_BASE_URL:-https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9}"
package_dir="${base_url%/}/${basearch}/baseos/os/Packages/o"
provider_nevra="openssl-fips-provider-${provider_nvr}.${basearch}"
provider_so_full_nevra="${provider_so_nevra}.${basearch}"

mkdir -p "${dest}"
manifest="${dest}/direct-rpms.lock"
: > "${manifest}"

rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

fetch_one() {
  local nevra="$1"
  local expected_sha="$2"
  local url="${package_dir}/${nevra}.rpm"
  local path="${dest}/${nevra}.rpm"
  local tmp="${path}.tmp"
  local actual_sha
  local sig_output

  curl -fsSL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2 \
    --output "${tmp}" \
    "${url}"
  actual_sha="$(sha256sum "${tmp}" | awk '{print $1}')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "${url}: sha256 mismatch: expected ${expected_sha}, got ${actual_sha}" >&2
    exit 1
  fi
  mv "${tmp}" "${path}"

  sig_output="$(rpm -K "${path}")"
  printf '%s\n' "${sig_output}"
  if [[ "${sig_output}" != *"digests signatures OK"* ]]; then
    echo "${path}: Red Hat RPM signature verification did not report digests signatures OK" >&2
    exit 1
  fi

  printf '# direct_rpm: %s|%s|%s\n' "${nevra}" "${url}" "${expected_sha}" >> "${manifest}"
}

fetch_one "${provider_nevra}" "${provider_sha}"
fetch_one "${provider_so_full_nevra}" "${provider_so_sha}"
