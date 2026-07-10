#!/usr/bin/env bash
# Purpose: Fetch the builder Python closure from direct CDN pins and verify each blob's sha256, Red Hat signature,
# and locked RPM header fields before installation.
# Role: container-build
# Python-convertible: yes — builder lock parsing can converge on rpmlock.py after the builder gains a consumer.
# Relocate: yes — build-process fetch script; move under containers/scripts/.

set -euo pipefail

usage() {
  cat >&2 << 'EOF'
usage: fetch-builder-rpms.sh --targetarch amd64|arm64 --lockfile LOCKFILE --dest DIR
EOF
}

targetarch=""
lockfile=""
dest=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --targetarch)
      targetarch="${2:-}"
      shift 2
      ;;
    --lockfile)
      lockfile="${2:-}"
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

if [[ -z "${targetarch}" || -z "${lockfile}" || -z "${dest}" ]]; then
  usage
  exit 2
fi

case "${targetarch}" in
  amd64) rpm_arch="x86_64" ;;
  arm64) rpm_arch="aarch64" ;;
  *)
    echo "unsupported TARGETARCH for builder RPM fetch: ${targetarch}" >&2
    exit 1
    ;;
esac

[[ -s "${lockfile}" ]] || {
  echo "builder RPM lockfile missing or empty: ${lockfile}" >&2
  exit 1
}

mkdir -p "${dest}"
manifest="${dest%/}/direct-builder-rpms.lock"
: > "${manifest}"

rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

declare -A direct_rpm_sha=()
declare -A direct_rpm_url=()
declare -A direct_rpm_seen=()
declare -A row_seen=()

while IFS= read -r line; do
  case "${line}" in
    "# direct_rpm: "*)
      direct_payload="${line#\# direct_rpm: }"
      IFS='|' read -r direct_package direct_url direct_sha direct_extra <<< "${direct_payload}"
      if [[ -n "${direct_extra:-}" || -z "${direct_package}" || -z "${direct_url}" || -z "${direct_sha}" ]]; then
        echo "invalid direct builder RPM lock entry: ${line}" >&2
        exit 1
      fi
      [[ "${direct_url}" == https://cdn-ubi.redhat.com/* ]] || {
        echo "direct builder RPM source must be the Red Hat UBI CDN for ${direct_package}: ${direct_url}" >&2
        exit 1
      }
      [[ "${direct_sha}" =~ ^[0-9a-f]{64}$ ]] || {
        echo "invalid direct builder RPM sha256 for ${direct_package}: ${direct_sha}" >&2
        exit 1
      }
      if [[ -n "${direct_rpm_sha[${direct_package}]+set}" ]]; then
        echo "duplicate direct builder RPM lock entry: ${direct_package}" >&2
        exit 1
      fi
      direct_rpm_sha["${direct_package}"]="${direct_sha}"
      direct_rpm_url["${direct_package}"]="${direct_url}"
      ;;
    *) ;;
  esac
done < "${lockfile}"

fetch_one() {
  local package="$1"
  local name="$2"
  local epoch="$3"
  local version="$4"
  local release="$5"
  local arch="$6"
  local sha256_header="$7"
  local sigmd5="$8"
  local url="${direct_rpm_url[${package}]:-}"
  local expected_sha="${direct_rpm_sha[${package}]:-}"
  local filename="${name}-${version}-${release}.${arch}.rpm"
  local path="${dest%/}/${filename}"
  local tmp="${path}.tmp"
  local actual_sha
  local sig_output
  local header_output

  [[ -n "${url}" && -n "${expected_sha}" ]] || {
    echo "missing direct builder RPM source pin for ${package}" >&2
    exit 1
  }
  [[ "${url##*/}" == "${filename}" ]] || {
    echo "direct builder RPM URL filename mismatch for ${package}: expected ${filename}, got ${url##*/}" >&2
    exit 1
  }

  curl -fL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2 \
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

  header_output="$(rpm -qp --qf '%{NEVRA}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SHA256HEADER}|%{SIGMD5}' "${path}")"
  if [[ "${header_output}" != "${package}|${name}|${epoch}|${version}|${release}|${arch}|${sha256_header}|${sigmd5}" ]]; then
    echo "${path}: RPM header does not match the locked builder row" >&2
    exit 1
  fi

  direct_rpm_seen["${package}"]=1
  printf '# direct_rpm: %s|%s|%s\n' "${package}" "${url}" "${expected_sha}" >> "${manifest}"
}

while IFS='|' read -r package name epoch version release arch sha256_header sigmd5 extra; do
  case "${package}" in
    "" | \#*) continue ;;
    *) ;;
  esac
  if [[ -n "${extra:-}" ]]; then
    echo "too many columns for builder RPM ${package}" >&2
    exit 1
  fi
  for field in "${package}" "${name}" "${epoch}" "${version}" "${release}" "${arch}" "${sha256_header}" "${sigmd5}"; do
    [[ -n "${field}" ]] || {
      echo "empty field in builder lock row ${package}" >&2
      exit 1
    }
  done
  case "${arch}" in
    noarch | "${rpm_arch}") ;;
    *)
      echo "locked builder package ${package} has wrong arch ${arch} for ${targetarch}" >&2
      exit 1
      ;;
  esac
  if [[ -n "${row_seen[${package}]+set}" ]]; then
    echo "duplicate builder package row: ${package}" >&2
    exit 1
  fi
  row_seen["${package}"]=1
  fetch_one "${package}" "${name}" "${epoch}" "${version}" "${release}" "${arch}" "${sha256_header}" "${sigmd5}"
done < "${lockfile}"

for direct_package in "${!direct_rpm_sha[@]}"; do
  [[ -n "${direct_rpm_seen[${direct_package}]+set}" ]] || {
    echo "direct builder RPM lock entry has no matching package row: ${direct_package}" >&2
    exit 1
  }
done

echo "builder RPM direct-CDN fetch verified: ${#row_seen[@]} packages"
