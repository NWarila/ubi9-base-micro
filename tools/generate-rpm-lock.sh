#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat >&2 <<'EOF'
usage: generate-rpm-lock.sh [--arch amd64|arm64|all] [--output-dir DIR]
       generate-rpm-lock.sh --check [--arch amd64|arm64|all]
       generate-rpm-lock.sh --self-test

Regenerates rpm-lock/runtime.<arch>.txt from the current UBI 9 repositories.
EOF
}

dockerfile_arg_default() {
  local name="$1"
  sed -n "s/^ARG ${name}=//p" "${repo_root}/containers/Dockerfile" | head -n1
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

arch_to_rpm_arch() {
  case "$1" in
    amd64) printf 'x86_64\n' ;;
    arm64) printf 'aarch64\n' ;;
    *) return 2 ;;
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
  cat > "${dockerfile}" <<'DOCKERFILE'
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

COPY fetch-openssl-fips-provider-rpms.sh /usr/local/bin/fetch-openssl-fips-provider-rpms.sh

RUN <<'CAPTURE'
set -euo pipefail

case "${TARGETARCH}" in
  amd64) rpm_arch="x86_64" ;;
  arm64) rpm_arch="aarch64" ;;
  *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;;
esac
openssl_fips_provider_nevra="${OPENSSL_FIPS_PROVIDER_NEVRA}"
fips_provider_nvr="${openssl_fips_provider_nevra#openssl-fips-provider-so-}"
if [[ "${fips_provider_nvr}" == "${openssl_fips_provider_nevra}" ]]; then
  echo "invalid FIPS provider NEVRA pin: ${openssl_fips_provider_nevra}" >&2
  exit 1
fi

runtime_package_specs=(
  basesystem
  ca-certificates
  crypto-policies
  filesystem
  glibc
  glibc-common
  glibc-minimal-langpack
  libgcc
  openssl-libs
  redhat-release
  setup
  tzdata
  zlib
)
required_final_names=(
  basesystem
  ca-certificates
  crypto-policies
  filesystem
  glibc
  glibc-common
  glibc-minimal-langpack
  libgcc
  openssl-fips-provider
  openssl-fips-provider-so
  openssl-libs
  redhat-release
  setup
  tzdata
  zlib
)

dnf_repo_args=()
if [[ -n "${DNF_REPOS}" ]]; then
  dnf_repo_args=(--disablerepo='*' "--enablerepo=${DNF_REPOS}")
fi

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

if rpm --root=/rootfs -q bash >/dev/null 2>&1; then
  rpm --root=/rootfs -e --nodeps --noscripts bash
fi

for executable in sh bash dash ash busybox ksh zsh tcsh csh dnf microdnf rpm yum; do
  rm -f "/rootfs/usr/bin/${executable}" "/rootfs/usr/sbin/${executable}" \
    "/rootfs/bin/${executable}" "/rootfs/sbin/${executable}"
done
for executable in sh bash dash ash busybox ksh zsh tcsh csh dnf microdnf rpm yum; do
  if [[ -e "/rootfs/usr/bin/${executable}" || -e "/rootfs/usr/sbin/${executable}" ||
        -e "/rootfs/bin/${executable}" || -e "/rootfs/sbin/${executable}" ]]; then
    echo "forbidden executable '${executable}' survived in generated runtime rootfs" >&2
    exit 1
  fi
done

test -s /rootfs/var/lib/rpm/rpmdb.sqlite || test -s /rootfs/var/lib/rpm/Packages || {
  echo "rpm database missing from generated rootfs" >&2
  exit 1
}
test -e /rootfs/etc/pki/tls/certs/ca-bundle.crt || {
  echo "RHEL CA bundle path missing from generated rootfs" >&2
  exit 1
}
test -s /rootfs/usr/lib64/ossl-modules/fips.so || {
  echo "OpenSSL FIPS provider missing from generated rootfs" >&2
  exit 1
}
test -s /rootfs/usr/lib64/libcrypto.so.3 || {
  echo "OpenSSL libcrypto missing from generated rootfs" >&2
  exit 1
}

protected_deps="$(mktemp)"
for object in \
  /rootfs/usr/lib64/libcrypto.so.3 \
  /rootfs/usr/lib64/libssl.so.3 \
  /rootfs/usr/lib64/ossl-modules/fips.so \
  /rootfs/usr/lib64/libc.so.6; do
  test -e "${object}" || {
    echo "required ldd root missing: ${object}" >&2
    exit 1
  }
  realpath "${object}" >> "${protected_deps}"
  LD_LIBRARY_PATH=/rootfs/usr/lib64 ldd "${object}" |
    awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }' |
    while IFS= read -r dep; do
      case "${dep}" in
        /rootfs/*) test -e "${dep}" && realpath "${dep}" ;;
        /usr/lib64/* | /lib64/*) test -e "/rootfs${dep}" && realpath "/rootfs${dep}" ;;
      esac
    done >> "${protected_deps}"
done
for loader in /rootfs/usr/lib64/ld-linux*.so.* /rootfs/lib64/ld-linux*.so.*; do
  [[ -e "${loader}" ]] && realpath "${loader}" >> "${protected_deps}"
done
sort -u -o "${protected_deps}" "${protected_deps}"

removable_packages=()
for candidate in \
  coreutils-single coreutils findutils grep sed p11-kit p11-kit-trust \
  libsepol libselinux gmp pcre2 pcre libpcre ncurses-libs ncurses-base \
  libsigsegv libffi libtasn1 libacl libattr libcap coreutils-common pcre2-syntax \
  alternatives; do
  if rpm --root=/rootfs -q "${candidate}" >/dev/null 2>&1; then
    candidate_nevra="$(rpm --root=/rootfs -q --qf '%{NEVRA}\n' "${candidate}")"
    protected_owned=""
    while IFS= read -r owned_path; do
      root_owned="/rootfs${owned_path}"
      [[ -e "${root_owned}" ]] || continue
      owned_real="$(realpath "${root_owned}" 2>/dev/null || true)"
      if [[ -n "${owned_real}" ]] && grep -Fxq "${owned_real}" "${protected_deps}"; then
        protected_owned="${owned_path}"
        break
      fi
    done < <(rpm --root=/rootfs -ql "${candidate}")
    if [[ -n "${protected_owned}" ]]; then
      echo "strip candidate ${candidate_nevra} owns protected runtime dependency ${protected_owned}" >&2
      exit 1
    fi
    removable_packages+=("${candidate}")
  fi
done

if (( ${#removable_packages[@]} > 0 )); then
  rpm --root=/rootfs -e --nodeps --noscripts "${removable_packages[@]}"
  for removed_package in "${removable_packages[@]}"; do
    if rpm --root=/rootfs -q "${removed_package}" >/dev/null 2>&1; then
      echo "runtime package survived rpm removal: ${removed_package}" >&2
      exit 1
    fi
  done
fi

rpm --root=/rootfs -qa --qf '%{NEVRA}\n' | LC_ALL=C sort > /tmp/runtime.final.nevras
actual_final_count="$(wc -l < /tmp/runtime.final.nevras | tr -d '[:space:]')"
if [[ "${actual_final_count}" != "15" ]]; then
  echo "final runtime RPM count mismatch: expected 15, got ${actual_final_count}" >&2
  cat /tmp/runtime.final.nevras >&2
  exit 1
fi
for package_name in "${required_final_names[@]}"; do
  if ! rpm --root=/rootfs -q "${package_name}" >/dev/null 2>&1; then
    echo "expected final runtime RPM missing after strip: ${package_name}" >&2
    cat /tmp/runtime.final.nevras >&2
    exit 1
  fi
done

rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
mkdir -p /tmp/direct-runtime-rpms
: > /tmp/runtime.direct.lock

fetch_direct_rpm_for_row() {
  local package="$1"
  local name="$2"
  local version="$3"
  local release="$4"
  local arch="$5"
  local filename="${name}-${version}-${release}.${arch}.rpm"
  local first_letter="${name:0:1}"
  local repo url tmp path actual_sha sig_output

  for repo in baseos appstream; do
    url="${OPENSSL_FIPS_PROVIDER_RPM_BASE_URL%/}/${rpm_arch}/${repo}/os/Packages/${first_letter}/${filename}"
    tmp="/tmp/direct-runtime-rpms/${filename}.${repo}.tmp"
    if curl -fL --retry 3 --retry-delay 2 --proto '=https' --tlsv1.2 --output "${tmp}" "${url}"; then
      actual_sha="$(sha256sum "${tmp}" | awk '{print $1}')"
      path="/tmp/direct-runtime-rpms/${filename}"
      mv "${tmp}" "${path}"
      sig_output="$(rpm -K "${path}")"
      printf '%s\n' "${sig_output}"
      if [[ "${sig_output}" != *"digests signatures OK"* ]]; then
        echo "${path}: Red Hat RPM signature verification did not report digests signatures OK" >&2
        exit 1
      fi
      printf '# direct_rpm: %s|%s|%s\n' "${package}" "${url}" "${actual_sha}" >> /tmp/runtime.direct.lock
      return 0
    fi
    rm -f "${tmp}"
  done

  echo "could not resolve direct CDN URL for ${package}" >&2
  exit 1
}

while IFS='|' read -r package name epoch version release arch sha256_header sigmd5; do
  fetch_direct_rpm_for_row "${package}" "${name}" "${version}" "${release}" "${arch}"
done < /tmp/runtime.full.tsv

{
  printf '# arch: %s\n' "${TARGETARCH}"
  printf '# source_date_epoch: %s\n' "${SOURCE_DATE_EPOCH}"
  printf '# columns: package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5\n'
  cat /tmp/runtime.direct.lock
  awk -F'|' '
    NR == FNR {
      final[$0] = 1
      next
    }
    {
      status = ($1 in final) ? "yes" : "no"
      print $1 "|" status "|" $2 "|" $3 "|" $4 "|" $5 "|" $6 "|" $7 "|" $8
    }
  ' /tmp/runtime.final.nevras /tmp/runtime.full.tsv
} > "/out/runtime.${TARGETARCH}.txt"

row_count="$(awk 'BEGIN { count=0 } /^[^#]/ { count++ } END { print count }' "/out/runtime.${TARGETARCH}.txt")"
if [[ "${row_count}" -lt "15" ]]; then
  echo "generated lockfile contains too few rows: ${row_count}" >&2
  exit 1
fi
CAPTURE

FROM scratch AS export
COPY --from=capture /out/ /
DOCKERFILE
}

validate_lockfile() {
  local path="$1"
  local platform_arch="$2"
  local rpm_arch
  rpm_arch="$(arch_to_rpm_arch "${platform_arch}")"
  local expected_provider_nvr="${openssl_fips_provider_nevra}"
  local fips_provider_nvr="${expected_provider_nvr#openssl-fips-provider-so-}"
  local expected_provider_package_nevra="openssl-fips-provider-${fips_provider_nvr}.${rpm_arch}"
  local expected_provider_nevra="${expected_provider_nvr}.${rpm_arch}"
  local expected_provider_sha expected_provider_so_sha rpm_basearch
  case "${platform_arch}" in
    amd64)
      rpm_basearch="x86_64"
      expected_provider_sha="${openssl_fips_provider_rpm_sha256_x86_64}"
      expected_provider_so_sha="${openssl_fips_provider_so_rpm_sha256_x86_64}"
      ;;
    arm64)
      rpm_basearch="aarch64"
      expected_provider_sha="${openssl_fips_provider_rpm_sha256_aarch64}"
      expected_provider_so_sha="${openssl_fips_provider_so_rpm_sha256_aarch64}"
      ;;
    *) return 2 ;;
  esac
  local expected_provider_url="${openssl_fips_provider_rpm_base_url%/}/${rpm_basearch}/baseos/os/Packages/o/${expected_provider_package_nevra}.rpm"
  local expected_provider_so_url="${openssl_fips_provider_rpm_base_url%/}/${rpm_basearch}/baseos/os/Packages/o/${expected_provider_nevra}.rpm"

  [[ -s "${path}" ]] || {
    echo "RPM lockfile missing or empty: ${path}" >&2
    return 1
  }

  mapfile -t lines < "${path}"
  [[ "${lines[0]:-}" == "# arch: ${platform_arch}" ]] || {
    echo "${path}: invalid arch header" >&2
    return 1
  }
  [[ "${lines[1]:-}" == "# source_date_epoch: ${source_date_epoch}" ]] || {
    echo "${path}: invalid source_date_epoch header" >&2
    return 1
  }
  [[ "${lines[2]:-}" == "# columns: package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5" ]] || {
    echo "${path}: invalid columns header" >&2
    return 1
  }

  local rows=0
  local final_rows=0
  local previous_package=""
  local package final_rpmdb name epoch version release arch sha256_header sigmd5 extra
  local required_final_names=(
    basesystem
    ca-certificates
    crypto-policies
    filesystem
    glibc
    glibc-common
    glibc-minimal-langpack
    libgcc
    openssl-fips-provider
    openssl-fips-provider-so
    openssl-libs
    redhat-release
    setup
    tzdata
    zlib
  )
  local final_seen=" "
  local provider_pin_seen=0
  local line direct_payload direct_package direct_url direct_sha direct_extra
  local direct_rows=0
  declare -A direct_rpm_sha=()
  declare -A direct_rpm_url=()
  declare -A direct_rpm_row_seen=()

  while IFS= read -r line; do
    case "${line}" in
      "# direct_rpm: "*)
        direct_payload="${line#\# direct_rpm: }"
        IFS='|' read -r direct_package direct_url direct_sha direct_extra <<< "${direct_payload}"
        if [[ -n "${direct_extra:-}" || -z "${direct_package}" || -z "${direct_url}" || -z "${direct_sha}" ]]; then
          echo "${path}: invalid direct RPM entry: ${line}" >&2
          return 1
        fi
        [[ "${direct_url}" == https://cdn-ubi.redhat.com/* ]] || {
          echo "${path}: direct RPM source must be cdn-ubi.redhat.com for ${direct_package}: ${direct_url}" >&2
          return 1
        }
        [[ "${direct_sha}" =~ ^[0-9a-f]{64}$ ]] || {
          echo "${path}: invalid direct RPM sha256 for ${direct_package}: ${direct_sha}" >&2
          return 1
        }
        if [[ -n "${direct_rpm_sha[${direct_package}]+set}" ]]; then
          echo "${path}: duplicate direct RPM entry: ${direct_package}" >&2
          return 1
        fi
        direct_rpm_sha["${direct_package}"]="${direct_sha}"
        direct_rpm_url["${direct_package}"]="${direct_url}"
        direct_rows=$((direct_rows + 1))
        ;;
    esac
  done < "${path}"

  while IFS='|' read -r package final_rpmdb name epoch version release arch sha256_header sigmd5 extra; do
    case "${package}" in
      "" | \#*) continue ;;
    esac
    if [[ -n "${extra:-}" ]]; then
      echo "${path}: too many columns for ${package}" >&2
      return 1
    fi
    for field in "${package}" "${final_rpmdb}" "${name}" "${epoch}" "${version}" "${release}" "${arch}" "${sha256_header}" "${sigmd5}"; do
      [[ -n "${field}" ]] || {
        echo "${path}: empty field in row ${package}" >&2
        return 1
      }
    done
    case "${final_rpmdb}" in
      yes) final_rows=$((final_rows + 1)); final_seen+="${name} " ;;
      no) ;;
      *)
        echo "${path}: invalid final_rpmdb=${final_rpmdb} for ${package}" >&2
        return 1
        ;;
    esac
    case "${arch}" in
      noarch | "${rpm_arch}") ;;
      *)
        echo "${path}: invalid arch=${arch} for ${package}" >&2
        return 1
        ;;
    esac
    [[ "${epoch}" =~ ^[0-9]+$ ]] || {
      echo "${path}: non-numeric epoch for ${package}" >&2
      return 1
    }
    [[ "${sha256_header}" =~ ^[0-9a-f]{64}$ ]] || {
      echo "${path}: invalid SHA256HEADER for ${package}" >&2
      return 1
    }
    [[ "${sigmd5}" =~ ^[0-9a-f]{32}$ ]] || {
      echo "${path}: invalid SIGMD5 for ${package}" >&2
      return 1
    }
    if [[ -z "${direct_rpm_sha[${package}]+set}" ]]; then
      echo "${path}: missing direct RPM source pin for ${package}" >&2
      return 1
    fi
    expected_filename="${name}-${version}-${release}.${arch}.rpm"
    direct_filename="${direct_rpm_url[${package}]##*/}"
    if [[ "${direct_filename}" != "${expected_filename}" ]]; then
      echo "${path}: direct RPM URL filename mismatch for ${package}: expected ${expected_filename}, got ${direct_filename}" >&2
      return 1
    fi
    if [[ "${package}" == "${expected_provider_package_nevra}" ]]; then
      [[ "${direct_rpm_url[${package}]}" == "${expected_provider_url}" && "${direct_rpm_sha[${package}]}" == "${expected_provider_sha}" ]] || {
        echo "${path}: FIPS provider package direct pin mismatch for ${package}" >&2
        return 1
      }
    fi
    if [[ "${package}" == "${expected_provider_nevra}" ]]; then
      [[ "${direct_rpm_url[${package}]}" == "${expected_provider_so_url}" && "${direct_rpm_sha[${package}]}" == "${expected_provider_so_sha}" ]] || {
        echo "${path}: FIPS provider shared-object direct pin mismatch for ${package}" >&2
        return 1
      }
    fi
    direct_rpm_row_seen["${package}"]=1
    if [[ -n "${previous_package}" && "${package}" < "${previous_package}" ]]; then
      echo "${path}: rows are not sorted by package: ${package} after ${previous_package}" >&2
      return 1
    fi
    if [[ "${package}" == "${previous_package}" ]]; then
      echo "${path}: duplicate package row: ${package}" >&2
      return 1
    fi
    if [[ "${package}" == "${expected_provider_nevra}" && "${name}" == "openssl-fips-provider-so" ]]; then
      provider_pin_seen=1
    fi
    previous_package="${package}"
    rows=$((rows + 1))
  done < "${path}"

  [[ "${rows}" -gt 0 ]] || {
    echo "${path}: lockfile has no package rows" >&2
    return 1
  }
  [[ "${direct_rows}" -eq "${rows}" ]] || {
    echo "${path}: expected ${rows} direct RPM pins, got ${direct_rows}" >&2
    return 1
  }
  for direct_package in "${!direct_rpm_sha[@]}"; do
    [[ -n "${direct_rpm_row_seen[${direct_package}]+set}" ]] || {
      echo "${path}: direct RPM entry has no matching package row: ${direct_package}" >&2
      return 1
    }
  done
  [[ "${final_rows}" -eq 15 ]] || {
    echo "${path}: expected 15 final runtime RPMs, got ${final_rows}" >&2
    return 1
  }
  for name in "${required_final_names[@]}"; do
    [[ "${final_seen}" == *" ${name} "* ]] || {
      echo "${path}: missing final runtime RPM ${name}" >&2
      return 1
    }
  done
  [[ "${provider_pin_seen}" -eq 1 ]] || {
    echo "${path}: missing pinned OpenSSL FIPS provider ${expected_provider_nevra}" >&2
    return 1
  }
}

generate_one() {
  local platform_arch="$1"
  local output_dir="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir:-}"' RETURN

  write_capture_dockerfile "${tmpdir}/Dockerfile"
  cp "${repo_root}/tools/fetch-openssl-fips-provider-rpms.sh" "${tmpdir}/fetch-openssl-fips-provider-rpms.sh"
  mkdir -p "${tmpdir}/out"

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
  while IFS= read -r platform_arch; do
    generate_one "${platform_arch}" "${generated_dir}"
    local expected="${repo_root}/rpm-lock/runtime.${platform_arch}.txt"
    local generated="${generated_dir}/runtime.${platform_arch}.txt"
    if ! cmp -s "${expected}" "${generated}"; then
      echo "RPM lockfile drift detected for ${platform_arch}: ${expected}" >&2
      diff -u "${expected}" "${generated}" >&2 || true
      failed=1
    fi
  done < <(arches_for "${arch}")

  [[ "${failed}" -eq 0 ]] || return 1
  echo "RPM lockfile check: ok (generated lockfiles match committed files)"
}

run_self_test() {
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir:-}"' RETURN

  validate_lockfile "${repo_root}/rpm-lock/runtime.amd64.txt" amd64
  validate_lockfile "${repo_root}/rpm-lock/runtime.arm64.txt" arm64

  cp "${repo_root}/rpm-lock/runtime.amd64.txt" "${tmpdir}/bad.txt"
  awk 'BEGIN { done=0 } /^#/ { print; next } done == 0 { sub(/\|no\|/, "|maybe|"); done=1 } { print }' "${tmpdir}/bad.txt" > "${tmpdir}/bad.next"
  mv "${tmpdir}/bad.next" "${tmpdir}/bad.txt"
  if validate_lockfile "${tmpdir}/bad.txt" amd64 >"${tmpdir}/bad.out" 2>&1; then
    echo "self-test invalid final_rpmdb unexpectedly passed" >&2
    return 1
  fi
  grep -Fq "invalid final_rpmdb=maybe" "${tmpdir}/bad.out"

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
  while IFS= read -r platform_arch; do
    generate_one "${platform_arch}" "${output_dir}"
  done < <(arches_for "${arch}")
}

main "$@"
