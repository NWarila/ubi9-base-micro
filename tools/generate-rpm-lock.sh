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
ARG SOURCE_DATE_EPOCH

RUN <<'CAPTURE'
set -euo pipefail

case "${TARGETARCH}" in
  amd64) rpm_arch="x86_64" ;;
  arm64) rpm_arch="aarch64" ;;
  *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;;
esac

runtime_packages=(
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

mkdir -p /rootfs /out
microdnf install -y --installroot=/rootfs --releasever=9 \
  --config=/etc/dnf/dnf.conf --noplugins \
  --setopt=reposdir=/etc/yum.repos.d \
  --setopt=varsdir=/etc/dnf/vars \
  --setopt=cachedir=/var/cache/microdnf-installroot \
  --nodocs --setopt=install_weak_deps=0 \
  "${dnf_repo_args[@]}" \
  "${runtime_packages[@]}"
microdnf clean all
rm -rf /rootfs/var/cache/* /var/cache/microdnf-installroot \
  /rootfs/var/log/dnf.log /rootfs/var/log/dnf.librepo.log /rootfs/var/log/hawkey.log

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
for package_name in "${runtime_packages[@]}"; do
  if ! rpm --root=/rootfs -q "${package_name}" >/dev/null 2>&1; then
    echo "expected final runtime RPM missing after strip: ${package_name}" >&2
    cat /tmp/runtime.final.nevras >&2
    exit 1
  fi
done

{
  printf '# arch: %s\n' "${TARGETARCH}"
  printf '# source_date_epoch: %s\n' "${SOURCE_DATE_EPOCH}"
  printf '# columns: package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5\n'
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
    if [[ -n "${previous_package}" && "${package}" < "${previous_package}" ]]; then
      echo "${path}: rows are not sorted by package: ${package} after ${previous_package}" >&2
      return 1
    fi
    if [[ "${package}" == "${previous_package}" ]]; then
      echo "${path}: duplicate package row: ${package}" >&2
      return 1
    fi
    previous_package="${package}"
    rows=$((rows + 1))
  done < "${path}"

  [[ "${rows}" -gt 0 ]] || {
    echo "${path}: lockfile has no package rows" >&2
    return 1
  }
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
}

generate_one() {
  local platform_arch="$1"
  local output_dir="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir:-}"' RETURN

  write_capture_dockerfile "${tmpdir}/Dockerfile"
  mkdir -p "${tmpdir}/out"

  docker buildx build \
    --progress plain \
    --platform "linux/${platform_arch}" \
    --target export \
    --build-arg "UBI_MINIMAL_IMAGE=${ubi_minimal_image}" \
    --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
    --build-arg "DNF_REPOS=${dnf_repos}" \
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
  sed -i '4s/|no|/|maybe|/' "${tmpdir}/bad.txt"
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
