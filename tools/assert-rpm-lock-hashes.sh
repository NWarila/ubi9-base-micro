#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 << 'EOF'
usage: assert-rpm-lock-hashes.sh --root ROOTFS --lockfile LOCKFILE [--direct-rpm-dir DIR]
       assert-rpm-lock-hashes.sh --self-test
EOF
}

verify_lock_hashes() {
  local rootfs="$1"
  local lockfile="$2"
  local direct_rpm_dir="${3:-}"
  local count=0
  local package final_rpmdb name epoch version release arch sha256_header sigmd5 extra
  local actual actual_sha256_header actual_sigmd5
  declare -A direct_rpm_sha=()
  declare -A direct_rpm_url=()
  declare -A direct_rpm_row_seen=()

  [[ -s "${lockfile}" ]] || {
    echo "RPM lockfile missing or empty: ${lockfile}" >&2
    return 1
  }

  while IFS= read -r line; do
    case "${line}" in
      "# direct_rpm: "*)
        local direct_payload="${line#\# direct_rpm: }"
        local direct_package direct_url direct_sha direct_extra
        IFS='|' read -r direct_package direct_url direct_sha direct_extra <<< "${direct_payload}"
        if [[ -n "${direct_extra:-}" || -z "${direct_package}" || -z "${direct_url}" || -z "${direct_sha}" ]]; then
          echo "invalid direct RPM lock entry: ${line}" >&2
          return 1
        fi
        [[ "${direct_url}" == https://cdn-ubi.redhat.com/* ]] || {
          echo "direct RPM source must be the Red Hat UBI CDN for ${direct_package}: ${direct_url}" >&2
          return 1
        }
        [[ "${direct_sha}" =~ ^[0-9a-f]{64}$ ]] || {
          echo "invalid direct RPM sha256 for ${direct_package}: ${direct_sha}" >&2
          return 1
        }
        direct_rpm_sha["${direct_package}"]="${direct_sha}"
        direct_rpm_url["${direct_package}"]="${direct_url}"
        continue
        ;;
      "" | \#*)
        continue
        ;;
      *) ;;
    esac

    IFS='|' read -r package final_rpmdb name epoch version release arch sha256_header sigmd5 extra <<< "${line}"

    if [[ -n "${extra:-}" ]]; then
      echo "too many columns for ${package}" >&2
      return 1
    fi
    for field in "${package}" "${final_rpmdb}" "${name}" "${epoch}" "${version}" "${release}" "${arch}" "${sha256_header}" "${sigmd5}"; do
      [[ -n "${field}" ]] || {
        echo "empty field in lock row ${package}" >&2
        return 1
      }
    done
    [[ "${sha256_header}" =~ ^[0-9a-f]{64}$ ]] || {
      echo "invalid locked SHA256HEADER for ${package}: ${sha256_header}" >&2
      return 1
    }
    [[ "${sigmd5}" =~ ^[0-9a-f]{32}$ ]] || {
      echo "invalid locked SIGMD5 for ${package}: ${sigmd5}" >&2
      return 1
    }

    if ! actual="$(rpm --root="${rootfs}" -q --qf '%{SHA256HEADER}|%{SIGMD5}\n' "${package}")"; then
      echo "locked RPM missing from installroot after transaction: ${package}" >&2
      return 1
    fi
    if [[ "${actual}" == *$'\n'* || "${actual}" != *"|"* ]]; then
      echo "unexpected RPM hash query output for ${package}: ${actual}" >&2
      return 1
    fi

    actual_sha256_header="${actual%%|*}"
    actual_sigmd5="${actual#*|}"
    if [[ "${actual_sha256_header}" != "${sha256_header}" ]]; then
      echo "SHA256HEADER mismatch for ${package}: expected ${sha256_header}, got ${actual_sha256_header}" >&2
      return 1
    fi
    if [[ "${actual_sigmd5}" != "${sigmd5}" ]]; then
      echo "SIGMD5 mismatch for ${package}: expected ${sigmd5}, got ${actual_sigmd5}" >&2
      return 1
    fi
    if [[ -z "${direct_rpm_sha[${package}]+set}" ]]; then
      echo "missing direct RPM source pin for ${package}" >&2
      return 1
    fi
    expected_filename="${name}-${version}-${release}.${arch}.rpm"
    direct_filename="${direct_rpm_url[${package}]##*/}"
    if [[ "${direct_filename}" != "${expected_filename}" ]]; then
      echo "direct RPM URL filename mismatch for ${package}: expected ${expected_filename}, got ${direct_filename}" >&2
      return 1
    fi
    direct_rpm_row_seen["${package}"]=1
    count=$((count + 1))
  done < "${lockfile}"

  [[ "${count}" -gt 0 ]] || {
    echo "RPM lockfile contained no package rows: ${lockfile}" >&2
    return 1
  }

  local direct_package
  for direct_package in "${!direct_rpm_sha[@]}"; do
    [[ -n "${direct_rpm_row_seen[${direct_package}]+set}" ]] || {
      echo "direct RPM lock entry has no matching package row: ${direct_package}" >&2
      return 1
    }
    if [[ -n "${direct_rpm_dir}" ]]; then
      local direct_url="${direct_rpm_url[${direct_package}]}"
      local filename="${direct_url##*/}"
      local direct_path="${direct_rpm_dir%/}/${filename}"
      local actual_direct_sha
      local sig_output
      [[ -s "${direct_path}" ]] || {
        echo "direct RPM file missing or empty: ${direct_path}" >&2
        return 1
      }
      actual_direct_sha="$(sha256sum "${direct_path}" | awk '{print $1}')"
      if [[ "${actual_direct_sha}" != "${direct_rpm_sha[${direct_package}]}" ]]; then
        echo "direct RPM sha256 mismatch for ${direct_package}: expected ${direct_rpm_sha[${direct_package}]}, got ${actual_direct_sha}" >&2
        return 1
      fi
      sig_output="$(rpm -K "${direct_path}")"
      printf '%s\n' "${sig_output}"
      if [[ "${sig_output}" != *"digests signatures OK"* ]]; then
        echo "direct RPM GPG verification failed for ${direct_package}" >&2
        return 1
      fi
    fi
  done

  echo "runtime RPM content hashes verified with %{SHA256HEADER}/%{SIGMD5}: ${count} packages"
  if [[ "${#direct_rpm_sha[@]}" -gt 0 ]]; then
    echo "direct RPM source pins verified from lockfile: ${#direct_rpm_sha[@]} packages"
  fi
}

run_self_test() {
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir:-}"' RETURN

  local sha_a="1111111111111111111111111111111111111111111111111111111111111111"
  local sha_b="2222222222222222222222222222222222222222222222222222222222222222"
  local sha_bad="3333333333333333333333333333333333333333333333333333333333333333"
  local sig_a="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local sig_b="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  mkdir -p "${tmpdir}/bin"
  cat > "${tmpdir}/bin/rpm" << EOF
#!/usr/bin/env bash
set -euo pipefail
package="\${@: -1}"
case "\${package}" in
  foo-1-1.x86_64) printf '${sha_a}|${sig_a}\\n' ;;
  bar-1-1.noarch) printf '${sha_b}|${sig_b}\\n' ;;
  *) echo "unexpected package \${package}" >&2; exit 1 ;;
esac
EOF
  chmod +x "${tmpdir}/bin/rpm"

  cat > "${tmpdir}/lock.good" << EOF
# columns: package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5
# direct_rpm: foo-1-1.x86_64|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/Packages/o/foo-1-1.x86_64.rpm|${sha_a}
# direct_rpm: bar-1-1.noarch|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/Packages/b/bar-1-1.noarch.rpm|${sha_b}
foo-1-1.x86_64|yes|foo|0|1|1|x86_64|${sha_a}|${sig_a}
bar-1-1.noarch|yes|bar|0|1|1|noarch|${sha_b}|${sig_b}
EOF
  PATH="${tmpdir}/bin:${PATH}" verify_lock_hashes "/fake-root" "${tmpdir}/lock.good" > "${tmpdir}/good.out"
  grep -Fq "2 packages" "${tmpdir}/good.out"
  grep -Fq "direct RPM source pins verified" "${tmpdir}/good.out"

  cat > "${tmpdir}/lock.bad" << EOF
# columns: package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5
# direct_rpm: foo-1-1.x86_64|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/Packages/f/foo-1-1.x86_64.rpm|${sha_a}
foo-1-1.x86_64|yes|foo|0|1|1|x86_64|${sha_bad}|${sig_a}
EOF
  # Negative self-test expects verify_lock_hashes to fail closed.
  # shellcheck disable=SC2310
  if PATH="${tmpdir}/bin:${PATH}" verify_lock_hashes "/fake-root" "${tmpdir}/lock.bad" > "${tmpdir}/bad.out" 2>&1; then
    echo "self-test mismatch unexpectedly passed" >&2
    return 1
  fi
  grep -Fq "SHA256HEADER mismatch for foo-1-1.x86_64" "${tmpdir}/bad.out"

  cat > "${tmpdir}/lock.missing-direct-row" << EOF
# direct_rpm: foo-1-1.x86_64|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/Packages/f/foo-1-1.x86_64.rpm|${sha_a}
# direct_rpm: missing-1-1.x86_64|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/Packages/m/missing-1-1.x86_64.rpm|${sha_a}
foo-1-1.x86_64|yes|foo|0|1|1|x86_64|${sha_a}|${sig_a}
EOF
  # Negative self-test expects missing direct-RPM rows to fail closed.
  # shellcheck disable=SC2310
  if PATH="${tmpdir}/bin:${PATH}" verify_lock_hashes "/fake-root" "${tmpdir}/lock.missing-direct-row" > "${tmpdir}/missing.out" 2>&1; then
    echo "self-test missing direct row unexpectedly passed" >&2
    return 1
  fi
  grep -Fq "direct RPM lock entry has no matching package row" "${tmpdir}/missing.out"

  echo "RPM lock hash assertion self-test: ok (synthetic SHA256HEADER and direct RPM failures failed closed)"
}

main() {
  local rootfs=""
  local lockfile=""
  local direct_rpm_dir=""

  if [[ "${1:-}" == "--self-test" ]]; then
    run_self_test
    return 0
  fi

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --root)
        rootfs="${2:-}"
        shift 2
        ;;
      --lockfile)
        lockfile="${2:-}"
        shift 2
        ;;
      --direct-rpm-dir)
        direct_rpm_dir="${2:-}"
        shift 2
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

  if [[ -z "${rootfs}" || -z "${lockfile}" ]]; then
    usage
    return 2
  fi

  verify_lock_hashes "${rootfs}" "${lockfile}" "${direct_rpm_dir}"
}

main "$@"
