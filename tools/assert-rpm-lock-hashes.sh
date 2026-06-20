#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: assert-rpm-lock-hashes.sh --root ROOTFS --lockfile LOCKFILE
       assert-rpm-lock-hashes.sh --self-test
EOF
}

verify_lock_hashes() {
  local rootfs="$1"
  local lockfile="$2"
  local count=0
  local package final_rpmdb name epoch version release arch sha256_header sigmd5
  local actual actual_sha256_header actual_sigmd5

  [[ -s "${lockfile}" ]] || {
    echo "RPM lockfile missing or empty: ${lockfile}" >&2
    return 1
  }

  while IFS='|' read -r package final_rpmdb name epoch version release arch sha256_header sigmd5; do
    case "${package}" in
      ""|\#*) continue ;;
    esac

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
    count=$((count + 1))
  done < "${lockfile}"

  [[ "${count}" -gt 0 ]] || {
    echo "RPM lockfile contained no package rows: ${lockfile}" >&2
    return 1
  }

  echo "runtime RPM content hashes verified with %{SHA256HEADER}/%{SIGMD5}: ${count} packages"
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
  cat > "${tmpdir}/bin/rpm" <<EOF
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

  cat > "${tmpdir}/lock.good" <<EOF
# columns: package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5
foo-1-1.x86_64|yes|foo|0|1|1|x86_64|${sha_a}|${sig_a}
bar-1-1.noarch|yes|bar|0|1|1|noarch|${sha_b}|${sig_b}
EOF
  PATH="${tmpdir}/bin:${PATH}" verify_lock_hashes "/fake-root" "${tmpdir}/lock.good" > "${tmpdir}/good.out"
  grep -Fq "2 packages" "${tmpdir}/good.out"

  cat > "${tmpdir}/lock.bad" <<EOF
# columns: package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5
foo-1-1.x86_64|yes|foo|0|1|1|x86_64|${sha_bad}|${sig_a}
EOF
  if PATH="${tmpdir}/bin:${PATH}" verify_lock_hashes "/fake-root" "${tmpdir}/lock.bad" > "${tmpdir}/bad.out" 2>&1; then
    echo "self-test mismatch unexpectedly passed" >&2
    return 1
  fi
  grep -Fq "SHA256HEADER mismatch for foo-1-1.x86_64" "${tmpdir}/bad.out"

  echo "RPM lock hash assertion self-test: ok (synthetic SHA256HEADER mismatch failed closed)"
}

main() {
  local rootfs=""
  local lockfile=""

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
      -h|--help)
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

  verify_lock_hashes "${rootfs}" "${lockfile}"
}

main "$@"