#!/usr/bin/env bash
# Purpose: Top-level gate pipeline — install scanners + STIG datastream, build images, then run hardening/FIPS tests,
# footprint, STIG ARF, SBOM gen+assertions, phantom-package check, fixable Trivy/Grype gates,
# rootfs secret scan, and NIST 800-190 predicate gen/validate.
# Role: workflow
# Python-convertible: partial — thin linear orchestration; all substance is in the called .py/.sh gates, conversion
# mainly relocates the call list.
# Micro-container candidate: yes — this is the gate workflow to collapse into pinned gate micro-container(s), dropping
# the install-on-runner preamble.
# Relocate: no — workflow/gate driver, not a build-process artifact script.

set -euo pipefail

run_bounded_gate() {
  local label="$1"
  local timeout_seconds="$2"
  local started_at
  local drain_tick
  local elapsed
  local gate_pid
  local grace_tick
  local monitor_status
  local pgid
  local status
  local timed_out=0
  shift 2

  # Scope: this is a process-group deadline, not a complete descendant or
  # engine-operation bound. TERM then KILL reaches the gate and descendants
  # only while they remain in this group. A descendant can escape with
  # setsid/setpgid; pre-existing daemons (such as Docker) and daemonizing
  # engine helpers (such as fuse-overlayfs or conmon) are outside it. SIGKILL
  # also cannot complete while a process remains in uninterruptible kernel
  # sleep. Whole-operation containment requires a cgroup/scope or equivalent
  # engine-specific cleanup.

  case "${timeout_seconds}" in
    "" | *[!0-9]*)
      echo "invalid timeout for ${label}: ${timeout_seconds}" >&2
      return 2
      ;;
    *) ;;
  esac
  if ((timeout_seconds < 1)); then
    echo "timeout for ${label} must be at least 1 second" >&2
    return 2
  fi
  command -v timeout > /dev/null 2>&1 || {
    echo "timeout is required to bound ${label}" >&2
    return 2
  }
  command -v setsid > /dev/null 2>&1 || {
    echo "setsid is required to isolate ${label}" >&2
    return 2
  }

  started_at=${SECONDS}
  printf 'GATE START: %s (timeout=%ss)\n' "${label}" "${timeout_seconds}"

  setsid "$@" < /dev/null &
  gate_pid=$!
  pgid=${gate_pid}

  # Wait until setsid establishes the gate's process group, or until a short-lived
  # gate exits. The group ID is the setsid process ID because Bash job control is
  # disabled in this non-interactive script.
  while ! kill -0 -- "-${pgid}" 2> /dev/null; do
    if ! kill -0 "${gate_pid}" 2> /dev/null; then
      break
    fi
    sleep 0.01
  done

  # Timeout supervises group liveness rather than the group leader. If the leader
  # exits while a descendant remains, the monitor still reaches the deadline.
  # shellcheck disable=SC2016
  if timeout --signal=TERM "${timeout_seconds}s" bash -c '
    pgid=$1
    while kill -0 -- "-${pgid}" 2> /dev/null; do
      sleep 0.1
    done
  ' bash "${pgid}" < /dev/null; then
    monitor_status=0
  else
    monitor_status=$?
  fi

  if ((monitor_status != 0)); then
    if ((monitor_status == 124)); then
      timed_out=1
    fi

    # Always signal the isolated process group if the monitor fails. TERM is
    # followed by a full ten-second grace period before KILL escalation.
    if kill -TERM -- "-${pgid}" 2> /dev/null; then
      :
    fi
    for ((grace_tick = 0; grace_tick < 100; grace_tick++)); do
      if ! kill -0 -- "-${pgid}" 2> /dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 -- "-${pgid}" 2> /dev/null; then
      if kill -KILL -- "-${pgid}" 2> /dev/null; then
        :
      fi
    fi
  fi

  if wait "${gate_pid}"; then
    status=0
  else
    status=$?
  fi
  elapsed=$((SECONDS - started_at))

  if ((timed_out)); then
    # Reaping the group leader above must leave no live member of this group.
    for ((drain_tick = 0; drain_tick < 100; drain_tick++)); do
      if ! kill -0 -- "-${pgid}" 2> /dev/null; then
        break
      fi
      sleep 0.01
    done
    if kill -0 -- "-${pgid}" 2> /dev/null; then
      printf 'GATE CLEANUP FAIL: %s process group %s survived KILL escalation\n' \
        "${label}" "${pgid}" >&2
      return 125
    fi
    printf 'GATE TIMEOUT: %s exceeded %ss (elapsed=%ss, status=%s)\n' \
      "${label}" "${timeout_seconds}" "${elapsed}" 124 >&2
    return 124
  fi
  if ((monitor_status != 0)); then
    printf 'GATE FAIL: %s timeout monitor failed (elapsed=%ss, status=%s)\n' \
      "${label}" "${elapsed}" "${monitor_status}" >&2
    return "${monitor_status}"
  fi
  if ((status != 0)); then
    printf 'GATE FAIL: %s (elapsed=%ss, status=%s)\n' "${label}" "${elapsed}" "${status}" >&2
    return "${status}"
  fi

  printf 'GATE PASS: %s (elapsed=%ss)\n' "${label}" "${elapsed}"
}

run_timeout_self_test() {
  local descendant_pid
  local descendant_pid_file
  local status

  status=0
  # The fixture must capture the production wrapper's nonzero timeout status.
  # shellcheck disable=SC2310
  run_bounded_gate "deliberate induced hang" 1 sleep 30 || status=$?
  if ((status != 124)); then
    echo "timeout self-test expected status 124, got ${status}" >&2
    return 1
  fi
  echo "timeout self-test caught and named the deliberate induced hang"

  descendant_pid_file=$(mktemp)
  status=0
  # The parent exits when TERM arrives, while its descendant ignores TERM and
  # keeps running. Only process-group KILL escalation can finish this fixture.
  # shellcheck disable=SC2016,SC2310
  run_bounded_gate "TERM-ignoring descendant" 1 bash -c '
    descendant_pid_file=$1
    trap "exit 0" TERM
    (
      trap "" TERM
      printf "%s\n" "${BASHPID}" > "${descendant_pid_file}"
      while :; do
        sleep 30
      done
    ) &
    wait
  ' bash "${descendant_pid_file}" || status=$?
  if ! read -r descendant_pid < "${descendant_pid_file}"; then
    rm -f "${descendant_pid_file}"
    echo "descendant timeout self-test did not record its child PID" >&2
    return 1
  fi
  rm -f "${descendant_pid_file}"
  if ((status != 124)); then
    if kill -KILL "${descendant_pid}" 2> /dev/null; then
      :
    fi
    echo "descendant timeout self-test expected status 124, got ${status}" >&2
    return 1
  fi
  if kill -0 "${descendant_pid}" 2> /dev/null; then
    if kill -KILL "${descendant_pid}" 2> /dev/null; then
      :
    fi
    echo "descendant timeout self-test left PID ${descendant_pid} alive" >&2
    return 1
  fi
  echo "timeout self-test killed the TERM-ignoring descendant"
}

case "${1:-}" in
  "") ;;
  --self-test-timeout)
    run_timeout_self_test
    exit 0
    ;;
  *)
    echo "unknown argument: $1" >&2
    exit 2
    ;;
esac

runtime_image="${RUNTIME_IMAGE:-ghcr.io/nwarila/ubi9-base-micro:base-micro}"
platform="${PLATFORM:-linux/amd64}"
arch="${platform#linux/}"
ubi_micro_image="${UBI_MICRO_IMAGE:-registry.access.redhat.com/ubi9/ubi-micro@sha256:f332c99eb8f798a8486821c91937f10ad64ee83d7e739303be2df051040918f6}"
source_uri="github.com/${GITHUB_REPOSITORY:-NWarila/ubi9-base-micro}"
revision="${GITHUB_SHA:-$(git rev-parse HEAD 2> /dev/null)}"
revision="${revision:-local}"

case "${arch}" in
  amd64 | arm64) ;;
  *)
    echo "unsupported gate architecture: ${arch}" >&2
    exit 1
    ;;
esac

bash tools/install-syft.sh
bash tools/install-trivy.sh
bash tools/install-grype.sh

scanner_db_max_age_days="${SCANNER_DB_MAX_AGE_DAYS:-7}"
case "${scanner_db_max_age_days}" in
  "" | *[!0-9]*)
    echo "SCANNER_DB_MAX_AGE_DAYS must be a positive integer, got: ${scanner_db_max_age_days}" >&2
    exit 1
    ;;
  *) ;;
esac
if ((scanner_db_max_age_days < 1)); then
  echo "SCANNER_DB_MAX_AGE_DAYS must be at least 1" >&2
  exit 1
fi

dist/tools/trivy image --download-db-only
dist/tools/grype db update
python tools/assert-scanner-db-freshness.py --max-age-days "${scanner_db_max_age_days}"

scanner_canary_fixture="tests/fixtures/scanner-canary/log4shell.cdx.json"
grype_canary_json="dist/vuln/scanner-canary.grype.json"
trivy_canary_json="dist/vuln/scanner-canary.trivy.json"
mkdir -p dist/vuln
: > "${grype_canary_json}"
: > "${trivy_canary_json}"
GRYPE_DB_AUTO_UPDATE=false dist/tools/grype "sbom:${scanner_canary_fixture}" -o json -q > "${grype_canary_json}"
dist/tools/trivy sbom "${scanner_canary_fixture}" \
  --format json \
  --output "${trivy_canary_json}" \
  --skip-db-update \
  --skip-java-db-update \
  --offline-scan \
  -q
python tools/assert-scanner-canary.py \
  --grype-json "${grype_canary_json}" \
  --trivy-json "${trivy_canary_json}" \
  --expect-cve CVE-2021-44228

export GRYPE_DB_VALIDATE_AGE=true
export GRYPE_DB_MAX_ALLOWED_BUILT_AGE="$((scanner_db_max_age_days * 24))h"

bash tools/install-openscap.sh
bash tools/build-stig-datastream.sh

bash tools/build.sh

run_bounded_gate "runtime hardening assertions" 300 bash tests/hardening.sh "${runtime_image}"
run_bounded_gate "FIPS artifact assertions" 300 bash tests/fips.sh "${runtime_image}"

mkdir -p dist/footprint
run_bounded_gate "runtime footprint assertion" 300 python tools/assert-footprint.py \
  --image "${runtime_image}" \
  --platform "${platform}" \
  --output "dist/footprint/base-micro.${arch}.json"

run_bounded_gate "STIG ARF scan" 300 \
  bash tools/run-stig-arf.sh "${runtime_image}" "${arch}" "${platform}" "dist/stig/${arch}"

mkdir -p dist/sbom
dist/tools/syft scan "${runtime_image}" \
  --platform "${platform}" \
  -o "json=dist/sbom/base-micro.${arch}.syft.json" \
  -o "spdx-json=dist/sbom/base-micro.${arch}.spdx.json" \
  -o "cyclonedx-json=dist/sbom/base-micro.${arch}.cdx.json"

python tools/assert-sbom-rpms.py \
  --source "dist/sbom/base-micro.${arch}.syft.json" \
  "dist/sbom/base-micro.${arch}.spdx.json" \
  "dist/sbom/base-micro.${arch}.cdx.json"

python tools/assert-no-phantom-packages.py \
  --image "${runtime_image}" \
  --platform "${platform}" \
  --syft-json "dist/sbom/base-micro.${arch}.syft.json" \
  --output "dist/sbom/base-micro.${arch}.phantom-packages.json" \
  --expect-absent libacl \
  --expect-absent libattr \
  --expect-absent libcap \
  --expect-absent coreutils-common \
  --expect-absent pcre2-syntax \
  --expect-absent alternatives

mkdir -p dist/vuln

dist/tools/trivy image \
  --vuln-type os,library \
  --ignore-unfixed \
  --severity MEDIUM,HIGH,CRITICAL \
  --ignorefile security/cve-ignore.trivyignore.yaml \
  --exit-code 1 \
  "${runtime_image}"

dist/tools/grype "${runtime_image}" \
  --only-fixed \
  --fail-on medium \
  -c security/cve-ignore.grype.yaml \
  -o table

rootfs_dir="dist/rootfs-secret-scan/rootfs.${arch}"
report="dist/rootfs-secret-scan/base-micro.${arch}.secret-scan.json"
rm -rf "${rootfs_dir}"
mkdir -p "${rootfs_dir}"

container_id="$(docker create "${runtime_image}" /secret-scan-export)"
cleanup() {
  docker rm "${container_id}" > /dev/null
}
trap cleanup EXIT

docker export "${container_id}" | tar --no-same-owner --no-same-permissions -x -C "${rootfs_dir}"
chmod -R u+rwX "${rootfs_dir}"
python tools/assert-no-rootfs-secrets.py \
  --rootfs "${rootfs_dir}" \
  --report "${report}"

predicate="dist/attestations/nist-800-190.base-micro.${arch}.json"
mkdir -p dist/attestations
python tools/generate-nist-800-190-predicate.py \
  --image-ref "${runtime_image}" \
  --platform "${platform}" \
  --arch "${arch}" \
  --base-image "${ubi_micro_image}" \
  --source-uri "${source_uri}" \
  --revision "${revision}" \
  --secret-scan-report "dist/rootfs-secret-scan/base-micro.${arch}.secret-scan.json" \
  --output "${predicate}"

python tools/generate-nist-800-190-predicate.py --validate "${predicate}"
