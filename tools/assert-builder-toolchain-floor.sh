#!/usr/bin/env bash
# Purpose: Fail closed if the RPM/rpmdb-writing toolchain NEVRAs differ across the builder Python transaction.
# Role: gate
# Python-convertible: no — thin comparison of rpm -q snapshots used before Python is trusted.
# Micro-container candidate: no — intrinsic builder-stage invariant.
# Relocate: yes — build-process assertion; move under containers/scripts/.

set -euo pipefail

usage() {
  cat >&2 << 'EOF'
usage: assert-builder-toolchain-floor.sh --before SNAPSHOT --after SNAPSHOT
EOF
}

before=""
after=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --before)
      before="${2:-}"
      shift 2
      ;;
    --after)
      after="${2:-}"
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

if [[ -z "${before}" || -z "${after}" ]]; then
  usage
  exit 2
fi

toolchain_packages=(rpm rpm-libs sqlite-libs glibc glibc-common)
declare -A required=()
declare -A before_nevra=()
declare -A after_nevra=()
for package in "${toolchain_packages[@]}"; do
  required["${package}"]=1
done

load_snapshot() {
  local path="$1"
  local map_name="$2"
  local line package nevra
  local -n values="${map_name}"

  [[ -s "${path}" ]] || {
    echo "builder toolchain snapshot missing or empty: ${path}" >&2
    return 1
  }
  while IFS= read -r line; do
    if [[ "${line}" != *"|"* || "${line#*|}" == *"|"* ]]; then
      echo "invalid builder toolchain snapshot row in ${path}: ${line}" >&2
      return 1
    fi
    package="${line%%|*}"
    nevra="${line#*|}"
    if [[ -z "${package}" || -z "${nevra}" ]]; then
      echo "invalid builder toolchain snapshot row in ${path}: ${line}" >&2
      return 1
    fi
    [[ -n "${required[${package}]+set}" ]] || {
      echo "unexpected builder toolchain package in ${path}: ${package}" >&2
      return 1
    }
    [[ -z "${values[${package}]+set}" ]] || {
      echo "duplicate builder toolchain package in ${path}: ${package}" >&2
      return 1
    }
    values["${package}"]="${nevra}"
  done < "${path}"
}

load_snapshot "${before}" before_nevra
load_snapshot "${after}" after_nevra

for package in "${toolchain_packages[@]}"; do
  [[ -n "${before_nevra[${package}]+set}" ]] || {
    echo "builder toolchain snapshot ${before} is missing package ${package}" >&2
    exit 1
  }
  [[ -n "${after_nevra[${package}]+set}" ]] || {
    echo "builder toolchain snapshot ${after} is missing package ${package}" >&2
    exit 1
  }
  if [[ "${before_nevra[${package}]}" != "${after_nevra[${package}]}" ]]; then
    echo "builder toolchain package ${package} moved: before=${before_nevra[${package}]} after=${after_nevra[${package}]}" >&2
    exit 1
  fi
done

echo "builder toolchain floor unchanged: ${toolchain_packages[*]}"
