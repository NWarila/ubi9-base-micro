#!/usr/bin/env bash
# Purpose: Export the runtime image rootfs and assert the hardening baseline (no shell, no dnf/microdnf/rpm/yum, user
# 65532:65532, populated rpmdb enumerable by Syft, populated RHEL CA bundle).
# Role: test
# Python-convertible: yes — already embeds a Python Syft-JSON parser; the awk filesystem scans + assertion loops fold
# into one Python gate.
# Micro-container candidate: yes — runtime hardening gate; run the assertions inside a pinned gate image.
# Relocate: no — runtime verification, not a build-process script.

set -euo pipefail

usage() {
  cat << 'USAGE'
Usage: tests/hardening.sh <image-ref>

Validates the base-micro runtime hardening baseline:
  B1 no shell resolves
  B2 no dnf/microdnf/rpm/yum executable resolves
  B3 image config User is 65532:65532
  B4 /var/lib/rpm is present and Syft enumerates RPM packages
  B5 the RHEL CA bundle is present and populated
USAGE
}

assert_no_shell_binaries() {
  local file_list="$1"
  local shell_hits

  shell_hits="$(awk '/(^|\/)(usr\/)?s?bin\/(sh|bash|dash|ash|busybox|ksh|zsh|tcsh|csh)$/ { print }' "${file_list}")"
  if [[ -n "${shell_hits}" ]]; then
    echo "shell binary present in runtime image:" >&2
    printf '%s\n' "${shell_hits}" | sed 's#^#  /#' >&2
    exit 1
  fi
}

assert_no_package_manager_executables() {
  local file_list="$1"
  local package_manager_hits

  package_manager_hits="$(awk '/(^|\/)(usr\/)?s?bin\/(microdnf|dnf|rpm|yum)$/ { print }' "${file_list}")"
  if [[ -n "${package_manager_hits}" ]]; then
    echo "package-manager executable present in runtime image:" >&2
    printf '%s\n' "${package_manager_hits}" | sed 's#^#  /#' >&2
    exit 1
  fi
}

run_self_test() (
  local self_test_tmp_dir
  local clean_file_list
  local shell_file_list
  local package_manager_file_list
  local output
  local status
  local expected_diagnostic

  self_test_tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${self_test_tmp_dir}"' EXIT

  clean_file_list="${self_test_tmp_dir}/clean-files.txt"
  shell_file_list="${self_test_tmp_dir}/shell-files.txt"
  package_manager_file_list="${self_test_tmp_dir}/package-manager-files.txt"

  printf '%s\n' 'usr/bin/application' > "${clean_file_list}"
  printf '%s\n' 'usr/bin/sh' > "${shell_file_list}"
  printf '%s\n' 'usr/bin/rpm' > "${package_manager_file_list}"

  assert_no_shell_binaries "${clean_file_list}"
  assert_no_package_manager_executables "${clean_file_list}"
  echo "self-test clean fixture passed shell and package-manager checks"

  status=0
  output="$(
    (
      assert_no_shell_binaries "${shell_file_list}"
    ) 2>&1
  )" || status=$?
  if [[ "${status}" -eq 0 ]]; then
    echo "shell negative self-test unexpectedly passed" >&2
    exit 1
  fi
  expected_diagnostic="shell binary present in runtime image:"
  if [[ "${output}" != *"${expected_diagnostic}"* ]]; then
    echo "shell negative self-test failed without the expected diagnostic" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  printf 'self-test shell fixture failed as expected (status=%s):\n%s\n' "${status}" "${output}"

  status=0
  output="$(
    (
      assert_no_package_manager_executables "${package_manager_file_list}"
    ) 2>&1
  )" || status=$?
  if [[ "${status}" -eq 0 ]]; then
    echo "package-manager negative self-test unexpectedly passed" >&2
    exit 1
  fi
  expected_diagnostic="package-manager executable present in runtime image:"
  if [[ "${output}" != *"${expected_diagnostic}"* ]]; then
    echo "package-manager negative self-test failed without the expected diagnostic" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  printf 'self-test package-manager fixture failed as expected (status=%s):\n%s\n' "${status}" "${output}"
)

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--self-test" ]]; then
  run_self_test
  exit 0
fi

image_ref="${1:-}"
if [[ -z "${image_ref}" ]]; then
  usage >&2
  exit 2
fi

command -v docker > /dev/null 2>&1 || {
  echo "docker is required for runtime hardening assertions" >&2
  exit 2
}

find_syft() {
  if command -v syft > /dev/null 2>&1; then
    command -v syft
    return 0
  fi
  if command -v syft.exe > /dev/null 2>&1; then
    command -v syft.exe
    return 0
  fi
  if [[ -x "dist/tools/syft" ]]; then
    printf '%s\n' "dist/tools/syft"
    return 0
  fi
  if [[ -x "dist/tools/syft.exe" ]]; then
    printf '%s\n' "dist/tools/syft.exe"
    return 0
  fi
  echo "syft is required for rpm package enumeration; run tools/install-syft.sh" >&2
  exit 2
}

syft_bin="$(find_syft)"

tmp_dir="$(mktemp -d)"
tar_path="${tmp_dir}/rootfs.tar"
container_id=""

cleanup() {
  if [[ -n "${container_id}" ]]; then
    docker rm "${container_id}" > /dev/null
  fi
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

container_id="$(docker create "${image_ref}" /hardening-export-probe)"
docker export "${container_id}" -o "${tar_path}"
tar -tf "${tar_path}" | sed -e 's#^\./##' -e 's#/$##' > "${tmp_dir}/files.txt"

extract_file() {
  local rel="${1#/}"
  if tar -xOf "${tar_path}" "${rel}" 2> /dev/null; then
    return 0
  fi
  if tar -xOf "${tar_path}" "./${rel}" 2> /dev/null; then
    return 0
  fi
  return 1
}

assert_entrypoint_missing() {
  local executable="$1"
  local output="${tmp_dir}/entrypoint.err"
  if docker run --rm --entrypoint "${executable}" "${image_ref}" --version > "${output}" 2>&1; then
    echo "forbidden executable resolves as an entrypoint: ${executable}" >&2
    exit 1
  fi
}

for executable in \
  /bin/sh \
  /bin/bash \
  /bin/dash \
  /usr/bin/sh \
  /usr/bin/bash \
  /usr/bin/dash \
  /usr/bin/ash \
  /usr/bin/busybox; do
  assert_entrypoint_missing "${executable}"
done

for executable in \
  /usr/bin/dnf \
  /usr/bin/microdnf \
  /usr/bin/rpm \
  /usr/bin/yum \
  /bin/dnf \
  /bin/microdnf \
  /bin/rpm \
  /bin/yum; do
  assert_entrypoint_missing "${executable}"
done

assert_no_shell_binaries "${tmp_dir}/files.txt"
assert_no_package_manager_executables "${tmp_dir}/files.txt"

runtime_user="$(docker image inspect --format '{{.Config.User}}' "${image_ref}")"
if [[ "${runtime_user}" != "65532:65532" ]]; then
  echo "image must run as 65532:65532; got '${runtime_user}'" >&2
  exit 1
fi

rpmdb_found=""
for candidate in \
  var/lib/rpm/rpmdb.sqlite \
  var/lib/rpm/Packages \
  var/lib/rpm/Packages.db; do
  extracted="${tmp_dir}/rpmdb-candidate"
  # extract_file intentionally probes alternative rpmdb tar paths.
  # shellcheck disable=SC2310
  if extract_file "${candidate}" > "${extracted}"; then
    bytes="$(wc -c < "${extracted}")"
    if [[ "${bytes}" -gt 0 ]]; then
      rpmdb_found="${candidate}"
      break
    fi
  fi
done
if [[ -z "${rpmdb_found}" ]]; then
  echo "rpm database missing or empty under /var/lib/rpm" >&2
  exit 1
fi

syft_json="${tmp_dir}/syft.json"
"${syft_bin}" scan "${image_ref}" -o json > "${syft_json}"
python - "${syft_json}" << 'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    document = json.load(handle)

artifacts = document.get("artifacts") or []
rpm_names = sorted(
    {
        artifact.get("name")
        for artifact in artifacts
        if artifact.get("type") == "rpm" and artifact.get("name")
    }
)

required = {"ca-certificates", "glibc"}
missing = sorted(required - set(rpm_names))
if missing:
    raise SystemExit(
        "syft did not enumerate required RPM packages: "
        + ", ".join(missing)
        + f" (rpm package count={len(rpm_names)})"
    )

print(f"syft rpm package count={len(rpm_names)}")
print("syft required packages=" + ",".join(sorted(required)))
PY

ca_ok=""
for candidate in \
  etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
  etc/pki/tls/certs/ca-bundle.crt; do
  extracted="${tmp_dir}/ca-candidate"
  # extract_file intentionally probes alternative CA bundle tar paths.
  # shellcheck disable=SC2310
  if extract_file "${candidate}" > "${extracted}"; then
    if grep -q "BEGIN CERTIFICATE" "${extracted}"; then
      ca_ok="${candidate}"
      break
    fi
  fi
done
if [[ -z "${ca_ok}" ]]; then
  echo "CA bundle empty or absent; expected RHEL trust at /etc/pki/tls/certs/ca-bundle.crt" >&2
  exit 1
fi

echo "hardening checks passed for ${image_ref}"
echo "proof: no shell resolves by entrypoint or filesystem scan"
echo "proof: no dnf/microdnf/rpm/yum resolves by entrypoint or filesystem scan"
echo "proof: default user is ${runtime_user}"
echo "proof: rpmdb present at /${rpmdb_found}"
echo "proof: Syft enumerated RPM packages from the image rpmdb"
echo "proof: CA bundle populated via /${ca_ok}"
