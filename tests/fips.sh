#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tests/fips.sh <image-ref>

Validates the base-micro runtime OpenSSL FIPS floor artifacts:
  C7/C7a/C7c provider activation and md5 refusal are build-time probes
  because the runtime image intentionally has no openssl CLI or shell.
  This script asserts the shipped runtime artifacts and image ENV.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

image_ref="${1:-}"
if [[ -z "${image_ref}" ]]; then
  usage >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || {
  echo "docker is required for runtime FIPS artifact assertions" >&2
  exit 2
}

tmp_dir="$(mktemp -d)"
tar_path="${tmp_dir}/rootfs.tar"
container_id=""

cleanup() {
  if [[ -n "${container_id}" ]]; then
    docker rm "${container_id}" >/dev/null
  fi
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

container_id="$(docker create "${image_ref}" /fips-export-probe)"
docker export "${container_id}" -o "${tar_path}"
tar -tf "${tar_path}" | sed -e 's#^\./##' -e 's#/$##' > "${tmp_dir}/files.txt"

extract_file() {
  local rel="${1#/}"
  if tar -xOf "${tar_path}" "${rel}" 2>/dev/null; then
    return 0
  fi
  if tar -xOf "${tar_path}" "./${rel}" 2>/dev/null; then
    return 0
  fi
  return 1
}

assert_path_present() {
  local rel="${1#/}"
  if ! grep -Fxq "${rel}" "${tmp_dir}/files.txt"; then
    echo "required runtime path missing: /${rel}" >&2
    exit 1
  fi
}

assert_path_absent() {
  local rel="${1#/}"
  if grep -Fxq "${rel}" "${tmp_dir}/files.txt"; then
    echo "forbidden runtime path present: /${rel}" >&2
    exit 1
  fi
}

assert_nonempty_file() {
  local rel="${1#/}"
  local extracted="${tmp_dir}/$(basename "${rel}")"
  if ! extract_file "${rel}" > "${extracted}"; then
    echo "required runtime file missing or unreadable: /${rel}" >&2
    exit 1
  fi
  if [[ ! -s "${extracted}" ]]; then
    echo "required runtime file is empty: /${rel}" >&2
    exit 1
  fi
}

assert_file_contains() {
  local rel="${1#/}"
  local needle="$2"
  local extracted="${tmp_dir}/$(basename "${rel}").content"
  if ! extract_file "${rel}" > "${extracted}"; then
    echo "required runtime file missing or unreadable: /${rel}" >&2
    exit 1
  fi
  if ! grep -Fq "${needle}" "${extracted}"; then
    echo "runtime file /${rel} missing required text: ${needle}" >&2
    exit 1
  fi
}

assert_path_present usr/lib64/ossl-modules/fips.so
assert_nonempty_file usr/lib64/ossl-modules/fips.so
assert_path_absent usr/lib64/ossl-modules/legacy.so
assert_path_absent etc/pki/tls/fipsmodule.cnf
assert_path_present usr/lib64/libcrypto.so.3
assert_path_present etc/pki/tls/openssl-fips.cnf
assert_nonempty_file etc/pki/tls/openssl-fips.cnf
assert_file_contains etc/pki/tls/openssl-fips.cnf "[fips_sect]"
assert_file_contains etc/pki/tls/openssl-fips.cnf "default_properties = fips=yes"
assert_path_absent usr/bin/openssl
assert_path_present etc/nwarila/fips-status.json
assert_nonempty_file etc/nwarila/fips-status.json

status_file="${tmp_dir}/fips-status.json"
if ! extract_file etc/nwarila/fips-status.json > "${status_file}"; then
  echo "required runtime file missing or unreadable: /etc/nwarila/fips-status.json" >&2
  exit 1
fi

image_arch="$(docker image inspect --format '{{ .Architecture }}' "${image_ref}")"
case "${image_arch}" in
  amd64)
    expected_module="3.0.7-395c1a240fbfffd8"
    expected_provider_nvr="openssl-fips-provider-so-3.0.7-8.el9"
    expected_provider_nevra="${expected_provider_nvr}.x86_64"
    expected_oe_validated=true
    expected_disclaimer="CMVP #4857-validated approved-mode configuration."
    ;;
  arm64)
    expected_module="3.0.7-cda111b5812c30d4"
    expected_provider_nvr="openssl-fips-provider-so-3.0.7-11.el9_8"
    expected_provider_nevra="${expected_provider_nvr}.aarch64"
    expected_oe_validated=false
    expected_disclaimer="The Red Hat OpenSSL FIPS provider is present, approved-mode-configured, and self-test-passing, but this aarch64 operational environment is NOT in CMVP #4857's validated or vendor-affirmed list - this is NOT a CMVP-validated configuration on this architecture."
    ;;
  *)
    echo "unsupported image architecture for FIPS status assertion: ${image_arch}" >&2
    exit 1
    ;;
esac

status_needles=(
  '"arch": "'"${image_arch}"'"'
  '"module": "'"${expected_module}"'"'
  '"cmvp": "#4857"'
  '"oe_validated": '"${expected_oe_validated}"
  "${expected_disclaimer}"
)
if [[ "${image_arch}" == "arm64" ]]; then
  status_needles+=(
    '"provider_nvr": "'"${expected_provider_nvr}"'"'
    '"provider_nevra": "'"${expected_provider_nevra}"'"'
  )
else
  for legacy_absent in '"provider_nvr":' '"provider_nevra":'; do
    if grep -Fq "${legacy_absent}" "${status_file}"; then
      echo "amd64 fips-status.json changed from the main byte-identity baseline: ${legacy_absent}" >&2
      cat "${status_file}" >&2
      exit 1
    fi
  done
fi

for needle in "${status_needles[@]}"; do
  if ! grep -Fq "${needle}" "${status_file}"; then
    echo "fips-status.json missing required value: ${needle}" >&2
    cat "${status_file}" >&2
    exit 1
  fi
done

env_values="$(docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${image_ref}")"
if ! grep -Fxq "OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf" <<<"${env_values}"; then
  echo "image ENV missing OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf" >&2
  exit 1
fi
if ! grep -Fxq "OPENSSL_MODULES=/usr/lib64/ossl-modules" <<<"${env_values}"; then
  echo "image ENV missing OPENSSL_MODULES=/usr/lib64/ossl-modules" >&2
  exit 1
fi

cmvp_label="$(docker image inspect --format '{{ index .Config.Labels "org.nwarila.fips.cmvp" }}' "${image_ref}")"
oe_label="$(docker image inspect --format '{{ index .Config.Labels "org.nwarila.fips.cmvp.oe-validated" }}' "${image_ref}")"
module_label="$(docker image inspect --format '{{ index .Config.Labels "org.nwarila.fips.module-version" }}' "${image_ref}")"
provider_label="$(docker image inspect --format '{{ index .Config.Labels "org.nwarila.fips.provider-nvr" }}' "${image_ref}")"
if [[ "${cmvp_label}" != "4857" ]]; then
  echo "image label org.nwarila.fips.cmvp mismatch: ${cmvp_label}" >&2
  exit 1
fi
if [[ "${oe_label}" != "${expected_oe_validated}" ]]; then
  echo "image label org.nwarila.fips.cmvp.oe-validated mismatch: ${oe_label}" >&2
  exit 1
fi
if [[ "${module_label}" != "${expected_module}" ]]; then
  echo "image label org.nwarila.fips.module-version mismatch: ${module_label}" >&2
  exit 1
fi
if [[ "${provider_label}" != "${expected_provider_nvr}" ]]; then
  echo "image label org.nwarila.fips.provider-nvr mismatch: ${provider_label}" >&2
  exit 1
fi

echo "FIPS artifact checks passed for ${image_ref}"
echo "proof: fips.so present and non-empty"
echo "proof: openssl-fips.cnf present with fips section and default_properties = fips=yes"
echo "proof: libcrypto.so.3 present"
echo "proof: legacy provider, fipsmodule.cnf, and openssl CLI absent from the runtime"
echo "proof: OPENSSL_CONF and OPENSSL_MODULES image ENV are set"
echo "proof: fips-status.json matches image architecture ${image_arch} with oe_validated=${expected_oe_validated}"
echo "proof: FIPS OCI labels match per-arch CMVP OE scope, module version, and provider NVR pins"
