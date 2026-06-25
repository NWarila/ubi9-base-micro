#!/usr/bin/env bash
# Purpose: Download the pinned Trivy release for the host OS/arch (Trivy Linux/windows + 64bit/ARM64 asset naming),
# verify it against the published checksums, extract into dist/tools/, and print its version.
# Role: tooling
# Python-convertible: no — thin uname/curl/sha256sum/extract installer glue.
# Micro-container candidate: no — CI tool installer.
# Relocate: no — host/CI scanner installer, not a build-process script.

set -euo pipefail

version="${TRIVY_VERSION:-0.71.0}"
dest="${1:-dist/tools}"
tmp_dir="$(mktemp -d)"

cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

kernel_name="$(uname -s)"
machine_arch="$(uname -m)"

case "${kernel_name}" in
  Linux*)
    os="Linux"
    archive_ext="tar.gz"
    binary="trivy"
    ;;
  MINGW* | MSYS* | CYGWIN*)
    os="windows"
    archive_ext="zip"
    binary="trivy.exe"
    ;;
  *)
    echo "unsupported OS for trivy install: ${kernel_name}" >&2
    exit 1
    ;;
esac

case "${machine_arch}" in
  x86_64 | amd64)
    arch="64bit"
    ;;
  aarch64 | arm64)
    arch="ARM64"
    ;;
  *)
    echo "unsupported architecture for trivy install: ${machine_arch}" >&2
    exit 1
    ;;
esac

mkdir -p "${dest}"
archive="trivy_${version}_${os}-${arch}.${archive_ext}"
checksums="trivy_${version}_checksums.txt"
base_url="https://github.com/aquasecurity/trivy/releases/download/v${version}"

(
  cd "${tmp_dir}"
  curl -fsSLO "${base_url}/${archive}"
  curl -fsSLO "${base_url}/${checksums}"
  grep " ${archive}\$" "${checksums}" | sha256sum -c -

  if [[ "${archive_ext}" == "tar.gz" ]]; then
    tar xzf "${archive}" "${binary}"
    cp "${binary}" "${OLDPWD}/${dest}/trivy"
    chmod 0755 "${OLDPWD}/${dest}/trivy"
  else
    archive_path="$(cygpath -w "${PWD}/${archive}")"
    extract_path="$(cygpath -w "${PWD}/extract")"
    powershell.exe -NoProfile -Command "Expand-Archive -LiteralPath '${archive_path}' -DestinationPath '${extract_path}' -Force"
    cp "extract/${binary}" "${OLDPWD}/${dest}/trivy.exe"
    chmod 0755 "${OLDPWD}/${dest}/trivy.exe"
  fi
)

if [[ -x "${dest}/trivy" ]]; then
  "${dest}/trivy" --version
else
  "${dest}/trivy.exe" --version
fi
