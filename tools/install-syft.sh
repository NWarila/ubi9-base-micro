#!/usr/bin/env bash
set -euo pipefail

version="${SYFT_VERSION:-1.45.1}"
dest="${1:-dist/tools}"
tmp_dir="$(mktemp -d)"

cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

case "$(uname -s)" in
  Linux*)
    os="linux"
    archive_ext="tar.gz"
    binary="syft"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    os="windows"
    archive_ext="zip"
    binary="syft.exe"
    ;;
  *)
    echo "unsupported OS for syft install: $(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64)
    arch="amd64"
    ;;
  aarch64|arm64)
    arch="arm64"
    ;;
  *)
    echo "unsupported architecture for syft install: $(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "${dest}"
archive="syft_${version}_${os}_${arch}.${archive_ext}"
checksums="syft_${version}_checksums.txt"
base_url="https://github.com/anchore/syft/releases/download/v${version}"

(
  cd "${tmp_dir}"
  curl -fsSLO "${base_url}/${archive}"
  curl -fsSLO "${base_url}/${checksums}"
  grep " ${archive}\$" "${checksums}" | sha256sum -c -

  if [[ "${archive_ext}" == "tar.gz" ]]; then
    tar xzf "${archive}" "${binary}"
    cp "${binary}" "${OLDPWD}/${dest}/syft"
    chmod 0755 "${OLDPWD}/${dest}/syft"
  else
    archive_path="$(cygpath -w "${PWD}/${archive}")"
    extract_path="$(cygpath -w "${PWD}/extract")"
    powershell.exe -NoProfile -Command "Expand-Archive -LiteralPath '${archive_path}' -DestinationPath '${extract_path}' -Force"
    cp "extract/${binary}" "${OLDPWD}/${dest}/syft.exe"
    chmod 0755 "${OLDPWD}/${dest}/syft.exe"
  fi
)

if [[ -x "${dest}/syft" ]]; then
  "${dest}/syft" version
else
  "${dest}/syft.exe" version
fi
