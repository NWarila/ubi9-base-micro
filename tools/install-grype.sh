#!/usr/bin/env bash
set -euo pipefail

version="${GRYPE_VERSION:-0.87.0}"
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
    binary="grype"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    os="windows"
    archive_ext="zip"
    binary="grype.exe"
    ;;
  *)
    echo "unsupported OS for grype install: $(uname -s)" >&2
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
    echo "unsupported architecture for grype install: $(uname -m)" >&2
    exit 1
    ;;
esac

mkdir -p "${dest}"
archive="grype_${version}_${os}_${arch}.${archive_ext}"
checksums="grype_${version}_checksums.txt"
base_url="https://github.com/anchore/grype/releases/download/v${version}"

(
  cd "${tmp_dir}"
  curl -fsSLO "${base_url}/${archive}"
  curl -fsSLO "${base_url}/${checksums}"
  grep " ${archive}\$" "${checksums}" | sha256sum -c -

  if [[ "${archive_ext}" == "tar.gz" ]]; then
    tar xzf "${archive}" "${binary}"
    cp "${binary}" "${OLDPWD}/${dest}/grype"
    chmod 0755 "${OLDPWD}/${dest}/grype"
  else
    archive_path="$(cygpath -w "${PWD}/${archive}")"
    extract_path="$(cygpath -w "${PWD}/extract")"
    powershell.exe -NoProfile -Command "Expand-Archive -LiteralPath '${archive_path}' -DestinationPath '${extract_path}' -Force"
    cp "extract/${binary}" "${OLDPWD}/${dest}/grype.exe"
    chmod 0755 "${OLDPWD}/${dest}/grype.exe"
  fi
)

if [[ -x "${dest}/grype" ]]; then
  "${dest}/grype" version
else
  "${dest}/grype.exe" version
fi
