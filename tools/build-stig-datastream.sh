#!/usr/bin/env bash
set -euo pipefail

version="${SSG_VERSION:-0.1.81}"
sha512="${SSG_TARBALL_SHA512:-}"
out_dir="${1:-dist/openscap}"

if [[ -z "${sha512}" ]]; then
  echo "SSG_TARBALL_SHA512 must be set" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${out_dir}"

ssg_python="/usr/bin/python3"
if [[ ! -x "${ssg_python}" ]]; then
  echo "required SSG Python interpreter is not executable: ${ssg_python}" >&2
  exit 1
fi

if ! "${ssg_python}" -c 'import jinja2, yaml' >/dev/null 2>&1; then
  echo "${ssg_python} cannot import jinja2 and yaml; run tools/install-openscap.sh to install python3-jinja2 and python3-yaml" >&2
  exit 1
fi

tarball="scap-security-guide-${version}.tar.bz2"
tarball_path="${out_dir}/${tarball}"
base_url="https://github.com/ComplianceAsCode/content/releases/download/v${version}"

if [[ ! -s "${tarball_path}" ]]; then
  curl -fsSL -o "${tarball_path}" "${base_url}/${tarball}"
fi

printf '%s  %s\n' "${sha512}" "${tarball_path}" | sha512sum -c -

src_dir="${out_dir}/scap-security-guide-${version}"
if [[ ! -d "${src_dir}" ]]; then
  tar xjf "${tarball_path}" -C "${out_dir}"
fi

build_dir="${src_dir}/build"
mkdir -p "${build_dir}"
cmake -S "${src_dir}" -B "${build_dir}" -G Ninja \
  -DPython_EXECUTABLE="${ssg_python}" \
  -DSSG_PRODUCT_DEFAULT=OFF \
  -DSSG_PRODUCT_RHEL9=ON
ninja -C "${build_dir}" generate-ssg-rhel9-ds.xml

datastream="$(find "${build_dir}" -name 'ssg-rhel9-ds.xml' -print -quit)"
if [[ -z "${datastream}" || ! -s "${datastream}" ]]; then
  echo "failed to locate generated ssg-rhel9-ds.xml under ${build_dir}" >&2
  exit 1
fi

controls="${src_dir}/products/rhel9/controls/stig_rhel9.yml"
if [[ ! -s "${controls}" ]]; then
  echo "failed to locate RHEL9 STIG controls at ${controls}" >&2
  exit 1
fi

cp "${datastream}" "${out_dir}/ssg-rhel9-ds.xml"
cp "${controls}" "${out_dir}/stig_rhel9.yml"

"${ssg_python}" "${repo_root}/tools/assert-stig-tailoring.py" \
  --tailoring "${repo_root}/stig/rhel9-base-micro-tailoring.xml" \
  --justifications "${repo_root}/stig/tailoring-justifications.json" \
  --controls-yaml "${out_dir}/stig_rhel9.yml" \
  --datastream "${out_dir}/ssg-rhel9-ds.xml"

echo "generated datastream: ${out_dir}/ssg-rhel9-ds.xml"
echo "copied STIG controls: ${out_dir}/stig_rhel9.yml"
