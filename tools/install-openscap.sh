#!/usr/bin/env bash
set -euo pipefail

kernel_name="$(uname -s)"
if [[ "${kernel_name}" != "Linux" ]]; then
  echo "OpenSCAP CI install helper only supports Linux runners; got ${kernel_name}" >&2
  exit 2
fi

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  bzip2 \
  ca-certificates \
  cmake \
  curl \
  libxml2-utils \
  ninja-build \
  openscap-utils \
  podman \
  rpm \
  python3-jinja2 \
  python3-yaml \
  xsltproc

command -v oscap > /dev/null
command -v oscap-podman > /dev/null
command -v podman > /dev/null
command -v rpm > /dev/null

oscap --version
podman --version
