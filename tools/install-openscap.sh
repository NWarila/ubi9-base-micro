#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "OpenSCAP CI install helper only supports Linux runners" >&2
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
  python3-jinja2 \
  python3-yaml \
  xsltproc

command -v oscap >/dev/null
command -v oscap-podman >/dev/null
command -v podman >/dev/null

oscap --version
podman --version
