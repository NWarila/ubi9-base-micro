#!/usr/bin/env bash
# Purpose: Runtime gate driver for a built base-python image — hardening sweep, ownership scan, functional
#          battery with a real loopback TLS handshake, and OCI config assertion against the contract.
# Role: gate
# Micro-container candidate: partial — image-exec battery must stay a driver; config assertion could move.

set -euo pipefail

usage() {
  echo "usage: run-python-gates.sh --image <ref> --targetarch <amd64|arm64> --contract <image-manifest.json>" >&2
  exit 2
}

engine="${CONTAINER_ENGINE:-podman}"
image=""
targetarch=""
contract=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      image="${2:?}"
      shift 2
      ;;
    --targetarch)
      targetarch="${2:?}"
      shift 2
      ;;
    --contract)
      contract="${2:?}"
      shift 2
      ;;
    -h | --help) usage ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      ;;
  esac
done
{ [[ -n "${image}" ]] && [[ -n "${targetarch}" ]] && [[ -n "${contract}" ]]; } || usage
case "${targetarch}" in
  amd64) platform="linux/amd64" ;;
  arm64) platform="linux/arm64" ;;
  *)
    echo "unsupported --targetarch: ${targetarch}" >&2
    exit 2
    ;;
esac

workdir="$(mktemp -d "${TMPDIR:-/tmp}/python-gates.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT

echo "gate C: OCI config contract (${targetarch})"
"${engine}" image inspect "${image}" --format '{{json .Config}}' > "${workdir}/config.json"
python3 - "${workdir}/config.json" "${contract}" "${targetarch}" << 'CONFIG'
import json
import sys

config_path, contract_path, arch = sys.argv[1:4]
config = json.load(open(config_path, encoding="utf-8"))
contract = json.load(open(contract_path, encoding="utf-8"))["config"]

failures = []


def expect(condition, message):
    if not condition:
        failures.append(message)


expect(config.get("User") == contract["user"], f"User={config.get('User')!r}")
expect(config.get("Entrypoint") == contract["entrypoint"], f"Entrypoint={config.get('Entrypoint')!r}")
cmd = config.get("Cmd") or None
expect(cmd == contract["cmd"], f"Cmd={cmd!r}")
expect((config.get("WorkingDir") or "/") == contract["working_dir"], f"WorkingDir={config.get('WorkingDir')!r}")
expect(sorted(config.get("Env") or []) == sorted(contract["env"]), f"Env={config.get('Env')!r}")
labels = config.get("Labels") or {}
for key, value in contract["labels_common"].items():
    expect(labels.get(key) == value, f"label {key}={labels.get(key)!r}")
for key, value in contract["labels_arch"][arch].items():
    expect(labels.get(key) == value, f"label {key}={labels.get(key)!r}")
for key in ("org.opencontainers.image.created", "org.opencontainers.image.version"):
    expect(bool(labels.get(key)), f"label {key} missing")
revision = labels.get("org.opencontainers.image.revision", "")
expect(
    revision == "local" or (len(revision) == 40 and all(c in "0123456789abcdef" for c in revision)),
    f"revision label not local/40-hex: {revision!r}",
)

if failures:
    raise SystemExit("config contract failed: " + "; ".join(failures))
print("config contract ok")
CONFIG

echo "gate T: TLS fixture generation"
openssl req -x509 -newkey rsa:2048 -keyout "${workdir}/tls.key" -out "${workdir}/tls.crt" \
  -days 2 -nodes -subj "/CN=localhost" > /dev/null 2>&1
chmod a+r "${workdir}/tls.key" "${workdir}/tls.crt"

echo "gate F: characterized FIPS import behavior"
"${engine}" run --rm --platform "${platform}" "${image}" -c "import hashlib, random, ssl" \
  > "${workdir}/import.out" 2> "${workdir}/import.err" \
  || {
    echo "import hashlib/random/ssl failed" >&2
    exit 1
  }
grep_status=0
grep -q -v -E \
  "^(ERROR:root:code for hash (md5|blake2b|blake2s|sha3_[0-9]+|shake_[0-9]+) was not found\\.|Traceback \\(most recent call last\\):|  File .*|    .*|_hashlib\\.UnsupportedDigestmodError: .*|ValueError: unsupported hash type .*|During handling of the above exception, another exception occurred:|^$)$" \
  "${workdir}/import.err" || grep_status=$?
if [[ "${grep_status}" -ne 1 ]]; then
  echo "uncharacterized stderr on stdlib import, or pattern-match error (status ${grep_status}):" >&2
  cat "${workdir}/import.err" >&2
  exit 1
fi
echo "import noise matches the characterized approved-mode pattern set"

echo "gate B/O/R: in-image hardening + ownership + functional battery"
"${engine}" run --rm -i --platform "${platform}" \
  -v "${workdir}/tls.crt:/tmp/tls.crt:ro" \
  -v "${workdir}/tls.key:/tmp/tls.key:ro" \
  "${image}" - << 'BATTERY'
import hashlib
import importlib.util
import os
import socket
import ssl
import stat
import sys
import threading

failures = []


def expect(condition, message):
    if not condition:
        failures.append(message)


expect(os.getuid() == 65532 and os.getgid() == 65532, f"uid/gid {os.getuid()}:{os.getgid()}")
expect(os.environ.get("HOME") == "/home/nonroot", f"HOME={os.environ.get('HOME')!r}")
expect(os.environ.get("PYTHONDONTWRITEBYTECODE") == "1", "PYTHONDONTWRITEBYTECODE unset")

forbidden = [
    "bash", "sh", "dash", "ksh", "zsh", "microdnf", "dnf", "yum", "rpm",
    "pip", "pip3", "pip3.12", "gawk", "awk", "grep", "sed", "coreutils", "ls", "cat",
]
for directory in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
    for name in forbidden:
        expect(not os.path.lexists(os.path.join(directory, name)), f"forbidden executable {directory}/{name}")

world_writable = []
setuid = []
for base in ("/usr", "/etc", "/var"):
    for dirpath, dirnames, filenames in os.walk(base):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if st.st_mode & 0o002 and not st.st_mode & 0o1000:
                world_writable.append(path)
            if st.st_mode & (0o4000 | 0o2000):
                setuid.append(path)
expect(not world_writable, f"world-writable paths: {world_writable[:5]}")
expect(not setuid, f"setuid/setgid paths: {setuid[:5]}")
expect(not os.path.exists("/var/lib/rpm/rpmdb.sqlite-shm"), "rpmdb -shm sidecar shipped")
expect(not os.path.exists("/var/lib/rpm/rpmdb.sqlite-wal"), "rpmdb -wal sidecar shipped")
expect(os.path.getsize("/var/lib/rpm/rpmdb.sqlite") > 0, "rpmdb.sqlite missing/empty")

expect(importlib.util.find_spec("sqlite3") is None, "sqlite3 stdlib package is still discoverable")
try:
    __import__("sqlite3")
except ModuleNotFoundError as error:
    expect(error.name == "sqlite3", f"sqlite3 import failed through a partial module: {error.name!r}")
else:
    expect(False, "sqlite3 import unexpectedly succeeded")

sqlite_libraries = []
for library_root in ("/usr/lib64", "/usr/lib", "/lib64", "/lib"):
    if os.path.isdir(library_root):
        for dirpath, _dirnames, filenames in os.walk(library_root):
            sqlite_libraries.extend(
                os.path.join(dirpath, name) for name in filenames if name.startswith("libsqlite3")
            )
expect(not sqlite_libraries, f"SQLite libraries survived: {sqlite_libraries[:5]}")
dynload = "/usr/lib64/python3.12/lib-dynload"
sqlite_extensions = [
    os.path.join(dynload, name)
    for name in os.listdir(dynload)
    if name.startswith("_sqlite3")
]
expect(not sqlite_extensions, f"CPython _sqlite3 extension survived: {sqlite_extensions}")
expect(not os.path.lexists("/usr/lib64/python3.12/sqlite3"), "CPython sqlite3 package directory survived")
sqlite_build_ids = []
for dirpath, _dirnames, filenames in os.walk("/usr/lib/.build-id"):
    for name in filenames:
        path = os.path.join(dirpath, name)
        if os.path.islink(path):
            target = os.readlink(path)
            if "_sqlite3" in target or "libsqlite3" in target:
                sqlite_build_ids.append(path)
expect(not sqlite_build_ids, f"SQLite build-id links survived: {sqlite_build_ids}")

import bz2  # noqa: E402
import ctypes  # noqa: E402
import curses  # noqa: E402
import dbm.gnu  # noqa: E402
import decimal  # noqa: E402
import json  # noqa: E402
import lzma  # noqa: E402
import readline  # noqa: E402
import uuid  # noqa: E402
import zlib  # noqa: E402

import _hashlib  # noqa: E402

expect(_hashlib.get_fips_mode() == 1, f"FIPS mode not active: {_hashlib.get_fips_mode()}")
expect(len(hashlib.sha256(b"probe").hexdigest()) == 64, "sha256 failed")
expect(hashlib.new("sha512", b"probe").hexdigest() != "", "sha512 failed")
try:
    hashlib.new("md5", b"probe")
    md5_refused = False
except Exception:  # noqa: BLE001 - any refusal shape (ValueError/Unsupported/AttributeError) is correct
    md5_refused = True
expect(md5_refused, "md5 unexpectedly allowed in approved mode")

ctx = ssl.create_default_context()
expect(ctx.cert_store_stats()["x509_ca"] > 100, f"CA store too small: {ctx.cert_store_stats()}")

server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain("/tmp/tls.crt", "/tmp/tls.key")
client_ctx = ssl.create_default_context(cafile="/tmp/tls.crt")
listener = socket.create_server(("127.0.0.1", 0))
port = listener.getsockname()[1]
result = {}


def serve():
    conn, _ = listener.accept()
    with server_ctx.wrap_socket(conn, server_side=True) as tls:
        result["server_version"] = tls.version()
        tls.sendall(b"tlsprobe")


thread = threading.Thread(target=serve)
thread.start()
with socket.create_connection(("127.0.0.1", port)) as raw, client_ctx.wrap_socket(
    raw, server_hostname="localhost"
) as tls:
    payload = tls.recv(16)
    result["client_version"] = tls.version()
thread.join(timeout=10)
listener.close()
expect(payload == b"tlsprobe", f"TLS payload mismatch: {payload!r}")
expect(result.get("client_version") == result.get("server_version") and result.get("client_version"),
       f"TLS handshake versions: {result}")

if failures:
    print("BATTERY FAILURES:", file=sys.stderr)
    for failure in failures:
        print(f"  {failure}", file=sys.stderr)
    raise SystemExit(1)
print(f"battery ok: TLS {result['client_version']}, CA store live, hardening sweep clean")
BATTERY

echo "python gates passed for ${image} (${targetarch})"
