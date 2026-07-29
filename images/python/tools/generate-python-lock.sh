#!/usr/bin/env bash
# Purpose: Refresh harness for the python delta lock — resolve the closure against a clone of the pinned
#          parent, derive shipped-vs-strip, render the lock, and regenerate micro-floor + scriptlet evidence.
# Role: refresh (host-run, podman + crane; never part of the image build)
# Micro-container candidate: no (drives containers; produces committed artifacts)

set -euo pipefail

usage() {
  cat >&2 << 'USAGE'
usage: generate-python-lock.sh --targetarch <amd64|arm64> --image-dir <images/python>

Regenerates rpm-lock/python.<arch>.txt, rpm-lock/scriptlets.<arch>.txt, and the
<arch> sections of rpm-lock/micro-floor.json from the parent digest pinned in
the Dockerfile. Fails if any scriptlet lacks a classification in
rpm-lock/scriptlet-classification.md.
USAGE
  exit 2
}

targetarch=""
image_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --targetarch)
      targetarch="${2:?}"
      shift 2
      ;;
    --image-dir)
      image_dir="${2:?}"
      shift 2
      ;;
    -h | --help) usage ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      ;;
  esac
done
{ [[ -n "${targetarch}" ]] && [[ -n "${image_dir}" ]]; } || usage
image_dir="$(cd "${image_dir}" && pwd)"
case "${targetarch}" in
  amd64)
    rpm_arch="x86_64"
    platform="linux/amd64"
    ;;
  arm64)
    rpm_arch="aarch64"
    platform="linux/arm64"
    ;;
  *)
    echo "unsupported --targetarch: ${targetarch}" >&2
    exit 2
    ;;
esac

dockerfile="${image_dir}/Dockerfile"
ubi_minimal="$(sed -n 's/^ARG UBI_MINIMAL_IMAGE=\(.*\)$/\1/p' "${dockerfile}")"
parent_ref="$(sed -n 's/^ARG BASE_MICRO_IMAGE=\(.*\)$/\1/p' "${dockerfile}")"
{ [[ -n "${ubi_minimal}" ]] && [[ -n "${parent_ref}" ]]; } || {
  echo "Dockerfile pins missing" >&2
  exit 1
}

workdir="$(mktemp -d "${TMPDIR:-/tmp}/python-lock.XXXXXX")"
trap 'rm -rf "${workdir}"' EXIT

echo "resolving parent ${platform} child digest for ${parent_ref}" >&2
child_digest="$(crane manifest "${parent_ref}" \
  | python3 -c 'import json,sys; ms=json.load(sys.stdin)["manifests"]; print(next(m["digest"] for m in ms if m.get("platform",{}).get("architecture")=="'"${targetarch}"'" and m["platform"]["os"]=="linux"))')"
parent_repo="${parent_ref%@*}"
crane export "${parent_repo}@${child_digest}" "${workdir}/parent.tar"

cp "${image_dir}/rpm-lock/requires-exceptions.json" "${workdir}/requires-exceptions.json"
cp "${image_dir}/rpm-lock/retained-payload-trim.json" "${workdir}/retained-payload-trim.json"
cp "${image_dir}/tools/retained_payload_trim.py" "${workdir}/retained_payload_trim.py"

podman run --rm --platform "${platform}" \
  -e TARGETARCH="${targetarch}" \
  -v "${workdir}:/work" \
  "${ubi_minimal}" bash -e -o pipefail -c '
  microdnf install -y tar findutils python3.12 >/dev/null 2>&1
  mkdir /rootfs && tar -xf /work/parent.tar -C /rootfs

  rpm --root=/rootfs -qa --qf "%{NEVRA}\n" | LC_ALL=C sort > /work/parent-floor.nevras
  for package in rpm rpm-libs sqlite-libs glibc glibc-common; do
    rpm -q --qf "%{NEVRA}\n" "${package}"
  done | LC_ALL=C sort > /work/txn-writer.nevras

  microdnf install -y --installroot=/rootfs --releasever=9 \
    --config=/etc/dnf/dnf.conf --noplugins \
    --setopt=reposdir=/etc/yum.repos.d \
    --setopt=varsdir=/etc/dnf/vars \
    --setopt=cachedir=/var/cache/mdnf \
    --setopt=keepcache=1 \
    --nodocs --setopt=install_weak_deps=0 \
    python3.12 2>&1 | grep -E "^Installing" | sed "s/^Installing: //" > /work/txn.log
  mkdir -p /work/rpms
  find /var/cache/mdnf -name "*.rpm" -exec cp {} /work/rpms/ \;

  : > /work/rows.tsv
  : > /work/scriptlets.txt
  for blob in /work/rpms/*.rpm; do
    rpm -qp --qf "%{NEVRA}|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SHA256HEADER}|%{SIGMD5}\n" "${blob}" >> /work/rows.tsv
    sha256sum "${blob}" >> /work/blob-shas.txt
    name="$(rpm -qp --qf "%{NAME}" "${blob}")"
    scripts="$(rpm -qp --scripts --triggers "${blob}" 2>/dev/null || true)"
    if [ -n "${scripts}" ]; then
      printf "===== %s =====\n%s\n" "${name}" "${scripts}" >> /work/scriptlets.txt
    fi
  done

  python3.12 - << "DERIVE"
import json
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, "/work")
from retained_payload_trim import (  # noqa: E402
    apply_retained_payload_trim,
    assert_exact_rpm_verify_deviations,
    load_trim_contract,
)

work = pathlib.Path("/work")
exceptions_raw = json.loads((work / "requires-exceptions.json").read_text())
exceptions = {name: set(tokens) for name, tokens in exceptions_raw.items() if not name.startswith("_")}
rows = {}
for line in (work / "rows.tsv").read_text().splitlines():
    nevra, name, epoch, version, release, arch, sha_header, sigmd5 = line.split("|")
    rows[name] = {
        "nevra": nevra, "name": name, "epoch": epoch, "version": version,
        "release": release, "arch": arch, "sha_header": sha_header, "sigmd5": sigmd5,
    }

def rpm_root(args):
    return subprocess.run(["rpm", "--root=/rootfs", *args], capture_output=True, text=True, check=True).stdout

floor_names = {line.rsplit("-", 2)[0] for line in (work / "parent-floor.nevras").read_text().split()}
overlap = sorted(set(rows) & floor_names)
if overlap:
    raise SystemExit(f"resolved closure overlaps the parent floor (CDN drift?): {overlap}")

# This is the same exact retained-package payload trim consumed by the image
# build. It is load-bearing: trim before deriving the protected ELF closure.
trim_entries = load_trim_contract(work / "retained-payload-trim.json", os.environ["TARGETARCH"])
apply_retained_payload_trim(
    pathlib.Path("/rootfs"),
    trim_entries,
    lambda path: rpm_root(["-qf", "--qf", "%{NAME}\n", path]).strip(),
)
assert_exact_rpm_verify_deviations(
    trim_entries,
    lambda package: subprocess.run(
        ["rpm", "--root=/rootfs", "-V", "--nodeps", package],
        capture_output=True,
        text=True,
    ),
)
print(f"exact retained-payload trim: {len(trim_entries)} paths")

# Shipped derivation: ELF-reachability closure from the python roots plus RPM Requires/Provides closure.
protected = set()
ldd_env = {"LD_LIBRARY_PATH": "/rootfs/usr/lib64"}
roots = ["/rootfs/usr/bin/python3.12", "/rootfs/usr/lib64/libpython3.12.so.1.0"]
roots += [str(p) for p in sorted(pathlib.Path("/rootfs/usr/lib64/python3.12/lib-dynload").glob("*.so"))]
for obj in roots:
    protected.add(obj.removeprefix("/rootfs"))
    out = subprocess.run(["ldd", obj], capture_output=True, text=True, env=ldd_env).stdout
    for line in out.splitlines():
        fields = line.split()
        if "=> /" in line and len(fields) >= 3:
            protected.add(fields[2].removeprefix("/rootfs"))
        elif line[:1].isspace() and fields and fields[0].startswith("/"):
            protected.add(fields[0].removeprefix("/rootfs"))

shipped = {"python3.12", "python3.12-libs", "python3.12-pip-wheel"}
for name in rows:
    if name in shipped:
        continue
    files = rpm_root(["-ql", name]).splitlines()
    if any(f in protected for f in files):
        shipped.add(name)

SCRIPTLET_KINDS = ("pre", "post", "preun", "postun", "verify", "interp")


def runtime_requires(name):
    out = rpm_root(["-q", "--qf", "[%{REQUIRENAME}\t%{REQUIREFLAGS:deptype}\n]", name])
    tokens = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        token, deptype = line.split("\t", 1)
        if any(kind in deptype for kind in SCRIPTLET_KINDS):
            continue
        if not token or token.startswith(("rpmlib(", "config(", "/")):
            continue
        if token in exceptions.get(name, set()):
            continue
        tokens.append(token)
    return tokens


changed = True
while changed:
    changed = False
    for name in sorted(shipped):
        for token in runtime_requires(name):
            provider = subprocess.run(
                ["rpm", "--root=/rootfs", "-q", "--whatprovides", token, "--qf", "%{NAME}\n"],
                capture_output=True, text=True,
            )
            if provider.returncode != 0:
                continue
            for pname in provider.stdout.split():
                if pname in rows and pname not in shipped and pname not in floor_names:
                    shipped.add(pname)
                    changed = True

result = {name: ("yes" if name in shipped else "no") for name in rows}
(work / "shipped.json").write_text(json.dumps(result, indent=1, sort_keys=True))
print("shipped:", sorted(n for n, v in result.items() if v == "yes"))
print("strip:", sorted(n for n, v in result.items() if v == "no"))
DERIVE

  repo_map_file=/work/repo-map.tsv
  : > "${repo_map_file}"
  while read -r line; do
    name="$(printf "%s" "${line}" | cut -d";" -f1)"
    repo="$(printf "%s" "${line}" | cut -d";" -f4)"
    printf "%s\t%s\n" "${name}" "${repo}" >> "${repo_map_file}"
  done < /work/txn.log
'

echo "deriving CDN URLs and rendering the lock" >&2
python3 - "${workdir}" "${targetarch}" "${rpm_arch}" "${image_dir}" << 'RENDER'
import hashlib
import json
import pathlib
import subprocess
import sys

work, targetarch, rpm_arch, image_dir = sys.argv[1:5]
work = pathlib.Path(work)
image_dir = pathlib.Path(image_dir)
base = "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9"
repo_by_name = {}
for line in (work / "repo-map.tsv").read_text().splitlines():
    name, repo = line.split("\t")
    repo_by_name[name] = "baseos" if "baseos" in repo else "appstream"
shipped = json.loads((work / "shipped.json").read_text())
blob_shas = {}
for line in (work / "blob-shas.txt").read_text().splitlines():
    sha, path = line.split(maxsplit=1)
    blob_shas[pathlib.Path(path).name] = sha

rows = []
for line in (work / "rows.tsv").read_text().splitlines():
    nevra, name, epoch, version, release, arch, sha_header, sigmd5 = line.split("|")
    filename = f"{name}-{version}-{release}.{arch}.rpm"
    repo = repo_by_name.get(name)
    candidates = [f"{base}/{rpm_arch}/{r}/os/Packages/{name[0].lower()}/{filename}" for r in
                  ([repo, "baseos" if repo == "appstream" else "appstream"] if repo else ["baseos", "appstream"])]
    url = None
    for candidate in candidates:
        probe = subprocess.run(["curl", "-fsI", "--proto", "=https", "--tlsv1.2", candidate], capture_output=True)
        if probe.returncode == 0:
            url = candidate
            break
    if url is None:
        raise SystemExit(f"no CDN URL found for {filename}")
    fetched = subprocess.run(
        ["curl", "-fsL", "--retry", "3", "--proto", "=https", "--tlsv1.2", url], capture_output=True
    )
    if fetched.returncode != 0:
        raise SystemExit(f"CDN fetch failed for {url}")
    sha = hashlib.sha256(fetched.stdout).hexdigest()
    if sha != blob_shas[filename]:
        raise SystemExit(f"CDN blob for {filename} does not match the resolved blob: {sha}")
    rows.append({
        "package": nevra, "final": shipped[name], "name": name, "epoch": epoch, "version": version,
        "release": release, "arch": arch, "sha_header": sha_header, "sigmd5": sigmd5, "url": url, "sha": sha,
    })

rows.sort(key=lambda row: row["package"])
source_date_epoch = "1704067200"
lines = [f"# arch: {targetarch}", f"# source_date_epoch: {source_date_epoch}",
         "# columns: package|final_rpmdb|name|epoch|version|release|arch|sha256_header|sigmd5"]
lines += [f"# direct_rpm: {row['package']}|{row['url']}|{row['sha']}" for row in rows]
lines += ["|".join((row["package"], row["final"], row["name"], row["epoch"], row["version"], row["release"],
                    row["arch"], row["sha_header"], row["sigmd5"])) for row in rows]
lock_path = image_dir / "rpm-lock" / f"python.{targetarch}.txt"
lock_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"wrote {lock_path} ({len(rows)} rows, "
      f"{sum(1 for row in rows if row['final'] == 'yes')} shipped)")
RENDER

echo "updating micro-floor.json and scriptlet evidence" >&2
python3 - "${workdir}" "${targetarch}" "${parent_ref}" "${child_digest}" "${ubi_minimal}" "${image_dir}" << 'FLOOR'
import json
import pathlib
import sys

work, targetarch, parent_ref, child_digest, ubi_minimal, image_dir = sys.argv[1:7]
work = pathlib.Path(work)
floor_path = pathlib.Path(image_dir) / "rpm-lock" / "micro-floor.json"
data = json.loads(floor_path.read_text()) if floor_path.is_file() else {}
parent = data.setdefault("parent", {})
parent["digest"] = parent_ref.split("@", 1)[1]
parent.setdefault("children", {})[targetarch] = child_digest
parent.setdefault("floor", {})[targetarch] = (work / "parent-floor.nevras").read_text().split()
writer = (work / "txn-writer.nevras").read_text().split()
data.setdefault("txn_writer", {})[targetarch] = writer
provenance = data.setdefault("provenance", {})
provenance["builder_image"] = ubi_minimal
provenance["capture"] = "rpm -q --qf %{NEVRA} on the pinned UBI-minimal builder for the five ADR-0014 packages"
provenance.setdefault("builder_toolchain", {})[targetarch] = writer
floor_path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
print(f"updated {floor_path}")
FLOOR
cp "${workdir}/scriptlets.txt" "${image_dir}/rpm-lock/scriptlets.${targetarch}.txt"

classification="${image_dir}/rpm-lock/scriptlet-classification.md"
if [[ ! -s "${classification}" ]]; then
  echo "missing ${classification}; classify every scriptlet before committing" >&2
  exit 1
fi
while read -r pkg; do
  if ! grep -q "^## ${pkg}\$" "${classification}"; then
    echo "unclassified scriptlet-bearing package: ${pkg} (add a '## ${pkg}' section to ${classification})" >&2
    exit 1
  fi
done < <(sed -n 's/^===== \(.*\) =====$/\1/p' "${image_dir}/rpm-lock/scriptlets.${targetarch}.txt" || true)

echo "python lock refresh complete for ${targetarch}"
