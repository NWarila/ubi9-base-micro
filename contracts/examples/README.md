# Consumer Verification Example

This example verifies a pulled `ubi9-base-micro` digest against the declared
image manifest. Set the digest, publish ref, and platform architecture first:

```sh
IMAGE_REF="ghcr.io/nwarila/ubi9-base-micro@sha256:<digest>"
PUBLISH_REF="refs/heads/main"
ARCH="amd64"
PLATFORM="linux/${ARCH}"
MANIFEST="contracts/image-manifest.json"
```

Validate the manifest and read the expected FIPS status:

```sh
python tools/verify.py
python - "${MANIFEST}" "${ARCH}" <<'PY'
import json
import sys

manifest_path, arch = sys.argv[1:3]
manifest = json.load(open(manifest_path, encoding="utf-8"))
arch_contract = manifest["fips"]["architectures"][arch]
print("expected module=" + manifest["fips"]["module_version"])
print("expected provider=" + manifest["fips"]["provider_nevra"] + "." + arch_contract["rpm_arch"])
print("expected fips.so sha256=" + arch_contract["fips_so_sha256"])
print("expected oe_validated=" + str(arch_contract["oe_validated"]).lower())
PY
```

Pull by digest, export the runtime files, and compare `fips-status.json`,
`fips.so`, the rpmdb package floor, and the footprint ceiling to the manifest:

```sh
docker pull --platform "${PLATFORM}" "${IMAGE_REF}"
container_id="$(docker create --platform "${PLATFORM}" "${IMAGE_REF}" /contract-export)"
mkdir -p contract-check/rootfs
docker cp "${container_id}:/etc/nwarila/fips-status.json" contract-check/fips-status.json
docker export "${container_id}" | tar --no-same-owner --no-same-permissions -x -C contract-check/rootfs
docker rm "${container_id}"
```

```sh
python - "${MANIFEST}" "${ARCH}" contract-check/fips-status.json contract-check/rootfs <<'PY'
import json
import hashlib
import os
import sys
from pathlib import Path

manifest_path, arch, status_path, rootfs_path = sys.argv[1:5]
manifest = json.load(open(manifest_path, encoding="utf-8"))
status = json.load(open(status_path, encoding="utf-8"))
rootfs = Path(rootfs_path)
arch_contract = manifest["fips"]["architectures"][arch]
expected_status = {
    "arch": arch,
    "module": manifest["fips"]["module_version"],
    "provider_nvr": manifest["fips"]["provider_nevra"],
    "provider_nevra": manifest["fips"]["provider_nevra"] + "." + arch_contract["rpm_arch"],
    "cmvp": "#" + manifest["fips"]["cmvp"],
    "oe_validated": arch_contract["oe_validated"],
    "disclaimer": arch_contract["disclaimer"],
}
if status != expected_status:
    raise SystemExit("fips-status.json does not match manifest")

fips_so = rootfs / "usr/lib64/ossl-modules/fips.so"
if not fips_so.is_file():
    raise SystemExit("missing fips.so")
actual_sha = hashlib.sha256(fips_so.read_bytes()).hexdigest()
if actual_sha != arch_contract["fips_so_sha256"]:
    raise SystemExit("fips.so sha256 does not match manifest")
print("fips.so sha256=" + actual_sha)

regular_file_bytes = sum(path.stat().st_size for path in rootfs.rglob("*") if path.is_file())
if regular_file_bytes > manifest["runtime"]["footprint_limit_bytes"]:
    raise SystemExit("footprint exceeds manifest limit")
print("regular_file_bytes=" + str(regular_file_bytes))
print("footprint_limit_bytes=" + str(manifest["runtime"]["footprint_limit_bytes"]))

print("expected package floor=" + ",".join(manifest["runtime"]["package_floor"]))
print("compare the rpmdb package names from a scanner or rpm-capable rootfs against that floor")
PY
```

Verify the Cosign signature, repository-generated attestations, and SLSA
provenance with the identities in the manifest:

```sh
CERT_IDENTITY="$(python - "${MANIFEST}" "${PUBLISH_REF}" <<'PY'
import json
import sys

manifest_path, publish_ref = sys.argv[1:3]
identity = json.load(open(manifest_path, encoding="utf-8"))["provenance"]["cosign"]["certificate_identity"]
print(identity.replace("<ref>", publish_ref))
PY
)"
OIDC_ISSUER="$(python - "${MANIFEST}" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))["provenance"]["cosign"]["oidc_issuer"])
PY
)"
```

```sh
cosign verify "${IMAGE_REF}" \
  --certificate-identity "${CERT_IDENTITY}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}"
```

```sh
for type_name in spdx cyclonedx openvex nist_800_190 stig_arf; do
  predicate_type="$(python - "${MANIFEST}" "${type_name}" <<'PY'
import json
import sys

manifest_path, type_name = sys.argv[1:3]
print(json.load(open(manifest_path, encoding="utf-8"))["provenance"]["attestation_predicate_types"][type_name])
PY
)"
  cosign verify-attestation --type "${predicate_type}" "${IMAGE_REF}" \
    --certificate-identity "${CERT_IDENTITY}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}"
done
```

```sh
SLSA_BUILDER_ID="$(python - "${MANIFEST}" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))["provenance"]["slsa"]["builder_id"])
PY
)"
slsa-verifier verify-image "${IMAGE_REF}" \
  --source-uri github.com/NWarila/ubi9-base-micro \
  --builder-id "${SLSA_BUILDER_ID}"
```
