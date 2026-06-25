# Reproduce a Build Byte for Byte

Use this task when proving the F3 rootfs byte-identity gate locally. The design
rationale is in [`../explanation/reproducibility.md`](../explanation/reproducibility.md).

## Prerequisites

- Docker with Buildx
- QEMU/binfmt support for `linux/arm64`
- Network access for the pinned Red Hat UBI direct-CDN RPM URLs and pinned tool downloads

## Procedure

Run the amd64 gate:

```sh
python tools/assert-reproducible.py \
  --platform linux/amd64 \
  --assert-byte-identical \
  --report dist/reproducibility/base-micro.amd64.reproducibility.json \
  --summary dist/reproducibility/base-micro.amd64.reproducibility.txt \
  --workdir dist/reproducibility/work.amd64
```

Run the arm64 gate:

```sh
python tools/assert-reproducible.py \
  --platform linux/arm64 \
  --assert-byte-identical \
  --report dist/reproducibility/base-micro.arm64.reproducibility.json \
  --summary dist/reproducibility/base-micro.arm64.reproducibility.txt \
  --workdir dist/reproducibility/work.arm64
```

The arm64 result is reproducible relative to the pinned QEMU/binfmt path used by
CI. A byte difference in either platform is a failing gate, including
differences under `/var/lib/rpm/rpmdb.sqlite`.
