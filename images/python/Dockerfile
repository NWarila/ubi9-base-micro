# Purpose: base-python image build — clone the pinned published micro parent, apply the pinned python RPM
#          transaction with one combined rpmdb, strip build-support packages behind guards, ship FROM scratch.
# Role: build
# Build context: images/python/ (never the repository root).

ARG UBI_MINIMAL_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal@sha256:dd334afa72444fa46238fcf9e6bd399245adf746378735348cf84b9dfdca38f1
ARG BASE_MICRO_IMAGE=ghcr.io/nwarila/ubi9-base-micro@sha256:f1ad33e69ac71564a9a51f905772daacaf827aeef20dcdeedd1a10a27be80b88

# The literal published parent: both the runtime ancestor and the rootfs clone source.
# hadolint ignore=DL3026
FROM ${BASE_MICRO_IMAGE} AS micro-base

# Discarded builder stage: pinned python3.12 toolchain, pinned transaction, guarded strip.
# hadolint ignore=DL3026
FROM ${UBI_MINIMAL_IMAGE} AS python-rootfs
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TARGETARCH
ARG SOURCE_DATE_EPOCH=1704067200

COPY rpm-lock/builder.amd64.txt rpm-lock/builder.arm64.txt /tmp/rpm-lock/
COPY rpm-lock/python.amd64.txt rpm-lock/python.arm64.txt /tmp/rpm-lock/
COPY rpm-lock/micro-floor.json /tmp/micro-floor.json
COPY rpm-lock/requires-exceptions.json /tmp/requires-exceptions.json
COPY rpm-lock/retained-payload-trim.json /tmp/retained-payload-trim.json
COPY tools/assert-builder-toolchain-floor.sh /tmp/assert-builder-toolchain-floor.sh
COPY tools/fetch-builder-rpms.sh /tmp/fetch-builder-rpms.sh
COPY tools/fetch-python-rpms.sh /tmp/fetch-python-rpms.sh
COPY tools/build-python-rootfs.py /tmp/build-python-rootfs.py
COPY tools/retained_payload_trim.py /tmp/retained_payload_trim.py
COPY tools/rpmlock.py /tmp/rpmlock.py

COPY --from=micro-base / /rootfs

# Bootstrap the locked builder python closure (micro's proven pattern), guarding the rpmdb-writing
# toolchain across it; the same five-package writer floor is re-asserted against micro-floor.json's
# txn_writer section because THIS stage's rpm stack writes the shipped combined rpmdb.
RUN set -eux; \
    export SOURCE_DATE_EPOCH; \
    case "${TARGETARCH}" in \
      amd64) rpm_arch="x86_64"; builder_lockfile="/tmp/rpm-lock/builder.amd64.txt"; python_lockfile="/tmp/rpm-lock/python.amd64.txt" ;; \
      arm64) rpm_arch="aarch64"; builder_lockfile="/tmp/rpm-lock/builder.arm64.txt"; python_lockfile="/tmp/rpm-lock/python.arm64.txt" ;; \
      *) echo "unsupported TARGETARCH for RPM lockfile: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    test -s "${builder_lockfile}"; \
    test -s "${python_lockfile}"; \
    builder_rpm_paths=(); \
    while IFS='|' read -r package name epoch version release arch sha256_header sigmd5; do \
      case "${package}" in ""|\#*) continue ;; esac; \
      test -n "${name}" && test -n "${epoch}" && test -n "${version}" && test -n "${release}" && test -n "${arch}" && test -n "${sha256_header}" && test -n "${sigmd5}"; \
      case "${arch}" in noarch|"${rpm_arch}") ;; *) echo "locked builder package ${package} has wrong arch ${arch} for ${TARGETARCH}" >&2; exit 1 ;; esac; \
      builder_rpm_paths+=("/tmp/builder-rpms/${name}-${version}-${release}.${arch}.rpm"); \
    done < "${builder_lockfile}"; \
    test "${#builder_rpm_paths[@]}" -eq 7 || { echo "builder RPM lockfile must yield exactly 7 packages" >&2; exit 1; }; \
    snapshot_builder_toolchain() { \
      snapshot="$1"; \
      : > "${snapshot}"; \
      for package in rpm rpm-libs sqlite-libs glibc glibc-common; do \
        nevra="$(rpm -q --qf '%{NEVRA}\n' "${package}")"; \
        printf '%s|%s\n' "${package}" "${nevra}" >> "${snapshot}"; \
      done; \
    }; \
    snapshot_builder_toolchain /tmp/builder-toolchain.before; \
    mkdir -p /tmp/builder-rpms; \
    bash /tmp/fetch-builder-rpms.sh --targetarch "${TARGETARCH}" --lockfile "${builder_lockfile}" --dest /tmp/builder-rpms; \
    rpm -Uvh --oldpackage --replacepkgs --excludedocs "${builder_rpm_paths[@]}"; \
    snapshot_builder_toolchain /tmp/builder-toolchain.after; \
    bash /tmp/assert-builder-toolchain-floor.sh --before /tmp/builder-toolchain.before --after /tmp/builder-toolchain.after; \
    python3.12 -c 'import sys; print(sys.version)'; \
    rm -rf /tmp/builder-rpms /tmp/builder-toolchain.before; \
    mkdir -p /tmp/python-rpms /tmp/manifests; \
    bash /tmp/fetch-python-rpms.sh --targetarch "${TARGETARCH}" --lockfile "${python_lockfile}" --dest /tmp/python-rpms; \
    python3.12 /tmp/build-python-rootfs.py \
      --rootfs /rootfs \
      --lockfile "${python_lockfile}" \
      --micro-floor /tmp/micro-floor.json \
      --rpm-dir /tmp/python-rpms \
      --manifest-dir /tmp/manifests \
      --target-arch "${TARGETARCH}" \
      --txn-writer-snapshot /tmp/builder-toolchain.after \
      --requires-exceptions /tmp/requires-exceptions.json \
      --retained-payload-trim /tmp/retained-payload-trim.json

# Shipped image: the assembled combined rootfs as one layer. FROM scratch inherits nothing, so the
# full runtime configuration is restated here and asserted against the committed config contract.
FROM scratch AS runtime-common
ARG SOURCE_DATE_EPOCH

ARG OCI_CREATED="1970-01-01T00:00:00Z"
ARG OCI_DESCRIPTION="Hardened UBI 9 python3.12 runtime on the base-micro floor"
ARG OCI_REVISION="local"
ARG OCI_SOURCE="https://github.com/NWarila/ubi9-base-micro"
ARG OCI_TITLE="ubi9-base-python"
ARG OCI_VERSION="dev"

LABEL org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.description="${OCI_DESCRIPTION}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.title="${OCI_TITLE}" \
      org.opencontainers.image.version="${OCI_VERSION}"

COPY --from=python-rootfs /rootfs/ /

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV HOME=/home/nonroot
ENV OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf
ENV OPENSSL_MODULES=/usr/lib64/ossl-modules
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /
USER 65532:65532
ENTRYPOINT ["/usr/bin/python3.12"]

FROM runtime-common AS runtime-amd64
ARG OPENSSL_FIPS_MODULE_VERSION="3.0.7-395c1a240fbfffd8"
ARG OPENSSL_FIPS_PROVIDER_NEVRA="openssl-fips-provider-so-3.0.7-8.el9"
LABEL org.nwarila.fips.cmvp="4857" \
      org.nwarila.fips.cmvp.oe-validated="true" \
      org.nwarila.fips.module-version="${OPENSSL_FIPS_MODULE_VERSION}" \
      org.nwarila.fips.provider-nvr="${OPENSSL_FIPS_PROVIDER_NEVRA}"

FROM runtime-common AS runtime-arm64
ARG OPENSSL_FIPS_MODULE_VERSION="3.0.7-395c1a240fbfffd8"
ARG OPENSSL_FIPS_PROVIDER_NEVRA="openssl-fips-provider-so-3.0.7-8.el9"
LABEL org.nwarila.fips.cmvp="4857" \
      org.nwarila.fips.cmvp.oe-validated="false" \
      org.nwarila.fips.module-version="${OPENSSL_FIPS_MODULE_VERSION}" \
      org.nwarila.fips.provider-nvr="${OPENSSL_FIPS_PROVIDER_NEVRA}"

ARG TARGETARCH
# TARGETARCH selects the per-architecture runtime stage defined above.
# hadolint ignore=DL3006,DL3026
FROM runtime-${TARGETARCH} AS runtime
