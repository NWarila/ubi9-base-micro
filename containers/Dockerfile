# syntax=docker/dockerfile:1.7
# Purpose: Multi-stage hardened build for ubi9-base-micro: FIPS-provider proof, shell-free runtime rootfs from the
# pinned RPM lockfile, and distroless ubi-micro runtime + dev images.
# Role: container-build
# Relocate: no (Dockerfile stays; extract the inline RUN shell into containers/scripts/ helpers)
# NOTE: header must follow the `# syntax=` directive line (line 1 must remain the parser directive).

ARG BUILDKIT_SBOM_SCAN_CONTEXT=true

# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-minimal
ARG UBI_MINIMAL_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal@sha256:ae09ecc3d754bc1726cbda3e2599cc7839e09fe1cc547ce173cf669b645be3cc
# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-micro
ARG UBI_MICRO_IMAGE=registry.access.redhat.com/ubi9/ubi-micro@sha256:b498b3ea26111ab4b81d65139f2ebd2ef9a2abb7a4588b7fdcc54889f95e9caa
ARG OPENSSL_FIPS_MODULE_VERSION=3.0.7-395c1a240fbfffd8
ARG OPENSSL_FIPS_PROVIDER_NEVRA=openssl-fips-provider-so-3.0.7-8.el9
ARG OPENSSL_FIPS_PROVIDER_RPM_BASE_URL=https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9
ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64=bbf25303def8e1270675531c47bdad432f6ad8ef4c327556ae65bd6abaf8edb5
ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64=0cfe7b281ae2ca3cb0ceaa1a0b84f8c087c4ac16662ebb9c19b5681cf39f99a9
ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64=ab48d98504fae6f8636de027a1ee06d21d5e9c27b7beb247017a6fe55567c5e9
ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64=18c77b9b37e7abf0e8cf1dac4b3de770efe895547bdcab8aea8d8d8592954947
ARG OPENSSL_FIPS_SO_SHA256_AMD64=c197b6ddf74532f477bcb34e25b6e109491765d577b9fe1a4c4759239b6aae06
ARG OPENSSL_FIPS_SO_SHA256_ARM64=669910b59bca2c9a9cf5a33d3e63e6d94224d2e3b0fecd259cd235c9cf9c71cd
ARG SOURCE_DATE_EPOCH=1704067200

# UBI build-arg defaults are registry-qualified, digest-pinned, and verified by tools/verify.py.
# hadolint ignore=DL3026
FROM ${UBI_MINIMAL_IMAGE} AS fips-verify
ARG BUILDKIT_SBOM_SCAN_STAGE=true
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TARGETARCH
ARG DNF_REPOS=""
ARG OPENSSL_FIPS_MODULE_VERSION
ARG OPENSSL_FIPS_PROVIDER_NEVRA
ARG OPENSSL_FIPS_PROVIDER_RPM_BASE_URL
ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64
ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64
ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64
ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64
ARG OPENSSL_FIPS_SO_SHA256_AMD64
ARG OPENSSL_FIPS_SO_SHA256_ARM64
ARG SOURCE_DATE_EPOCH

COPY containers/fips/openssl.cnf /tmp/openssl-fips.cnf
COPY rpm-lock/builder.amd64.txt rpm-lock/builder.arm64.txt /tmp/rpm-lock/
COPY rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt /tmp/rpm-lock/
COPY tools/fetch-builder-rpms.sh /tmp/fetch-builder-rpms.sh
COPY tools/fetch-runtime-rpms.sh /tmp/fetch-runtime-rpms.sh
COPY tools/verify-fips-provider.py /tmp/verify-fips-provider.py

# The FIPS provider NEVRA is asserted after install; this verification stage does not ship directly.
# hadolint ignore=DL3041
# The builder loop below bootstraps python, so it cannot use rpmlock.py (ADR-0014).
RUN set -eux; \
    export SOURCE_DATE_EPOCH; \
    case "${TARGETARCH}" in \
      amd64) rpm_arch="x86_64"; builder_lockfile="/tmp/rpm-lock/builder.amd64.txt"; runtime_lockfile="/tmp/rpm-lock/runtime.amd64.txt"; expected_fips_so_sha256="${OPENSSL_FIPS_SO_SHA256_AMD64}" ;; \
      arm64) rpm_arch="aarch64"; builder_lockfile="/tmp/rpm-lock/builder.arm64.txt"; runtime_lockfile="/tmp/rpm-lock/runtime.arm64.txt"; expected_fips_so_sha256="${OPENSSL_FIPS_SO_SHA256_ARM64}" ;; \
      *) echo "unsupported TARGETARCH for FIPS provider pin: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    test -s "${builder_lockfile}" || { echo "builder RPM lockfile missing: ${builder_lockfile}" >&2; exit 1; }; \
    test -s "${runtime_lockfile}" || { echo "runtime RPM lockfile missing: ${runtime_lockfile}" >&2; exit 1; }; \
    builder_rpm_paths=(); \
    while IFS='|' read -r package name epoch version release arch sha256_header sigmd5; do \
      case "${package}" in ""|\#*) continue ;; esac; \
      test -n "${name}" && test -n "${epoch}" && test -n "${version}" && test -n "${release}" && test -n "${arch}" && test -n "${sha256_header}" && test -n "${sigmd5}"; \
      case "${arch}" in noarch|"${rpm_arch}") ;; *) echo "locked builder package ${package} has wrong arch ${arch} for ${TARGETARCH}" >&2; exit 1 ;; esac; \
      builder_rpm_paths+=("/tmp/builder-rpms/${name}-${version}-${release}.${arch}.rpm"); \
    done < "${builder_lockfile}"; \
    test "${#builder_rpm_paths[@]}" -eq 7 || { echo "builder RPM lockfile must yield exactly 7 packages" >&2; exit 1; }; \
    mkdir -p /tmp/builder-rpms; \
    bash /tmp/fetch-builder-rpms.sh --targetarch "${TARGETARCH}" --lockfile "${builder_lockfile}" --dest /tmp/builder-rpms; \
    echo "installing locked builder Python RPM transaction"; \
    rpm -Uvh --oldpackage --replacepkgs --excludedocs "${builder_rpm_paths[@]}"; \
    python3.12 -c 'import sys; print(sys.version)'; \
    rm -rf /tmp/builder-rpms; \
    fips_provider_nvr="${OPENSSL_FIPS_PROVIDER_NEVRA#openssl-fips-provider-so-}"; \
    test "${fips_provider_nvr}" != "${OPENSSL_FIPS_PROVIDER_NEVRA}" || { echo "invalid FIPS provider NEVRA pin: ${OPENSSL_FIPS_PROVIDER_NEVRA}" >&2; exit 1; }; \
    mkdir -p /tmp/runtime-rpms; \
    bash /tmp/fetch-runtime-rpms.sh --targetarch "${TARGETARCH}" --lockfile "${runtime_lockfile}" --dest /tmp/runtime-rpms; \
    dnf_repo_args=(); \
    if [ -n "${DNF_REPOS}" ]; then dnf_repo_args=("--disablerepo=*" "--enablerepo=${DNF_REPOS}"); fi; \
    microdnf install -y --releasever=9 \
      --config=/etc/dnf/dnf.conf --noplugins \
      --setopt=reposdir=/etc/yum.repos.d \
      --setopt=varsdir=/etc/dnf/vars \
      --nodocs --setopt=install_weak_deps=0 \
      "${dnf_repo_args[@]}" \
      openssl crypto-policies; \
    rpm -Uvh --oldpackage --replacepkgs \
      "/tmp/runtime-rpms/openssl-fips-provider-${fips_provider_nvr}.${rpm_arch}.rpm" \
      "/tmp/runtime-rpms/${OPENSSL_FIPS_PROVIDER_NEVRA}.${rpm_arch}.rpm"; \
    microdnf clean all; \
    python3.12 /tmp/verify-fips-provider.py \
      --target-arch "${TARGETARCH}" \
      --provider-nevra "${OPENSSL_FIPS_PROVIDER_NEVRA}" \
      --module-version "${OPENSSL_FIPS_MODULE_VERSION}" \
      --expected-fips-so-sha256 "${expected_fips_so_sha256}" \
      --openssl-cnf /tmp/openssl-fips.cnf \
      --modules-dir /usr/lib64/ossl-modules \
      --proof-dir /fips-proof

# UBI build-arg defaults are registry-qualified, digest-pinned, and verified by tools/verify.py.
# hadolint ignore=DL3026
FROM ${UBI_MINIMAL_IMAGE} AS rpm-rootfs
ARG BUILDKIT_SBOM_SCAN_STAGE=true
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TARGETARCH
ARG DNF_REPOS=""
ARG OPENSSL_FIPS_MODULE_VERSION
ARG OPENSSL_FIPS_PROVIDER_NEVRA
ARG OPENSSL_FIPS_PROVIDER_RPM_BASE_URL
ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64
ARG OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64
ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64
ARG OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64
ARG SOURCE_DATE_EPOCH

COPY rpm-lock/builder.amd64.txt rpm-lock/builder.arm64.txt /tmp/rpm-lock/
COPY rpm-lock/runtime.amd64.txt rpm-lock/runtime.arm64.txt /tmp/rpm-lock/
COPY contracts/image-manifest.json /tmp/image-manifest.json
COPY tools/assert-builder-toolchain-floor.sh /tmp/assert-builder-toolchain-floor.sh
COPY tools/assert-rpm-lock-hashes.sh /tmp/assert-rpm-lock-hashes.sh
COPY tools/build-runtime-rootfs.py /tmp/build-runtime-rootfs.py
COPY tools/fetch-builder-rpms.sh /tmp/fetch-builder-rpms.sh
COPY tools/fetch-runtime-rpms.sh /tmp/fetch-runtime-rpms.sh
COPY tools/rpmlock.py /tmp/rpmlock.py
COPY tools/write-fips-status.py /tmp/write-fips-status.py

# Install the direct-CDN-pinned Python closure into this discarded stage's own
# root before creating /rootfs. Guard the rpmdb-writing toolchain across it.
# Assemble the runtime rootfs with a raw rpm transaction (rpm --initdb + rpm -Uvh)
# over the fetched, sha256+GPG-verified local RPM paths in lockfile (LC_ALL=C)
# order -- no microdnf/metadata resolution; the lockfile is the complete
# pre-resolved closure (rpm -Uvh without --nodeps aborts on any missing dep).
# /var/lib/rpm is retained for scanners; only regenerable caches and logs are pruned.
# The builder loop below bootstraps python, so it cannot use rpmlock.py (ADR-0014).
RUN --mount=from=fips-verify,source=/fips-proof,target=/tmp/fips-proof,ro \
    --mount=from=fips-verify,source=/usr/bin/openssl,target=/tmp/fips-openssl,ro \
    --mount=from=fips-verify,source=/usr/lib64,target=/tmp/fips-lib64,ro \
    set -eux; \
    export SOURCE_DATE_EPOCH; \
    case "${TARGETARCH}" in \
      amd64) rpm_arch="x86_64"; builder_lockfile="/tmp/rpm-lock/builder.amd64.txt"; runtime_lockfile="/tmp/rpm-lock/runtime.amd64.txt" ;; \
      arm64) rpm_arch="aarch64"; builder_lockfile="/tmp/rpm-lock/builder.arm64.txt"; runtime_lockfile="/tmp/rpm-lock/runtime.arm64.txt" ;; \
      *) echo "unsupported TARGETARCH for RPM lockfile: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    test -s "${builder_lockfile}" || { echo "builder RPM lockfile missing: ${builder_lockfile}" >&2; exit 1; }; \
    test -s "${runtime_lockfile}" || { echo "runtime RPM lockfile missing: ${runtime_lockfile}" >&2; exit 1; }; \
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
    echo "installing locked builder Python RPM transaction"; \
    rpm -Uvh --oldpackage --replacepkgs --excludedocs "${builder_rpm_paths[@]}"; \
    snapshot_builder_toolchain /tmp/builder-toolchain.after; \
    bash /tmp/assert-builder-toolchain-floor.sh --before /tmp/builder-toolchain.before --after /tmp/builder-toolchain.after; \
    python3.12 -c 'import sys; print(sys.version)'; \
    rm -rf /tmp/builder-rpms /tmp/builder-toolchain.before /tmp/builder-toolchain.after; \
    rt_tmp="/tmp/runtime-rpm-filenames.txt"; \
    python3.12 /tmp/rpmlock.py rpm-filenames --lockfile "${runtime_lockfile}" --arch "${TARGETARCH}" --source-date-epoch "${SOURCE_DATE_EPOCH}" --openssl-fips-provider-nevra "${OPENSSL_FIPS_PROVIDER_NEVRA}" --openssl-fips-provider-rpm-base-url "${OPENSSL_FIPS_PROVIDER_RPM_BASE_URL}" --openssl-fips-provider-rpm-sha256-x86-64 "${OPENSSL_FIPS_PROVIDER_RPM_SHA256_X86_64}" --openssl-fips-provider-rpm-sha256-aarch64 "${OPENSSL_FIPS_PROVIDER_RPM_SHA256_AARCH64}" --openssl-fips-provider-so-rpm-sha256-x86-64 "${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_X86_64}" --openssl-fips-provider-so-rpm-sha256-aarch64 "${OPENSSL_FIPS_PROVIDER_SO_RPM_SHA256_AARCH64}" > "${rt_tmp}"; \
    mapfile -t rt_names < "${rt_tmp}"; \
    locked_rpm_paths=(); \
    for rt_name in "${rt_names[@]}"; do \
      locked_rpm_paths+=("/tmp/runtime-rpms/${rt_name}"); \
    done; \
    rm -f "${rt_tmp}"; \
    test "${#locked_rpm_paths[@]}" -gt 0 || { echo "runtime RPM lockfile yielded no local RPM paths" >&2; exit 1; }; \
    mkdir -p /tmp/runtime-rpms; \
    bash /tmp/fetch-runtime-rpms.sh --targetarch "${TARGETARCH}" --lockfile "${runtime_lockfile}" --dest /tmp/runtime-rpms; \
    echo "installing locked runtime RPM transaction"; \
    mkdir -p /rootfs; \
    rpm --root=/rootfs --initdb; \
    rpm --root=/rootfs -Uvh --oldpackage --replacepkgs --excludedocs "${locked_rpm_paths[@]}"; \
    microdnf clean all; \
    rm -rf /rootfs/var/cache/* /var/cache/microdnf-installroot \
      /rootfs/var/log/dnf.log /rootfs/var/log/dnf.librepo.log /rootfs/var/log/hawkey.log; \
    bash /tmp/assert-rpm-lock-hashes.sh --root /rootfs --lockfile "${runtime_lockfile}" --direct-rpm-dir /tmp/runtime-rpms; \
    python3.12 /tmp/build-runtime-rootfs.py build \
      --rootfs /rootfs \
      --runtime-lockfile "${runtime_lockfile}" \
      --fips-proof /tmp/fips-proof \
      --fips-openssl /tmp/fips-openssl \
      --fips-lib64 /tmp/fips-lib64 \
      --target-arch "${TARGETARCH}" \
      --provider-nevra "${OPENSSL_FIPS_PROVIDER_NEVRA}" \
      --module-version "${OPENSSL_FIPS_MODULE_VERSION}"; \
    python3.12 /tmp/write-fips-status.py --contract /tmp/image-manifest.json --target-arch "${TARGETARCH}" --provider-nevra "${OPENSSL_FIPS_PROVIDER_NEVRA}" --module-version "${OPENSSL_FIPS_MODULE_VERSION}" --output /rootfs/etc/nwarila/fips-status.json; \
    find /rootfs -xdev -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# UBI build-arg defaults are registry-qualified, digest-pinned, and verified by tools/verify.py.
# hadolint ignore=DL3026
FROM ${UBI_MINIMAL_IMAGE} AS dev-rootfs
ARG BUILDKIT_SBOM_SCAN_STAGE=true
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG DEV_PACKAGES="bash ca-certificates coreutils findutils gcc glibc-devel grep gzip make pkgconf-pkg-config sed tar xz"
ARG DNF_REPOS=""
ARG SOURCE_DATE_EPOCH

# The dev image intentionally follows the current UBI build-tool RPM set; runtime bytes are locked separately.
# hadolint ignore=DL3041
RUN set -eux; \
    export SOURCE_DATE_EPOCH; \
    test -n "${DEV_PACKAGES}" || { echo "DEV_PACKAGES must be set" >&2; exit 1; }; \
    dnf_repo_args=(); \
    if [ -n "${DNF_REPOS}" ]; then dnf_repo_args=("--disablerepo=*" "--enablerepo=${DNF_REPOS}"); fi; \
    read -r -a dev_packages <<< "${DEV_PACKAGES}"; \
    mkdir -p /rootfs /tmp/no-repos; \
    microdnf install -y --installroot=/rootfs --releasever=9 \
      --config=/etc/dnf/dnf.conf --noplugins \
      --setopt=reposdir=/etc/yum.repos.d \
      --setopt=varsdir=/etc/dnf/vars \
      --setopt=cachedir=/var/cache/microdnf-installroot \
      --nodocs --setopt=install_weak_deps=0 \
      "${dnf_repo_args[@]}" \
      "${dev_packages[@]}"; \
    microdnf clean all; \
    rm -rf /rootfs/var/cache/* /var/cache/microdnf-installroot \
      /rootfs/var/log/dnf.log /rootfs/var/log/dnf.librepo.log /rootfs/var/log/hawkey.log; \
    for executable in dnf microdnf yum; do \
      rm -f "/rootfs/usr/bin/${executable}" "/rootfs/usr/sbin/${executable}" \
        "/rootfs/bin/${executable}" "/rootfs/sbin/${executable}"; \
    done; \
    test -x /rootfs/usr/bin/bash || { echo "dev rootfs must include bash" >&2; exit 1; }; \
    test -x /rootfs/usr/bin/gcc || { echo "dev rootfs must include gcc" >&2; exit 1; }; \
    test -s /rootfs/var/lib/rpm/rpmdb.sqlite || test -s /rootfs/var/lib/rpm/Packages || \
      { echo "rpm database missing from dev rootfs; scanners would see zero packages" >&2; exit 1; }; \
    find /rootfs -xdev -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# UBI build-arg defaults are registry-qualified, digest-pinned, and verified by tools/verify.py.
# hadolint ignore=DL3026
FROM ${UBI_MICRO_IMAGE} AS runtime-common
ARG TARGETARCH
ARG OPENSSL_FIPS_MODULE_VERSION
ARG OPENSSL_FIPS_PROVIDER_NEVRA
ARG SOURCE_DATE_EPOCH

ARG OCI_CREATED="1970-01-01T00:00:00Z"
ARG OCI_DESCRIPTION="Hardened UBI 9 micro runtime base for NWarila images"
ARG OCI_REVISION="local"
ARG OCI_SOURCE="https://github.com/NWarila/ubi9-base-micro"
ARG OCI_TITLE="ubi9-base-micro"
ARG OCI_VERSION="dev"

LABEL org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.description="${OCI_DESCRIPTION}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.title="${OCI_TITLE}" \
      org.opencontainers.image.version="${OCI_VERSION}"

COPY --from=rpm-rootfs /rootfs/ /
COPY containers/fips/openssl.cnf /etc/pki/tls/openssl-fips.cnf

ENV OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf
ENV OPENSSL_MODULES=/usr/lib64/ossl-modules

# ubi-micro carries shell entry points for build-time RUN. Delete them last and
# fail closed if any shell or package-manager executable remains.
# Literal system directory pruning is intentional and followed by executable absence assertions.
# hadolint ignore=SC2115
RUN --mount=from=fips-verify,source=/fips-proof,target=/tmp/fips-proof,ro \
    set -eu; \
    case "${TARGETARCH}" in \
      amd64) rpm_arch="x86_64" ;; \
      arm64) rpm_arch="aarch64" ;; \
      *) echo "unsupported TARGETARCH for FIPS status: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    expected_provider_nevra="${OPENSSL_FIPS_PROVIDER_NEVRA}.${rpm_arch}"; \
    test -s /tmp/fips-proof/proof.txt; \
    test "$(cat /tmp/fips-proof/provider.nevra)" = "${expected_provider_nevra}"; \
    test "$(cat /tmp/fips-proof/expected-provider.nevra)" = "${expected_provider_nevra}"; \
    test "$(cat /tmp/fips-proof/module.version)" = "${OPENSSL_FIPS_MODULE_VERSION}"; \
    test -s /usr/lib64/ossl-modules/fips.so; \
    test -s /usr/lib64/libcrypto.so.3; \
    test -s /etc/pki/tls/openssl-fips.cnf; \
    test ! -e /usr/lib64/ossl-modules/legacy.so; \
    test ! -e /etc/pki/tls/fipsmodule.cnf; \
    test ! -e /usr/bin/openssl; \
    test -s /etc/nwarila/fips-status.json; \
    touch -h -d "@${SOURCE_DATE_EPOCH}" /etc/nwarila/fips-status.json /etc/pki/tls/openssl-fips.cnf; \
    rm -rf \
      /usr/bin/* \
      /usr/sbin/* \
      /usr/libexec/getconf \
      /usr/libexec/coreutils \
      /usr/lib64/engines-3 \
      /usr/lib64/libsepol.so* \
      /usr/lib64/libpcre2-8.so* \
      /usr/lib64/libpcre2-posix.so* \
      /usr/lib64/libselinux.so* \
      /usr/lib64/libacl.so* \
      /usr/lib64/libcap.so* \
      /usr/lib64/libattr.so* \
      /usr/lib64/libpsx.so* \
      /usr/lib64/security/pam_cap.so \
      /etc/xattr.conf \
      /usr/lib64/libncurses*.so* \
      /usr/lib64/libtinfo.so* \
      /usr/lib64/libtic.so* \
      /usr/lib64/libform*.so* \
      /usr/lib64/libmenu*.so* \
      /usr/lib64/libpanel*.so* \
      /usr/lib64/libpanelw*.so* \
      /var/lib/dnf/* \
      /var/lib/rhsm \
      /var/lib/alternatives \
      /etc/alternatives \
      /usr/lib/rpm \
      /usr/share/licenses/libcap \
      /usr/share/licenses/pcre2-syntax \
      /var/cache/* \
      /etc/pki/ca-trust/extracted/openssl \
      /etc/pki/ca-trust/extracted/java \
      /etc/pki/ca-trust/extracted/edk2 \
      /etc/pki/ca-trust/extracted/email \
      /etc/pki/ca-trust/extracted/pem/directory-hash \
      /usr/share/pki/ca-trust-source \
      /usr/share/terminfo \
      /etc/terminfo \
      /usr/share/crypto-policies \
      /bin/sh /bin/bash /bin/dash /bin/ash /bin/busybox /bin/ksh /bin/zsh /bin/tcsh /bin/csh \
      /sbin/sh /sbin/bash /sbin/dash /sbin/ash /sbin/busybox /sbin/ksh /sbin/zsh /sbin/tcsh /sbin/csh \
      /bin/dnf /bin/microdnf /bin/rpm /bin/yum \
      /sbin/dnf /sbin/microdnf /sbin/rpm /sbin/yum; \
    for trimmed_executable in coreutils find xargs grep sed p11-kit trust ldconfig localedef iconv zic getconf alternatives update-alternatives; do \
      if [ -e "/usr/bin/${trimmed_executable}" ] || [ -e "/usr/sbin/${trimmed_executable}" ] || \
         [ -e "/bin/${trimmed_executable}" ] || [ -e "/sbin/${trimmed_executable}" ]; then \
        echo "trimmed executable ${trimmed_executable} survived in runtime image" >&2; exit 1; \
      fi; \
    done; \
    for executable in sh bash dash ash busybox ksh zsh tcsh csh dnf microdnf rpm yum python python3 python3.12; do if [ -e "/usr/bin/${executable}" ] || [ -e "/usr/sbin/${executable}" ] || [ -e "/bin/${executable}" ] || [ -e "/sbin/${executable}" ]; then echo "forbidden executable ${executable} survived in runtime image" >&2; exit 1; fi; done; \
    test -s /var/lib/rpm/rpmdb.sqlite || test -s /var/lib/rpm/Packages

USER 65532:65532

FROM runtime-common AS runtime-amd64
ARG OPENSSL_FIPS_MODULE_VERSION
ARG OPENSSL_FIPS_PROVIDER_NEVRA
LABEL org.nwarila.fips.cmvp="4857" \
      org.nwarila.fips.cmvp.oe-validated="true" \
      org.nwarila.fips.module-version="${OPENSSL_FIPS_MODULE_VERSION}" \
      org.nwarila.fips.provider-nvr="${OPENSSL_FIPS_PROVIDER_NEVRA}"

FROM runtime-common AS runtime-arm64
ARG OPENSSL_FIPS_MODULE_VERSION
ARG OPENSSL_FIPS_PROVIDER_NEVRA
LABEL org.nwarila.fips.cmvp="4857" \
      org.nwarila.fips.cmvp.oe-validated="false" \
      org.nwarila.fips.module-version="${OPENSSL_FIPS_MODULE_VERSION}" \
      org.nwarila.fips.provider-nvr="${OPENSSL_FIPS_PROVIDER_NEVRA}"

ARG TARGETARCH
# TARGETARCH selects the per-architecture runtime stage defined above.
# hadolint ignore=DL3006,DL3026
FROM runtime-${TARGETARCH} AS runtime

# UBI build-arg defaults are registry-qualified, digest-pinned, and verified by tools/verify.py.
# hadolint ignore=DL3026
FROM ${UBI_MICRO_IMAGE} AS dev
ARG SOURCE_DATE_EPOCH

ARG OCI_CREATED="1970-01-01T00:00:00Z"
ARG OCI_DESCRIPTION="UBI 9 micro development base with shell and native build toolchain"
ARG OCI_REVISION="local"
ARG OCI_SOURCE="https://github.com/NWarila/ubi9-base-micro"
ARG OCI_TITLE="ubi9-base-micro-dev"
ARG OCI_VERSION="dev"

LABEL org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.description="${OCI_DESCRIPTION}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.title="${OCI_TITLE}" \
      org.opencontainers.image.version="${OCI_VERSION}"

COPY --from=dev-rootfs /rootfs/ /

RUN ["/bin/sh", "-c", "set -eu; touch -h -d \"@${SOURCE_DATE_EPOCH}\" /; rm -f /usr/bin/dnf /usr/sbin/dnf /bin/dnf /sbin/dnf /usr/bin/microdnf /usr/sbin/microdnf /bin/microdnf /sbin/microdnf /usr/bin/yum /usr/sbin/yum /bin/yum /sbin/yum; test -x /usr/bin/bash; test -x /usr/bin/gcc; test -s /var/lib/rpm/rpmdb.sqlite || test -s /var/lib/rpm/Packages"]

USER 65532:65532
