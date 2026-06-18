# syntax=docker/dockerfile:1.7

ARG BUILDKIT_SBOM_SCAN_CONTEXT=true

# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-minimal
ARG UBI_MINIMAL_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal@sha256:ae09ecc3d754bc1726cbda3e2599cc7839e09fe1cc547ce173cf669b645be3cc
# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-micro
ARG UBI_MICRO_IMAGE=registry.access.redhat.com/ubi9/ubi-micro@sha256:b498b3ea26111ab4b81d65139f2ebd2ef9a2abb7a4588b7fdcc54889f95e9caa

FROM ${UBI_MINIMAL_IMAGE} AS rpm-rootfs
ARG BUILDKIT_SBOM_SCAN_STAGE=true
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG RUNTIME_PACKAGES="ca-certificates"
ARG DNF_REPOS=""

# Assemble the runtime rootfs with microdnf --installroot so /var/lib/rpm
# remains available to scanners. Only regenerable caches and logs are pruned.
RUN set -eux; \
    test -n "${RUNTIME_PACKAGES}" || { echo "RUNTIME_PACKAGES must be set" >&2; exit 1; }; \
    mkdir -p /rootfs; \
    microdnf install -y --installroot=/rootfs --releasever=9 \
      --config=/etc/dnf/dnf.conf --noplugins \
      --setopt=reposdir=/etc/yum.repos.d \
      --setopt=varsdir=/etc/dnf/vars \
      --setopt=cachedir=/var/cache/microdnf-installroot \
      --nodocs --setopt=install_weak_deps=0 \
      ${DNF_REPOS:+--disablerepo=* --enablerepo=${DNF_REPOS}} \
      ${RUNTIME_PACKAGES}; \
    microdnf clean all; \
    rm -rf /rootfs/var/cache/* /var/cache/microdnf-installroot \
      /rootfs/var/log/dnf.log /rootfs/var/log/dnf.librepo.log /rootfs/var/log/hawkey.log; \
    if rpm --root=/rootfs -q bash >/dev/null 2>&1; then \
      rpm --root=/rootfs -e --nodeps --noscripts bash; \
    fi; \
    for executable in sh bash dash ash busybox ksh zsh tcsh csh dnf microdnf rpm yum; do \
      rm -f "/rootfs/usr/bin/${executable}" "/rootfs/usr/sbin/${executable}" \
        "/rootfs/bin/${executable}" "/rootfs/sbin/${executable}"; \
    done; \
    for executable in sh bash dash ash busybox ksh zsh tcsh csh dnf microdnf rpm yum; do \
      if [ -e "/rootfs/usr/bin/${executable}" ] || [ -e "/rootfs/usr/sbin/${executable}" ] || \
         [ -e "/rootfs/bin/${executable}" ] || [ -e "/rootfs/sbin/${executable}" ]; then \
        echo "forbidden executable '${executable}' survived in runtime rootfs" >&2; exit 1; \
      fi; \
    done; \
    test -s /rootfs/var/lib/rpm/rpmdb.sqlite || test -s /rootfs/var/lib/rpm/Packages || \
      { echo "rpm database missing from rootfs; scanners would see zero packages" >&2; exit 1; }; \
    test -e /rootfs/etc/pki/tls/certs/ca-bundle.crt || \
      { echo "RHEL CA bundle path missing from runtime rootfs" >&2; exit 1; }

FROM ${UBI_MINIMAL_IMAGE} AS dev-rootfs
ARG BUILDKIT_SBOM_SCAN_STAGE=true
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG DEV_PACKAGES="bash ca-certificates coreutils findutils gcc glibc-devel grep gzip make pkgconf-pkg-config sed tar xz"
ARG DNF_REPOS=""

RUN set -eux; \
    test -n "${DEV_PACKAGES}" || { echo "DEV_PACKAGES must be set" >&2; exit 1; }; \
    mkdir -p /rootfs; \
    microdnf install -y --installroot=/rootfs --releasever=9 \
      --config=/etc/dnf/dnf.conf --noplugins \
      --setopt=reposdir=/etc/yum.repos.d \
      --setopt=varsdir=/etc/dnf/vars \
      --setopt=cachedir=/var/cache/microdnf-installroot \
      --nodocs --setopt=install_weak_deps=0 \
      ${DNF_REPOS:+--disablerepo=* --enablerepo=${DNF_REPOS}} \
      ${DEV_PACKAGES}; \
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
      { echo "rpm database missing from dev rootfs; scanners would see zero packages" >&2; exit 1; }

FROM ${UBI_MICRO_IMAGE} AS runtime

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

# ubi-micro carries shell entry points for build-time RUN. Delete them last and
# fail closed if any shell or package-manager executable remains.
RUN ["/bin/sh", "-c", "set -eu; for executable in sh bash dash ash busybox ksh zsh tcsh csh dnf microdnf rpm yum; do rm -f \"/usr/bin/${executable}\" \"/usr/sbin/${executable}\" \"/bin/${executable}\" \"/sbin/${executable}\"; done; for executable in sh bash dash ash busybox ksh zsh tcsh csh dnf microdnf rpm yum; do if [ -e \"/usr/bin/${executable}\" ] || [ -e \"/usr/sbin/${executable}\" ] || [ -e \"/bin/${executable}\" ] || [ -e \"/sbin/${executable}\" ]; then echo \"forbidden executable ${executable} survived in runtime image\" >&2; exit 1; fi; done; test -s /var/lib/rpm/rpmdb.sqlite || test -s /var/lib/rpm/Packages"]

USER 65532:65532

FROM ${UBI_MICRO_IMAGE} AS dev

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

RUN ["/bin/sh", "-c", "set -eu; rm -f /usr/bin/dnf /usr/sbin/dnf /bin/dnf /sbin/dnf /usr/bin/microdnf /usr/sbin/microdnf /bin/microdnf /sbin/microdnf /usr/bin/yum /usr/sbin/yum /bin/yum /sbin/yum; test -x /usr/bin/bash; test -x /usr/bin/gcc; test -s /var/lib/rpm/rpmdb.sqlite || test -s /var/lib/rpm/Packages"]

USER 65532:65532
