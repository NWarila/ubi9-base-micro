# syntax=docker/dockerfile:1.7

ARG BUILDKIT_SBOM_SCAN_CONTEXT=true

# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-minimal
ARG UBI_MINIMAL_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal@sha256:ae09ecc3d754bc1726cbda3e2599cc7839e09fe1cc547ce173cf669b645be3cc
# renovate: datasource=docker depName=registry.access.redhat.com/ubi9/ubi-micro
ARG UBI_MICRO_IMAGE=registry.access.redhat.com/ubi9/ubi-micro@sha256:b498b3ea26111ab4b81d65139f2ebd2ef9a2abb7a4588b7fdcc54889f95e9caa
ARG OPENSSL_FIPS_MODULE_VERSION=3.0.7-395c1a240fbfffd8
ARG OPENSSL_FIPS_PROVIDER_NEVRA=openssl-fips-provider-so-3.0.7-8.el9

FROM ${UBI_MINIMAL_IMAGE} AS fips-verify
ARG BUILDKIT_SBOM_SCAN_STAGE=true
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TARGETARCH
ARG DNF_REPOS=""
ARG OPENSSL_FIPS_MODULE_VERSION
ARG OPENSSL_FIPS_PROVIDER_NEVRA

COPY containers/fips/openssl.cnf /tmp/openssl-fips.cnf

RUN set -eux; \
    microdnf install -y --releasever=9 \
      --config=/etc/dnf/dnf.conf --noplugins \
      --setopt=reposdir=/etc/yum.repos.d \
      --setopt=varsdir=/etc/dnf/vars \
      --nodocs --setopt=install_weak_deps=0 \
      ${DNF_REPOS:+--disablerepo=* --enablerepo=${DNF_REPOS}} \
      openssl openssl-fips-provider crypto-policies; \
    microdnf clean all; \
    provider_nevra="$(rpm -q --qf '%{NEVRA}\n' openssl-fips-provider-so)"; \
    libs_nevra="$(rpm -q --qf '%{NEVRA}\n' openssl-libs)"; \
    fips_so_sha256="$(sha256sum /usr/lib64/ossl-modules/fips.so | awk '{print $1}')"; \
    case "${TARGETARCH}" in \
      amd64) rpm_arch="x86_64" ;; \
      arm64) rpm_arch="aarch64" ;; \
      *) echo "unsupported TARGETARCH for FIPS provider pin: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    expected_provider_nevra="${OPENSSL_FIPS_PROVIDER_NEVRA}.${rpm_arch}"; \
    echo "openssl-fips-provider-so NEVRA=${provider_nevra}"; \
    echo "openssl-libs NEVRA=${libs_nevra}"; \
    echo "openssl-fips-provider-so fips.so sha256=${fips_so_sha256}"; \
    test "${provider_nevra}" = "${expected_provider_nevra}" || { \
      echo "unexpected openssl-fips-provider-so NEVRA: ${provider_nevra}" >&2; exit 1; \
    }; \
    providers_verbose="$(OPENSSL_CONF=/tmp/openssl-fips.cnf OPENSSL_MODULES=/usr/lib64/ossl-modules openssl list -providers -verbose 2>&1)"; \
    printf '%s\n' "${providers_verbose}"; \
    printf '%s\n' "${providers_verbose}" | grep -q '^  fips$'; \
    printf '%s\n' "${providers_verbose}" | grep -q '^  base$'; \
    ! printf '%s\n' "${providers_verbose}" | grep -q '^  default$'; \
    module_version="$(printf '%s\n' "${providers_verbose}" | grep -A8 '^  fips$' | sed -n 's/^[[:space:]]*version: //p' | head -n1)"; \
    test "${module_version}" = "${OPENSSL_FIPS_MODULE_VERSION}" || { \
      echo "unexpected OpenSSL FIPS provider module version: ${module_version}" >&2; exit 1; \
    }; \
    printf '%s\n' "${providers_verbose}" | grep -A8 '^  fips$' | grep -q 'status: active'; \
    if printf x | OPENSSL_CONF=/tmp/openssl-fips.cnf OPENSSL_MODULES=/usr/lib64/ossl-modules openssl dgst -md5 > /tmp/fips-md5.out 2>&1; then \
      cat /tmp/fips-md5.out; \
      echo "md5 unexpectedly succeeded under OpenSSL FIPS approved mode" >&2; exit 1; \
    fi; \
    cat /tmp/fips-md5.out; \
    printf x | OPENSSL_CONF=/tmp/openssl-fips.cnf OPENSSL_MODULES=/usr/lib64/ossl-modules openssl dgst -sha256 | tee /tmp/fips-sha256.out; \
    printf x | OPENSSL_CONF=/tmp/openssl-fips.cnf OPENSSL_MODULES=/usr/lib64/ossl-modules openssl enc -aes-256-cbc -pbkdf2 -pass pass:test -out /tmp/fips-aes.out; \
    test -s /tmp/fips-aes.out; \
    mkdir -p /fips-proof; \
    printf '%s\n' "${provider_nevra}" > /fips-proof/provider.nevra; \
    printf '%s\n' "${expected_provider_nevra}" > /fips-proof/expected-provider.nevra; \
    printf '%s\n' "${libs_nevra}" > /fips-proof/libs.nevra; \
    printf '%s\n' "${fips_so_sha256}" > /fips-proof/fips.so.sha256; \
    printf '%s\n' "${module_version}" > /fips-proof/module.version; \
    { \
      echo "openssl-fips-provider-so NEVRA=${provider_nevra}"; \
      echo "openssl-libs NEVRA=${libs_nevra}"; \
      echo "openssl-fips-provider-so fips.so sha256=${fips_so_sha256}"; \
      echo "openssl-fips-provider module-version=${module_version}"; \
      printf '%s\n' "${providers_verbose}" | grep -A8 '^  fips$'; \
      printf '%s\n' "${providers_verbose}" | grep -A8 '^  base$'; \
      echo "md5 failure:"; cat /tmp/fips-md5.out; \
      echo "sha256 success:"; cat /tmp/fips-sha256.out; \
      echo "aes-256-cbc success bytes=$(wc -c < /tmp/fips-aes.out)"; \
    } > /fips-proof/proof.txt; \
    test -s /fips-proof/proof.txt; \
    test -s /fips-proof/provider.nevra; \
    test -s /fips-proof/expected-provider.nevra; \
    test -s /fips-proof/libs.nevra; \
    test -s /fips-proof/fips.so.sha256; \
    test -s /fips-proof/module.version

FROM ${UBI_MINIMAL_IMAGE} AS rpm-rootfs
ARG BUILDKIT_SBOM_SCAN_STAGE=true
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG RUNTIME_PACKAGES="ca-certificates openssl-fips-provider"
ARG TARGETARCH
ARG DNF_REPOS=""
ARG OPENSSL_FIPS_MODULE_VERSION
ARG OPENSSL_FIPS_PROVIDER_NEVRA

# Assemble the runtime rootfs with microdnf --installroot so /var/lib/rpm
# remains available to scanners. Only regenerable caches and logs are pruned.
RUN --mount=from=fips-verify,source=/fips-proof,target=/tmp/fips-proof,ro \
    --mount=from=fips-verify,source=/usr/bin/openssl,target=/tmp/fips-openssl,ro \
    --mount=from=fips-verify,source=/usr/lib64,target=/tmp/fips-lib64,ro \
    set -eux; \
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
      { echo "RHEL CA bundle path missing from runtime rootfs" >&2; exit 1; }; \
    test -s /rootfs/usr/lib64/ossl-modules/fips.so || \
      { echo "OpenSSL FIPS provider missing from runtime rootfs" >&2; exit 1; }; \
    test -s /rootfs/usr/lib64/libcrypto.so.3 || \
      { echo "OpenSSL libcrypto missing from runtime rootfs" >&2; exit 1; }; \
    shipped_provider_nevra="$(rpm --root=/rootfs -q --qf '%{NEVRA}\n' openssl-fips-provider-so)"; \
    shipped_libs_nevra="$(rpm --root=/rootfs -q --qf '%{NEVRA}\n' openssl-libs)"; \
    shipped_fips_so_sha256="$(sha256sum /rootfs/usr/lib64/ossl-modules/fips.so | awk '{print $1}')"; \
    case "${TARGETARCH}" in \
      amd64) rpm_arch="x86_64" ;; \
      arm64) rpm_arch="aarch64" ;; \
      *) echo "unsupported TARGETARCH for FIPS provider pin: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    expected_provider_nevra="${OPENSSL_FIPS_PROVIDER_NEVRA}.${rpm_arch}"; \
    verified_provider_nevra="$(cat /tmp/fips-proof/provider.nevra)"; \
    verified_libs_nevra="$(cat /tmp/fips-proof/libs.nevra)"; \
    verified_fips_so_sha256="$(cat /tmp/fips-proof/fips.so.sha256)"; \
    verified_module_version="$(cat /tmp/fips-proof/module.version)"; \
    echo "runtime rootfs openssl-fips-provider-so NEVRA=${shipped_provider_nevra}"; \
    echo "runtime rootfs openssl-libs NEVRA=${shipped_libs_nevra}"; \
    echo "runtime rootfs fips.so sha256=${shipped_fips_so_sha256}"; \
    test "${verified_provider_nevra}" = "${expected_provider_nevra}" || { \
      echo "verified provider NEVRA does not match pin: ${verified_provider_nevra}" >&2; exit 1; \
    }; \
    test "${verified_module_version}" = "${OPENSSL_FIPS_MODULE_VERSION}" || { \
      echo "verified module version does not match pin: ${verified_module_version}" >&2; exit 1; \
    }; \
    test "${shipped_provider_nevra}" = "${expected_provider_nevra}" || { \
      echo "runtime rootfs provider NEVRA does not match pin: ${shipped_provider_nevra}" >&2; exit 1; \
    }; \
    test "${shipped_provider_nevra}" = "${verified_provider_nevra}" || { \
      echo "runtime rootfs provider NEVRA does not match verified stage: ${shipped_provider_nevra} != ${verified_provider_nevra}" >&2; exit 1; \
    }; \
    test "${shipped_libs_nevra}" = "${verified_libs_nevra}" || { \
      echo "runtime rootfs openssl-libs NEVRA does not match verified stage: ${shipped_libs_nevra} != ${verified_libs_nevra}" >&2; exit 1; \
    }; \
    test "${shipped_fips_so_sha256}" = "${verified_fips_so_sha256}" || { \
      echo "runtime rootfs fips.so sha256 does not match verified stage: ${shipped_fips_so_sha256} != ${verified_fips_so_sha256}" >&2; exit 1; \
    }; \
    protected_deps="$(mktemp)"; \
    for object in \
      /rootfs/usr/lib64/libcrypto.so.3 \
      /rootfs/usr/lib64/libssl.so.3 \
      /rootfs/usr/lib64/ossl-modules/fips.so \
      /rootfs/usr/lib64/libc.so.6; do \
      test -e "${object}" || { echo "required ldd root missing: ${object}" >&2; exit 1; }; \
      realpath "${object}" >> "${protected_deps}"; \
      LD_LIBRARY_PATH=/rootfs/usr/lib64 ldd "${object}" | \
        awk '/=> \// { print $3 } /^[[:space:]]*\// { print $1 }' | \
        while IFS= read -r dep; do \
          case "${dep}" in \
            /rootfs/*) test -e "${dep}" && realpath "${dep}" ;; \
            /usr/lib64/*|/lib64/*) test -e "/rootfs${dep}" && realpath "/rootfs${dep}" ;; \
          esac; \
        done >> "${protected_deps}"; \
    done; \
    for loader in /rootfs/usr/lib64/ld-linux*.so.* /rootfs/lib64/ld-linux*.so.*; do \
      [ -e "${loader}" ] && realpath "${loader}" >> "${protected_deps}"; \
    done; \
    sort -u -o "${protected_deps}" "${protected_deps}"; \
    echo "ldd-protected FIPS/glibc runtime dependency paths:"; \
    cat "${protected_deps}"; \
    removable_packages=""; \
    for candidate in \
      coreutils-single coreutils findutils grep sed p11-kit p11-kit-trust \
      libsepol libselinux gmp pcre2 pcre libpcre ncurses-libs ncurses-base \
      libsigsegv libffi libtasn1; do \
      if rpm --root=/rootfs -q "${candidate}" >/dev/null 2>&1; then \
        candidate_nevra="$(rpm --root=/rootfs -q --qf '%{NEVRA}\n' "${candidate}")"; \
        echo "strip candidate installed: ${candidate_nevra}"; \
        protected_owned=""; \
        while IFS= read -r owned_path; do \
          root_owned="/rootfs${owned_path}"; \
          [ -e "${root_owned}" ] || continue; \
          owned_real="$(realpath "${root_owned}" 2>/dev/null || true)"; \
          if [ -n "${owned_real}" ] && grep -Fxq "${owned_real}" "${protected_deps}"; then \
            protected_owned="${owned_path}"; \
            break; \
          fi; \
        done < <(rpm --root=/rootfs -ql "${candidate}"); \
        if [ -n "${protected_owned}" ]; then \
          echo "strip candidate ${candidate_nevra} owns protected FIPS/glibc runtime dependency ${protected_owned}" >&2; \
          exit 1; \
        fi; \
        removable_packages="${removable_packages} ${candidate}"; \
      fi; \
    done; \
    if [ -n "${removable_packages}" ]; then \
      echo "removing runtime packages via rpmdb:${removable_packages}"; \
      rpm --root=/rootfs -e --nodeps --noscripts ${removable_packages}; \
      for removed_package in ${removable_packages}; do \
        if rpm --root=/rootfs -q "${removed_package}" >/dev/null 2>&1; then \
          echo "runtime package survived rpm removal: ${removed_package}" >&2; exit 1; \
        fi; \
      done; \
    fi; \
    ldconfig -r /rootfs; \
    test -s /rootfs/etc/ld.so.cache || { echo "ld.so.cache was not populated before removing ldconfig" >&2; exit 1; }; \
    rm -f \
      /rootfs/usr/sbin/ldconfig /rootfs/sbin/ldconfig \
      /rootfs/usr/bin/localedef /rootfs/usr/bin/iconv \
      /rootfs/usr/sbin/zic /rootfs/usr/bin/zic \
      /rootfs/usr/bin/getconf /rootfs/bin/getconf; \
    if [ -d /rootfs/usr/lib/locale ]; then \
      test -e /rootfs/usr/lib/locale/C.utf8 || { echo "C.utf8 locale missing from runtime rootfs" >&2; exit 1; }; \
      find /rootfs/usr/lib/locale -mindepth 1 -maxdepth 1 ! -name C.utf8 -exec rm -rf {} +; \
    fi; \
    test -s /rootfs/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem || { \
      echo "TLS CA PEM bundle missing before CA trust trim" >&2; exit 1; \
    }; \
    rm -rf \
      /rootfs/usr/share/pki/ca-trust-source/* \
      /rootfs/etc/pki/ca-trust/extracted/openssl \
      /rootfs/etc/pki/ca-trust/extracted/java \
      /rootfs/etc/pki/ca-trust/extracted/edk2 \
      /rootfs/etc/pki/ca-trust/extracted/email; \
    rm -f \
      /rootfs/etc/pki/ca-trust/extracted/pem/objsign* \
      /rootfs/etc/pki/ca-trust/extracted/pem/email*; \
    rm -rf /rootfs/etc/pki/ca-trust/extracted/pem/directory-hash /rootfs/usr/lib64/engines-3; \
    if [ -d /rootfs/etc/pki/tls/certs ]; then \
      find /rootfs/etc/pki/tls/certs -mindepth 1 ! -name ca-bundle.crt -exec rm -rf {} +; \
    fi; \
    test -L /rootfs/etc/pki/tls/certs/ca-bundle.crt || { \
      echo "CA bundle path must remain a symlink" >&2; exit 1; \
    }; \
    test -s /rootfs/etc/pki/tls/certs/ca-bundle.crt || { \
      echo "CA bundle symlink target is empty after CA trust trim" >&2; exit 1; \
    }; \
    awk 'BEGIN {emit=0} /-----BEGIN CERTIFICATE-----/ {emit=1} emit {print} /-----END CERTIFICATE-----/ {exit}' \
      /rootfs/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem > /tmp/ca-first.pem; \
    test -s /tmp/ca-first.pem || { echo "could not extract a CA certificate for trust verification" >&2; exit 1; }; \
    LD_LIBRARY_PATH=/tmp/fips-lib64 /tmp/fips-openssl verify \
      -CAfile /rootfs/etc/pki/tls/certs/ca-bundle.crt /tmp/ca-first.pem; \
    rm -rf \
      /rootfs/var/lib/dnf/* \
      /rootfs/var/lib/rhsm \
      /rootfs/var/lib/alternatives \
      /rootfs/usr/lib/rpm \
      /rootfs/var/cache/*; \
    if [ -d /rootfs/usr/share/zoneinfo ]; then \
      zone_tmp="$(mktemp -d)"; \
      mkdir -p "${zone_tmp}/Etc"; \
      cp -a /rootfs/usr/share/zoneinfo/UTC "${zone_tmp}/UTC"; \
      cp -a /rootfs/usr/share/zoneinfo/Etc/UTC "${zone_tmp}/Etc/UTC"; \
      for leap_file in /rootfs/usr/share/zoneinfo/leap*; do \
        [ -e "${leap_file}" ] && cp -a "${leap_file}" "${zone_tmp}/"; \
      done; \
      rm -rf /rootfs/usr/share/zoneinfo; \
      mkdir -p /rootfs/usr/share; \
      mv "${zone_tmp}" /rootfs/usr/share/zoneinfo; \
    fi; \
    ln -sfn /usr/share/zoneinfo/UTC /rootfs/etc/localtime; \
    test -e /rootfs/usr/share/zoneinfo/UTC; \
    test -e /rootfs/usr/share/zoneinfo/Etc/UTC; \
    test "$(readlink /rootfs/etc/localtime)" = "/usr/share/zoneinfo/UTC"; \
    rm -rf \
      /rootfs/usr/share/terminfo \
      /rootfs/etc/terminfo \
      /rootfs/usr/share/crypto-policies; \
    for trimmed_executable in coreutils find xargs grep sed p11-kit trust ldconfig localedef iconv zic getconf; do \
      if [ -e "/rootfs/usr/bin/${trimmed_executable}" ] || [ -e "/rootfs/usr/sbin/${trimmed_executable}" ] || \
         [ -e "/rootfs/bin/${trimmed_executable}" ] || [ -e "/rootfs/sbin/${trimmed_executable}" ]; then \
        echo "trimmed executable '${trimmed_executable}' survived in runtime rootfs" >&2; exit 1; \
      fi; \
    done; \
    if [ -e /rootfs/usr/bin/openssl ]; then \
      echo "runtime rootfs must not include the openssl CLI" >&2; exit 1; \
    fi; \
    rm -f /rootfs/usr/lib64/ossl-modules/legacy.so /rootfs/etc/pki/tls/fipsmodule.cnf; \
    if [ -e /rootfs/usr/lib64/ossl-modules/legacy.so ]; then \
      echo "legacy OpenSSL provider survived in runtime rootfs" >&2; exit 1; \
    fi; \
    if [ -e /rootfs/etc/pki/tls/fipsmodule.cnf ]; then \
      echo "fipsmodule.cnf survived in runtime rootfs" >&2; exit 1; \
    fi

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
ARG TARGETARCH
ARG OPENSSL_FIPS_MODULE_VERSION
ARG OPENSSL_FIPS_PROVIDER_NEVRA

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
      org.opencontainers.image.version="${OCI_VERSION}" \
      org.nwarila.fips.cmvp="4857" \
      org.nwarila.fips.module-version="${OPENSSL_FIPS_MODULE_VERSION}" \
      org.nwarila.fips.provider-nvr="${OPENSSL_FIPS_PROVIDER_NEVRA}"

COPY --from=rpm-rootfs /rootfs/ /
COPY containers/fips/openssl.cnf /etc/pki/tls/openssl-fips.cnf

ENV OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf
ENV OPENSSL_MODULES=/usr/lib64/ossl-modules

# ubi-micro carries shell entry points for build-time RUN. Delete them last and
# fail closed if any shell or package-manager executable remains.
RUN --mount=from=fips-verify,source=/fips-proof,target=/tmp/fips-proof,ro \
    set -eu; \
    case "${TARGETARCH}" in \
      amd64) rpm_arch="x86_64"; oe_validated=true; disclaimer="CMVP #4857-validated approved-mode configuration." ;; \
      arm64) rpm_arch="aarch64"; oe_validated=false; disclaimer="The Red Hat OpenSSL FIPS provider (module #4857, v3.0.7-395c1a240fbfffd8) is present, approved-mode-configured, and self-test-passing, but this aarch64 operational environment is NOT in CMVP #4857's validated or vendor-affirmed list — this is NOT a CMVP-validated configuration on this architecture." ;; \
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
    mkdir -p /etc/nwarila; \
    { \
      printf '{\n'; \
      printf '  "arch": "%s",\n' "${TARGETARCH}"; \
      printf '  "module": "%s",\n' "${OPENSSL_FIPS_MODULE_VERSION}"; \
      printf '  "cmvp": "#4857",\n'; \
      printf '  "oe_validated": %s,\n' "${oe_validated}"; \
      printf '  "disclaimer": "%s"\n' "${disclaimer}"; \
      printf '}\n'; \
    } > /etc/nwarila/fips-status.json; \
    test -s /etc/nwarila/fips-status.json; \
    rm -rf \
      /usr/bin/* \
      /usr/sbin/* \
      /usr/libexec/getconf \
      /usr/lib64/engines-3 \
      /usr/lib64/libsepol.so* \
      /usr/lib64/libpcre2-8.so* \
      /usr/lib64/libselinux.so* \
      /usr/lib64/libacl.so* \
      /usr/lib64/libcap.so* \
      /usr/lib64/libattr.so* \
      /usr/lib64/libncurses*.so* \
      /usr/lib64/libtinfo.so* \
      /usr/lib64/libtic.so* \
      /usr/lib64/libform*.so* \
      /usr/lib64/libmenu*.so* \
      /var/lib/dnf/* \
      /var/lib/rhsm \
      /var/lib/alternatives \
      /usr/lib/rpm \
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
    for trimmed_executable in coreutils find xargs grep sed p11-kit trust ldconfig localedef iconv zic getconf; do \
      if [ -e "/usr/bin/${trimmed_executable}" ] || [ -e "/usr/sbin/${trimmed_executable}" ] || \
         [ -e "/bin/${trimmed_executable}" ] || [ -e "/sbin/${trimmed_executable}" ]; then \
        echo "trimmed executable ${trimmed_executable} survived in runtime image" >&2; exit 1; \
      fi; \
    done; \
    for executable in sh bash dash ash busybox ksh zsh tcsh csh dnf microdnf rpm yum; do if [ -e "/usr/bin/${executable}" ] || [ -e "/usr/sbin/${executable}" ] || [ -e "/bin/${executable}" ] || [ -e "/sbin/${executable}" ]; then echo "forbidden executable ${executable} survived in runtime image" >&2; exit 1; fi; done; \
    test -s /var/lib/rpm/rpmdb.sqlite || test -s /var/lib/rpm/Packages

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
