# ubi9-python-312-runtime
#
# Runs Python 3.12 applications: the interpreter and its complete standard
# library on top of the ubi9-micro packages. No pip, no shell and no package
# manager.
#
# Files in this folder
#   packages.txt           The packages this image ships. Edit this file to
#                          change the image.
#   packages.lock.<arch>   The exact RPM files those names mean. Written by
#                          build/generate-lock.sh; never edited by hand.
#
# Build, from the repository root
#   build/build-image.sh python-312-runtime

ARG BUILDER=registry.access.redhat.com/ubi9/ubi-minimal@sha256:1d7c5517a4a1a8e2688620b39ee980e82505ca1ab7ae5541b5463120ae9b3897

# ---------------------------------------------------------------------------
# Stage 1 of 3: download
#
# Fetch every RPM file named in the lock. The build stops if a file is not
# exactly the one the lock records, or is not signed by Red Hat.
# ---------------------------------------------------------------------------
FROM ${BUILDER} AS download

COPY images/python-312-runtime/packages.lock.* /lock/
COPY build/download-rpms.sh /build/
RUN /build/download-rpms.sh

# ---------------------------------------------------------------------------
# Stage 2 of 3: install
#
# Assemble the image's files in /rootfs. The network is off for every step,
# so nothing can be installed that stage 1 did not verify.
# ---------------------------------------------------------------------------
FROM ${BUILDER} AS install

# The fixed date for this build, supplied by build/build-image.sh from the lock.
# Programs that record "when" use it in place of the clock, so two builds of
# the same lock produce the same bytes.
ARG SOURCE_DATE_EPOCH

COPY --from=download /rpms /rpms
COPY images/python-312-runtime/packages.lock.* /lock/
COPY build/remove-install-only.sh /build/

# Install the RPM files into an empty directory.
RUN --network=none rpm --root=/rootfs --initdb
RUN --network=none rpm --root=/rootfs --install --excludedocs /rpms/*.rpm

# Set the system crypto policy to FIPS:STIG, using Red Hat's own tool.
# STIG.pmod is DISA's addition to the FIPS policy (it restricts SSH ciphers).
COPY --chmod=0644 build/STIG.pmod /rootfs/etc/crypto-policies/policies/modules/STIG.pmod
RUN --network=none chroot /rootfs update-crypto-policies --no-reload --set FIPS:STIG

# Remove the packages that were needed only for the steps above (the lines
# marked "install" in the lock). What remains is exactly packages.txt.
RUN --network=none /build/remove-install-only.sh
RUN --network=none ldconfig -r /rootfs

# Add the unprivileged user the image runs as.
RUN --network=none echo 'nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin' >> /rootfs/etc/passwd
RUN --network=none echo 'nonroot:x:65532:' >> /rootfs/etc/group
RUN --network=none install --directory --mode=0700 --owner=65532 --group=65532 /rootfs/home/nonroot

# Two settings the DISA STIG checks for: Red Hat's signing key is registered
# in the package database, and new files are private by default.
RUN --network=none rpm --root=/rootfs --import /rootfs/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
RUN --network=none printf '\numask 077\n' >> /rootfs/etc/profile

# OpenSSL loads the FIPS provider and uses FIPS-approved algorithms by default.
COPY --chmod=0644 build/openssl-fips.cnf /rootfs/etc/pki/tls/openssl-fips.cnf

# Give the two files that came from this repository the fixed date. Their date
# on disk depends on when the repository was checked out.
RUN --network=none touch --date="@${SOURCE_DATE_EPOCH}" /rootfs/etc/pki/tls/openssl-fips.cnf
RUN --network=none touch --date="@${SOURCE_DATE_EPOCH}" /rootfs/etc/crypto-policies/policies/modules/STIG.pmod

# Delete files that belong to no package: a stray /dev/null written by install
# scripts, links left behind by removed packages, and empty folders.
RUN --network=none rm --force /rootfs/dev/null
RUN --network=none rm --force /rootfs/etc/alternatives/libnssckbi.so.* /rootfs/var/lib/alternatives/libnssckbi.so.*
RUN --network=none find /rootfs/usr/lib/.build-id -type d -empty -delete

# Compact the package database now that the install-only packages are gone:
# write its records out, delete the old database, load the records into a new one.
RUN --network=none rpmdb --root=/rootfs --exportdb > /build/package-records
RUN --network=none rm --force /rootfs/var/lib/rpm/rpmdb.sqlite*
RUN --network=none rpmdb --root=/rootfs --importdb < /build/package-records

# Two files record where the build ran, not what is in the image. The library
# cache's bookkeeping file is optional: delete it. The package database's lock
# table must exist for the database to be read: write it as zeros.
RUN --network=none rm --force /rootfs/var/cache/ldconfig/aux-cache
RUN --network=none head --bytes=32768 /dev/zero > /rootfs/var/lib/rpm/rpmdb.sqlite-shm

# ---------------------------------------------------------------------------
# Stage 3 of 3: the image
#
# Start from nothing and copy in the finished files.
# ---------------------------------------------------------------------------
FROM scratch

COPY --from=install /rootfs/ /

# Point OpenSSL at the FIPS configuration installed in stage 2.
ENV OPENSSL_CONF=/etc/pki/tls/openssl-fips.cnf
ENV OPENSSL_MODULES=/usr/lib64/ossl-modules

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
ENV HOME=/home/nonroot
USER 65532:65532
ENTRYPOINT ["/usr/bin/python3.12"]
