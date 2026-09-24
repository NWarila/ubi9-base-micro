# Purpose: Hardened OpenJDK 21 headless server JRE on the pinned ubi9-base-micro floor, FIPS-capable through NSS.
# Role: container-build
# Micro-container candidate: no (image definition)

# Preserve the published micro root as the runtime floor.
FROM ghcr.io/nwarila/ubi9-base-micro@sha256:81e604e496e11289f662610a8da60a4dcfa206b14f1d3d4e0239a35ff60b21f6 AS parent

# Use the pinned minimal image only to assemble and verify the runtime root.
FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:8ebe2ad8fdf3cab3e5a53c1edc69194c98209cfadab24b884f4ad9ebcf7bbbfc AS builder
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# Install the archive tool used to extract the two directly pinned RPMs.
# hadolint ignore=DL3041
RUN microdnf install -y cpio > /dev/null && microdnf clean all > /dev/null

COPY --from=parent / /rootfs

# Install the pinned Java transaction and verify every downloaded RPM.
RUN microdnf install -y --installroot=/rootfs --releasever=9 --config=/etc/dnf/dnf.conf --noplugins \
    --setopt=reposdir=/etc/yum.repos.d --setopt=varsdir=/etc/dnf/vars \
    --setopt=cachedir=/var/cache/mdnf --setopt=keepcache=1 \
    --nodocs --setopt=install_weak_deps=0 'java-21-openjdk-headless-1:21.0.12.1.1-1.2.el9.x86_64'; \
    if [ "$(rpm --root=/rootfs -q --qf '%{NAME}|%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}' java-21-openjdk-headless)" != 'java-21-openjdk-headless|1:21.0.12.1.1-1.2.el9.x86_64' ]; then echo "JAVA EVR MISMATCH"; exit 1; fi; \
    : RPM-SIGNATURE-CHECK; \
    shopt -s nullglob; rpms=(/var/cache/mdnf/metadata/*/packages/*.rpm); \
    if [ "${#rpms[@]}" -eq 0 ]; then echo "SIGNATURE CHECK FAILED: no downloaded RPMs found"; exit 1; fi; \
    for r in "${rpms[@]}"; do if ! rpmkeys --checksig "$r" | grep -q ': digests signatures OK$'; then echo "SIGNATURE CHECK FAILED: $r"; exit 1; fi; done; \
    echo "signature-verified rpms: ${#rpms[@]}"; \
    rm -rf /var/cache/mdnf

# Restore only the pinned Java crypto-policy payload missing from the micro floor.
RUN curl -fsSL -o /tmp/cp.rpm https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/Packages/c/crypto-policies-20260224-1.gitea0f072.el9_8.noarch.rpm; \
    if ! rpmkeys --checksig /tmp/cp.rpm | grep -q ': digests signatures OK$'; then echo "SIGNATURE CHECK FAILED: crypto-policies RPM"; exit 1; fi; \
    if [ "$(sha256sum /tmp/cp.rpm | cut -d' ' -f1)" != a9ad86b8df75a7c9c29c6f6dd4b8f78cfa1f42b492eff0d11b82c457d37a7f9f ]; then echo "SHA256 MISMATCH: crypto-policies RPM"; exit 1; fi; \
    install -d -m 0755 /tmp/cp; \
    rpm2cpio /tmp/cp.rpm | cpio -idm --quiet -D /tmp/cp; \
    install -d -m 0755 /rootfs/usr/share/crypto-policies/DEFAULT; \
    install -m 0644 /tmp/cp/usr/share/crypto-policies/DEFAULT/java.txt /rootfs/usr/share/crypto-policies/DEFAULT/java.txt; \
    if [ "$(sha256sum /rootfs/usr/share/crypto-policies/DEFAULT/java.txt | cut -d' ' -f1)" != 21e27a8d83a44a6c1179effe601e95cb3d7373735cc7520cd47be0652dd18945 ]; then echo "SHA256 MISMATCH: java.txt"; exit 1; fi; \
    if [ "$(readlink /rootfs/etc/crypto-policies/back-ends/java.config)" != /usr/share/crypto-policies/DEFAULT/java.txt ] || [ ! -f /rootfs/usr/share/crypto-policies/DEFAULT/java.txt ]; then echo "JAVA CONFIG LINK DANGLING"; exit 1; fi

# Restore the pinned CA source used by the rooted trust extraction.
# ANCHOR-RESTORE-BEGIN
RUN curl -fsSL -o /tmp/ca.rpm https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/Packages/c/ca-certificates-2025.2.80_v9.0.305-91.el9.noarch.rpm; \
    if ! rpmkeys --checksig /tmp/ca.rpm | grep -q ': digests signatures OK$'; then echo "SIGNATURE CHECK FAILED: ca-certificates RPM"; exit 1; fi; \
    if [ "$(sha256sum /tmp/ca.rpm | cut -d' ' -f1)" != 0554bf65d573950e7d550a07bf7d0b3def85ca3b45a7fbde4cce7cadd9a476a7 ]; then echo "SHA256 MISMATCH: ca-certificates RPM"; exit 1; fi; \
    install -d -m 0755 /tmp/ca; \
    rpm2cpio /tmp/ca.rpm | cpio -idm --quiet -D /tmp/ca; \
    install -d -m 0755 /rootfs/usr/share/pki; \
    cp -a /tmp/ca/usr/share/pki/ca-trust-source /rootfs/usr/share/pki/.
# ANCHOR-RESTORE-END

# Generate the Java truststore inside the runtime root and prove it is live.
RUN install -d -m 0755 /rootfs/etc/pki/ca-trust/extracted/java; \
    chroot /rootfs /usr/bin/trust extract --format=java-cacerts --purpose=server-auth --filter=ca-anchors --overwrite /etc/pki/ca-trust/extracted/java/cacerts; \
    CA=/rootfs/etc/pki/ca-trust/extracted/java/cacerts; \
    magic="$(od -An -tx4 -N4 --endian=big "$CA" | tr -d ' ')"; \
    if [ "$magic" != feedfeed ]; then echo "TRUSTSTORE MAGIC MISMATCH: $magic"; exit 1; fi; \
    N=$(od -An -tu4 -j8 -N4 --endian=big "$CA" | tr -d ' '); \
    echo "EXTRACTION COMPLETE: $(stat -c%s "$CA") bytes, $N entries"; \
    if ! [[ "$N" =~ ^[0-9]+$ ]]; then echo "TRUSTSTORE FLOOR FAILED: entry count missing or malformed: '$N'"; exit 1; fi; \
    if [ "$N" -lt 100 ]; then echo "TRUSTSTORE FLOOR FAILED: $N entries, minimum 100"; exit 1; fi; \
    if [ "$( { printf '\0c\0h\0a\0n\0g\0e\0i\0t'; printf 'Mighty Aphrodite'; head -c -20 "$CA"; } | sha1sum | cut -d' ' -f1)" != "$(tail -c 20 "$CA" | od -An -tx1 | tr -d ' \n')" ]; then echo "TRUSTSTORE FLOOR FAILED: store integrity digest mismatch"; exit 1; fi; \
    if [ "$(readlink /rootfs/etc/pki/java/cacerts)" != /etc/pki/ca-trust/extracted/java/cacerts ] || [ ! -f /rootfs/etc/pki/ca-trust/extracted/java/cacerts ]; then echo "CACERTS LINK DANGLING"; exit 1; fi; \
    echo "TRUSTSTORE FLOOR PASSED: $N entries"

COPY strip.txt /strip.txt
COPY unsatisfied-requirements.txt /unsatisfied-requirements.txt

# Apply the reviewed server profile and verify the resulting runtime payload.
RUN mapfile -t T < <(awk '$1 == "tool" {print $2}' /strip.txt); \
    mapfile -t P < <(awk '$1 == "profile" {print $2}' /strip.txt); \
    if [ "${#T[@]}" -ne 23 ] || [ "${#P[@]}" -ne 16 ] || [ "$(grep -vc '^#' /strip.txt)" -ne 39 ]; then echo "STRIP LIST COUNT MISMATCH"; exit 1; fi; \
    S=("${T[@]}" "${P[@]}"); \
    mapfile -t ALLOW < <(awk '$1 == "install-time" || $1 == "omission" {sub(/^[^ ]+ /, ""); print}' /unsatisfied-requirements.txt); \
    mapfile -t OMIT < <(awk '$1 == "omission" {sub(/^[^ ]+ /, ""); print}' /unsatisfied-requirements.txt); \
    if [ "${#ALLOW[@]}" -ne 28 ] || [ "${#OMIT[@]}" -ne 7 ] || [ "$(grep -vc '^#' /unsatisfied-requirements.txt)" -ne 28 ]; then echo "ALLOWLIST COUNT MISMATCH"; exit 1; fi; \
    for p in "${S[@]}"; do rpm --root=/rootfs -q "$p" > /dev/null || { echo "STRIP PRECONDITION FAILED: $p not installed"; exit 1; }; done; \
    rpm --root=/rootfs -e --nodeps --noscripts "${S[@]}"; \
    for p in "${S[@]}"; do if rpm --root=/rootfs -q "$p" > /dev/null; then echo "STRIP POSTCONDITION FAILED: $p still installed"; exit 1; fi; done; \
    for p in ca-certificates java-21-openjdk-headless nss nss-softokn nss-softokn-freebl nss-sysinit nss-util nspr sqlite-libs; do rpm --root=/rootfs -q "$p" > /dev/null || { echo "PROTECTED PACKAGE MISSING: $p"; exit 1; }; done; \
    for s in /rootfs/usr/bin/sh /rootfs/usr/bin/bash; do if [ -e "$s" ] || [ -L "$s" ]; then echo "SHELL PRESENT: $s"; exit 1; fi; done; \
    rc=0; rpm --root=/rootfs -Va --nofiles --nodigest --nosignature > /tmp/va.txt 2>&1 || rc=$?; \
    awk '!/^Unsatisfied dependencies for .+:$/ && !/^[[:space:]]+.+ is needed by \(installed\) .+$/ {print "DEPENDENCY GATE FAILED: unexpected rpm -Va output: " $0; bad=1} END {exit bad}' /tmp/va.txt; \
    awk '/ is needed by \(installed\) / {sub(/^[[:space:]]+/, ""); print}' /tmp/va.txt | LC_ALL=C sort -u > /tmp/needs.txt; \
    : > /tmp/seen.txt; k=0; \
    while IFS= read -r line; do cap="${line%% is needed by *}"; nevra="${line##* is needed by (installed) }"; who="$(rpm --root=/rootfs -q --qf '%{NAME}' "$nevra")" || { echo "DEPENDENCY GATE FAILED: cannot resolve consumer: $line"; exit 1; }; pair="$cap|$who"; k=$((k + 1)); ok=0; for a in "${ALLOW[@]}"; do if [ "$a" = "$pair" ]; then ok=1; fi; done; if [ "$ok" -ne 1 ]; then echo "DEPENDENCY GATE FAILED: unreviewed requirement: $pair"; exit 1; fi; echo "$pair" >> /tmp/seen.txt; done < /tmp/needs.txt; \
    if [ "$k" -eq 0 ]; then echo "DEPENDENCY GATE FAILED: no requirement lines parsed (rpm -Va exit $rc)"; exit 1; fi; \
    for o in "${OMIT[@]}"; do grep -qxF "$o" /tmp/seen.txt || { echo "DEPENDENCY GATE FAILED: declared omission not observed: $o"; exit 1; }; done; \
    echo "DEPENDENCY GATE PASSED: $k RPM-declared requirements unsatisfied, all reviewed, 7 declared omissions observed; 0 unreviewed (rpm -Va exit $rc)"; \
    rc=0; rpm --root=/rootfs -V --nodeps java-21-openjdk-headless nss nss-softokn nss-softokn-freebl nss-sysinit nss-util nspr sqlite-libs > /tmp/payload.txt 2>&1 || rc=$?; \
    if [ "$rc" -ne 0 ] || [ -s /tmp/payload.txt ]; then sed 's/^/PAYLOAD CHECK FAILED: /' /tmp/payload.txt; echo "PAYLOAD CHECK FAILED: rpm -V exit $rc"; exit 1; fi; \
    echo "PAYLOAD CHECK PASSED: 8 packages verified"; \
    if [ "$(readlink /rootfs/usr/bin/java)" != /etc/alternatives/java ]; then echo "ENTRYPOINT CHAIN FAILED: /usr/bin/java"; exit 1; fi; \
    if [ "$(readlink /rootfs/etc/alternatives/java)" != /usr/lib/jvm/java-21-openjdk-21.0.12.1.1-1.2.el9.x86_64/bin/java ]; then echo "ENTRYPOINT CHAIN FAILED: /etc/alternatives/java"; exit 1; fi; \
    if [ ! -x /rootfs/usr/lib/jvm/java-21-openjdk-21.0.12.1.1-1.2.el9.x86_64/bin/java ]; then echo "ENTRYPOINT CHAIN FAILED: java binary"; exit 1; fi; \
    echo "ENTRYPOINT CHAIN OK"; \
    echo "final: $(rpm --root=/rootfs -qa | wc -l) packages, $(du -sm /rootfs | cut -f1) MB, shell absent"

# Ship only the verified runtime root with the stable Java entrypoint.
FROM scratch
COPY --from=builder /rootfs/ /
LABEL org.opencontainers.image.source="https://github.com/NWarila/ubi9-base-micro"
ENV JAVA_HOME=/usr/lib/jvm/jre-21-openjdk
USER 65532:65532
ENTRYPOINT ["/usr/bin/java"]
