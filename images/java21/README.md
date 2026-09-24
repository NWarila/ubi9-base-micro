# java21

`images/java21` builds a hardened OpenJDK 21 headless **server** JRE on the
pinned `ubi9-base-micro` floor, as the base for Keycloak-class Java servers.
`.github/workflows/publish-java21.yaml` is configured to build and smoke-test
it on pull requests and `main`; it is not published yet.

## Runtime

- `java-21-openjdk-headless` `1:21.0.12.1.1-1.2.el9` from the Red Hat UBI 9
  repositories. The build checks the RPM signature of every package in the live
  Java transaction and of the two pinned `crypto-policies` and `ca-certificates`
  RPMs it restores files from; those two are also pinned by SHA-256.
- Entry point `/usr/bin/java`, `JAVA_HOME=/usr/lib/jvm/jre-21-openjdk`, user
  `65532:65532`, no shell.
- TLS trust comes from `/etc/pki/java/cacerts`, extracted during the build from
  the pinned `ca-certificates` anchors; the build fails if it holds fewer than
  100 entries.

## FIPS mode

On a host whose kernel runs in FIPS mode, the JDK enters FIPS mode and JCA
cryptography is served by NSS in FIPS mode (`SunPKCS11-NSS-FIPS`); this was
tested with the kernel's FIPS flag simulated. It is tested behaviour,
not a CMVP validation claim: the NSS build in this image matches no current
CMVP certificate.

## Server profile: unsupported features

Per ADR-0016 this image declares the standard features whose native libraries
it omits. The build fails if the RPM-declared requirements that the strip
leaves unsatisfied differ from the reviewed list in
`unsatisfied-requirements.txt`, whose seven `omission` entries are the
RPM-visible part of this table.

| Feature | Behaviour in this image | Omitted package |
| --- | --- | --- |
| Java Sound (`javax.sound.*`) | no mixers; `libjsound.so` cannot load because `libasound.so.2` is absent | `alsa-lib` |
| CUPS printing (`javax.print`) | no print services are found | `cups-libs` and its avahi, dbus and gnutls closure |
| SCTP (`com.sun.nio.sctp`) | `UnsupportedOperationException`, because `libsctp.so.1` is absent | `lksctp-tools` |
| NSS root-certificate module | `libnssckbi.so` is absent (only a dangling alternatives link remains); Java trusts `/etc/pki/java/cacerts` | `p11-kit-trust` |
| PKCS#11 modules through p11-kit | `libp11-kit.so.0` and `p11-kit-proxy.so` are absent; the FIPS provider loads NSS directly | `p11-kit` |
| CA trust tooling | `trust` is absent (the micro floor already omits `update-ca-trust`); the truststore is fixed at build time | `p11-kit-trust` |
| Local-hostname fallback | `InetAddress.getLocalHost()` resolves through the container runtime's `/etc/hosts` entry (tested with Podman) and fails without one | `systemd-libs` (`nss-myhostname`) |

## Every omitted package and the native files it carried

Generated from the RPM payloads of these packages as the build installs them:
every ELF library and program, named by its soname where it has one. None of
these files is in the image.

| Package | Libraries and programs |
| --- | --- |
| `alsa-lib` | `aserver`, `libasound.so.2`, `libatopology.so.2` |
| `avahi-libs` | `libavahi-client.so.3`, `libavahi-common.so.3`, `libavahi-libevent.so.1` |
| `cups-libs` | `libcups.so.2`, `libcupsimage.so.2` |
| `dbus-libs` | `libdbus-1.so.3` |
| `gnutls` | `libgnutls.so.30` |
| `libevent` | `libevent-2.1.so.7`, `libevent_core-2.1.so.7`, `libevent_extra-2.1.so.7`, `libevent_openssl-2.1.so.7`, `libevent_pthreads-2.1.so.7` |
| `libgcrypt` | `libgcrypt.so.20` |
| `libgpg-error` | `gpg-error`, `libgpg-error.so.0` |
| `libidn2` | `libidn2.so.0` |
| `libtasn1` | `libtasn1.so.6` |
| `libunistring` | `libunistring.so.2` |
| `lksctp-tools` | `checksctp`, `libsctp.so.1`, `libwithsctp.so.1`, `sctp_darn`, `sctp_status`, `sctp_test` |
| `nettle` | `libhogweed.so.6`, `libnettle.so.8` |
| `p11-kit` | `libp11-kit.so.0`, `p11-kit`, `p11-kit-remote` |
| `p11-kit-trust` | `p11-kit-trust.so`, `trust` |
| `systemd-libs` | `libnss_myhostname.so.2`, `libnss_resolve.so.2`, `libnss_systemd.so.2`, `libsystemd.so.0`, `libudev.so.1` |

The build also erases 23 install-time packages that the Java installation pulls
in and that the micro floor does not carry: shells, coreutils, text tools, Lua,
Python 3 and their libraries (the `tool` lines of `strip.txt`).

## Evidence not produced yet

No SBOM or vulnerability-scan evidence is produced for this image yet; it is
planned with the shared `workflow-*` containers for every image.

## Alternative

If you need any omitted feature, use Red Hat's runtime image instead:
`registry.access.redhat.com/ubi9/openjdk-21-runtime@sha256:908540a90db3dea9dcc8b80de84c9d44ced2dd328d3ed36930b0b04ad8a0f4e8`
(tag `1.24` on 2026-09-23).
