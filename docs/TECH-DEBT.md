# Technical Debt

## TD-4: OpenSSL FIPS provider z-stream availability

Red Hat UBI repository metadata can purge older z-stream RPM builds while this image still needs exact provider pins for reproducibility and FIPS scope. The `openssl-fips-provider` and `openssl-fips-provider-so` `3.0.7-8.el9` RPMs are currently absent from normal repo metadata for both `x86_64` and `aarch64`, so the build fetches the authentic Red-Hat-GPG-signed RPMs from Red Hat UBI CDN direct URLs and verifies pinned SHA-256 values before local install.

The nightly sentinel detects if a direct CDN RPM is later purged, returns 404, changes bytes, or fails signature/hash verification. Any such 404 or SHA mismatch forces an explicit provider bump plus amd64 revalidation decision before the image can move away from the #4857 `3.0.7-395c1a240fbfffd8` validated module. Do not substitute a rebuild, EPEL package, rpmrebuild output, or newer z-stream just to keep the build green.