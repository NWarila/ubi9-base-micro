# Technical Debt

## TD-4: OpenSSL FIPS provider z-stream availability

Red Hat UBI repositories can purge older z-stream RPM builds while this image still needs exact provider pins for reproducibility and FIPS scope. The arm64 `openssl-fips-provider-so-3.0.7-8.el9.aarch64` RPM is already gone from the current arm64 UBI repository, so arm64 now pins `openssl-fips-provider-so-3.0.7-11.el9_8` and carries an explicit no-#4857-arm64-OE disclaimer.

The amd64 `openssl-fips-provider-so-3.0.7-8.el9.x86_64` RPM is still available and remains the validated #4857 baseline for amd64. When Red Hat eventually purges that amd64 RPM too, the amd64 image cannot stay byte-identical to the #4857 `-8.el9` baseline. That event forces a new amd64 z-stream decision: either identify primary evidence that the replacement provider remains within the intended #4857 coverage, or revise the amd64 FIPS claim before bumping the pin.
