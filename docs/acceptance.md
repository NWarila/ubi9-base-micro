# Repository Namespace Note

This repository publishes under `ghcr.io/nwarila/ubi9-base-micro`. Any copied acceptance-spec references to `ghcr.io/nwarila-platform/*` are superseded for this repository by the own-account namespace above.
# `ubi9-base` — Definition of Done (Phase-1 Acceptance Spec)

> **Status:** the formal, objective acceptance gate for the platform's first repo, `ubi9-base`.
> **Enforced two ways:** (1) **in-CI** — the publish workflow fails the build if a gating criterion is unmet; (2) **independent post-publish audit** — from a clean, unauthenticated machine, every published image is pulled and verified. A criterion is "done" only when *both* pass.
> **Companion docs:** [PLATFORM-PLAN.md](PLATFORM-PLAN.md) (architecture + rollout) · [ROCKCRAFT-PARITY.md](ROCKCRAFT-PARITY.md) (Section-H rationale, numbers, measurement protocol) · [FINDINGS.md](FINDINGS.md) (org-wide audit).
> This file ships into the repo (e.g. `docs/acceptance.md`) so CI and the audit enforce the same spec.

## The one-line DoD
> An unrelated person, on a clean machine, can **anonymously pull all 8 images by digest** and have **`cosign` + `slsa-verifier` + every attestation check pass against the exact signer identity**; CI's **hardening + per-variant STIG-ARF + dual-scanner CVE + OpenVEX-default-deny** gates are green; the **FIPS/CMVP evidence is recorded truthfully** (proven or honestly scoped); **nightly rebuild is proven**; and **each variant meets-or-beats its Canonical rock on security while landing within its documented footprint target** — shipping STIG ARF + CMVP FIPS + SLSA L3 that rocks don't.

## Scope — the 8 images
**Topology (validated 2026-06-17): POLYREPO** — **four repos** (`ubi9-base-micro` root + `ubi9-base-python`/`-node`/`-java`, each `FROM ubi9-base-micro@digest`) publish **4 runtime variants** + **4 `-dev` siblings** to `ghcr.io/nwarila-platform/*`. **This DoD applies per-repo:** the `ubi9-base-micro` DoD is the full A–H below; each variant repo inherits A–H and adds (a) its `FROM ubi9-base-micro@digest` pin is the *current* micro digest, (b) its own incremental signed STIG ARF + 800-190, (c) its CMVP delta (python rides #4857 / node OpenSSL-linkage-or-VOID / java FIPS = Keycloak-leaf), (d) its own exact per-repo signer identity. The **family-coherence gate (A5)** binds them. Per the topology decision, the variant tables below describe the 4 variants regardless of repo:

| Runtime variant | `-dev` sibling | Runtime serves |
|---|---|---|
| `base-micro` (glibc + ca, no shell) | `base-micro-dev` | static / CGO / glibc-dynamic apps |
| `base-python` (CPython 3.12) | `base-python-dev` | interpreter-required Python |
| `base-node` (Node 22 LTS, RHEL nodejs:22 RPM) | `base-node-dev` | all JS/TS |
| `base-java` (OpenJDK 21 **headless JRE**) | `base-java-dev` (JDK 21) | JVM — **Keycloak** + future JVM |

**Applicability:** Sections **B** (distroless hardening) and **H** (footprint ceilings) apply to the **4 runtime variants only** — the `-dev` siblings legitimately carry a shell + toolchain. The **supply-chain evidence in C** (sign/SBOM/scan/attest) applies to **all 8 images** (a poisoned builder is a supply-chain risk too); `-dev` images need not be distroless or hit a footprint ceiling.

## Responsibility boundary (governs the whole spec)
The platform owns the **hardened base floor**: the standard runtime (full CPython / Node / headless JRE), minimized only by **standard RPM hygiene** (`install_weak_deps=0`, `--nodocs`, locale/man + binary strip, shell removed, builder discarded), **rpmdb preserved**. There is **no Chisel-equivalent** (Chisel can't run on RPM anyway). **Any app-specific minimization — `jlink`/`jdeps` for Java, stdlib pruning for Python — is the leaf/user's job** in their own Dockerfile. The footprint delta this leaves vs a fully-sliced/`jlink`'d rock is **by design**, never a base failure.

---

## A. Artifacts exist & are correctly shaped
- **A1.** All **8 images** publish to `ghcr.io/nwarila-platform/*` and are addressable by digest. *(check: `docker buildx imagetools inspect <img>@<digest>`)*
- **A2.** Each image is **multi-arch** (`linux/amd64` + `linux/arm64`) — the digest resolves to an OCI index with both platforms.
- **A3.** Runtime versions assert: `base-python`→Python 3.12.x, `base-node`→Node 22.x, `base-java`→OpenJDK 21.x. *(check: run the runtime with `--version`)*
- **A4.** Footprint of each runtime variant is **recorded** (compressed registry-layer sum **and** uncompressed unpacked rootfs, single-arch amd64) as build evidence, per the §H measurement protocol.
- **A5. Family coherence (polyrepo gate):** each variant repo's `FROM ubi9-base-micro@sha256:…` equals the **current published `ubi9-base-micro` digest**. A coherence check fails the build / flags drift if a variant lags micro (this is how the polyrepo family stays coherent without monorepo co-location).

## B. Runtime hardening — **runtime variants only** (gating)
- **B1. No shell:** `/bin/sh`, `/bin/bash`, busybox, etc. do not resolve. *(check: `docker run --rm --entrypoint /bin/sh <img>@<digest>` exits non-zero / not-found)*
- **B2. No package manager:** no `dnf`/`microdnf`/`rpm`/`apt`/`dpkg` executable; the builder stage is discarded.
- **B3. Non-root:** image config `User` = `65532` (non-zero); never `0:0`.
- **B4. rpmdb preserved & valid:** `/var/lib/rpm` is present and a native scanner enumerates the installed RPMs (this is what makes scanning *truthful* — see H).
- **B5. CA bundle present** at the RHEL path(s).
- **B6.** The repo's `tests/hardening.sh` runs B1–B5 as a **build-failing gate**.

## C. Supply-chain evidence — **all 8 images**, **per image** (gating)
- **C1. cosign keyless signature** present; verifies with an **exact** `--certificate-identity` = the **SLSA generator workflow ref** + `--certificate-oidc-issuer=https://token.actions.githubusercontent.com`. A wildcard/regex identity is a **FAIL**.
- **C2. SLSA L3 provenance** present; `slsa-verifier` confirms `builderID` = the **trusted `slsa-github-generator`** (proves L3, not L2 `attest-build-provenance`).
- **C3. SBOM** (SPDX **and** CycloneDX), **generated from the rpmdb**, attached as an attestation, and enumerating real packages. *(check: `cosign download sbom <img>@<digest> | grep <a known RHEL rpm>` succeeds; a near-empty SBOM is a FAIL)*
- **C4. CVE gate:** **0 fixable HIGH/CRITICAL** under **both Trivy and Grype** (disagreement → fail-if-either); every **unfixed** HIGH/CRIT carries a **signed OpenVEX** statement (un-vexed unfixed crit = **hard FAIL**). VEX docs live under a CODEOWNERS-gated `vex/` path and are cosign-signed.
- **C5. Per-variant signed STIG ARF:** tailored OpenSCAP GPOS-SRG scan, **0 applicable-rule failures**, ARF attached as a signed attestation; the **XCCDF tailoring file is committed + reviewed** with documented per-check N/A (a mass-N/A scan with no justification is a FAIL).
- **C6. NIST 800-190 §4.1** image-control attestation present (the correct *image* evidence; **not** CIS-Docker, which is host/daemon).
- **C7. FIPS evidence (container-level, kernel-independent):** each runtime variant bakes in its module's **approved-mode config** + a captured **build-time self-test PASS** probe — OpenSSL variants: `openssl fipsinstall`-generated `fipsmodule.cnf` + `openssl.cnf` (`default_properties=fips=yes`) + `OPENSSL_CONF`/`OPENSSL_MODULES` ENV (the RHEL OpenSSL **FIPS provider**, *not* kernel-triggered `crypto-policies`, which is inert at `fips_enabled=0`); Go-static: `GOFIPS140=v1.0.0` build + `GODEBUG=fips140=on`; Java/Keycloak (leaf): pinned BC-FIPS jars + `java.security` (BCFIPS first) + `--fips-mode=strict`. CMVP ledger committed (G2). Runtime `fips_enabled` is explicitly **= 0 (Talos-kernel property)**, never inherited from the image — host is non-FIPS by decision.
- **C7a. Module-version pin gate (build-failing):** shipped module version == the cert's validated version — OpenSSL `3.0.7-395c1a240fbfffd8` (#4857), Go module `v1.0.0` (#5247), BC-FJA `2.0.0` (#4743). Drift fails the build.
- **C7b. `base-node` linkage gate (build-failing):** `ldd $(which node)` shows **system** `libcrypto.so.3`/`libssl.so.3` from `/usr/lib64`, `node_shared_openssl==true`, `process.versions.openssl` is system 3.0.x; launch `--force-fips` and assert `crypto.getFips()===1`. A vendored OpenSSL **voids the Node FIPS claim** → FAIL.
- **C7c. Negative-test gate:** OpenSSL variants — `openssl list -providers` shows fips+base active AND a non-approved op (`openssl md5`) fails; Go — `go version -m` shows `GOFIPS140=v1.0.0`; Node — `getFips()===1`; Keycloak — startup log shows `BCFIPS … Approved Mode`.
- **C8.** All attestations are **cosign keyless DSSE, logged in Rekor**.

## D. A consumer can verify it (gating, post-publish)
- **D1.** From a **clean machine with no auth**, anonymous `docker pull <runtime>@<digest>` succeeds for every runtime variant (public GHCR).
- **D2.** The full chain passes **anonymously**: `cosign verify` (C1) + `slsa-verifier verify-image` (C2) + `cosign verify-attestation` for each predicate type (sbom / vuln / stig-arf / 800-190 / openvex) — all success against the exact signer identity. (`gh attestation verify` is intentionally NOT in the contract: it verifies GitHub-native Artifact Attestations, not the cosign OCI attestation `generator_container_slsa3.yml` writes — see PLAN STEP006 rev. b.)

## E. Build integrity & discipline (gating)
- **E1. Signed builds ran on GitHub-hosted ephemeral runners** via the trusted generator (confirmed by the provenance `builderID`); not self-hosted.
- **E2. One self-owned workflow** in the repo; **no `uses:` into any NWarila-owned/internal shared reusable-workflow repo** (copy-and-own). **Exception:** the external **SLSA trusted-builder generator** reusable required by E1 — that trusted, audited, L3-built reusable IS the provenance mechanism, not an internal-coupling smell.
- **E3.** Every `uses:` is a **40-char commit SHA**; `actionlint` is clean. **Exception (owner-ratified 2026-06-18; named MANDATE §6 exception — TECH-DEBT TD-1):** SLSA trusted reusable workflows (e.g. `generator_container_slsa3.yml`) are pinned by semantic-version **tag** `@vX.Y.Z` (upstream mandates a tag ref) + a CI **tag→SHA integrity guard** asserting the tag resolves to the audited commit; the EXACT `--certificate-identity` is the tag ref.
- **E4. PR builds are test-only** (build + hardening + scan, **no push/sign/attest**); publish happens only on `push:main` + `v*` tags.
- **E5.** The UBI `FROM` lines are **digest-pinned** (`@sha256:`) with Renovate annotations.

## F. Operational (gating)
- **F1. Nightly + on-CVE rebuild** workflow exists and has run **green** at least once.
- **F2.** The repo is wired into the **shared Renovate preset** (base-digest bump cascades downstream; the SLSA signer-identity ref pin rides the cascade).
- **F3. Reproducibility posture is *resolved*:** either a rebuild-bit-for-bit check passes (`SOURCE_DATE_EPOCH` + rpm install-order pinned) **or** the "reproducible" claim is explicitly retracted in the README. (No aspirational middle.)

## G. Evidence honesty & docs (gating — the showcase bar)
- **G1.** README/docs make the **4-variant set + the per-image evidence obvious** (transparency relocates to the repo), and **document the responsibility boundary** (base = standard hardened floor; leaf owns `jlink`/stdlib trimming).
- **G2. CMVP module ledger committed** (real, verified): **RHEL 9 OpenSSL FIPS Provider #4857 ACTIVE** (corrects the earlier #4754) backing OpenSSL/C, Python `ssl`, and Node; **Go Cryptographic Module v1.0.0 #5247 ACTIVE** for Go-static; **BC-FJA v2.0.0 #4743 ACTIVE** for Java/Keycloak; **Node = no own cert, FIPS via the linked OpenSSL #4857** (contingent on C7b). Full spec → [FIPS-IMPLEMENTATION.md](FIPS-IMPLEMENTATION.md).
- **G2a. Out-of-scope certs flagged** (never cite unless that exact version ships): RHEL 9.0 OpenSSL #4746; BC-FJA 2.1.0 interim #4943; Go module v1.26.0 (Pending Review). **Owner decision (Keycloak leaf):** ship BC-FIPS **2.0.0** (ACTIVE #4743) or accept Keycloak-26-default **2.1.x** (interim #4943).
- **G3. FIPS claims scoped honestly:** the published claim is **module-scoped + approved-mode-scoped, never OS/host/container-scoped** ("containers use FIPS-validated modules in approved mode," not "FIPS-compliant system"). **`base-python` is explicitly bounded to TLS/OpenSSL-routed crypto** — hashlib built-ins (md5/sha1/sha2/sha3/blake2) bypass the provider, so "Python in FIPS mode" is never claimed (app-code algorithm discipline required). The non-FIPS-host limitation is stated verbatim. Publish the exact statement from [FIPS-IMPLEMENTATION.md](FIPS-IMPLEMENTATION.md).

## H. Rockcraft parity — footprint targets + the parity verdict (gating where noted)
*Security parity is already enforced by B + C (we match-or-beat the rock's distroless posture and exceed it on scanner-truthfulness, RHSA/OVAL lineage, SLSA L3, STIG ARF, CMVP FIPS). Section H adds the **footprint** ceilings + the parity bookkeeping. Full rationale + measurement protocol: [ROCKCRAFT-PARITY.md](ROCKCRAFT-PARITY.md).*

- **H1. Measurement protocol (mandatory):** same-runtime / same-date, **single-arch amd64**, compressed (registry-layer sum) **and** uncompressed (unpacked rootfs) stated separately — never subtract one unit from the other; never use a vendor "vs full distro" headline as the denominator. Scanner run is **native** (no manifest-bridge shim).
- **H2. `base-micro`:** uncompressed **≤ 16 MB(u)** (rpmdb retained); meets-or-beats a real (Pebble-bearing) bare rock; bounded delta vs the pure-chiselled ~5–13 MB(u) floor conceded. **FAIL above 16 MB(u) without justification.**
- **H3. `base-python`:** **MUST beat** stock `ubi9/python-312-minimal` (181 MB(u)) by **≥2×** (target ≤ 70 MB(u)); the ~2–3× premium vs the ~18.7 MB(c) rock is recorded as justified (RPM granularity). **FAIL if ≥ stock minimal.**
- **H4. `base-node`:** compressed **≤ 55 MB(c)** (same band as the ~41–46 MB(c) rock); **MUST beat** stock `nodejs-22-minimal` (86.7 MB(c)). Comparator is the published **Node-18** rock (no first-party Node 22 rock exists) — recorded as such. **FAIL above 55 MB(c) (or above stock minimal at all) without justification.**
- **H5. `base-java`:** **MUST beat** stock `ubi9/openjdk-21-runtime` (376 MB(u)) **decisively**; record compressed + uncompressed. **No fixed sub-rock ceiling at the base** — the `jlink` delta to the ~53 MB(c) rock is **leaf-owned** (Keycloak runs `jdeps`→`jlink`), explicitly **not** a base FAIL.
- **H6. "Where we exceed" recorded per variant:** native scanner truthfulness (rpmdb vs chisel's stripped DB / unmerged manifest analyzer), per-package RHSA/OVAL CVE accountability, RHEL ~10-yr lifecycle, SLSA L3 + cosign keyless + per-variant STIG ARF + CMVP FIPS — none shipped by a stock rock.

---

## Dependency caveats (true before this DoD can be hit)
- **Phase-0 prerequisites must exist** for C/D/E: the **public GHCR namespace**, the **SLSA `generator_container_slsa3` wired** into the hosted build path, and the **GitHub-hosted runner path**. `ubi9-base` cannot reach its DoD before these.
- **FIPS residuals #1–#3 RESOLVED (2026-06-17):** #1 Go module = **#5247 ACTIVE**; #2 Node FIPS = **in**, via linked OpenSSL #4857 (contingent on the C7b linkage gate); #3 Talos kernel FIPS = **no** (non-FIPS host; module-scoped container claim only). **Remaining build-time confirmations** (don't block the design): pin the exact `openssl-libs` NEVRA whose `fips.so` == the #4857-validated `3.0.7-395c1a240fbfffd8`; the **BC-FIPS 2.0.0 vs 2.1.0** Keycloak choice (G2a); Go toolchain **1.24/1.25, not 1.26**; and confirm linux/amd64+arm64 are within #5247's tested OEs (the A2 multi-arch requirement).
- **`-dev` images** are signed/SBOM'd/scanned/attested (C) but exempt from B and H (they are builders, not shipped runtimes).

## Acceptance command sketch (independent audit, anonymous)
```sh
D=ghcr.io/nwarila-platform/base-micro@sha256:...          # repeat per runtime variant
GEN='https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/vX.Y.Z'

docker pull "$D"                                            # D1 (anonymous)
cosign verify "$D" --certificate-identity="$GEN" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com   # C1/D2
slsa-verifier verify-image "$D" --source-uri github.com/NWarila/ubi9-base # C2 (builderID=generator ⇒ L3)
# (gh attestation verify removed rev. b — wrong mechanism for a cosign OCI attestation; contract = cosign verify + slsa-verifier + cosign verify-attestation)                  # D2
cosign verify-attestation "$D" --type spdxjson  --certificate-identity="$GEN" --certificate-oidc-issuer=...  # C3
cosign verify-attestation "$D" --type openvex   --certificate-identity="$GEN" --certificate-oidc-issuer=...  # C4
cosign verify-attestation "$D" --type <stig-arf> --certificate-identity="$GEN" --certificate-oidc-issuer=... # C5
cosign download sbom "$D" | grep -q glibc                  # C3 (rpmdb-derived, non-empty)
docker run --rm --entrypoint /bin/sh "$D"; test $? -ne 0   # B1 (no shell ⇒ must fail)
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$D"  # C4 (0 fixable)
grype "$D" --only-fixed --fail-on high                     # C4 (cross-check)
openssl list -providers | grep -q fips                     # C7/C7c (OpenSSL variants: fips provider active)
node --force-fips -e 'process.exit(crypto.getFips()?0:1)'  # C7b (base-node: getFips()===1)
go version -m "$BIN" | grep -q 'GOFIPS140=v1.0.0'          # C7c (Go-static leaves)
```
