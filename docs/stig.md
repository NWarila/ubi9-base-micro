# Tailored RHEL9 STIG ARF

P1.5a adds an image-scoped OpenSCAP gate for `base-micro`.

The workflow builds the RHEL9 SSG datastream from the pinned
ComplianceAsCode/content release below:

| Input | Pin |
| --- | --- |
| SSG release | `0.1.81` |
| Source tarball SHA512 | `11e26cfa96a6f1bd98b3a131837e2f86c9a9851239337d86d624b01627faf10f7a03c395a5839ddab018e0fa47719ade05a9946f90d5ca96b1261776a9164379` |
| Tailored profile | `xccdf_org.nwarila.content_profile_ubi9_base_micro_stig` |
| Predicate type | `https://nwarila.dev/attestations/stig-arf/v1` |

The committed tailoring is `stig/rhel9-base-micro-tailoring.xml`. Its
reviewed scope ledger is `stig/tailoring-justifications.json`, both
CODEOWNERS-gated under `/stig/ @NWarila`.

The tailored profile keeps image-rootfs controls selected:

- `/etc/passwd`, `/etc/group`, `/etc/shadow`, and `/etc/gshadow` ownership and
  mode.
- The setup-shipped backup account databases: `/etc/passwd-`, `/etc/group-`,
  `/etc/shadow-`, and `/etc/gshadow-`.
- Ownership and mode for populated binary and library trees.
- Valid user and group ownership for shipped files.
- Public world-writable directory ownership and sticky-bit state.
- UID 0 uniqueness.
- Supplemental SSG checks for unexpected world-writable, setuid, and setgid
  files.

Host-only controls are not claimed as image passes. The scope ledger documents
why omitted control groups belong to the consuming host or runtime: bootloader,
kernel/sysctl, auditd, PAM, SSH, firewall, GUI, systemd services, mount options,
interactive account policy, mutable host package-management state, host log
paths, cron paths, user home directories, and SELinux device labeling.

`tools/assert-stig-tailoring.py` derives the full RHEL9 STIG control set from
the pinned source tree and fails unless every omitted control is covered by a
documented omission group; this is the mass-N/A guard. `tools/assert-rootfs-identity.py`
checks the exported runtime rootfs tar for UID 0 uniqueness and unknown file
UID/GID ownership. `tools/assert-stig-arf.py` then fails closed on ARF parse
errors, `error`/`unknown` rule results, any `fail` at the configured threshold,
or a must-verify selected rule returning `notapplicable` without a passing
equivalent deterministic assertion. The configured threshold is `low`, so any
applicable failure blocks the build.

The ARF summary JSON records every `rule-result` as `idref`, severity, and
result, plus any equivalent assertion report used to cover a selected
`notapplicable` identity or ownership rule. The signed STIG ARF predicate embeds
that summary unchanged.

On `pull_request`, CI builds the datastream, runs the tailored scan, and emits
the ARF and summary locally only. On `push` to `main` or `v*` tags, the publish
workflow runs the same scan per platform child digest, signs the structured ARF
summary predicate with Cosign keyless, and includes it in the Rekor roll-up.
