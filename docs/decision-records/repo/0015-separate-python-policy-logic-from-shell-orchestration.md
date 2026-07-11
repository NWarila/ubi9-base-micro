# ADR-0015: Separate Python Policy Logic From Shell Orchestration

- Status: Accepted
- Date: 2026-07-11
- Scope: repo

## Context

The repository uses shell entrypoints to drive image builds, provision tools,
fetch packages, and run gates. It also has Python helpers for structured parsing,
policy decisions, invariant checks, and deterministic artifact generation. Keeping
those responsibilities mixed in shell makes substantive behavior harder to unit
test and has produced duplicate RPM-lock grammar and validation paths.

The existing split is a direction, not complete conformance. Some shell files are
thin drivers, three build boundaries require inline shell, and several scripts and
Dockerfile blocks still contain policy logic. This record distinguishes those
states so that an existing mixed implementation is not mistaken for a permanent
exception.

## Decision

Substantive logic that parses structured data, makes policy decisions, asserts
invariants, or generates artifacts belongs in a Python helper testable through
pytest or a `--self-test` entrypoint. Shell owns installation, network-fetch
execution, external-command orchestration, environment and file plumbing, and
exit-status propagation. Dockerfile `RUN` instructions should be thin invocations
of those helpers. Small checks needed to validate a shell interface do not by
themselves transfer substantive policy into shell.

Three boundary classes may retain inline shell:

1. **Bootstrap before Python.** The named `fips-verify` and `rpm-rootfs` stage
   bootstrap loops in `containers/Dockerfile` must install the locked interpreter
   before a Python parser can run. ADR-0014
   ratified those two loops. This decision extends the same rationale to the
   generated capture-stage bootstrap in `write_capture_dockerfile()` that installs
   the locked builder-Python closure before assembling `/rootfs`; ADR-0014 did not
   cover that generated stage. The bootstrap-bound snapshot comparison in
   `tools/assert-builder-toolchain-floor.sh` remains shell for the same reason.
2. **Terminal reproducibility normalization.** The terminal
   `find /rootfs -xdev … touch` command in the `rpm-rootfs` stage's rootfs-assembly
   `RUN` remains inline and last so no later helper invocation can introduce
   metadata drift.
3. **Final shell removal.** The deletion and survivor checks in the
   `runtime-common` stage's shell-removal `RUN` block remain inline because that
   block removes the shell used to execute the instruction and verifies that
   shell, package managers, and Python do not survive in the runtime.

Source classification comments are working design metadata. Shell sources carry
the applicable `Role`, `Python-convertible`, `Micro-container candidate`, and
`Relocate` annotations; applicability varies, and five shell drivers omit
`Micro-container candidate`. Python tools carry `Role` and
`Micro-container candidate` but not the shell-specific conversion and relocation
fields. `tools/verify.py` does not enforce an annotation schema.

The test layout follows the same ownership rule: `tests/*.sh` are external
black-box gate drivers against a built image, while `tools/tests/test_*.py` are
unit tests for repository Python helpers. The one remaining shell gate and five
current Python unit suites are named in the required-files manifest in
`tools/verify.py`, and the Python suites are wired independently by the pytest
hooks in `.pre-commit-config.yaml`. This describes the current semantic split; it
does not constrain every future test to those directories.

The current-state ledger is:

### Conforming thin shell

- `tools/build.sh` and `tools/build-stig-datastream.sh` orchestrate build tools;
  the latter delegates its substantive assertion to Python.
- `tools/install-crane.sh`, `tools/install-grype.sh`,
  `tools/install-openscap.sh`, `tools/install-syft.sh`, and
  `tools/install-trivy.sh` are installer and provisioning glue.
- `tools/run-stig-arf.sh` and `tools/run-test-gates.sh` orchestrate external tools
  and the repository's gate helpers.
- `tests/fips.sh` and `tests/hardening.sh` remain deliberate built-image shell
  entrypoints. Their current policy internals are non-converged as recorded below.
- After its bootstrap, `rpm-rootfs` uses a thin filename adapter, raw RPM install,
  and helper invocations in the rootfs-assembly `RUN` between the runtime filename
  projection and terminal metadata normalization.

### Conforming Python gates

- `tools/assert-rpm-lock-hashes.py` imports the public policy-independent
  `rpmlock.py` validation seam for lock grammar and cross-row invariants, then owns
  only installed-rpm queries, downloaded-file hashing, and `rpm -K` orchestration.
  Its exhaustive unit suite and small operational self-test both fail closed.

### Declared boundaries

- The two source-Dockerfile bootstraps, the generated capture-stage bootstrap,
  and `tools/assert-builder-toolchain-floor.sh` are the bootstrap-before-Python
  boundary.
- The `find /rootfs -xdev -exec touch -h -d "@${SOURCE_DATE_EPOCH}"` command is
  the terminal reproducibility boundary.
- The `runtime-common` `RUN` block that removes `/usr/bin/sh`, package managers,
  and Python is the final shell-removal boundary.

### Non-converged surfaces

- The direct-entry reader, package-row reader, and orphan-verification blocks in
  `tools/fetch-runtime-rpms.sh`, and `tools/fetch-builder-rpms.sh:69-100,156-191`,
  duplicate lock grammar, URL and hash decisions, row validation, and orphan
  detection. Their curl, RPM, and installation orchestration remains shell-owned.
- `tools/fetch-openssl-fips-provider-rpms.sh:46-68,81-108` mixes architecture and
  pin decisions, hashing, signature assertions, and manifest generation with
  fetch orchestration.
- `tools/generate-rpm-lock.sh` parses Dockerfile argument defaults at lines 25-38.
  Its capture heredoc retains architecture and pin decisions at lines 87-140,
  final-package-floor decisions at lines 208-221, CDN resolution and signature
  assertions at lines 223-262, and AWK generation and row assertions at lines
  264-285. The `generate_one`, `run_check`, and command-line driving at lines
  293-438 are the intended shell orchestration.
- In `fips-verify`, the bootstrap `RUN` retains inline provider-pin, repository,
  and installation decisions before invoking `verify-fips-provider.py`.
- The `dev-rootfs` stage mixes shell-owned installation with package parsing,
  executable removal, and assertions.
- Before the final shell-removal boundary, the `runtime-common` setup block
  retains architecture selection and cross-stage FIPS assertions.
- The final `dev` stage repeats inline pruning and assertions in its closing
  `RUN` instruction.
- The outer image-test drivers remain shell, but the tar, JSON, label, and table
  assertions in `tests/fips.sh:51-53,66-113,136-206` and the AWK scans, decision
  loops, and embedded Python in `tests/hardening.sh:76-98,100-163,165-213` are
  pending extraction into testable Python helpers.

## Consequences

- Policy behavior gains a stable unit-test boundary without replacing shell where
  it is the natural interface to package managers, build engines, and gate tools.
- The three declared boundaries stay explicit and narrow; they do not authorize
  unrelated inline policy logic.
- The non-converged ledger is migration debt, not accepted permanent behavior.
  Future extractions preserve the shell entrypoints where they remain useful.
- Classification annotations communicate intended ownership during that work but
  remain advisory until a separate repository rule explicitly validates them.
- Keeping the test convention in this decision record avoids a second policy
  source while preserving external image gates as shell entrypoints.

## References

- `docs/decision-records/repo/0001-byte-for-byte-rootfs-reproducibility.md`
- `docs/decision-records/repo/0014-pin-builder-python-closure.md`
- `containers/Dockerfile`
- `tools/rpmlock.py`
- `tools/assert-rpm-lock-hashes.py`
- `tools/build-runtime-rootfs.py`
- `tools/verify.py`
- `.pre-commit-config.yaml`
