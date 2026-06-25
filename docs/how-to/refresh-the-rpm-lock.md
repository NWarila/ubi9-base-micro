# Refresh the RPM Lock

Use this task to absorb patched runtime RPMs deliberately after the nightly
sentinel or a local scanner run finds a fixable CVE in the pinned runtime set.

## Prerequisites

- Bash
- Network access to Red Hat UBI metadata and direct `cdn-ubi.redhat.com` RPM URLs
- Docker or compatible local tooling required by the generator

## Procedure

Check whether the committed lockfiles are still reproducible:

```sh
bash tools/generate-rpm-lock.sh --check
```

Regenerate the lockfiles when a controlled bump is required:

```sh
bash tools/generate-rpm-lock.sh
```

Review changes to `rpm-lock/runtime.amd64.txt` and
`rpm-lock/runtime.arm64.txt`. Each runtime package row must retain exact NEVRA,
direct-CDN URL, whole-RPM SHA-256, `%{SHA256HEADER}`, and `%{SIGMD5}` values.

Run the repository verifier:

```sh
python tools/verify.py
```

For a real lock refresh, run the affected image gates before opening the pull
request:

```sh
bash tools/run-test-gates.sh
```

The build installs locked RPMs from fetched local paths with raw `rpm -Uvh`.
There is no install-time microdnf resolution in the runtime build path.
