# Scriptlet effect classification for the python delta closure

Every scriptlet- or trigger-bearing package in `rpm-lock/scriptlets.<arch>.txt` must have a section
here classifying its observable effects and why the `--noscripts --notriggers` build is correct
without them. The refresh harness fails on any unclassified package; a new entry here requires
re-review before the lock lands.

## bash

Lua `postinstall`/`postuninstall` scriptlets append or prune `/bin/sh` and `/bin/bash` lines in
`/etc/shells`. Effect classification: NOT REQUIRED. `bash` is a build-support package: it is
installed and later erased with scriptlets and triggers suppressed, so `/etc/shells` is never
touched, and the file's state remains exactly the parent's. The shipped image contains no shell,
so shell registration is meaningless there.

## krb5-libs

`triggerun` on `krb5-libs < 1.15.1-5` rewrites an `includedir` line into `/etc/krb5.conf` when a
pre-2017 krb5 is uninstalled during an upgrade. Effect classification: UNREACHABLE. The cloned
parent contains no krb5 at all, so this fresh installation can never trigger an uninstall of an
older krb5; the packaged `/etc/krb5.conf` payload (which already carries the `includedir`
configuration) installs verbatim.
