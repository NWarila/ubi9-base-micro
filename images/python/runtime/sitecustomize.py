# Purpose: keep the interpreter's stderr clean under the approved-mode (FIPS-only provider) OpenSSL
# configuration. CPython's hashlib probes md5/blake2b/blake2s at import with usedforsecurity=False; the
# fips+base providers cannot serve them, and hashlib reports each miss through logging.exception, which
# would auto-configure a stderr handler on the root logger. Importing hashlib ONCE here, with a root
# handler present only for the duration of the import, prevents that import from auto-configuring root logging.
# The root handler list is restored to its prior contents. Skipped only under -S, which also skips all of site.
import logging as _logging

_root = _logging.getLogger()
_sink = _logging.NullHandler()
_root.addHandler(_sink)
try:
    import hashlib  # noqa: F401
finally:
    _root.removeHandler(_sink)
del _logging, _root, _sink
