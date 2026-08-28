#!/usr/bin/env python3
# Purpose: Fail if a container rootfs contains high-confidence clear-text secrets, with exact
#          content-addressed exemptions for reviewed CPython regex false positives
# Role: gate
# Micro-container candidate: yes - pure-stdlib, rootfs-in/exit-out, has --self-test

"""Rootfs secret gate for images that ship a Python standard library.

This is a deliberately narrow fork of the root scanner. It detects the inherited
high-confidence token patterns and credential-named assignments only when the
assignment value matches the inherited textual pattern. Exact reviewed CPython
false positives are exempted by rootfs-relative path, statement span, the SHA-256
of the exact physical source bytes in that span, and a separate AST proof of the
expected statement kind. Comments, whitespace, quoting, and line endings are part
of the source identity; any byte drift loses the exemption.

This gate does not claim general hard-coded-secret coverage. Encoded, composed,
or indirect values are outside the generic assignment pattern, including
``str()``, ``bytes().decode()``, ``.join()``, ``.format()``, ``%`` formatting,
dict or tuple indexing, walrus expressions, conditionals, annotated class
attributes, comprehensions, lambda values, star-args, ``+=``, and alias chains.
Those inherited coverage limits are explicit self-test fixtures below.

The generic pattern covers only the listed credential names at regex word
boundaries. Underscore is a word character, so prefixed or suffixed forms such as
``ADMIN_PASSWORD``, ``db_passwd``, and ``MY_API_KEY`` are outside that coverage.

Files larger than 8 MiB, and files with a NUL within the first 65,536 bytes, take
the sampled path. Sampled files receive only their first 65,536 bytes and only the named high-confidence
patterns; generic assignments and later bytes are outside coverage.
A NUL appearing only after the first 65,536 bytes does not select the sampled path.

Classification is fail-closed for surfaced matches: parse failures, exemption
drift, moved statements, new statements, and unreviewed paths remain findings.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final

MAX_TEXT_BYTES = 8 * 1024 * 1024
SAMPLE_SCAN_BYTES = 64 * 1024
WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class SecretPattern:
    name: str
    expression: re.Pattern[str]


SECRET_PATTERNS = [
    SecretPattern("private-key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    SecretPattern("openssh-private-key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    SecretPattern("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    SecretPattern("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b")),
    SecretPattern("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82,255}\b")),
    SecretPattern("slack-token", re.compile(r"\bxox(?:b|p|a|r)-[A-Za-z0-9-]{20,}\b")),
    SecretPattern("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b")),
    SecretPattern("pypi-token", re.compile(r"\bpypi-[A-Za-z0-9_-]{40,}\b")),
    SecretPattern(
        "generic-secret-assignment",
        re.compile(
            r"(?i)\b(?P<key>aws_secret_access_key|secret_access_key|client_secret|"
            r"api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|"
            r"private[_-]?key)\b\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9+/_=.!@#$%^&*~:\\-]{12,})"
        ),
    ),
]

HIGH_CONFIDENCE_SAMPLE_PATTERN_NAMES = {
    "private-key",
    "openssh-private-key",
    "aws-access-key-id",
    "github-token",
    "github-fine-grained-token",
    "slack-token",
}
HIGH_CONFIDENCE_SAMPLE_PATTERNS = [
    pattern for pattern in SECRET_PATTERNS if pattern.name in HIGH_CONFIDENCE_SAMPLE_PATTERN_NAMES
]


@dataclass(frozen=True)
class StatementExemption:
    """One measured CPython statement, bound to exact source, location, and AST shape."""

    path: str
    start_line: int
    end_line: int
    source_hash: str
    expected_kind: str


# These are the 23 generic-assignment matches measured in the pinned CPython 3.12.13 rootfs.
# The hash is sha256(exact physical source bytes for the complete line span), including comments,
# whitespace, quoting, and line endings. AST kind is proved separately. A package update, source
# relocation, or any byte edit intentionally loses the exemption and requires fresh review.
CPYTHON_STATEMENT_EXEMPTIONS: Final[tuple[StatementExemption, ...]] = (
    StatementExemption(
        "usr/lib64/python3.12/ftplib.py",
        952,
        952,
        "7edd18a012c3b5db675b79cf134e8a2918927e9d350093c6d85a1d8d99cd723a",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/getpass.py",
        62,
        62,
        "19a52eefc30ffb16ba0e7ba0f29adcd0c186f4922afba10452d4afc44d3126fd",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/getpass.py",
        91,
        91,
        "19a52eefc30ffb16ba0e7ba0f29adcd0c186f4922afba10452d4afc44d3126fd",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/imaplib.py",
        1565,
        1565,
        "b8086451ba4c162c4755ffbde87ebe8484e32b0aaebeb8d92a8f6b3a5a80c68e",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/netrc.py",
        138,
        138,
        "3ab733ff81ac05d7b0708fabe22136daa7f22e98cbe57a1196c8f8df00620665",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/parse.py",
        198,
        198,
        "09d523c59071f8ea2294030c7df2010e4d95d219f3b5393ac2742efbf8e7408f",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/parse.py",
        228,
        228,
        "23a21b735901ec7e326c866ed4f65e06cc86e6ab4bec9ab16943be10008ae3f1",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/parse.py",
        1157,
        1157,
        "5e5e46ba761da0f52ef87fcadde04b38b2048a2c5edd8b5130781772452bdece",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        1,
        68,
        "f64d26ae8396af8efb7b2c39c6936e31ad0609f8ab13f2e4f3c19a29e242cfb3",
        "module-docstring",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        782,
        782,
        "116e0f8ac8378d69577a633d040c55d07b5bcf69b4310296480ef28fd210d4cd",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        897,
        898,
        "92fdb5014659fa011dcd56f2a0ebd6534f989a901c8d014ae35d86ec9eb65c3d",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        959,
        959,
        "0204cd78a5ed4adc110c528d2ae48529dad6fd18d9c8f0fc9dd04d0c03f07273",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        1026,
        1026,
        "2d4fe156c131418689c4781591361f03c3971130e07ff663a9a797e862166f3c",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        1089,
        1089,
        "7fbcf5b99b4493ebb3bad7948708f09c24607e1af560f941cd361d21b43b9f12",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        1548,
        1548,
        "647533f2454f179fa8ca4d134183e88b6bcdc01da7c7d2daa7b849e2d9f275af",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2074,
        2074,
        "86c2a4f45dcc5540d3e522d793d28c574ad549c559707061d2abfde83d0fff73",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2304,
        2304,
        "248bfca4985348e4e6abdff730e5cf6cace1523052ab34a466c8cd4c6a93c104",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2322,
        2322,
        "248bfca4985348e4e6abdff730e5cf6cace1523052ab34a466c8cd4c6a93c104",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2336,
        2336,
        "93aea40dec25eacb64ca787ce6185e93b36c9a1d6f9c949f87edf89d2046ea01",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2350,
        2350,
        "93aea40dec25eacb64ca787ce6185e93b36c9a1d6f9c949f87edf89d2046ea01",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2367,
        2367,
        "d0e632aed995b3d49f5d767a9742a740d896ee1845c29be9bedf9652af0b7ac3",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2368,
        2368,
        "a5c2d219616b76b31a728c35aadcec6ed746e8f75eb6ae2ce6594e9d4a05d5d2",
        "conditional-test-artifact",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2376,
        2377,
        "60d2179bd3bd653f42d358b3d118cb629f25cef4fda544575ea039163994ecbb",
        "credential-assignment",
    ),
)

KNOWN_COVERAGE_LIMIT_FIXTURES: Final[tuple[tuple[str, str], ...]] = (
    ("str()", 'password = str("correcthorsebatterystaple")\n'),
    ("bytes().decode()", 'password = bytes("correcthorsebatterystaple", "utf-8").decode()\n'),
    (".join()", 'password = "".join(["correcthorsebatterystaple", suffix])\n'),
    (".format()", 'password = "{}{}".format("correcthorsebatterystaple", suffix)\n'),
    ("% formatting", 'password = "%s" % "correcthorsebatterystaple"\n'),
    ("dict indexing", 'd = {"secret": "correcthorsebatterystaple"}\npassword = d["secret"]\n'),
    ("tuple indexing", 't = ("correcthorsebatterystaple",)\npassword = t[0]\n'),
    ("walrus", 'if (password := "correcthorsebatterystaple"):\n    use(password)\n'),
    ("conditional", 'password = source if ready else "correcthorsebatterystaple"\n'),
    ("annotated class attribute", 'class Config:\n    password: str = "correcthorsebatterystaple"\n'),
    ("comprehension", 'password = [value for value in ["correcthorsebatterystaple"]]\n'),
    ("lambda value", 'password = lambda: "correcthorsebatterystaple"\n'),
    ("star-args", 'password, *rest = ["correcthorsebatterystaple", "unused"]\n'),
    ("+=", 'password = ""\npassword += "correcthorsebatterystaple"\n'),
    ("short alias chain", 'a = "correcthorsebatterystaple"; b = a; password = b\n'),
)

CREDENTIAL_NAME_BOUNDARY_LIMIT_FIXTURES: Final[tuple[tuple[str, str], ...]] = (
    ("uppercase password prefix", 'ADMIN_PASSWORD = "correcthorsebatterystaple"\n'),
    ("lowercase password prefix", 'admin_password = "correcthorsebatterystaple"\n'),
    ("passwd prefix", 'db_passwd = "correcthorsebatterystaple"\n'),
    ("api-key prefix", 'MY_API_KEY = "correcthorsebatterystaple"\n'),
)


class ClassifierCounters:
    """Per-scan exemption count, exposed in the JSON report for auditability."""

    def __init__(self) -> None:
        self.content_addressed_exemption = 0

    def as_dict(self) -> dict[str, int]:
        return {"contentAddressedExemption": self.content_addressed_exemption}


def is_probably_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def is_private_key_path_reference(value: str) -> bool:
    if value.startswith(("/", "./", "../", "~", "$", "%")):
        return True
    return WINDOWS_DRIVE_PATH.match(value) is not None


def is_benign_generic_assignment(match: re.Match[str]) -> bool:
    key = (match.groupdict().get("key") or "").lower().replace("-", "_")
    value = (match.groupdict().get("value") or "").strip().strip("\"'")
    lowered = value.lower()
    placeholders = {"changeme", "change_me", "example", "example_secret", "placeholder"}
    if lowered in placeholders:
        return True
    return key == "private_key" and is_private_key_path_reference(value)


def _offset_to_position(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    line_start = text.rfind("\n", 0, offset) + 1
    return line, offset - line_start


def _node_contains(node: ast.AST, line: int, column: int) -> bool:
    start_line = getattr(node, "lineno", None)
    end_line = getattr(node, "end_lineno", None)
    if start_line is None or end_line is None:
        return False
    if line < start_line or line > end_line:
        return False
    if line == start_line and column < getattr(node, "col_offset", 0):
        return False
    return not (line == end_line and column > getattr(node, "end_col_offset", 0))


def _target_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for subnode in ast.walk(node):
        if isinstance(subnode, ast.Name):
            names.add(subnode.id.lower())
        elif isinstance(subnode, ast.Attribute):
            names.add(subnode.attr.lower())
    return names


def _enclosing_statement(tree: ast.AST, line: int, column: int) -> ast.stmt | None:
    statements = [node for node in ast.walk(tree) if isinstance(node, ast.stmt) and _node_contains(node, line, column)]
    if not statements:
        return None
    return min(
        statements,
        key=lambda node: (
            (node.end_lineno or node.lineno) - node.lineno,
            (node.end_col_offset or node.col_offset) - node.col_offset,
        ),
    )


def _exact_statement_source_hash(text: str, statement: ast.stmt) -> str:
    """Hash the exact physical bytes for every source line occupied by statement."""
    physical_lines = text.splitlines(keepends=True)
    source = "".join(physical_lines[statement.lineno - 1 : statement.end_lineno])
    return hashlib.sha256(source.encode("utf-8", errors="surrogateescape")).hexdigest()


def _statement_proves_expected_kind(
    statement: ast.stmt,
    tree: ast.AST,
    expected_kind: str,
    key: str,
    line: int,
    column: int,
) -> bool:
    if expected_kind == "credential-assignment":
        return isinstance(statement, ast.Assign) and any(key in _target_names(target) for target in statement.targets)
    if expected_kind == "conditional-test-artifact":
        return isinstance(statement, ast.If) and _node_contains(statement.test, line, column)
    if expected_kind == "module-docstring":
        return (
            isinstance(tree, ast.Module)
            and bool(tree.body)
            and tree.body[0] is statement
            and isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
            and _node_contains(statement.value, line, column)
        )
    return False


def _is_reviewed_cpython_statement(
    rel: str,
    text: str,
    match: re.Match[str],
    tree: ast.AST,
    exemptions: tuple[StatementExemption, ...],
) -> bool:
    line, column = _offset_to_position(text, match.start("key"))
    statement = _enclosing_statement(tree, line, column)
    if statement is None:
        return False
    key = (match.groupdict().get("key") or "").lower()
    source_hash = _exact_statement_source_hash(text, statement)
    for record in exemptions:
        if (
            record.path == rel
            and record.start_line == statement.lineno
            and record.end_line == statement.end_lineno
            and record.source_hash == source_hash
            and _statement_proves_expected_kind(
                statement,
                tree,
                record.expected_kind,
                key,
                line,
                column,
            )
        ):
            return True
    return False


def append_findings(
    findings: list[dict[str, Any]],
    rel: str,
    text: str,
    patterns: list[SecretPattern],
    counters: ClassifierCounters,
    exemptions: tuple[StatementExemption, ...],
) -> None:
    python_source = rel.endswith(".py")
    tree: ast.AST | None = None
    parsed = False

    for pattern in patterns:
        for match in pattern.expression.finditer(text):
            if pattern.name == "generic-secret-assignment":
                if is_benign_generic_assignment(match):
                    continue
                if python_source:
                    if not parsed:
                        parsed = True
                        try:
                            tree = ast.parse(text)
                        except (SyntaxError, ValueError, RecursionError, UnicodeError):
                            tree = None  # fail closed: every surfaced match stays a finding
                    if tree is not None and _is_reviewed_cpython_statement(
                        rel,
                        text,
                        match,
                        tree,
                        exemptions,
                    ):
                        counters.content_addressed_exemption += 1
                        continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append({"path": rel, "line": line, "pattern": pattern.name})


def scan(
    rootfs: Path,
    exemptions: tuple[StatementExemption, ...] = CPYTHON_STATEMENT_EXEMPTIONS,
) -> dict[str, Any]:
    if not rootfs.is_dir():
        raise SystemExit(f"rootfs directory does not exist: {rootfs}")

    findings: list[dict[str, Any]] = []
    counters = ClassifierCounters()
    files_scanned = 0
    skipped_binary = 0
    skipped_large = 0
    skipped_symlinks = 0

    for path in sorted(rootfs.rglob("*")):
        if path.is_symlink():
            skipped_symlinks += 1
            continue
        if not path.is_file():
            continue
        rel = path.relative_to(rootfs).as_posix()
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                sample = handle.read(SAMPLE_SCAN_BYTES)
                sample_text = sample.decode("utf-8", errors="surrogateescape")
                if is_probably_binary(sample):
                    append_findings(
                        findings,
                        rel,
                        sample_text,
                        HIGH_CONFIDENCE_SAMPLE_PATTERNS,
                        counters,
                        exemptions,
                    )
                    skipped_binary += 1
                    continue
                if size > MAX_TEXT_BYTES:
                    append_findings(
                        findings,
                        rel,
                        sample_text,
                        HIGH_CONFIDENCE_SAMPLE_PATTERNS,
                        counters,
                        exemptions,
                    )
                    skipped_large += 1
                    continue
                remainder = handle.read()
        except OSError as exc:
            raise SystemExit(f"failed to read {rel}: {exc}") from exc

        text = (sample + remainder).decode("utf-8", errors="surrogateescape")
        files_scanned += 1
        append_findings(findings, rel, text, SECRET_PATTERNS, counters, exemptions)

    return {
        "result": "failed" if findings else "passed",
        "rootfs": str(rootfs),
        "filesScanned": files_scanned,
        "skippedBinaryFiles": skipped_binary,
        "skippedLargeTextFiles": skipped_large,
        "skippedSymlinks": skipped_symlinks,
        "sampleScanBytes": SAMPLE_SCAN_BYTES,
        "sampledPatterns": [pattern.name for pattern in HIGH_CONFIDENCE_SAMPLE_PATTERNS],
        "patterns": [pattern.name for pattern in SECRET_PATTERNS],
        "pythonClassifier": counters.as_dict(),
        "findings": findings,
    }


def write_report(report: dict[str, Any], path: Path | None) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


CLAIMED_DETECTION_FIXTURES: Final[tuple[tuple[str, str], ...]] = (
    ("direct credential assignment", 'password = "correcthorsebatterystaple"\n'),
    ("direct API-key assignment", 'api_key = "correcthorsebatterystaple"\n'),
    ("unreviewed dynamic assignment", "password = lexer.get_token()\n"),
    ("private key token", "-----BEGIN PRIVATE KEY-----\n"),
    ("non-Python text assignment", "password=correcthorsebatterystaple\n"),
)


def _assert_scan_result(
    root: Path,
    label: str,
    source: str,
    expected: str,
    *,
    suffix: str = ".py",
    exemptions: tuple[StatementExemption, ...] = CPYTHON_STATEMENT_EXEMPTIONS,
) -> dict[str, Any]:
    case_root = root / re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
    case_root.mkdir()
    (case_root / f"case{suffix}").write_text(source, encoding="utf-8")
    report = scan(case_root, exemptions)
    if report["result"] != expected:
        raise SystemExit(f"self-test: {label} expected {expected}, got {report['result']}: {report['findings']}")
    return report


def run_self_test() -> None:
    if len(CPYTHON_STATEMENT_EXEMPTIONS) != 23:
        raise SystemExit("self-test: the reviewed CPython exemption set must contain exactly 23 statements")
    if len({(record.path, record.start_line) for record in CPYTHON_STATEMENT_EXEMPTIONS}) != 23:
        raise SystemExit("self-test: each reviewed CPython exemption must have a unique path and start line")

    expected_limit_labels = {
        "str()",
        "bytes().decode()",
        ".join()",
        ".format()",
        "% formatting",
        "dict indexing",
        "tuple indexing",
        "walrus",
        "conditional",
        "annotated class attribute",
        "comprehension",
        "lambda value",
        "star-args",
        "+=",
        "short alias chain",
    }
    if {label for label, _source in KNOWN_COVERAGE_LIMIT_FIXTURES} != expected_limit_labels:
        raise SystemExit("self-test: the explicit B2 known-coverage-limit set drifted")
    short_chain = dict(KNOWN_COVERAGE_LIMIT_FIXTURES)["short alias chain"]
    if short_chain != 'a = "correcthorsebatterystaple"; b = a; password = b\n':
        raise SystemExit("self-test: the short-name alias fixture must remain the adjudicated a -> b chain")

    required_doc_terms = (
        "does not claim general hard-coded-secret coverage",
        "inherited textual pattern",
        "alias chains",
        "Underscore is a word character",
        "first 65,536 bytes",
        "only the named high-confidence",
    )
    docstring = __doc__ or ""
    if any(term not in docstring for term in required_doc_terms):
        raise SystemExit("self-test: scanner coverage claim is no longer precise")
    if "Hard-coded credential material remains a finding wherever it appears" in docstring:
        raise SystemExit("self-test: scanner docstring restored an absolute coverage claim")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for label, source in CLAIMED_DETECTION_FIXTURES:
            suffix = ".conf" if label == "non-Python text assignment" else ".py"
            _assert_scan_result(root, f"detected-{label}", source, "failed", suffix=suffix)

        _assert_scan_result(
            root,
            "parse fallback",
            'password = "correcthorsebatterystaple"\ndef broken(:\n',
            "failed",
        )

        for label, source in KNOWN_COVERAGE_LIMIT_FIXTURES:
            _assert_scan_result(root, f"known-limit-{label}", source, "passed")
        for label, source in CREDENTIAL_NAME_BOUNDARY_LIMIT_FIXTURES:
            _assert_scan_result(root, f"name-boundary-limit-{label}", source, "passed")

        reviewed_source = 'password = lexer.get_token("Password: ")\n'
        reviewed_tree = ast.parse(reviewed_source)
        reviewed_statement = reviewed_tree.body[0]
        if not isinstance(reviewed_statement, ast.stmt):
            raise SystemExit("self-test: synthetic reviewed statement is not an AST statement")
        reviewed_path = "usr/lib64/python3.12/reviewed.py"
        reviewed = StatementExemption(
            reviewed_path,
            1,
            1,
            _exact_statement_source_hash(reviewed_source, reviewed_statement),
            "credential-assignment",
        )

        exact_root = root / "exact-reviewed"
        exact_file = exact_root / reviewed_path
        exact_file.parent.mkdir(parents=True)
        exact_file.write_text(reviewed_source, encoding="utf-8")
        exact_report = scan(exact_root, (reviewed,))
        if exact_report["result"] != "passed":
            raise SystemExit("self-test: exact content-addressed exemption did not pass")
        if exact_report["pythonClassifier"]["contentAddressedExemption"] != 1:
            raise SystemExit("self-test: exact content-addressed exemption branch did not execute")

        drift_cases = (
            ("changed statement", 'password = other_source.get_token("Password: ")\n', reviewed),
            ("moved statement", "\n" + reviewed_source, reviewed),
            ("wrong path", reviewed_source, replace(reviewed, path="usr/lib64/python3.12/other.py")),
            ("wrong AST kind", reviewed_source, replace(reviewed, expected_kind="module-docstring")),
            ("quote-style drift", "password = lexer.get_token('Password: ')\n", reviewed),
        )
        for label, source, record in drift_cases:
            exact_file.write_text(source, encoding="utf-8")
            drifted = scan(exact_root, (record,))
            if drifted["result"] != "failed":
                raise SystemExit(f"self-test: exemption drift unexpectedly passed: {label}")

        multiline_source = "password = (\n    # reviewed prompt retrieval\n    lexer.get_token()\n)\n"
        multiline_statement = ast.parse(multiline_source).body[0]
        if not isinstance(multiline_statement, ast.stmt):
            raise SystemExit("self-test: multiline reviewed statement is not an AST statement")
        multiline_path = "usr/lib64/python3.12/multiline.py"
        multiline = StatementExemption(
            multiline_path,
            1,
            4,
            _exact_statement_source_hash(multiline_source, multiline_statement),
            "credential-assignment",
        )
        multiline_root = root / "multiline-reviewed"
        multiline_file = multiline_root / multiline_path
        multiline_file.parent.mkdir(parents=True)
        multiline_file.write_text(multiline_source, encoding="utf-8")
        if scan(multiline_root, (multiline,))["result"] != "passed":
            raise SystemExit("self-test: exact multiline source exemption did not pass")
        multiline_file.write_text(
            "password = (\n    # password=correcthorsebatterystaple\n    lexer.get_token()\n)\n",
            encoding="utf-8",
        )
        if scan(multiline_root, (multiline,))["result"] != "failed":
            raise SystemExit("self-test: credential-looking comment inside exempt span unexpectedly passed")

        legacy_root = root / "legacy"
        legacy_root.mkdir()
        (legacy_root / "openssl.cnf").write_text(
            "private_key = /etc/pki/tls/private/x.key\n",
            encoding="utf-8",
        )
        (legacy_root / "key.bin").write_bytes(b"\x00-----BEGIN PRIVATE KEY-----\n")
        legacy = scan(legacy_root)
        if legacy["result"] != "failed" or legacy["skippedBinaryFiles"] != 1:
            raise SystemExit("self-test: inherited binary/high-confidence behavior regressed")

        sampled_root = root / "sampled-semantics"
        sampled_root.mkdir()
        (sampled_root / "nul-generic.bin").write_bytes(b"\x00password=correcthorsebatterystaple\n")
        (sampled_root / "large-generic.txt").write_bytes(
            b"password=correcthorsebatterystaple\n" + b"x" * MAX_TEXT_BYTES
        )
        (sampled_root / "post-sample-token.bin").write_bytes(
            b"\x00" + b"x" * (SAMPLE_SCAN_BYTES - 1) + b"-----BEGIN PRIVATE KEY-----\n"
        )
        sampled = scan(sampled_root)
        if sampled["result"] != "passed":
            raise SystemExit("self-test: sampled-path out-of-coverage fixtures unexpectedly failed")
        if sampled["skippedBinaryFiles"] != 2 or sampled["skippedLargeTextFiles"] != 1:
            raise SystemExit("self-test: sampled-path counters do not reflect NUL/large fixtures exactly")
        if sampled["sampleScanBytes"] != SAMPLE_SCAN_BYTES or sampled["sampledPatterns"] != [
            pattern.name for pattern in HIGH_CONFIDENCE_SAMPLE_PATTERNS
        ]:
            raise SystemExit("self-test: sampled-path bytes or named high-confidence patterns drifted")

        late_nul_root = root / "late-nul"
        late_nul_root.mkdir()
        (late_nul_root / "late-nul.bin").write_bytes(b"x" * SAMPLE_SCAN_BYTES + b"\x00-----BEGIN PRIVATE KEY-----\n")
        late_nul = scan(late_nul_root)
        if late_nul["result"] != "failed" or late_nul["filesScanned"] != 1 or late_nul["skippedBinaryFiles"] != 0:
            raise SystemExit("self-test: a NUL after the sample incorrectly selected the sampled path")

    print(
        "python rootfs secret scanner self-test passed: "
        f"{len(CLAIMED_DETECTION_FIXTURES)} claimed detections found, "
        "exact exemption accepted with five drift forms and comment injection rejected, "
        "parse fallback failed closed, sampled-file semantics and counters confirmed, "
        f"{len(KNOWN_COVERAGE_LIMIT_FIXTURES)} value-shape and "
        f"{len(CREDENTIAL_NAME_BOUNDARY_LIMIT_FIXTURES)} name-boundary limits confirmed"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, help="exported rootfs directory to scan")
    parser.add_argument("--report", type=Path, help="JSON report path")
    parser.add_argument("--self-test", action="store_true", help="run positive and negative self-tests")
    args = parser.parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if args.rootfs is None:
        raise SystemExit("--rootfs is required unless --self-test is used")

    report = scan(args.rootfs)
    write_report(report, args.report)
    if report["result"] != "passed":
        print("clear-text secret findings in rootfs:", file=sys.stderr)
        for finding in report["findings"]:
            print(f"  {finding['path']}:{finding['line']} matched {finding['pattern']}", file=sys.stderr)
        return 1

    print(
        "rootfs secret scan passed: "
        f"{report['filesScanned']} text files scanned, "
        f"{report['skippedBinaryFiles']} binary files sampled/skipped, "
        f"{report['skippedLargeTextFiles']} large text files sampled/skipped, "
        f"{report['skippedSymlinks']} symlinks skipped, "
        f"python classifier {report['pythonClassifier']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
