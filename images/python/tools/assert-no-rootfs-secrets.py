#!/usr/bin/env python3
# Purpose: Fail if a container rootfs contains high-confidence clear-text secrets, with exact
#          content-addressed exemptions for reviewed CPython regex false positives
# Role: gate
# Micro-container candidate: yes - pure-stdlib, rootfs-in/exit-out, has --self-test

"""Rootfs secret gate for images that ship a Python standard library.

This is a deliberately narrow fork of the root scanner. It detects the inherited
high-confidence token patterns and credential-named assignments only when the
assignment value matches the inherited textual pattern. Exact reviewed CPython
false positives are exempted by rootfs-relative path, statement span, normalized
enclosing-statement hash, and an AST proof of the expected statement kind.

This gate does not claim general hard-coded-secret coverage. Encoded, composed,
or indirect values are outside the generic assignment pattern, including
``str()``, ``bytes().decode()``, ``.join()``, ``.format()``, ``%`` formatting,
dict or tuple indexing, walrus expressions, conditionals, annotated class
attributes, comprehensions, lambda values, star-args, ``+=``, and alias chains.
Those inherited coverage limits are explicit self-test fixtures below.

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
    """One measured CPython statement, bound to content, location, and AST shape."""

    path: str
    start_line: int
    end_line: int
    statement_hash: str
    expected_kind: str


# These are the 23 generic-assignment matches measured in the pinned CPython 3.12.13 rootfs.
# The hash is sha256(ast.dump(statement, include_attributes=False)). A package update, source
# relocation, or statement edit intentionally loses the exemption and requires fresh review.
CPYTHON_STATEMENT_EXEMPTIONS: Final[tuple[StatementExemption, ...]] = (
    StatementExemption(
        "usr/lib64/python3.12/ftplib.py",
        943,
        943,
        "cb8194107c08d9c2bdc617a2b9dace5519a52e13b2dad6db4dc4359a5ca317d6",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/getpass.py",
        62,
        62,
        "771073b30ca7c10870b083b35f86949019cbc84d090562526d242a9c4d115072",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/getpass.py",
        91,
        91,
        "771073b30ca7c10870b083b35f86949019cbc84d090562526d242a9c4d115072",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/imaplib.py",
        1565,
        1565,
        "ac45565227fdd07d427d4c029a91e7bc5bb2e42397a21b343e3c383540cd09db",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/netrc.py",
        138,
        138,
        "b96895a5a21507fde1ea2e1651baf80509423c0fa9c39772fd20794ca556a59c",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/parse.py",
        198,
        198,
        "f97cb77ecd5ecc4f585ca175d5d665801f008ab835110811ce0ef2493ec97af9",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/parse.py",
        228,
        228,
        "a7b6aa6aa9a059419352aa5658794e1659da2802b711bb0b837ac3ee479bda15",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/parse.py",
        1157,
        1157,
        "3583ce5ff4cd6ef189bf3a2997374d5f7646d2afe1aba5c73975e65601b68c20",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        1,
        68,
        "bbe2ec8b9a6ab52c1ed04b97a657c8e362890cdaa94cb0bdff77f48eb98d1b8c",
        "module-docstring",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        782,
        782,
        "3e6eb2f5d600551a85470b99efb8fa902ec5bd9e88b7b792296794b0d6e95b59",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        897,
        898,
        "6e07a0d837833fbec393598d38683249e2ac178869fd432acaa5ba1a711d5075",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        959,
        959,
        "8ad7fb3d088dcc793035b9c8a66b4d84548a0617e30dcd5fbe86272671b6e569",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        1026,
        1026,
        "27ce53ce8467932203fa48cf4210597d2f961bf860915295516e6e499a3cb844",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        1089,
        1089,
        "286ba1f2afed78804f965b70bb8efa43832f78d691dc13b7a17ed3367111cf66",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        1548,
        1548,
        "7af5901a10d55f76db49025f4c4aa32ba37d8a9a31e833f57ab60274521935da",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2074,
        2074,
        "7af5901a10d55f76db49025f4c4aa32ba37d8a9a31e833f57ab60274521935da",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2304,
        2304,
        "dfd155a710256dc8f338832497d70a288a8d9893465af49190bc023c15cd2945",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2322,
        2322,
        "dfd155a710256dc8f338832497d70a288a8d9893465af49190bc023c15cd2945",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2336,
        2336,
        "ff2554b4ec291817c441a5d94c24036eef9505d43be9346313f9a28aa7a42d4b",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2350,
        2350,
        "ff2554b4ec291817c441a5d94c24036eef9505d43be9346313f9a28aa7a42d4b",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2367,
        2367,
        "4cc19560e297c8c835dd39e1d44c0cfb1b2ef31b194926114c40d91de84ed1f5",
        "credential-assignment",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2368,
        2368,
        "9f6d815cd1e039f74457748c96232043779b2a26d03d7416a8545d874ae00ad0",
        "conditional-test-artifact",
    ),
    StatementExemption(
        "usr/lib64/python3.12/urllib/request.py",
        2376,
        2377,
        "761da6d80a8c89a32eb73e99104da67dcd0c8038fad4566507918174184b8797",
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


def _normalized_statement_hash(statement: ast.stmt) -> str:
    normalized = ast.dump(statement, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


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
    statement_hash = _normalized_statement_hash(statement)
    for record in exemptions:
        if (
            record.path == rel
            and record.start_line == statement.lineno
            and record.end_line == statement.end_lineno
            and record.statement_hash == statement_hash
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
                        except (SyntaxError, ValueError, RecursionError):
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
                sample_text = sample.decode("utf-8", errors="ignore")
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

        text = (sample + remainder).decode("utf-8", errors="ignore")
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

        reviewed_source = "password = lexer.get_token()\n"
        reviewed_tree = ast.parse(reviewed_source)
        reviewed_statement = reviewed_tree.body[0]
        if not isinstance(reviewed_statement, ast.stmt):
            raise SystemExit("self-test: synthetic reviewed statement is not an AST statement")
        reviewed_path = "usr/lib64/python3.12/reviewed.py"
        reviewed = StatementExemption(
            reviewed_path,
            1,
            1,
            _normalized_statement_hash(reviewed_statement),
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
            ("changed statement", "password = other_source.get_token()\n", reviewed),
            ("moved statement", "\npassword = lexer.get_token()\n", reviewed),
            ("wrong path", reviewed_source, replace(reviewed, path="usr/lib64/python3.12/other.py")),
            ("wrong AST kind", reviewed_source, replace(reviewed, expected_kind="module-docstring")),
        )
        for label, source, record in drift_cases:
            exact_file.write_text(source, encoding="utf-8")
            drifted = scan(exact_root, (record,))
            if drifted["result"] != "failed":
                raise SystemExit(f"self-test: exemption drift unexpectedly passed: {label}")

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

    print(
        "python rootfs secret scanner self-test passed: "
        f"{len(CLAIMED_DETECTION_FIXTURES)} claimed detections found, "
        "exact exemption accepted with four drift forms rejected, parse fallback failed closed, "
        f"{len(KNOWN_COVERAGE_LIMIT_FIXTURES)} inherited coverage limits confirmed"
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
