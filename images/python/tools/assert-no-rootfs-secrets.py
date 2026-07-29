#!/usr/bin/env python3
# Purpose: Fail if a container rootfs contains high-confidence clear-text secrets, with role-aware
#          classification of credential-named assignments in shipped Python source
# Role: gate
# Micro-container candidate: yes - pure-stdlib, rootfs-in/exit-out, has --self-test

"""Rootfs secret gate for images that ship a Python standard library.

Fork of the root scanner. Every pattern, threshold, and traversal rule is
inherited unchanged; the single addition is a classifier for
``generic-secret-assignment`` matches inside ``*.py`` files, because the shipped
CPython standard library assigns credential-named variables from dynamic
expressions (``password = lexer.get_token()``) and passes long prompt strings to
``getpass``. Those are not secrets. Hard-coded credential material remains a
finding wherever it appears, including inside such expressions.

Classification is fail-closed: any parse failure, any unresolved alias, and any
credential-named match that does not map to a recognized shape stays a finding.

Inherited limitation, unchanged by this fork: the generic assignment pattern does
not match an f-string right-hand side, because ``f"`` falls outside its value
character class. Such a literal is therefore never surfaced to the classifier by
either the root scanner or this one. Constants reached through concatenation,
call arguments, and aliases are covered.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_TEXT_BYTES = 8 * 1024 * 1024
SAMPLE_SCAN_BYTES = 64 * 1024
WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
MIN_SECRET_CONSTANT_LENGTH = 12

# Closed prompt-source rule: only these callees may carry a long literal that is not credential
# material, and only in argument 0 or the `prompt=` keyword. Any other callee is a VALUE role.
PROMPT_CALLEE_NAMES = frozenset({"getpass", "getuser", "unix_getpass", "win_getpass", "fallback_getpass"})
PROMPT_CALLEE_MODULES = frozenset({"getpass"})
# Lookup-key roles: a long literal naming a variable to read is not credential material.
KEY_CALLEE_NAMES = frozenset({"get", "getenv", "environ"})


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

# Semantic docstring exemptions: an illustrative credential literal inside a module/class/function
# docstring. Keyed by rootfs-relative path plus the sha256 of the COMPLETE docstring text, so an RPM
# update that merely moves the docstring does not churn the entry, and identical text in executable
# code cannot inherit the exemption. Reviewed individually; additions require re-review.
DOCSTRING_EXEMPTIONS: dict[str, frozenset[str]] = {
    # urllib/request.py module docstring: the ProxyHandler usage example carries passwd='geheim$parole'.
    "usr/lib64/python3.12/urllib/request.py": frozenset(
        {"dc98f56bac25b2064f7873b73e84c7fd062fe4c39de85323b3501f528cc1d8b1"}
    ),
}


class ClassifierCounters:
    """Per-scan branch hit counts; asserted by the self-test so no branch can go untested."""

    def __init__(self) -> None:
        self.dynamic_assignment = 0
        self.prompt_argument = 0
        self.lookup_key = 0
        self.non_assignment_artifact = 0
        self.docstring_exemption = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "dynamicAssignment": self.dynamic_assignment,
            "promptArgument": self.prompt_argument,
            "lookupKey": self.lookup_key,
            "nonAssignmentArtifact": self.non_assignment_artifact,
            "docstringExemption": self.docstring_exemption,
        }


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


def _build_parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _target_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.append(sub.id.lower())
        elif isinstance(sub, ast.Attribute):
            names.append(sub.attr.lower())
    return names


def _callee_labels(call: ast.Call) -> tuple[str, str]:
    func = call.func
    if isinstance(func, ast.Attribute):
        module = func.value.id.lower() if isinstance(func.value, ast.Name) else ""
        return module, func.attr.lower()
    if isinstance(func, ast.Name):
        return "", func.id.lower()
    return "", ""


def _constant_role(constant: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    """Classify a string constant by the role it plays in the enclosing expression."""
    parent = parents.get(constant)
    child: ast.AST = constant
    # A constant inside a format expression belongs to the same role as that expression.
    while isinstance(parent, ast.BinOp | ast.JoinedStr | ast.FormattedValue | ast.Tuple):
        child, parent = parent, parents.get(parent)
    if isinstance(parent, ast.Subscript):
        return "lookup-key"
    if isinstance(parent, ast.keyword):
        keyword_parent = parents.get(parent)
        if parent.arg == "prompt" and isinstance(keyword_parent, ast.Call):
            module, name = _callee_labels(keyword_parent)
            if name in PROMPT_CALLEE_NAMES and (module in PROMPT_CALLEE_MODULES or module == ""):
                return "prompt"
        return "value"
    if isinstance(parent, ast.Call):
        module, name = _callee_labels(parent)
        position = parent.args.index(child) if child in parent.args else -1
        if position == 0:
            if name in PROMPT_CALLEE_NAMES and (module in PROMPT_CALLEE_MODULES or module == ""):
                return "prompt"
            if name in KEY_CALLEE_NAMES:
                return "lookup-key"
        return "value"
    return "value"


def _expression_is_benign(
    expression: ast.AST,
    parents: dict[ast.AST, ast.AST],
    module_bindings: dict[str, ast.AST],
    counters: ClassifierCounters,
    depth: int = 0,
) -> bool:
    """True when no constant in the expression plays a credential-VALUE role."""
    if isinstance(expression, ast.Name) and depth == 0:
        bound = module_bindings.get(expression.id)
        if bound is None:
            return False  # unresolved alias: fail closed
        return _expression_is_benign(bound, parents, module_bindings, counters, depth + 1)
    saw_prompt = False
    saw_key = False
    for node in ast.walk(expression):
        if isinstance(node, ast.Name) and node is not expression:
            bound = module_bindings.get(node.id)
            if bound is not None and not _expression_is_benign(bound, parents, module_bindings, counters, depth + 1):
                return False
        if not isinstance(node, ast.Constant):
            continue
        value = node.value
        if not isinstance(value, str | bytes) or len(value) < MIN_SECRET_CONSTANT_LENGTH:
            continue
        role = _constant_role(node, parents)
        if role == "value":
            return False
        saw_prompt = saw_prompt or role == "prompt"
        saw_key = saw_key or role == "lookup-key"
    if depth == 0:
        if saw_prompt:
            counters.prompt_argument += 1
        elif saw_key:
            counters.lookup_key += 1
        else:
            counters.dynamic_assignment += 1
    return True


def _is_artifact_match(node: ast.AST, parents: dict[ast.AST, ast.AST], key: str) -> bool:
    """The measured regex artifact: a credential Name inside an `if` test, where the regex ran on
    past the suite colon into an unrelated one-line assignment target."""
    if not isinstance(node, ast.Name) or node.id.lower() != key:
        return False
    parent = parents.get(node)
    while parent is not None and not isinstance(parent, ast.If | ast.While):
        if isinstance(parent, ast.stmt):
            return False
        parent = parents.get(parent)
    if not isinstance(parent, ast.If | ast.While):
        return False
    return _node_contains(parent.test, node.lineno, node.col_offset)


def _docstring_text(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    parent = parents.get(node)
    grandparent = parents.get(parent) if parent is not None else None
    if not isinstance(parent, ast.Expr) or not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return None
    if not isinstance(grandparent, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
        return None
    body = getattr(grandparent, "body", [])
    if not body or body[0] is not parent:
        return None
    return node.value


def classify_python_match(
    rel: str,
    text: str,
    match: re.Match[str],
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
    module_bindings: dict[str, ast.AST],
    counters: ClassifierCounters,
) -> bool:
    """True when a credential-named match in Python source is provably not credential material."""
    key = (match.groupdict().get("key") or "").lower()
    line, column = _offset_to_position(text, match.start("key"))

    innermost: ast.AST | None = None
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name | ast.Attribute | ast.keyword | ast.arg | ast.Constant)
            and _node_contains(node, line, column)
            and (innermost is None or getattr(node, "col_offset", -1) >= getattr(innermost, "col_offset", -1))
        ):
            innermost = node

    if innermost is None:
        return False

    docstring = _docstring_text(innermost, parents)
    if docstring is not None:
        digest = hashlib.sha256(docstring.encode("utf-8")).hexdigest()
        if digest in DOCSTRING_EXEMPTIONS.get(rel, frozenset()):
            counters.docstring_exemption += 1
            return True
        return False

    # Walk up to the credential-binding statement, if any.
    current: ast.AST | None = innermost
    while current is not None:
        parent = parents.get(current)
        if isinstance(parent, ast.Assign) and any(key in _target_names(target) for target in parent.targets):
            return _expression_is_benign(parent.value, parents, module_bindings, counters)
        if isinstance(parent, ast.AnnAssign | ast.AugAssign) and key in _target_names(parent.target):
            return parent.value is not None and _expression_is_benign(parent.value, parents, module_bindings, counters)
        if isinstance(parent, ast.keyword) and (parent.arg or "").lower() == key:
            return _expression_is_benign(parent.value, parents, module_bindings, counters)
        if isinstance(parent, ast.arguments):
            for arg, default in _parameter_defaults(parent):
                if arg.arg.lower() == key and default is not None:
                    return _expression_is_benign(default, parents, module_bindings, counters)
        if isinstance(parent, ast.stmt):
            break
        current = parent

    if _is_artifact_match(innermost, parents, key):
        counters.non_assignment_artifact += 1
        return True
    return False


def _parameter_defaults(arguments: ast.arguments) -> list[tuple[ast.arg, ast.expr | None]]:
    positional = list(arguments.posonlyargs) + list(arguments.args)
    padded: list[ast.expr | None] = [None] * (len(positional) - len(arguments.defaults))
    pairs = list(zip(positional, padded + list(arguments.defaults), strict=True))
    pairs.extend(zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True))
    return pairs


def _module_bindings(tree: ast.AST) -> dict[str, ast.AST]:
    bindings: dict[str, ast.AST] = {}
    duplicates: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id in bindings:
                        duplicates.add(target.id)
                    bindings[target.id] = node.value
    for name in duplicates:  # ambiguous rebinding: refuse to resolve
        bindings.pop(name, None)
    return bindings


def append_findings(
    findings: list[dict[str, Any]],
    rel: str,
    text: str,
    patterns: list[SecretPattern],
    counters: ClassifierCounters,
) -> None:
    python_source = rel.endswith(".py")
    tree: ast.AST | None = None
    parents: dict[ast.AST, ast.AST] = {}
    bindings: dict[str, ast.AST] = {}
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
                            tree = None  # fail closed: every match in this file stays a finding
                        if tree is not None:
                            parents = _build_parents(tree)
                            bindings = _module_bindings(tree)
                    if tree is not None and classify_python_match(rel, text, match, tree, parents, bindings, counters):
                        continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append({"path": rel, "line": line, "pattern": pattern.name})


def scan(rootfs: Path) -> dict[str, Any]:
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
                    append_findings(findings, rel, sample_text, HIGH_CONFIDENCE_SAMPLE_PATTERNS, counters)
                    skipped_binary += 1
                    continue
                if size > MAX_TEXT_BYTES:
                    append_findings(findings, rel, sample_text, HIGH_CONFIDENCE_SAMPLE_PATTERNS, counters)
                    skipped_large += 1
                    continue
                remainder = handle.read()
        except OSError as exc:
            raise SystemExit(f"failed to read {rel}: {exc}") from exc

        text = (sample + remainder).decode("utf-8", errors="ignore")
        files_scanned += 1
        append_findings(findings, rel, text, SECRET_PATTERNS, counters)

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


REAL_WORLD_BENIGN_FIXTURES: list[tuple[str, str]] = [
    ("dynamic call", "password = lexer.get_token()\n"),
    (
        "dynamic attribute from bound parameter",
        "def __init__(self, password_mgr=None):\n"
        "    if password_mgr is None:\n"
        "        password_mgr = HTTPPasswordMgr()\n"
        "    self.passwd = password_mgr\n",
    ),
    ("tuple unpack from call", "username, have_password, password = userinfo.partition(':')\n"),
    ("prompt argument", 'import getpass\nPASSWD = getpass.getpass("IMAP password for %s on %s: " % (u, h))\n'),
    ("prompt keyword", 'import getpass\npassword = getpass.getpass(prompt="Enter the account password: ")\n'),
    ("environ key", 'import os\npassword = os.environ.get("DATABASE_PASSWORD_VARIABLE")\n'),
    ("alias to environ key", 'import os\nsource = os.environ.get("DATABASE_PASSWORD_VARIABLE")\npassword = source\n'),
    ("non-assignment artifact", "if user or passwd: self.auth_cache[key] = (user, passwd)\n"),
]

REAL_WORLD_FINDING_FIXTURES: list[tuple[str, str]] = [
    ("direct literal", 'password = "correcthorsebatterystaple"\n'),
    ("key-equal literal", 'client_secret = "client_secret_value_x"\n'),
    ("literal plus suffix", 'password = "correcthorsebattery" + suffix\n'),
    ("environ default literal", 'import os\npassword = os.environ.get("PW", "correcthorsebatterystaple")\n'),
    ("aliased literal", 'hardcoded_value = "correcthorsebatterystaple"\npassword = hardcoded_value\n'),
    (
        "aliased through call",
        'hardcoded_value = identity_value("correcthorsebatterystaple")\npassword = hardcoded_value\n',
    ),
    ("non-getpass call literal", 'password = identity_value("correcthorsebatterystaple")\n'),
    ("parameter default", 'def connect(password="correcthorsebatterystaple"):\n    return password\n'),
    ("keyword argument", 'connect(password="correcthorsebatterystaple")\n'),
    ("unresolved alias", "password = mystery_value\n"),
    ("different artifact shape", "if user: passwd = fetch_from_disk_constant_name\n"),
    ("parse error file", 'password = "correcthorsebatterystaple"\ndef broken(:\n'),
    ("non-python file keeps text scan", "password=correcthorsebatterystaple\n"),
]


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        benign_root = root / "benign"
        (benign_root / "usr/lib64/python3.12").mkdir(parents=True)
        for index, (label, source) in enumerate(REAL_WORLD_BENIGN_FIXTURES):
            (benign_root / f"usr/lib64/python3.12/case{index}.py").write_text(source, encoding="utf-8")
            assert label
        report = scan(benign_root)
        if report["result"] != "passed":
            raise SystemExit(f"self-test: measured-benign shapes produced findings: {report['findings']}")
        counters = report["pythonClassifier"]
        if counters["promptArgument"] < 2:
            raise SystemExit(f"self-test: prompt branch not exercised: {counters}")
        if counters["nonAssignmentArtifact"] < 1:
            raise SystemExit(f"self-test: artifact branch not exercised: {counters}")
        if counters["dynamicAssignment"] < 2:
            raise SystemExit(f"self-test: dynamic branch not exercised: {counters}")
        if counters["lookupKey"] < 1:
            raise SystemExit(f"self-test: lookup-key branch not exercised: {counters}")

        rejected = 0
        for label, source in REAL_WORLD_FINDING_FIXTURES:
            case_root = root / f"finding-{rejected}"
            (case_root / "usr/lib64/python3.12").mkdir(parents=True)
            name = "case.py" if label != "non-python file keeps text scan" else "case.conf"
            (case_root / "usr/lib64/python3.12" / name).write_text(source, encoding="utf-8")
            case_report = scan(case_root)
            if case_report["result"] != "failed" or not case_report["findings"]:
                raise SystemExit(f"self-test: hard-coded secret shape was not detected: {label}")
            rejected += 1

        docstring_root = root / "docstring"
        (docstring_root / "usr/lib64/python3.12/urllib").mkdir(parents=True)
        (docstring_root / "usr/lib64/python3.12/urllib/request.py").write_text(
            '"""Example usage.\n\n    ProxyHandler(passwd=\'geheim$parole_value\')\n"""\n',
            encoding="utf-8",
        )
        unlisted = scan(docstring_root)
        if unlisted["result"] != "failed":
            raise SystemExit("self-test: an unlisted docstring literal must remain a finding")

        legacy_root = root / "legacy"
        legacy_root.mkdir()
        (legacy_root / "openssl.cnf").write_text("private_key = /etc/pki/tls/private/x.key\n", encoding="utf-8")
        (legacy_root / "key.bin").write_bytes(b"\x00-----BEGIN PRIVATE KEY-----\n")
        legacy = scan(legacy_root)
        if legacy["result"] != "failed" or legacy["skippedBinaryFiles"] != 1:
            raise SystemExit("self-test: inherited binary/high-confidence behavior regressed")

    print(
        f"python rootfs secret scanner self-test passed: {len(REAL_WORLD_BENIGN_FIXTURES)} measured-benign "
        f"shapes accepted, {rejected}/{len(REAL_WORLD_FINDING_FIXTURES)} hard-coded shapes rejected, "
        "unlisted docstring literal rejected, inherited behavior intact"
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
