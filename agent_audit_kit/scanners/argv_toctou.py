"""Argv TOCTOU: allowlist-approval then argv rebuild before spawn — CVE-2026-53822.

Flags the check-then-mutate-then-exec data flow where a command / argv buffer is
**approved against an allow/deny list and then reassigned, rebuilt, re-split, or
extended before it is spawned**, so a different (unapproved) command shape
executes than the one that was approved.

Anchor: **CVE-2026-53822** — "OpenClaw before 2026.5.18 contains a command
injection vulnerability where shell wrapper argv could change between approval
and execution." CWE-77 (Command Injection) + CWE-367 (TOCTOU Race Condition),
CVSS 8.8. The OpenClaw instance is Node.js, so both Python (`subprocess` /
`os.exec*`) and TS/JS (`child_process.spawn` / `exec` / `execFile`, `execa`) are
analysed.

Detection is order-sensitive on a single command variable ``V``:
  1. **approve**  — ``V`` is tested against an allow/deny list / `is_allowed` /
     `validateCommand` guard;
  2. **mutate**   — ``V`` is reassigned, re-split (`shlex.split` / `.split()`),
     re-joined, concatenated, `.extend()`/`.push()`-ed, or `V[i] = ...` after
     the approval;
  3. **exec**     — ``V`` is passed to a spawn sink with **no re-validation**
     between the mutation and the spawn.

FP guards: approve → spawn with no mutation in between PASSES; a re-check after
the mutation (approve → mutate → approve → spawn) PASSES. Python uses stdlib
``ast``; TS/JS uses a comment-stripped, line-ordered regex pass.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

_RULE_ID = "AAK-MCP-ARGV-TOCTOU-001"

# Allow/deny-list / approval markers (identifier, attribute, or string literal).
_ALLOW_RE = re.compile(
    r"allow(?:ed|list)?|whitelist|deny(?:list)?|blocklist|blacklist"
    r"|is_allowed|isallowed|approve|approved|permit|permitted|sanction"
    r"|authori[sz]e|validate_?command|check_?command|assert_allowed|allowlisted",
    re.IGNORECASE,
)
# Approval-verb call names (func name matches -> the call is an approval check).
_APPROVAL_CALL_RE = re.compile(
    r"^(?:is_allowed|isAllowed|approve|validate_?command|validateCommand"
    r"|check_?command|assert_allowed|is_permitted|authori[sz]e)$",
    re.IGNORECASE,
)

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")


# ---------------------------------------------------------------------------
# Python (AST)
# ---------------------------------------------------------------------------

# subprocess sinks, matched case-insensitively (subprocess.Popen vs run/call).
_PY_SPAWN_ATTRS = {"run", "popen", "call", "check_output", "check_call"}
_PY_OS_EXEC = {
    "system", "popen", "execv", "execve", "execvp", "execvpe", "execl",
    "execle", "execlp", "execlpe", "spawnv", "spawnl", "spawnvp",
}
_REBUILD_CALL_RE = re.compile(
    r"shlex\.split|shlex\.quote|\.split\(|\.join\(|re\.sub|\.format\(|str\.split",
)


def _callee_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Attribute):
        base = f.value.id if isinstance(f.value, ast.Name) else ""
        return f"{base}.{f.attr}" if base else f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _has_allow_token(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and _ALLOW_RE.search(sub.id):
            return True
        if isinstance(sub, ast.Attribute) and _ALLOW_RE.search(sub.attr):
            return True
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if _ALLOW_RE.search(sub.value):
                return True
    return False


def _is_rebuild(value: ast.AST, var: str) -> bool:
    """True if the RHS rebuilds/transforms the approved buffer."""
    if any(isinstance(s, ast.Name) and s.id == var for s in ast.walk(value)):
        return True  # derived from the approved var
    try:
        src = ast.unparse(value)
    except Exception:
        src = ""
    if _REBUILD_CALL_RE.search(src):
        return True
    return isinstance(value, (ast.JoinedStr, ast.BinOp))


def _is_py_spawn(call: ast.Call) -> bool:
    name = _callee_name(call)
    short = name.split(".")[-1]
    if "subprocess" in name and short.lower() in _PY_SPAWN_ATTRS:
        return True
    if name.startswith("os.") and short in _PY_OS_EXEC:
        return True
    return name in ("os.system", "os.popen")


def _scan_python(text: str) -> int | None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None

    approvals: dict[str, set[int]] = defaultdict(set)
    mutations: dict[str, set[int]] = defaultdict(set)
    execs: dict[str, set[int]] = defaultdict(set)

    for node in ast.walk(tree):
        # approvals
        if isinstance(node, (ast.If, ast.Assert)) and _has_allow_token(node.test):
            for name in _names_in(node.test):
                approvals[name].add(node.lineno)
        elif isinstance(node, ast.Call):
            cn = _callee_name(node).split(".")[-1]
            if _APPROVAL_CALL_RE.match(cn):
                for name in _names_in(node):
                    approvals[name].add(node.lineno)
        # mutations
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and _is_rebuild(node.value, tgt.id):
                    mutations[tgt.id].add(node.lineno)
                elif isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
                    mutations[tgt.value.id].add(node.lineno)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            mutations[node.target.id].add(node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("extend", "append", "insert") and isinstance(
                node.func.value, ast.Name
            ):
                mutations[node.func.value.id].add(node.lineno)
        # execs
        if isinstance(node, ast.Call) and _is_py_spawn(node):
            arg_names: set[str] = set()
            for a in node.args:
                arg_names |= _names_in(a)
            for kw in node.keywords:
                if kw.arg in ("executable", "args"):
                    arg_names |= _names_in(kw.value)
            for name in arg_names:
                execs[name].add(node.lineno)

    return _flag(approvals, mutations, execs)


# ---------------------------------------------------------------------------
# TS / JS (comment-stripped, line-ordered regex)
# ---------------------------------------------------------------------------

_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_TS_SPAWN_RE = re.compile(
    r"(?:child_process|cp)?\.?(?:spawn|spawnSync|exec|execSync|execFile|"
    r"execFileSync)\s*\(\s*([A-Za-z_$][\w$]*)"
    r"|\bexeca(?:Sync)?\s*\(\s*([A-Za-z_$][\w$]*)",
)


def _strip_ts_comments(text: str) -> str:
    text = _TS_BLOCK_COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    return _TS_LINE_COMMENT_RE.sub("", text)


def _scan_ts(text: str) -> int | None:
    text = _strip_ts_comments(text)
    lines = text.split("\n")
    spawns: list[tuple[str, int]] = []
    for m in _TS_SPAWN_RE.finditer(text):
        var = m.group(1) or m.group(2)
        if var:
            spawns.append((var, text.count("\n", 0, m.start()) + 1))
    if not spawns:
        return None

    for var, eline in spawns:
        approval_lines: list[int] = []
        mutation_lines: list[int] = []
        word = re.compile(rf"(?<![\w$]){re.escape(var)}(?![\w$])")
        reassign = re.compile(
            rf"(?<![\w$]){re.escape(var)}(?![\w$])\s*=(?!=)"
            rf"|(?<![\w$]){re.escape(var)}(?![\w$])\.(?:push|splice|concat|unshift)\s*\(",
        )
        for i, line in enumerate(lines, start=1):
            if i >= eline:
                break
            if word.search(line) and _ALLOW_RE.search(line):
                approval_lines.append(i)
            if reassign.search(line):
                mutation_lines.append(i)
        muts = [m for m in mutation_lines if m < eline]
        if not muts:
            continue
        last_mut = max(muts)
        if not any(a < last_mut for a in approval_lines):
            continue
        if any(last_mut < a < eline for a in approval_lines):
            continue  # re-validated after mutation
        return eline
    return None


# ---------------------------------------------------------------------------
# Shared ordering check
# ---------------------------------------------------------------------------


def _flag(
    approvals: dict[str, set[int]],
    mutations: dict[str, set[int]],
    execs: dict[str, set[int]],
) -> int | None:
    for var, elines in execs.items():
        for e in sorted(elines):
            muts = [m for m in mutations.get(var, ()) if m < e]
            if not muts:
                continue
            last_mut = max(muts)
            apps = approvals.get(var, set())
            if not any(a < last_mut for a in apps):
                continue
            if any(last_mut < a <= e for a in apps):
                continue  # re-validated after the mutation -> safe
            return e
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for argv TOCTOU (approve -> rebuild -> spawn), CVE-2026-53822.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _PY_SUFFIXES + _TS_SUFFIXES:
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        line = (
            _scan_python(text) if path.suffix in _PY_SUFFIXES
            else _scan_ts(text)
        )
        if line is None:
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                "Command/argv buffer is approved against an allow/deny list and "
                "then rebuilt (reassigned / re-split / re-joined / extended) "
                "before being spawned, with no re-validation in between — a "
                "different command shape executes than the one approved "
                "(CVE-2026-53822, CWE-77 + CWE-367 TOCTOU)."
            ),
            line,
        ))

    return findings, scanned_files
