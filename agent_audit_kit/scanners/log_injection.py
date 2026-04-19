"""Log-injection scanner for MCP tool handlers (AAK-LOGINJ-001 / CVE-2026-6494).

A `@tool`-decorated function parameter flows into `logger.*` / `print` /
`sys.stdout.write` / `console.log` without stripping CRLF or ANSI
escape sequences. Attackers can forge log entries + inject escape
sequences to social-engineer an operator into running dangerous
commands.

Detection is pragmatic:
- locate functions decorated with anything ending in `tool`
- for each, check the body for logger.* / print / sys.stdout.write
  calls whose args reference a parameter name
- fire unless the function has obvious sanitization:
    * `.replace('\\r', '').replace('\\n', '')`, or
    * `.encode('ascii', 'ignore').decode()`, or
    * a call to `re.sub` with a control-character class, or
    * a call to a function whose name contains `sanitize` / `strip_control`.

References:
- CVE-2026-6494: https://nvd.nist.gov/vuln/detail/CVE-2026-6494
- CWE-117: Improper Output Neutralization for Logs.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS


_LOG_CALL_PATTERNS = {
    ("logger", "info"), ("logger", "debug"), ("logger", "warning"),
    ("logger", "error"), ("logger", "critical"), ("logger", "log"),
    ("log", "info"), ("log", "debug"), ("log", "warning"), ("log", "error"),
    ("sys", "stdout"), ("sys", "stderr"),
    ("console", "log"), ("console", "info"), ("console", "warn"), ("console", "error"),
}
_SANITIZERS = re.compile(
    r"""sanitize|strip_control|escape_controls|re\.sub\s*\(\s*r?['"]\\?\\[rn\\x1b\\x7f]|
        \.replace\s*\(\s*['"]\\r['"]|
        \.replace\s*\(\s*['"]\\n['"]|
        \.encode\s*\(\s*['"]ascii['"]\s*,\s*['"]ignore['"]""",
    re.VERBOSE | re.IGNORECASE,
)


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _is_tool_decorated(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        name = _decorator_name(dec)
        if name.endswith("tool") or name.endswith(".tool"):
            return True
    return False


def _log_target(call: ast.Call) -> tuple[str, str] | None:
    func = call.func
    if isinstance(func, ast.Name) and func.id == "print":
        return ("", "print")
    if isinstance(func, ast.Attribute):
        node = func.value
        if isinstance(node, ast.Name):
            return (node.id, func.attr)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            # `sys.stdout.write` → (stdout, write) after peeling sys.
            if node.value.id == "sys" and node.attr == "stdout":
                return ("sys", "stdout")
    return None


def _arg_refs_param(node: ast.AST, param_names: set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in param_names:
            return True
    return False


def _func_is_sanitizing(func: ast.FunctionDef | ast.AsyncFunctionDef, source: str) -> bool:
    start = func.lineno - 1
    end = getattr(func, "end_lineno", None) or (start + 1)
    body = "\n".join(source.splitlines()[start:end])
    return bool(_SANITIZERS.search(body))


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return []

    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_tool_decorated(node):
            continue
        params = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
        if not params:
            continue
        if _func_is_sanitizing(node, text):
            continue
        for call in (c for c in ast.walk(node) if isinstance(c, ast.Call)):
            target = _log_target(call)
            if target is None or target not in _LOG_CALL_PATTERNS:
                continue
            for arg in list(call.args) + [kw.value for kw in call.keywords]:
                if _arg_refs_param(arg, params):
                    findings.append(make_finding(
                        "AAK-LOGINJ-001",
                        rel,
                        f"Tool function {node.name!r} logs caller-controlled parameter "
                        f"via {'.'.join(filter(None, target))}(...) without CRLF/ANSI sanitization",
                        line_number=call.lineno,
                    ))
                    break
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
