"""AAK-OPENCLAW-PRIVESC-001 — OpenClaw missing-role privesc.

IronPlate's 2026-04-07 weekly intel flagged a CVSS 9.9 privilege
escalation in OpenClaw where `OpenClawAgent(role=...)` is unset/None
or assigned from untrusted input without an allow-list check. AAK ships
this rule as `provisional` until a public CVE is assigned;
`scripts/refresh_openclaw_status.py` will auto-promote it.

Sanitiser bypass: a call to `assert_role_allowlisted(role)` in the
same function suppresses the rule.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_OPENCLAW_IMPORT_RE = re.compile(
    r"""
    (?:
        from\s+openclaw(?:\.\w+)*\s+import\b
      | import\s+openclaw\b
    )
    """,
    re.VERBOSE,
)
_GUARD_RE = re.compile(r"\bassert_role_allowlisted\s*\(")
_TAINT_HINT_RE = re.compile(
    r"""
    (?:
        \brequest\.(?:json|body|args|form|data|values|files)\b
      | \bawait\s+request\.json\(\)
      | \bos\.environ\b
      | \bsys\.argv\b
      | \bllm_input\b
      | \buser_input\b
    )
    """,
    re.VERBOSE,
)


def _func_body(text: str, node: ast.AST) -> str:
    lines = text.splitlines()
    start = max(0, getattr(node, "lineno", 1) - 1)
    end_lineno = getattr(node, "end_lineno", node.lineno) or node.lineno  # type: ignore[attr-defined]
    end = min(len(lines), end_lineno)
    return "\n".join(lines[start:end])


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _OPENCLAW_IMPORT_RE.search(text):
        return []
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []
    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))

    def _scan_call(call: ast.Call, body: str) -> None:
        callee = ""
        if isinstance(call.func, ast.Attribute):
            callee = call.func.attr
        elif isinstance(call.func, ast.Name):
            callee = call.func.id
        if callee != "OpenClawAgent":
            return
        # Find role kwarg.
        role: ast.AST | None = None
        seen_role = False
        for kw in call.keywords:
            if kw.arg == "role":
                seen_role = True
                role = kw.value
                break
        # Missing role kwarg → fires.
        if not seen_role:
            findings.append(make_finding(
                "AAK-OPENCLAW-PRIVESC-001",
                rel,
                "OpenClawAgent(...) instantiated without `role=` — "
                "default-admin privesc class (IronPlate 2026-04-07).",
                line_number=call.lineno,
            ))
            return
        # role=None / role=untrusted → fires unless guard present.
        if isinstance(role, ast.Constant) and role.value is None:
            findings.append(make_finding(
                "AAK-OPENCLAW-PRIVESC-001",
                rel,
                "OpenClawAgent(role=None) — empty role escalates to "
                "admin in vulnerable OpenClaw versions.",
                line_number=call.lineno,
            ))
            return
        if not isinstance(role, ast.Constant):
            if _GUARD_RE.search(body):
                return
            if _TAINT_HINT_RE.search(body):
                findings.append(make_finding(
                    "AAK-OPENCLAW-PRIVESC-001",
                    rel,
                    "OpenClawAgent(role=...) takes a non-constant role "
                    "from an untrusted source without "
                    "assert_role_allowlisted(role). IronPlate-cited "
                    "CVSS 9.9 privesc class.",
                    line_number=call.lineno,
                ))

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            body = _func_body(text, node)
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    _scan_call(child, body)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            body = _func_body(text, node)
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    _scan_call(child, body)
            self.generic_visit(node)

        def visit_Module(self, node: ast.Module) -> None:
            # Scan module-level calls too (the most common privesc shape).
            body = text
            for child in node.body:
                for inner in ast.walk(child):
                    if isinstance(inner, ast.Call):
                        _scan_call(inner, body)
            self.generic_visit(node)

    V().visit(tree)
    if findings:
        scanned.add(rel)
    # Deduplicate by line — module-level + function visitor double-counts.
    seen: set[int] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = f.line_number or 0
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_walk_python(text, path, project_root, scanned))
    return findings, scanned
