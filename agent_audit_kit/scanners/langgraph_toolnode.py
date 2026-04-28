"""AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001 — ToolNode positional list misuse.

LangGraph prebuilt 1.0.11 (2026-04-24) regressed: `ToolNode` no
longer accepts a bare list and silently coerces single tools, leading
to lost-call and message-loop bugs. Fires when source uses
`ToolNode([...])` (positional list) instead of `ToolNode(tools=[...])`.

Restricted to imports from `langgraph.prebuilt.ToolNode` to avoid
matching unrelated `ToolNode` subclasses.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_TOOLNODE_IMPORT_RE = re.compile(
    r"""
    (?:
        from\s+langgraph\.prebuilt\s+import[^\n]*\bToolNode\b
      | from\s+langgraph\s+import\s+prebuilt
      | import\s+langgraph\.prebuilt
    )
    """,
    re.VERBOSE,
)


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _TOOLNODE_IMPORT_RE.search(text):
        return []
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []
    findings: list[Finding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            callee = ""
            if isinstance(node.func, ast.Name):
                callee = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callee = node.func.attr
            if callee != "ToolNode":
                self.generic_visit(node)
                return
            # Safe shape: ToolNode(tools=[...]) or ToolNode(tools_by_name=...)
            kwarg_names = {kw.arg for kw in node.keywords if kw.arg}
            if "tools" in kwarg_names or "tools_by_name" in kwarg_names:
                self.generic_visit(node)
                return
            # Vulnerable shape: positional argument that is a List or Name resolving to a list.
            if not node.args:
                self.generic_visit(node)
                return
            first = node.args[0]
            is_list_like = isinstance(first, (ast.List, ast.Name))
            if not is_list_like:
                self.generic_visit(node)
                return
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            findings.append(make_finding(
                "AAK-LANGGRAPH-TOOLNODE-LIST-REGRESSION-001",
                rel,
                "ToolNode(...) called with a positional list argument. "
                "langgraph.prebuilt 1.0.11 silently coerces this; "
                "switch to `ToolNode(tools=[...])`.",
                line_number=node.lineno,
            ))
            self.generic_visit(node)

    V().visit(tree)
    return findings


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
