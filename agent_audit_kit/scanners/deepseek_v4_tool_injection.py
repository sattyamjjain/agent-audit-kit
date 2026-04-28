"""AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001 — MoE-routed tool prompt injection.

DeepSeek V4 (Apache 2.0, 2026-04-24) introduces a tool-call envelope
where MoE routing is exposed. Untrusted document text reaching a tool
description can poison routing into a higher-privileged expert. LLM01
class with MoE-specific surface.

Speculative shape per spec — `route_id` envelope behaviour inferred
from V4 release notes. Sanitiser bypass available via
`agent_audit_kit.sanitizers.deepseek.sanitize_tool_description`.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_DEEPSEEK_HINT_RE = re.compile(
    r"""
    (?:
        OpenAI\s*\([^)]*base_url\s*=\s*['"][^'"]*deepseek[^'"]*['"]
      | base_url\s*=\s*['"][^'"]*deepseek[^'"]*['"]
      | from\s+deepseek
      | import\s+deepseek
    )
    """,
    re.VERBOSE,
)
_TAINT_RE = re.compile(
    r"""
    (?:
        \brequest\.(?:json|body|args|form|data|values|files)\b
      | \brequest\s*\.\s*get_json
      | \bflask\.request\.\w+
      | \bfastapi\.Request
      | \bawait\s+request\.json\(\)
      | \bpdfplumber\.open
      | \bunstructured\.partition
      | \bUnstructuredFileLoader
      | \bopen\([^)]*\)\.read\(\)
    )
    """,
    re.VERBOSE,
)
_SANITIZE_RE = re.compile(
    r"""
    (?:
        sanitize_tool_description\s*\(
      | aak\.sanitizers\.deepseek
      | re\.sub\s*\(
    )
    """,
    re.VERBOSE,
)


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _DEEPSEEK_HINT_RE.search(text):
        return []
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []
    findings: list[Finding] = []

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def _scan(self, func: ast.AST) -> None:
            lines = text.splitlines()
            start = max(0, func.lineno - 1)  # type: ignore[attr-defined]
            end_lineno = getattr(func, "end_lineno", func.lineno) or func.lineno  # type: ignore[attr-defined]
            end = min(len(lines), end_lineno)
            body = "\n".join(lines[start:end])
            if not _TAINT_RE.search(body):
                return
            if _SANITIZE_RE.search(body):
                return
            # Look for tools=[{ ... description: <tainted> ... }] passing
            # in an LLM call. Heuristic: presence of `tools=` AND a dict
            # literal with `description` key in the function body.
            if "tools=" not in body and "tools =" not in body:
                return
            if "description" not in body:
                return
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            findings.append(make_finding(
                "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001",
                rel,
                "DeepSeek V4-shaped LLM call passes `tools=[{description: "
                "...}]` in a function that reads from a network / "
                "document source without sanitize_tool_description. "
                "Untrusted text can poison MoE routing.",
                line_number=getattr(func, "lineno", 1),
            ))

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
