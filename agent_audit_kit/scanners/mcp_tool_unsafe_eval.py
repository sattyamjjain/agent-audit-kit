"""MCP tool handler unsafe-eval AST detector.

Generalizes v0.3.18's `AAK-MCPCALC-CVE-2026-44717-PIN-001` (pin-arm
only) to catch the architectural class: any Python function decorated
as an MCP tool (`@mcp.tool`, `@server.tool`, `@app.tool`,
`@fastmcp.tool`) that routes a parameter through `eval()`, `exec()`,
`compile()`, `__import__()`, or `sympy.parsing.sympy_parser.parse_expr`
without `local_dict` / `global_dict` pinning.

This is the source-side companion to the named pin row. The pin rule
catches consumers of one specific upstream (`mcp-calculate-server`);
this rule catches anyone with the same shape — single-author MCP
servers, in-house tools, fork-and-modify deployments, etc.

Trigger anchor: CVE-2026-44717 disclosure (NVD 2026-05-15) showed the
shape is realistic in production single-author MCP servers; this
generalization closes the "rule fires only when you grep CHANGELOG.cves
for our specific package name" gap.

Detector contract:
    scan(project_root) -> (list[Finding], set[str])
"""
from __future__ import annotations

import ast
from pathlib import Path

from agent_audit_kit.models import Category, Finding, Severity


_MCP_TOOL_DECORATOR_NAMES: frozenset[str] = frozenset({
    "tool",            # @mcp.tool / @server.tool / @app.tool / @fastmcp.tool — bare-attribute form
    "add_tool",        # server.add_tool(fn) wrappers (less common, handled separately)
})

_UNSAFE_CALL_NAMES: frozenset[str] = frozenset({
    "eval",
    "exec",
    "compile",
    "__import__",
})


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    """Match @mcp.tool / @server.tool / @app.tool / @fastmcp.tool /
    @tool (bare-name) / @something.tool(...) call forms."""
    if isinstance(decorator, ast.Name) and decorator.id == "tool":
        return True
    if isinstance(decorator, ast.Attribute) and decorator.attr in _MCP_TOOL_DECORATOR_NAMES:
        return True
    if isinstance(decorator, ast.Call):
        return _is_mcp_tool_decorator(decorator.func)
    return False


def _function_param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Collect all positional / keyword / vararg / kwarg parameter names."""
    names: set[str] = set()
    args = fn.args
    for a in args.posonlyargs + args.args + args.kwonlyargs:
        names.add(a.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


class _UnsafeEvalVisitor(ast.NodeVisitor):
    """Walks a function body for unsafe eval-shaped calls whose
    arguments are tainted by the function's parameter set."""

    def __init__(self, tainted: set[str]) -> None:
        self.tainted = tainted
        self.findings: list[tuple[int, str, str]] = []  # (lineno, call_name, evidence)

    def visit_Call(self, node: ast.Call) -> None:
        # Direct unsafe call shape: eval(x) / exec(x) / compile(x, ...)
        # / __import__(x). Also matches sympy.parsing.sympy_parser.parse_expr
        # below as an attribute-call shape.
        func_name = self._call_name(node.func)
        if func_name in _UNSAFE_CALL_NAMES:
            tainted_arg = self._first_tainted_arg(node)
            if tainted_arg is not None:
                self.findings.append((
                    node.lineno,
                    func_name,
                    f"{func_name}({tainted_arg!r}) where {tainted_arg!r} is a tool parameter",
                ))
        # SymPy parse_expr without local_dict / global_dict pin.
        elif func_name == "parse_expr":
            tainted_arg = self._first_tainted_arg(node)
            has_local_dict = any(kw.arg == "local_dict" for kw in node.keywords)
            has_global_dict = any(kw.arg == "global_dict" for kw in node.keywords)
            if tainted_arg is not None and not (has_local_dict and has_global_dict):
                self.findings.append((
                    node.lineno,
                    "parse_expr",
                    f"parse_expr({tainted_arg!r}) without local_dict + global_dict pinning",
                ))
        self.generic_visit(node)

    def _call_name(self, expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            return expr.attr
        return None

    def _first_tainted_arg(self, call: ast.Call) -> str | None:
        for a in call.args:
            if isinstance(a, ast.Name) and a.id in self.tainted:
                return a.id
        return None


def _scan_python_file(path: Path, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    if "@mcp.tool" not in src and "@server.tool" not in src and "@app.tool" not in src \
            and "@fastmcp.tool" not in src and "@tool" not in src:
        return findings
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_mcp_tool_decorator(d) for d in node.decorator_list):
            continue
        tainted = _function_param_names(node)
        if not tainted:
            continue
        visitor = _UnsafeEvalVisitor(tainted)
        for child in node.body:
            visitor.visit(child)
        for lineno, _call_name, evidence in visitor.findings:
            findings.append(Finding(
                rule_id="AAK-MCP-TOOL-UNSAFE-EVAL-001",
                title="Unsafe eval()/exec()/compile() inside @mcp.tool handler",
                description=(
                    "An MCP tool handler routes a tool-parameter value through "
                    "`eval()`, `exec()`, `compile()`, `__import__()`, or SymPy "
                    "`parse_expr()` without `local_dict` / `global_dict` "
                    "pinning. This is the architectural class behind "
                    "CVE-2026-44717 (mcp-calculate-server) and generalizes to "
                    "any single-author MCP server with the same shape — see "
                    "AAK-MCPCALC-CVE-2026-44717-PIN-001 for the named-product "
                    "pin row that v0.3.18 shipped."
                ),
                severity=Severity.CRITICAL,
                category=Category.TOOL_POISONING,
                file_path=rel,
                line_number=lineno,
                evidence=evidence,
                remediation=(
                    "Replace `eval(expr)` with `ast.literal_eval(expr)` for "
                    "trusted-literal inputs, or with SymPy "
                    "`parse_expr(expr, local_dict={}, global_dict={}, "
                    "evaluate=True)` and a strict symbol allow-list for math. "
                    "Validate input length + char-set before evaluation."
                ),
                cve_references=["CVE-2026-44717"],
                owasp_mcp_references=["MCP01:2025", "MCP05:2025"],
                owasp_agentic_references=["ASI02", "ASI05"],
                incident_references=["NVD-CVE-2026-44717"],
            ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    skip_dirs = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__"}
    for path in project_root.rglob("*.py"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        rel = str(path.relative_to(project_root))
        fires = _scan_python_file(path, rel)
        if fires:
            scanned.add(rel)
            findings.extend(fires)
    return findings, scanned


__all__ = ["scan"]
