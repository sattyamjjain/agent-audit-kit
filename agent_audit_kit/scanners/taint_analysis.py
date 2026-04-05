from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

# ---- Tool decorator names to recognise ----
_TOOL_DECORATORS: frozenset[str] = frozenset({
    "tool",
    "mcp.tool",
    "server.tool",
    "langchain.tools.tool",
    "crewai.tool",
    "autogen.tool",
})

# ---- Dangerous sink categories, keyed by rule ID ----
#
# Each entry maps a rule ID to a set of (module_or_none, function_name) tuples.
# module_or_none is ``None`` for builtins, otherwise the dotted module prefix.
_SINKS: dict[str, set[tuple[str | None, str]]] = {
    "AAK-TAINT-001": {
        ("os", "system"),
        ("os", "popen"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "Popen"),
        ("subprocess", "check_output"),
        ("subprocess", "check_call"),
    },
    "AAK-TAINT-002": {
        (None, "eval"),
        (None, "exec"),
        (None, "compile"),
    },
    "AAK-TAINT-003": {
        (None, "open"),
        ("pathlib", "Path"),
    },
    "AAK-TAINT-004": {
        ("requests", "get"),
        ("requests", "post"),
        ("requests", "put"),
        ("requests", "delete"),
        ("urllib.request", "urlopen"),
        ("httpx", "get"),
        ("httpx", "post"),
    },
    "AAK-TAINT-005": {
        ("cursor", "execute"),
        ("connection", "execute"),
        ("session", "execute"),
    },
    "AAK-TAINT-006": {
        ("pickle", "loads"),
        ("pickle", "load"),
        ("yaml", "load"),
        ("yaml", "unsafe_load"),
        ("marshal", "loads"),
    },
}

# Flat lookup: (module_or_none, func_name) -> rule_id
_SINK_LOOKUP: dict[tuple[str | None, str], str] = {}
for _rule_id, _sink_set in _SINKS.items():
    for _sink in _sink_set:
        _SINK_LOOKUP[_sink] = _rule_id


def _get_decorator_name(decorator: ast.expr) -> str:
    """Extract the full dotted name from a decorator node.

    Handles:
      - ``@tool``                -> "tool"
      - ``@mcp.tool``           -> "mcp.tool"
      - ``@server.tool()``      -> "server.tool"
      - ``@langchain.tools.tool`` -> "langchain.tools.tool"
    """
    node = decorator
    # Unwrap Call nodes: @tool() -> tool, @server.tool() -> server.tool
    if isinstance(node, ast.Call):
        node = node.func

    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    parts.reverse()
    return ".".join(parts)


def _is_tool_function(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function is decorated with a recognised tool decorator."""
    for deco in func_def.decorator_list:
        name = _get_decorator_name(deco)
        if name in _TOOL_DECORATORS:
            return True
    return False


def _get_param_names(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Collect all parameter names from a function definition (excluding ``self`` / ``cls``)."""
    names: set[str] = set()
    args = func_def.args
    for arg in args.args + args.posonlyargs + args.kwonlyargs:
        if arg.arg not in ("self", "cls"):
            names.add(arg.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _resolve_callee(node: ast.Call) -> tuple[str | None, str] | None:
    """Resolve a Call node to (module_or_none, func_name).

    Returns None if the callee cannot be resolved to a known pattern.
    Handles:
      - eval(...)                 -> (None, "eval")
      - os.system(...)            -> ("os", "system")
      - subprocess.run(...)       -> ("subprocess", "run")
      - cursor.execute(...)       -> ("cursor", "execute")
      - pathlib.Path(...)         -> ("pathlib", "Path")
    """
    func = node.func

    if isinstance(func, ast.Name):
        # Simple name: eval, exec, compile, open
        return (None, func.id)

    if isinstance(func, ast.Attribute):
        # Single-level attribute: os.system, cursor.execute
        if isinstance(func.value, ast.Name):
            return (func.value.id, func.attr)
        # Two-level attribute: urllib.request.urlopen, langchain.tools.tool
        if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            module = f"{func.value.value.id}.{func.value.attr}"
            return (module, func.attr)

    return None


def _call_uses_param(call_node: ast.Call, param_names: set[str]) -> bool:
    """Return True if any positional or keyword argument is a bare Name matching a parameter."""
    for arg in call_node.args:
        if isinstance(arg, ast.Name) and arg.id in param_names:
            return True
        # Also check starred args: *args
        if isinstance(arg, ast.Starred) and isinstance(arg.value, ast.Name) and arg.value.id in param_names:
            return True
    for kw in call_node.keywords:
        if isinstance(kw.value, ast.Name) and kw.value.id in param_names:
            return True
    return False


def _has_any_type_hints(func_def: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if at least one parameter (excluding self/cls) has a type annotation."""
    args = func_def.args
    for arg in args.args + args.posonlyargs + args.kwonlyargs:
        if arg.arg in ("self", "cls"):
            continue
        if arg.annotation is not None:
            return True
    return False


def _analyse_tool_function(
    func_def: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_path: str,
) -> list[Finding]:
    """Perform taint analysis on a single @tool function."""
    findings: list[Finding] = []
    param_names = _get_param_names(func_def)
    func_name = func_def.name

    # Track which rule categories have dangerous sinks (for AAK-TAINT-008)
    triggered_categories: set[str] = set()

    # Walk function body for Call nodes
    for node in ast.walk(func_def):
        if not isinstance(node, ast.Call):
            continue

        callee = _resolve_callee(node)
        if callee is None:
            continue

        rule_id = _SINK_LOOKUP.get(callee)
        if rule_id is None:
            continue

        # Track category regardless of param taint
        triggered_categories.add(rule_id)

        # Check if any argument is a tainted parameter
        if param_names and _call_uses_param(node, param_names):
            sink_label = f"{callee[0]}.{callee[1]}" if callee[0] else callee[1]
            line = getattr(node, "lineno", func_def.lineno)
            findings.append(make_finding(
                rule_id,
                rel_path,
                f"Function '{func_name}': param flows to {sink_label}()",
                line,
            ))

    # AAK-TAINT-007: No type hints on any parameter
    if param_names and not _has_any_type_hints(func_def):
        findings.append(make_finding(
            "AAK-TAINT-007",
            rel_path,
            f"Function '{func_name}': no type hints on any parameter",
            func_def.lineno,
        ))

    # AAK-TAINT-008: >= 3 different dangerous sink categories in the body
    if len(triggered_categories) >= 3:
        cats = ", ".join(sorted(triggered_categories))
        findings.append(make_finding(
            "AAK-TAINT-008",
            rel_path,
            f"Function '{func_name}': {len(triggered_categories)} dangerous sink categories ({cats})",
            func_def.lineno,
        ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan Python files for taint flows in @tool functions.

    Algorithm:
        1. Recursively find .py files (skip SKIP_DIRS, skip files > 1 MB).
        2. Parse each file with ``ast.parse``.
        3. Walk AST for FunctionDef / AsyncFunctionDef with tool decorators.
        4. For each tool function, collect parameter names and walk the body
           for calls to dangerous sinks that receive a parameter directly.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for py_path in project_root.rglob("*.py"):
        # Skip excluded directories
        try:
            rel_parts = py_path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not py_path.is_file():
            continue

        # Skip large files
        try:
            if py_path.stat().st_size > 1_000_000:
                continue
            source = py_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_path = str(py_path.relative_to(project_root))

        # Parse AST
        try:
            tree = ast.parse(source, filename=rel_path)
        except SyntaxError:
            continue

        scanned_files.add(rel_path)

        # Walk top-level and nested function definitions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _is_tool_function(node):
                    findings.extend(_analyse_tool_function(node, rel_path))

    return findings, scanned_files
