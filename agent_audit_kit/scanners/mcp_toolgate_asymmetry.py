"""MCP tool-gate enforcement-asymmetry scanner — CVE-2026-46519 class.

Flags an MCP server that gates tools by an allowlist / read-only /
non-destructive control and applies that check in the **discovery** handler
(`tools/list` / `list_tools` / `ListToolsRequestSchema`) but NOT in the
**execution** handler (`tools/call` / `call_tool` / `CallToolRequestSchema`).
A client that calls a hidden tool name directly then bypasses the gate.

CVE-2026-46519: mcp-server-kubernetes < 3.6.0 documented three env vars as
access controls but enforced them only at the discovery layer (CWE-863
Incorrect Authorization, CVSS 8.8).

This is an **enforcement-layer asymmetry**. It is deliberately distinct from
``AAK-MCPWN-001`` (a transport-middleware *route* asymmetry, `/mcp_message`
vs `/mcp`, CVE-2026-33032) and from ``mcp_stateless_migration`` (session/
caching smells). Python is analysed with stdlib ``ast`` (precise per-handler
bodies); TS/JS uses region-sliced regex.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding, SKIP_DIRS

_RULE_ID = "AAK-MCP-TOOLGATE-ASYMMETRY-001"

# An allowlist / read-only / non-destructive gating control. Matched against
# identifier names AND string literals (env keys), case-insensitive so both
# UPPER_SNAKE env vars and camelCase config keys are covered.
_GATE_RE = re.compile(
    r"allowed[_-]?tools"
    r"|allow[_-]?only"
    r"|read[_-]?only"
    r"|readonly"
    r"|non[_-]?destructive"
    r"|destructive[_-]?tools"
    r"|disable[_-]?destructive",
    re.IGNORECASE,
)

# An MCP server file must reference the protocol at all (import gate / markers).
_MCP_HINT_RE = re.compile(
    r"\bmcp\b|modelcontextprotocol|McpServer|FastMCP|\bServer\s*\(|"
    r"ListToolsRequestSchema|CallToolRequestSchema|list_tools|call_tool",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Python (AST)
# ---------------------------------------------------------------------------


def _decorator_names(fn: ast.AST) -> list[str]:
    out: list[str] = []
    for dec in getattr(fn, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute):
            out.append(target.attr)
        elif isinstance(target, ast.Name):
            out.append(target.id)
    return out


def _classify(fn: ast.AST) -> str | None:
    """Return 'discovery', 'exec', or None for a function node."""
    name = getattr(fn, "name", "").lower()
    tokens = [name, *(_d.lower() for _d in _decorator_names(fn))]
    blob = " ".join(tokens)
    if any(m in blob for m in ("list_tools", "listtools")):
        return "discovery"
    if any(m in blob for m in ("call_tool", "calltool", "dispatch_tool",
                               "execute_tool", "run_tool", "invoke_tool")):
        return "exec"
    return None


def _gate_in_body(fn: ast.AST) -> bool:
    """True if a gate control is referenced anywhere in the function body —
    as an identifier (Name/Attribute) or a string literal (env key)."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and _GATE_RE.search(node.id):
            return True
        if isinstance(node, ast.Attribute) and _GATE_RE.search(node.attr):
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _GATE_RE.search(node.value):
                return True
    return False


def _scan_python(text: str) -> bool:
    """Return True if a discovery-gated-but-not-exec-gated asymmetry is found."""
    if not _MCP_HINT_RE.search(text):
        return False
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False

    discovery_gated = False
    exec_funcs = 0
    exec_gated = False
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        kind = _classify(node)
        if kind == "discovery" and _gate_in_body(node):
            discovery_gated = True
        elif kind == "exec":
            exec_funcs += 1
            if _gate_in_body(node):
                exec_gated = True

    return discovery_gated and exec_funcs > 0 and not exec_gated


# ---------------------------------------------------------------------------
# TS / JS (region-sliced regex)
# ---------------------------------------------------------------------------

# Matches the start of a request-handler registration or a named handler so we
# can slice the source into per-handler regions.
_HANDLER_START_RE = re.compile(
    r"setRequestHandler\s*\(\s*(ListTools|CallTools?|CallTool)RequestSchema"
    r"|\b(list_tools|listTools|call_tool|callTool)\b"
    r"|[\"'](tools/list|tools/call)[\"']",
    re.IGNORECASE,
)


def _region_kind(marker: str) -> str | None:
    m = marker.lower()
    if "listtools" in m or "list_tools" in m or "tools/list" in m:
        return "discovery"
    if "calltool" in m or "call_tool" in m or "tools/call" in m:
        return "exec"
    return None


_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _strip_ts_comments(text: str) -> str:
    """Remove block + line comments so a comment mentioning the gate word
    (e.g. ``// TODO: add readOnly check``) cannot mask the asymmetry."""
    text = _TS_BLOCK_COMMENT_RE.sub(" ", text)
    text = _TS_LINE_COMMENT_RE.sub(" ", text)
    return text


def _scan_ts(text: str) -> bool:
    if not _MCP_HINT_RE.search(text):
        return False
    text = _strip_ts_comments(text)
    starts = list(_HANDLER_START_RE.finditer(text))
    if not starts:
        return False

    discovery_gated = False
    exec_regions = 0
    exec_gated = False
    for i, m in enumerate(starts):
        kind = _region_kind(m.group(0))
        if kind is None:
            continue
        region_end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        region = text[m.start():region_end]
        gated = bool(_GATE_RE.search(region))
        if kind == "discovery" and gated:
            discovery_gated = True
        elif kind == "exec":
            exec_regions += 1
            if gated:
                exec_gated = True

    return discovery_gated and exec_regions > 0 and not exec_gated


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for MCP tool-gate enforcement asymmetry (CVE-2026-46519 class).

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

        if path.suffix in _PY_SUFFIXES:
            asymmetric = _scan_python(text)
        else:
            asymmetric = _scan_ts(text)

        if not asymmetric:
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                "MCP tool gate (allowlist / read-only / non-destructive) is "
                "applied in the tools/list discovery handler but absent from "
                "the tools/call execution handler — a direct call to a hidden "
                "tool bypasses it. Enforce the same check in the call path "
                "(CVE-2026-46519, CWE-863)."
            ),
            None,
        ))

    return findings, scanned_files
