"""Ox MCP STDIO command-injection scanner (AAK-STDIO-001).

Fires when user-controlled input flows into a shell-style executor
inside an MCP server implementation. This is the architectural shape
the Ox Security April-16 2026 disclosure traced through **10 CVEs and
200,000+ exposed servers**:

    ┌──────────────┐      ┌────────────────────────────┐      ┌─────────┐
    │  MCP tool    │─────▶│ StdioServerParameters /    │─────▶│  shell  │
    │  caller      │ args │ subprocess.*(shell=True)   │      │  exec   │
    └──────────────┘      └────────────────────────────┘      └─────────┘

References:
- Ox disclosure (Apr 16 2026):
  https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/
- Windsurf RCE (2026-04-15): https://nvd.nist.gov/vuln/detail/CVE-2026-30615
- Associated CVEs: CVE-2025-65720, CVE-2026-30617, CVE-2026-30618,
  CVE-2026-30623, CVE-2026-30624, CVE-2026-30625, CVE-2026-33224,
  CVE-2026-26015.

Python side: AST walk. We look for MCP-server hint files (modules that
register @tool or import StdioServerParameters) and flag every
`subprocess.*` / `os.system` / `os.popen` / `exec` / `eval` call whose
args reference a taint source: `request.params`, `stdin`, `sys.stdin`,
`json.loads(...)` wrapped around stdin, `StdioServerParameters`
construction, or a parameter of a `@tool`-decorated function.

TS/JS side: regex on `.ts` / `.tsx` / `.js` / `.mjs` files that hint at
MCP server code; matches on `child_process.spawn` / `execa` / `exec`
with `shell: true` plus a request-body interpolation.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_PY_EXTS = {".py"}
_JS_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs"}
_MAX_FILE_BYTES = 512_000


_PY_MCP_HINT_RE = re.compile(
    r"\b(?:StdioServerParameters|FastMCP|@tool|McpServer|Server\.run_streamable_http|mcp\.server)\b"
)

# Taint sources: things that make an argument "attacker-controlled" in the
# Ox threat model.
_TAINT_NAME = frozenset({
    "stdin", "request", "req", "event", "params", "tool_input",
    "input_data", "args", "payload",
})
_TAINT_ATTR_CHAINS = {
    ("request", "params"),
    ("request", "body"),
    ("request", "json"),
    ("req", "body"),
    ("req", "json"),
    ("req", "query"),
    ("event", "body"),
    ("sys", "stdin"),
    ("process", "stdin"),
}

_DANGEROUS_CALLS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_call", "subprocess.check_output",
    "os.system", "os.popen", "os.exec", "os.execv", "os.execvp",
    "commands.getoutput", "commands.getstatusoutput",
    "eval", "exec",
}


def _iter_python_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _iter_js_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _JS_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _call_fqn(func: ast.expr) -> str:
    """Resolve `foo.bar.baz(...)` → 'foo.bar.baz' (best-effort)."""
    parts: list[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _node_references_taint(node: ast.AST) -> bool:
    """Return True if an AST subtree references any known taint source."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in _TAINT_NAME:
            return True
        if isinstance(sub, ast.Attribute):
            chain = []
            cur: ast.expr = sub
            while isinstance(cur, ast.Attribute):
                chain.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                chain.append(cur.id)
                chain = list(reversed(chain))
                for length in range(2, len(chain) + 1):
                    if tuple(chain[: length][-2:]) in _TAINT_ATTR_CHAINS:
                        return True
                    # Match (prefix[-2], prefix[-1]) windows.
                # fall through
            # check "sys.stdin.read()" etc.
            if isinstance(cur, ast.Name) and len(chain) >= 2:
                if (chain[-2], chain[-1]) in _TAINT_ATTR_CHAINS:
                    return True
        if isinstance(sub, ast.Call):
            fqn = _call_fqn(sub.func)
            if fqn == "json.loads":
                # json.loads(stdin.read()) — tainted.
                for arg in sub.args:
                    if _node_references_taint(arg):
                        return True
    return False


def _python_hint_match(text: str) -> bool:
    return bool(_PY_MCP_HINT_RE.search(text))


def _check_python_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not _python_hint_match(text):
        return []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        return []

    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))

    # Track parameters of @tool-decorated functions as taint sources.
    tool_params: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = [
                (_call_fqn(d) if isinstance(d, ast.Call) else _call_fqn(d))
                for d in node.decorator_list
            ]
            if any(dec.endswith("tool") or dec.endswith(".tool") for dec in decorators):
                tool_params.update(arg.arg for arg in node.args.args)
                tool_params.update(arg.arg for arg in node.args.kwonlyargs)

    taint_names_in_file = set(_TAINT_NAME) | tool_params

    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        fqn = _call_fqn(call.func)
        if not fqn:
            continue
        if fqn not in _DANGEROUS_CALLS and fqn.split(".")[-1] not in {
            "system", "popen", "exec", "eval", "run", "Popen", "call", "check_call", "check_output",
        }:
            continue

        # For subprocess.*, only fire if shell=True OR the first arg is a
        # dynamic expression. For os.system / os.popen / exec / eval we
        # always fire when tainted.
        is_subprocess = fqn.startswith("subprocess.")
        shell_true = False
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                shell_true = True

        def _args_reference_taint() -> bool:
            for arg in call.args:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name) and sub.id in taint_names_in_file:
                        return True
                    if _node_references_taint(sub):
                        return True
            return False

        if is_subprocess and not shell_true and not _args_reference_taint():
            continue
        if not _args_reference_taint():
            continue

        snippet = ast.unparse(call) if hasattr(ast, "unparse") else fqn
        findings.append(
            make_finding(
                "AAK-STDIO-001",
                rel,
                f"STDIO command injection path: {snippet[:200]!r}"
                + (" (shell=True)" if shell_true else ""),
                line_number=call.lineno,
            )
        )

    return findings


# ---- TS / JS side ----

_JS_MCP_HINT_RE = re.compile(
    r"\b(?:StdioServerParameters|createServer|McpServer|@tool|stdio\s*:|mcp\.server)\b",
    re.IGNORECASE,
)

_JS_SHELL_TRUE_RE = re.compile(
    r"""(?:child_process\.)?(?:spawn|exec|execFile|execa)\s*\(
        [^)]*?
        \{\s*[^}]*?\bshell\s*:\s*true\b
    """,
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

_JS_DYNAMIC_CMD_RE = re.compile(
    r"""(?:child_process\.)?(?:spawn|exec|execFile|execa)\s*\(\s*
        (?:`[^`]*\$\{[^}]*(?:req|request|body|params|event|stdin|tool_input)[^`]*`
         |\s*[\"'][^\"']*[\"']\s*\+\s*\w*(?:req|request|body|params|event|stdin|tool_input)
         |\s*\w+(?:\.\w+)*(?:req|request|body|params|event|stdin|tool_input)
         )""",
    re.IGNORECASE | re.VERBOSE,
)


def _check_js_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not _JS_MCP_HINT_RE.search(text):
        return []
    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))

    for match in _JS_SHELL_TRUE_RE.finditer(text):
        findings.append(
            make_finding(
                "AAK-STDIO-001",
                rel,
                f"child_process spawn/exec/execa with {{shell: true}} in MCP server: {match.group(0)[:200]!r}",
                line_number=find_line_number(text, match.group(0).splitlines()[0]),
            )
        )

    for match in _JS_DYNAMIC_CMD_RE.finditer(text):
        findings.append(
            make_finding(
                "AAK-STDIO-001",
                rel,
                f"child_process invocation with request-derived command: {match.group(0)[:200]!r}",
                line_number=find_line_number(text, match.group(0).splitlines()[0]),
            )
        )

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_python_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_python_file(path, project_root))
    for path in _iter_js_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_js_file(path, project_root))
    return findings, scanned
