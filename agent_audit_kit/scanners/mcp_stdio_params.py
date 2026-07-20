"""AAK-MCP-STDIO-CMD-INJ-001..004 — config-to-spawn taint for the OX class.

The April 2026 OX MCP advisory hub aggregated 8 CVEs (CVE-2026-30615,
30617, 30623, 22252, 22688, 33224, 40933, 6980) under a single
architectural class: the upstream MCP SDK exposes a
`StdioServerParameters(command=, args=)` API that *executes whatever
you pass*. Downstream agents that build the params from
network-controlled input (a request body, a fetched marketplace
manifest, an env var fed by an HTTP webhook) inherit the bug.

This scanner is the SDK-named-API counterpart to the broader
AAK-STDIO-001 sink-pattern detector. Where AAK-STDIO-001 fires on any
`subprocess.run(shell=True, ..., tainted)` shape, this scanner fires
*specifically* on `StdioServerParameters(command=tainted)` (Python),
`new StdioClientTransport({command, args})` (TS),
`StdioServerParameters.Builder().command(tainted)` (Java), and
`tokio::process::Command::new(tainted)` adjacent to MCP imports
(Rust). Cross-link the two from descriptions; do not collapse.

Rules emitted:

- AAK-MCP-STDIO-CMD-INJ-001 — language=python (AST)
- AAK-MCP-STDIO-CMD-INJ-002 — language=typescript (regex+AST hybrid)
- AAK-MCP-STDIO-CMD-INJ-003 — language=java (regex)
- AAK-MCP-STDIO-CMD-INJ-004 — language=rust (regex; ~10% FP rate
  on heavy macro use until #22 lands tree-sitter-rust)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


# ---------------------------------------------------------------------------
# Python — AAK-MCP-STDIO-CMD-INJ-001
# ---------------------------------------------------------------------------


_PY_TAINT_MODULES_RE = re.compile(
    r"""
    (?:
        \brequest\.(?:json|form|args|data|values|headers|files)\b
      | \bflask\.request\.\w+\b
      | \bfastapi\.Request\.\w+
      | \bstarlette\.requests\.Request\.\w+
      | \brequests\.(?:get|post|put|delete)\([^)]*\)\s*\.(?:json|text)\(\)
      | \bhttpx\.(?:get|post|put|delete)\([^)]*\)\s*\.(?:json|text)\(\)
      | \burllib\.request\.urlopen\(
      | \bos\.environ\b
      | \bjson\.loads\b
      | \byaml\.safe_load\b
      | \byaml\.load\b
    )
    """,
    re.VERBOSE,
)


def _attr_chain(node: ast.AST) -> str:
    """Return a dotted form of an Attribute / Name chain ('a.b.c')."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            break
    return ".".join(reversed(parts))


def _is_stdio_server_params_call(call: ast.Call) -> bool:
    chain = _attr_chain(call.func)
    if not chain:
        return False
    # Match `StdioServerParameters(...)` directly or as `mcp.client.stdio.StdioServerParameters`
    return chain.split(".")[-1] == "StdioServerParameters"


# Function parameters whose *name* strongly implies untrusted, network-shaped
# input. Deliberately excludes generic names like `config`/`data` (a config
# object is normally trusted) so we don't fire on every builder function.
_SUSPICIOUS_PARAMS = frozenset(
    {"body", "payload", "req", "request", "event", "untrusted", "user_input"}
)


def _is_static(node: ast.AST) -> bool:
    """True if the expression is a compile-time-constant literal."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_static(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (k is None or _is_static(k)) and _is_static(v)
            for k, v in zip(node.keys, node.values)
        )
    return False


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - unparse is available on 3.9+
        return ""


def _command_arg_exprs(call: ast.Call) -> list[ast.expr]:
    """The `command=` / `args=` expressions of a StdioServerParameters call.

    Positionally, StdioServerParameters(command, args, env, ...) — so arg 0 is
    command and arg 1 is args.
    """
    exprs: list[ast.expr] = []
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    if "command" in kw:
        exprs.append(kw["command"])
    elif call.args:
        exprs.append(call.args[0])
    if "args" in kw:
        exprs.append(kw["args"])
    elif len(call.args) > 1:
        exprs.append(call.args[1])
    return exprs


def _taint_flows_to_command(
    call: ast.Call, func: ast.FunctionDef | ast.AsyncFunctionDef
) -> bool:
    """True only when the `command`/`args` fed to StdioServerParameters is a
    dynamic value that traces back to a network-controlled source — a real
    source→sink path, not merely 'a taint marker appears somewhere in the
    function'. Constant command/args (allow-lists, literals) never fire."""
    exprs = _command_arg_exprs(call)
    if not exprs or all(_is_static(e) for e in exprs):
        return False

    referenced: set[str] = set()
    for expr in exprs:
        if _PY_TAINT_MODULES_RE.search(_unparse(expr)):
            return True  # e.g. command=request.json()["cmd"] / os.environ[...]
        referenced |= _names_in(expr)

    # A referenced name that is a suspicious *parameter* of this function.
    params = {a.arg for a in func.args.args}
    params |= {a.arg for a in func.args.posonlyargs}
    params |= {a.arg for a in func.args.kwonlyargs}
    if referenced & (params & _SUSPICIOUS_PARAMS):
        return True

    # A referenced name that is locally assigned from a taint expression
    # (`cmd = os.environ[...]` / `body = await request.json()`).
    for stmt in ast.walk(func):
        if isinstance(stmt, ast.Assign):
            targets: set[str] = set()
            for tgt in stmt.targets:
                targets |= _names_in(tgt)
            if targets & referenced and _PY_TAINT_MODULES_RE.search(_unparse(stmt.value)):
                return True
    return False


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
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

        def _scan(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            calls = sorted(
                (n for n in ast.walk(func) if isinstance(n, ast.Call)),
                key=lambda c: (c.lineno, c.col_offset),
            )
            for call in calls:
                if not _is_stdio_server_params_call(call):
                    continue
                # We have StdioServerParameters(command=X, args=Y). Fire only
                # when a network-controlled value actually flows into the
                # command/args sink — not merely because a taint marker or a
                # generically-named arg (`config`, `data`) exists somewhere in
                # the function. Constant command/args never fire.
                if not _taint_flows_to_command(call, func):
                    continue
                rel = str(path.relative_to(project_root))
                scanned.add(rel)
                findings.append(make_finding(
                    "AAK-MCP-STDIO-CMD-INJ-001",
                    rel,
                    f"StdioServerParameters(...) at line {call.lineno} "
                    "is built inside a function that reads from a "
                    "network-controlled source (request body, fetched "
                    "JSON, env var, or untrusted YAML). The OX MCP "
                    "Apr-2026 class lets the resulting `command`/`args` "
                    "be executed verbatim by the SDK.",
                    line_number=call.lineno,
                ))
                return  # one finding per function

    V().visit(tree)
    return findings


# ---------------------------------------------------------------------------
# TypeScript — AAK-MCP-STDIO-CMD-INJ-002
# ---------------------------------------------------------------------------


_TS_STDIO_TRANSPORT_RE = re.compile(
    r"""
    new\s+(?:StdioClientTransport|StdioServerTransport)\s*\(
    """,
    re.VERBOSE,
)
_TS_TAINT_RE = re.compile(
    r"""
    (?:
        req\.(?:body|query|params|headers)\b
      | request\.(?:body|query|params|headers)\b
      | await\s+fetch\s*\([^)]*\)\s*\.(?:then|catch|finally)
      | await\s+axios\s*\.\s*\w+\s*\(
      | process\.env\.[A-Z_][A-Z0-9_]*
      | JSON\.parse\s*\(
    )
    """,
    re.VERBOSE,
)


def _walk_ts(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for m in _TS_STDIO_TRANSPORT_RE.finditer(text):
        # Look at the 1024 chars immediately preceding for a taint marker.
        window_start = max(0, m.start() - 1024)
        window = text[window_start : m.start()]
        if not _TS_TAINT_RE.search(window):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, m.start()) + 1
        findings.append(make_finding(
            "AAK-MCP-STDIO-CMD-INJ-002",
            rel,
            "new StdioClientTransport({...}) is built shortly after a "
            "network-controlled source (req.body / fetch / axios / "
            "process.env / JSON.parse). OX MCP Apr-2026 class.",
            line_number=line,
        ))
        return findings  # one per file is plenty
    return findings


# ---------------------------------------------------------------------------
# Java — AAK-MCP-STDIO-CMD-INJ-003 (regex pass)
# ---------------------------------------------------------------------------


# Match `StdioServerParameters.Builder()` — context window then proves the
# chain calls `.command(...)`/`.args(...)`/`.build()` and is fed by
# tainted input. Avoids regex fighting with nested parens in the chain.
_JAVA_STDIO_BUILDER_RE = re.compile(
    r"StdioServerParameters\s*\.\s*Builder\s*\(\s*\)",
    re.DOTALL,
)
_JAVA_STDIO_TERMINATOR_RE = re.compile(r"\.\s*build\s*\(\s*\)")
_JAVA_TAINT_RE = re.compile(
    r"""
    (?:
        request\s*\.\s*getParameter\s*\(
      | HttpServletRequest\b
      | RestTemplate\s*\.\s*getForObject\s*\(
      | WebClient\s*\.\s*\w+\s*\(\s*\)\s*\.\s*\w+
      | ObjectMapper\s*\.\s*\w+\s*\(\s*[^)]*Network
      | new\s+ObjectMapper\s*\(\s*\)\s*\.\s*readValue\s*\(
      | System\s*\.\s*getenv\s*\(
    )
    """,
    re.VERBOSE,
)


def _walk_java(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for m in _JAVA_STDIO_BUILDER_RE.finditer(text):
        # Require `.build()` somewhere in the next 4KB to confirm chain.
        forward = text[m.end() : m.end() + 4096]
        if not _JAVA_STDIO_TERMINATOR_RE.search(forward):
            continue
        # Look for taint marker either before the Builder() or in the
        # chain itself (e.g. `.args(request.getParameter("args"))`).
        window_start = max(0, m.start() - 2048)
        window = text[window_start : m.start()] + forward
        if not _JAVA_TAINT_RE.search(window):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, m.start()) + 1
        findings.append(make_finding(
            "AAK-MCP-STDIO-CMD-INJ-003",
            rel,
            "StdioServerParameters.Builder().command(...).build() is "
            "built after a network-controlled source (request param, "
            "RestTemplate/WebClient response, ObjectMapper.readValue, "
            "or System.getenv). OX MCP Apr-2026 class.",
            line_number=line,
        ))
        return findings
    return findings


# ---------------------------------------------------------------------------
# Rust — AAK-MCP-STDIO-CMD-INJ-004 (regex pass; FP-prone on macros)
# ---------------------------------------------------------------------------


_RUST_PROCESS_NEW_RE = re.compile(
    r"""
    (?:
        (?:tokio::process|std::process)\s*::\s*Command\s*::\s*new\s*\(
      | \bCommand\s*::\s*new\s*\(           # bare Command::new (when imported via `use`)
    )
    """,
    re.VERBOSE,
)
_RUST_USE_COMMAND_RE = re.compile(
    r"use\s+(?:tokio::process|std::process)::Command\b"
)
_RUST_TAINT_RE = re.compile(
    r"""
    (?:
        reqwest\s*::\s*get\s*\(
      | reqwest\s*::\s*Client
      | serde_json\s*::\s*from_str\s*\(
      | serde_json\s*::\s*from_slice\s*\(
      | std\s*::\s*env\s*::\s*var\s*\(
      | hyper\s*::\s*body
      | actix_web\s*::\s*web\s*::\s*Json
      | axum\s*::\s*extract\s*::\s*Json
    )
    """,
    re.VERBOSE,
)
_RUST_MCP_HINT_RE = re.compile(r"\b(?:mcp_sdk|modelcontextprotocol|mcp::client::stdio)\b")


def _walk_rust(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _RUST_MCP_HINT_RE.search(text):
        return []
    has_use_command = bool(_RUST_USE_COMMAND_RE.search(text))
    findings: list[Finding] = []
    for m in _RUST_PROCESS_NEW_RE.finditer(text):
        # If the match is the bare `Command::new`, require a matching
        # `use ...::process::Command;` somewhere in the file.
        matched_text = m.group(0)
        if matched_text.lstrip().startswith("Command") and not has_use_command:
            continue
        window_start = max(0, m.start() - 2048)
        window = text[window_start : m.start()]
        if not _RUST_TAINT_RE.search(window):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, m.start()) + 1
        findings.append(make_finding(
            "AAK-MCP-STDIO-CMD-INJ-004",
            rel,
            "tokio::process::Command::new(...) is invoked in a file "
            "that imports `mcp_sdk` / `modelcontextprotocol` after a "
            "network-controlled source (reqwest, serde_json, env::var, "
            "hyper/actix/axum body extractors). OX MCP Apr-2026 class. "
            "Note: regex-only pass; expect ~10% FP on macro-heavy code "
            "until #22 lands tree-sitter-rust.",
            line_number=line,
        ))
        return findings
    return findings


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if suffix == ".py":
            findings.extend(_walk_python(text, path, project_root, scanned))
        elif suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            findings.extend(_walk_ts(text, path, project_root, scanned))
        elif suffix == ".java":
            findings.extend(_walk_java(text, path, project_root, scanned))
        elif suffix == ".rs":
            findings.extend(_walk_rust(text, path, project_root, scanned))
    return findings, scanned
