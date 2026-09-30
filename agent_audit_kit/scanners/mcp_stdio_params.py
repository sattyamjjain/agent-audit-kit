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
*specifically* on `StdioServerParameters(command=tainted)` (Python) and on a
hand-rolled Python launcher that spawns `shlex.split()` of a stored MCP
server's command with no executable allowlist (CVE-2026-93965),
`new StdioClientTransport({command, args})` (TS),
`StdioServerParameters.Builder().command(tainted)` (Java), and
`tokio::process::Command::new(tainted)` adjacent to MCP imports
(Rust). Cross-link the two from descriptions; do not collapse.

Rules emitted:

- AAK-MCP-STDIO-CMD-INJ-001 — language=python (AST)
- AAK-MCP-STDIO-CMD-INJ-002 — language=typescript (regex+AST hybrid)
- AAK-MCP-STDIO-CMD-INJ-003 — language=java (regex)
- AAK-MCP-STDIO-CMD-INJ-004 — language=rust (regex; ~10% FP rate on
  heavy macro use). No tree-sitter-rust grammar, and none is pending:
  #22 closed 2026-08-15 having shipped a TypeScript slice only.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from . import _ts_stdio_taint
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


# Hand-rolled launcher arm (CVE-2026-93965, SxDevOps). An application that
# stores the MCP servers its users register and starts a STDIO one itself, with
# `subprocess.Popen(shlex.split(server.endpoint_or_command))`, never touches the
# SDK names above, so the SDK arm cannot see it. Same class, same function-local
# posture: the split and the spawn sit in one function, the split reads a stored
# server's `command` field, the function manages MCP STDIO servers (its class,
# its name or its own strings say "MCP" and "stdio"), and nothing between the
# split and the spawn checks the executable against an allowlist.
_PY_SPAWN_CHAINS = frozenset({
    "subprocess.Popen", "subprocess.run", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
    "asyncio.create_subprocess_exec", "Popen", "create_subprocess_exec",
})
_ALLOWLIST_NAME_RE = re.compile(r"allow|permit|whitelist|approved", re.IGNORECASE)


def _spawn_argv(call: ast.Call) -> ast.expr | None:
    """The argv a process-spawn call runs, or None if it is not one."""
    if _attr_chain(call.func) not in _PY_SPAWN_CHAINS:
        return None
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    if "args" in kw:
        return kw["args"]
    if not call.args:
        return None
    first = call.args[0]
    return first.value if isinstance(first, ast.Starred) else first


def _is_shlex_split(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _attr_chain(node.func) == "shlex.split" and bool(node.args)


def _reads_stored_command(node: ast.AST) -> bool:
    """A server record's command field: `server.endpoint_or_command`, `cfg["command"]`."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and "command" in sub.attr.lower():
            return True
        if (
            isinstance(sub, ast.Subscript)
            and isinstance(sub.slice, ast.Constant)
            and isinstance(sub.slice.value, str)
            and "command" in sub.slice.value.lower()
        ):
            return True
    return False


def _split_source(
    call: ast.Call, func: ast.FunctionDef | ast.AsyncFunctionDef
) -> ast.expr | None:
    """What `shlex.split` was applied to, when a spawn's argv is its result.

    Either directly (`Popen(shlex.split(x))`) or through the last local
    assignment before the spawn (`command = shlex.split(x); Popen(command)`). An
    argv assigned from anything else, such as a validator, is not followed:
    that is exactly what the upstream fix looks like.
    """
    argv = _spawn_argv(call)
    if argv is None:
        return None
    if isinstance(argv, ast.Name):
        value: ast.expr | None = None
        for stmt in ast.walk(func):
            if isinstance(stmt, ast.Assign) and stmt.lineno < call.lineno:
                if any(isinstance(t, ast.Name) and t.id == argv.id for t in stmt.targets):
                    if value is None or stmt.lineno > getattr(value, "lineno", 0):
                        value = stmt.value
            elif isinstance(stmt, ast.AnnAssign) and stmt.lineno < call.lineno:
                if isinstance(stmt.target, ast.Name) and stmt.target.id == argv.id and stmt.value is not None:
                    if value is None or stmt.lineno > getattr(value, "lineno", 0):
                        value = stmt.value
        argv = value
    if not isinstance(argv, ast.Call) or not _is_shlex_split(argv):
        return None
    source = argv.args[0]
    if _is_static(source) or not _reads_stored_command(source):
        return None
    return source


def _manages_mcp_stdio(func: ast.FunctionDef | ast.AsyncFunctionDef, class_name: str) -> bool:
    words = [class_name, func.name]
    words += [
        n.value for n in ast.walk(func)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]
    blob = " ".join(words).lower()
    return "mcp" in blob and "stdio" in blob


def _checks_an_allowlist(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """`if command[0] not in ALLOWED_EXECUTABLES:` and its kin, inside the function."""
    for node in ast.walk(func):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            continue
        for side in (node.left, *node.comparators):
            if _ALLOWLIST_NAME_RE.search(_attr_chain(side)):
                return True
    return False


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    try:
        tree = ast.parse(text, str(path))
    except SyntaxError:
        return []
    findings: list[Finding] = []

    class V(ast.NodeVisitor):
        def __init__(self) -> None:
            self._classes: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self._classes.append(node.name)
            self.generic_visit(node)
            self._classes.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._scan(node)
            self.generic_visit(node)

        def _launcher_finding(
            self, call: ast.Call, func: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> Finding | None:
            source = _split_source(call, func)
            if source is None:
                return None
            if not _manages_mcp_stdio(func, self._classes[-1] if self._classes else ""):
                return None
            if _checks_an_allowlist(func):
                return None
            rel = str(path.relative_to(project_root))
            scanned.add(rel)
            return make_finding(
                "AAK-MCP-STDIO-CMD-INJ-001",
                rel,
                f"{_attr_chain(call.func)}(...) at line {call.lineno} launches "
                f"`shlex.split({_unparse(source)})`, a stored MCP STDIO server's "
                "command, with no executable allowlist between the split and the "
                "spawn. Whoever can register or edit that server record chooses "
                "the program this host runs (the CVE-2026-93965 launcher shape).",
                line_number=call.lineno,
            )

        def _scan(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            calls = sorted(
                (n for n in ast.walk(func) if isinstance(n, ast.Call)),
                key=lambda c: (c.lineno, c.col_offset),
            )
            for call in calls:
                if not _is_stdio_server_params_call(call):
                    launcher = self._launcher_finding(call, func)
                    if launcher is not None:
                        findings.append(launcher)
                        return  # one finding per function
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


def _walk_ts_proximity(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    """Original heuristic: a taint marker within 1024 chars before the sink.

    Retained as the fallback for when the tree-sitter grammar is unavailable, so
    the package keeps working with no new hard dependency. It both over-fires
    (an unrelated source that happens to sit nearby) and under-fires (a real
    source that reaches the sink from beyond the window).
    """
    findings: list[Finding] = []
    for m in _TS_STDIO_TRANSPORT_RE.finditer(text):
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
            "process.env / JSON.parse). OX MCP Apr-2026 class. "
            "[proximity heuristic — install tree-sitter for data-flow analysis]",
            line_number=line,
        ))
        return findings  # one per file is plenty
    return findings


def _walk_ts(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    """Data-flow when the grammar is present, proximity when it is not.

    What the rule reports is identical either way — same rule_id, severity and
    framework mappings. Only the decision changed: reachability from a
    caller-controlled source to the `command`/`args` of a StdioTransport,
    instead of "a marker appeared somewhere in the preceding 1024 characters".
    """
    if not _ts_stdio_taint.available():
        return _walk_ts_proximity(text, path, project_root, scanned)

    line = _ts_stdio_taint.find_tainted_sink(text)
    if line is None:
        return []

    rel = str(path.relative_to(project_root))
    scanned.add(rel)
    return [make_finding(
        "AAK-MCP-STDIO-CMD-INJ-002",
        rel,
        "new StdioClientTransport({...}) receives a command/args value that "
        "data-flow analysis traces back to a network-controlled source "
        "(req.body / fetch / axios / process.env / JSON.parse). OX MCP "
        "Apr-2026 class.",
        line_number=line,
    )]


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
            "Note: regex-only pass; expect ~10% FP on macro-heavy code. "
            "There is no tree-sitter-rust grammar and none is pending.",
            line_number=line,
        ))
        return findings
    return findings


# ---------------------------------------------------------------------------
# Go - AAK-MCP-STDIO-CMD-INJ-005 (regex + proximity; same posture as Rust)
# ---------------------------------------------------------------------------
#
# Modelled on _walk_rust deliberately, including its limits. This is not a
# go/ast pass and does not model flow; it reports that a spawn sink sits
# downstream of a network-shaped source in an MCP-shaped file.
#
# The MCP hint cannot be an SDK import the way Rust's is. CVE-2026-90898's
# handler imports `encoding/json`, `net/http` and `os/exec` and nothing else --
# the MCP identity lives in the type name (`MCPClientRequest`), the route
# (`/api/mcp/client`) and the field names (`stdio_command`). A hint gated on an
# SDK import would miss the exemplar this rule exists for.

_GO_EXEC_RE = re.compile(r"\bexec\s*\.\s*Command(?:Context)?\s*\(")
# A quoted literal in argv[0] position, optionally after a ctx argument.
_GO_LITERAL_ARGV0_RE = re.compile(r'\s*(?:\w+\s*,\s*)?["`]')
_GO_TAINT_RE = re.compile(
    r"""
    (?:
        json\s*\.\s*NewDecoder\s*\(\s*r\s*\.\s*Body\s*\)
      | json\s*\.\s*NewDecoder\s*\(\s*\w+\s*\.\s*Body\s*\)
      | \*\s*http\s*\.\s*Request\b
      | \bShouldBindJSON\s*\(
      | \bBindJSON\s*\(
      | io\s*\.\s*ReadAll\s*\(\s*\w+\s*\.\s*Body\s*\)
      | mux\s*\.\s*Vars\s*\(
      | r\s*\.\s*URL\s*\.\s*Query\s*\(\s*\)
    )
    """,
    re.VERBOSE,
)
# MCP identity in Go: an SDK path, a protocol name, an `MCPFoo` identifier, an
# /mcp route, or an mcp-prefixed JSON field.
_GO_MCP_HINT_RE = re.compile(
    r"""
    (?:
        modelcontextprotocol
      | \bmcp-go\b
      | \bMCP[A-Z]\w*
      | ["'`][^"'`]*/mcp(?:/|["'`])
      | \bmcpServers?\b
      | \bstdio_?[Cc]ommand\b
    )
    """,
    re.VERBOSE,
)


def _walk_go(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    if not _GO_MCP_HINT_RE.search(text):
        return []
    findings: list[Finding] = []
    for m in _GO_EXEC_RE.finditer(text):
        window = text[max(0, m.start() - 2048) : m.start()]
        if not _GO_TAINT_RE.search(window):
            continue
        # argv[0] is a string literal => the binary is chosen server-side and
        # the caller cannot pick it. This is what a patched handler looks like
        # (an allowlist resolves a constant, request data rides as later args),
        # and without this guard a proximity rule reports every server that
        # decoded a body anywhere in the preceding 2 KB. Narrow on purpose: a
        # literal first argument is decidable without parsing Go.
        if _GO_LITERAL_ARGV0_RE.match(text, m.end()):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        line = text.count("\n", 0, m.start()) + 1
        findings.append(make_finding(
            "AAK-MCP-STDIO-CMD-INJ-005",
            rel,
            "exec.Command(...) is invoked in an MCP-shaped Go file downstream "
            "of a network-controlled source (json.NewDecoder(r.Body), an "
            "*http.Request handler, or ShouldBindJSON). CVE-2026-90898 "
            "(Bifrost) class: an unauthenticated client-registration route "
            "that spawns the registered command. Note: regex and proximity "
            "only, not Go data-flow analysis, so a handler that decodes a body "
            "and separately shells out to a constant will also match.",
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
        elif suffix == ".go":
            findings.extend(_walk_go(text, path, project_root, scanned))
    return findings, scanned
