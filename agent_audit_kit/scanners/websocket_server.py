"""AAK-WEBSOCKET-SERVER-001 / -002: WebSocket servers for MCP, model or policy traffic left open.

001 reads a Python `websockets` server.

In `websockets` the origin check is opt-in: `origins` defaults to None, and None accepts every
Origin. A WebSocket handshake is not subject to the same-origin policy and gets no CORS preflight,
so any page open in a browser on that machine can connect to `ws://127.0.0.1:8000` and talk to the
server. Binding to loopback does not close that. `max_size=None` takes an unbounded frame from
whoever connected, `traceback.format_exc()` sent to the client hands them the server's internals,
and a 0.0.0.0 default with no authentication puts the rest on the network.

`process_request=` alone is no answer: it is the hook where an origin check goes, and openpi's
server, the shape this was written from, uses it for a health check. A file that reads the Origin
header anywhere is taken to check it.
A page cannot set an Authorization header on a handshake, so a file that reads a credential is
not reachable the same way, and the origin arm stands down there too.

002 reads a Node `ws` (or `isomorphic-ws`) server, where the check is opt-in as well: a
`WebSocketServer` built without `verifyClient` takes a handshake from any Origin.
Supergateway's stdio-to-WebSocket mode, 2.4.0 through 4.2.2 (CVE-2026-132121), is the
shape: a page opens its `/message` socket, loopback-bound or not, and calls the tools of
the stdio MCP server the gateway spawned. Through 4.1.0 it passed no `verifyClient`; 4.2.0
passes one only when its caller supplies one (`...(verifyClient ? { verifyClient } : {})`),
and that one checks an API key, not the Origin, so a `verifyClient` set that way does
not count. A file that reads the Origin, or a credential, is taken to check it, as in 001.
A file that also starts processes through `child_process` is the stdio bridge itself, and
the finding is CRITICAL.

What each rule reads, and where it stops, is in the registry's limitations.
"""

from __future__ import annotations

import ast
import dataclasses
import os
import re
from pathlib import Path

from agent_audit_kit.models import Finding, Severity

from ._helpers import SOURCE_MAX_BYTES, kept_dirs, make_finding, parse_python, read_text_capped, refusing_overflow, walk_tree
from ._http_routes import CodeIndex
from ._listener_routes import CREDENTIAL_RE, ORIGIN_READ_RE

RULE = "AAK-WEBSOCKET-SERVER-001"
RULE_NODE = "AAK-WEBSOCKET-SERVER-002"

_HINT_RE = re.compile(r"\bwebsockets\b")
# Which servers the rule is about, by the words of the path or an `mcp` import. A WebSocket server
# in a chat app or a dev tool is not, and `origins` is left out of nearly all of them.
_SERVER_WORDS = frozenset({
    "mcp", "policy", "policies", "model", "models", "inference", "agent", "agents", "llm", "llms",
})
_NOT_DEPLOYED = frozenset({
    "test", "tests", "testing", "fixture", "fixtures", "example", "examples", "sample", "samples", "demo", "demos",
})
_WORD_RE = re.compile(r"[a-z0-9]+")
_MCP_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+(?:mcp|fastmcp)\b", re.M)
_ORIGIN_READ_RE = ORIGIN_READ_RE
_AUTH_RE = CREDENTIAL_RE
_ANY_INTERFACE = frozenset({"0.0.0.0", "::", ""})
_TRACEBACK_CALLS = frozenset({"format_exc", "format_exception", "format_tb"})


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _serve_names(tree: ast.Module) -> tuple[set[str], set[str]]:
    """The names this file calls the `websockets` package by, and `serve` by."""
    modules: set[str] = set()
    functions: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.partition(".")[0] == "websockets":
                    modules.add(alias.asname or alias.name.partition(".")[0])
        elif isinstance(node, ast.ImportFrom) and (node.module or "").partition(".")[0] == "websockets":
            for alias in node.names:
                if alias.name == "serve":
                    functions.add(alias.asname or alias.name)
                else:
                    modules.add(alias.asname or alias.name)
    return modules, functions


def _is_serve(call: ast.Call, modules: set[str], functions: set[str]) -> bool:
    name = _dotted(call.func)
    if "." not in name:
        return name in functions
    head, _, last = name.rpartition(".")
    return last == "serve" and head.partition(".")[0] in modules


def _host_defaults(tree: ast.Module) -> dict[str, object]:
    """`{parameter: default}` for the file's parameters with `host` in their name."""
    out: dict[str, object] = {}
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = [*func.args.posonlyargs, *func.args.args]
        pairs = [
            *zip(args[len(args) - len(func.args.defaults):], func.args.defaults),
            *zip(func.args.kwonlyargs, func.args.kw_defaults),
        ]
        for arg, default in pairs:
            if "host" in arg.arg.lower() and isinstance(default, ast.Constant):
                out[arg.arg] = default.value
    return out


def _listens_everywhere(call: ast.Call, defaults: dict[str, object]) -> bool:
    keywords = {k.arg: k.value for k in call.keywords if k.arg}
    host = call.args[1] if len(call.args) > 1 else keywords.get("host")
    if isinstance(host, ast.Constant):
        return host.value in _ANY_INTERFACE
    name = _dotted(host) if host is not None else ""
    if not name:
        return False
    # `host` or `self._host`, set from a parameter with a default.
    return defaults.get(name.rpartition(".")[2].lstrip("_")) in _ANY_INTERFACE


def _serve_reasons(call: ast.Call, answered: bool, has_auth: bool, defaults: dict[str, object]) -> list[str]:
    keywords = {k.arg: k.value for k in call.keywords}
    reasons: list[str] = []
    origins = keywords.get("origins")
    unknown = None in keywords  # `**options` may set either
    if not unknown and not answered and (origins is None or (isinstance(origins, ast.Constant) and origins.value is None)):
        reasons.append("no `origins`, so any page open on this machine can connect, loopback or not")
    size = keywords.get("max_size")
    if isinstance(size, ast.Constant) and size.value is None:
        reasons.append("`max_size=None`, so a client can send a frame of any size")
    if not has_auth and _listens_everywhere(call, defaults):
        reasons.append("listens on every interface by default with no authentication in this file")
    return reasons


def _sends_traceback(call: ast.Call, held: set[str]) -> bool:
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "send") or not call.args:
        return False
    argument = call.args[0]
    if isinstance(argument, ast.Name):
        return argument.id in held
    return isinstance(argument, ast.Call) and _dotted(argument.func).rpartition(".")[2] in _TRACEBACK_CALLS


def _analyse(tree: ast.Module, rel: str, text: str) -> list[Finding]:
    modules, functions = _serve_names(tree)
    if not modules and not functions:
        return []
    defaults = _host_defaults(tree)
    held: set[str] = set()
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls.append(node)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                and _dotted(node.value.func).rpartition(".")[2] in _TRACEBACK_CALLS:
            held.update(t.id for t in node.targets if isinstance(t, ast.Name))
    # Each read once for the file: per call, a file of 10,000 calls grew with the square.
    has_auth = bool(_AUTH_RE.search(text))
    answered = has_auth or bool(_ORIGIN_READ_RE.search(text))
    findings: list[Finding] = []
    for call in calls:
        if _is_serve(call, modules, functions):
            reasons = _serve_reasons(call, answered, has_auth, defaults)
            if reasons:
                findings.append(make_finding(RULE, rel, f"`websockets` server: {'; '.join(reasons)}", call.lineno))
        elif _sends_traceback(call, held):
            findings.append(make_finding(
                RULE, rel, "sends a traceback to the WebSocket client, who may be anyone that connected", call.lineno,
            ))
    return findings


def _in_scope(rel: str, text: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    if any(p in _NOT_DEPLOYED for p in parts[:-1]) or name.startswith("test_") or name.endswith("_test.py"):
        return False
    return bool(_SERVER_WORDS & set(_WORD_RE.findall(rel.lower()))) or bool(_MCP_IMPORT_RE.search(text))


# ---------------------------------------------------------------------------
# AAK-WEBSOCKET-SERVER-002: Node `ws`
# ---------------------------------------------------------------------------

_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".mts", ".cts")
_JS_TEST_NAME_RE = re.compile(r"\.(?:test|spec)\.[cm]?[jt]sx?$|\.d\.[cm]?ts$")
# Where a module is loaded from: `from "ws"`, `require("ws")`, `import("ws")`.
_WS_SOURCE_RE = re.compile(r"""(\bfrom|\brequire\s*\(|\bimport\s*\()\s*["'](?:ws|isomorphic-ws)["']""")
_CHILD_SOURCE_RE = re.compile(r"""(\bfrom|\brequire\s*\(|\bimport\s*\()\s*["'](?:node:)?child_process["']""")
_JS_MCP_IMPORT_RE = re.compile(
    r"""(?:\bfrom|\brequire\s*\(|\bimport\s*\()\s*["'](?:@modelcontextprotocol/|fastmcp["'/]|mcp-framework["'/])"""
)
# How far before `from "ws"` its `import` keyword, or before `require("ws")` its binding, is looked for.
_CLAUSE_WINDOW = 600
_ASSIGNED_RE = re.compile(r"(?:const|let|var)\s+(?:([A-Za-z_$][\w$]*)|\{([^{}]*)\})\s*=\s*(?:await\s+)?$")
_MEMBER_AFTER_RE = re.compile(r"\s*\)\s*\.\s*([A-Za-z_$][\w$]*)")
_NAMESPACE_RE = re.compile(r"\*\s*as\s+([A-Za-z_$][\w$]*)")
_DEFAULT_RE = re.compile(r"\s*(?:type\s+)?([A-Za-z_$][\w$]*)\s*(?:,|$)")
_BRACES_RE = re.compile(r"\{([^{}]*)\}")
_SPECIFIER_RE = re.compile(r"^\s*(?:type\s+)?([A-Za-z_$][\w$]*)(?:\s*(?:as|:)\s*([A-Za-z_$][\w$]*))?\s*$")
_WS_SERVERS = frozenset({"WebSocketServer", "Server"})
_CHILD_CALLS = frozenset({"spawn", "exec", "execFile", "fork", "spawnSync", "execSync", "execFileSync"})
_OPTIONS_WINDOW = 4000
_VERIFY_RE = re.compile(r"\bverifyClient\b")
# `...(verifyClient ? { verifyClient } : {})`: set only when the caller passes one.
_CONDITIONAL_VERIFY_RE = re.compile(r"\.\.\.\s*\([^()]{0,400}?\bverifyClient\b")


def _imported(text: str, source: re.Pattern[str]) -> tuple[set[str], dict[str, str]]:
    """The names a TS/JS file loads a module under: its namespace and default bindings,
    and `{local: imported}` for the names it imports from it."""
    whole: set[str] = set()
    named: dict[str, str] = {}

    def specifiers(listed: str) -> None:
        for item in listed.split(","):
            m = _SPECIFIER_RE.match(item)
            if m:
                named[m.group(2) or m.group(1)] = m.group(1)

    for m in source.finditer(text):
        before = text[max(0, m.start() - _CLAUSE_WINDOW):m.start()]
        if m.group(1) == "from":
            at = before.rfind("import")
            if at < 0:
                continue
            clause = before[at + len("import"):]
            namespace = _NAMESPACE_RE.search(clause)
            if namespace:
                whole.add(namespace.group(1))
            braces = _BRACES_RE.search(clause)
            if braces:
                specifiers(braces.group(1))
            default = _DEFAULT_RE.match(clause)
            if default and not clause.lstrip().startswith(("{", "*")) and default.group(1) != "type":
                whole.add(default.group(1))
            continue
        assigned = _ASSIGNED_RE.search(before)
        member = _MEMBER_AFTER_RE.match(text, m.end())
        if assigned and assigned.group(1) and member:
            named[assigned.group(1)] = member.group(1)   # const WSS = require("ws").Server
        elif assigned and assigned.group(1):
            whole.add(assigned.group(1))
        elif assigned and assigned.group(2):
            specifiers(assigned.group(2))
    return whole, named


# A constructor or a call, with the member after a name when there is one: one pattern for
# every file, and the names it captures looked up in a set. An alternation built from the
# file's own names is tried name by name at every position, so a file of many aliases
# would be read once per alias.
_NEW_RE = re.compile(r"(?<![\w$.])new\s+([A-Za-z_$][\w$]*)(?:\s*\.\s*([A-Za-z_$][\w$]*))?\s*\(")
_CALL_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*([A-Za-z_$][\w$]*))?\s*\(")


def _ws_constructions(text: str) -> list[re.Match[str]]:
    """Each `new WebSocketServer(`, under every name this file gives it, and each
    `new <ws>.Server(` / `new <ws>.WebSocketServer(`."""
    whole, named = _imported(text, _WS_SOURCE_RE)
    if not whole and not named:
        return []
    classes = {local for local, name in named.items() if name in _WS_SERVERS}
    holders = whole | {local for local, name in named.items() if name == "WebSocket"}
    return [
        m for m in _NEW_RE.finditer(text)
        if (m.group(2) is None and m.group(1) in classes) or (m.group(2) in _WS_SERVERS and m.group(1) in holders)
    ]


def _starts_processes(text: str) -> str | None:
    """The `child_process` call this file makes, if it imports the module and calls one."""
    whole, named = _imported(text, _CHILD_SOURCE_RE)
    calls = {local: name for local, name in named.items() if name in _CHILD_CALLS}
    if not calls and not whole:
        return None
    for m in _CALL_RE.finditer(text):
        if m.group(2) is None and m.group(1) in calls:
            return calls[m.group(1)]
        if m.group(2) in _CHILD_CALLS and m.group(1) in whole:
            return m.group(2)
    return None


def _verify_client(options: str | None) -> str:
    """What the server's options say about `verifyClient`: "none", "conditional",
    "set", or "unknown" when they are not an object literal, or spread another object
    in that may hold one."""
    if options is None or not options.strip():
        return "none"
    if not options.lstrip().startswith("{"):
        return "unknown"
    if _CONDITIONAL_VERIFY_RE.search(options):
        return "conditional"
    if _VERIFY_RE.search(options):
        return "set"
    return "unknown" if "..." in options else "none"


def _js_in_scope(rel: str, text: str, spawns: bool) -> bool:
    parts = rel.split("/")
    if any(p in _NOT_DEPLOYED for p in parts[:-1]) or _JS_TEST_NAME_RE.search(parts[-1]):
        return False
    return spawns or bool(_SERVER_WORDS & set(_WORD_RE.findall(rel.lower()))) or bool(_JS_MCP_IMPORT_RE.search(text))


def _node_findings(rel: str, text: str) -> list[Finding] | None:
    """The file's AAK-WEBSOCKET-SERVER-002 findings, or None when it builds no `ws`
    server or is out of scope."""
    constructions = _ws_constructions(text)
    if not constructions:
        return None
    child_call = _starts_processes(text)
    if not _js_in_scope(rel, text, child_call is not None):
        return None
    if _ORIGIN_READ_RE.search(text) or _AUTH_RE.search(text):
        return []
    index = CodeIndex(text)
    findings: list[Finding] = []
    for m in constructions:
        if not index.in_code(m.start()):
            continue
        spans = index.args(m.end() - 1)
        if spans is None:
            continue
        options = text[spans[0][0]:min(spans[0][1], spans[0][0] + _OPTIONS_WINDOW)] if spans else None
        verdict = _verify_client(options)
        if verdict in ("set", "unknown"):
            continue
        what = ("whose `verifyClient` is set only when its caller passes one" if verdict == "conditional"
                else "with no `verifyClient`")
        evidence = (f"`ws` WebSocketServer {what}, and nothing in this file reads the Origin header or a "
                    "credential, so any page open in a browser on this machine can open it, loopback or not")
        if child_call is not None:
            evidence += (f". The file starts processes (`{child_call}` from child_process), the stdio bridge of "
                         "CVE-2026-132121, so that page drives what they run")
        finding = make_finding(RULE_NODE, rel, evidence, index.line_of(m.start()))
        if child_call is not None:
            finding = dataclasses.replace(finding, severity=Severity.CRITICAL)
        findings.append(finding)
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report WebSocket servers for MCP, model or policy traffic with open defaults:
    Python `websockets` (AAK-WEBSOCKET-SERVER-001) and Node `ws` (-002).

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = kept_dirs(dirpath, dirnames, project_root)
        for name in sorted(filenames):
            node = name.endswith(_JS_EXTS)
            if not node and not name.endswith(".py"):
                continue
            path = Path(dirpath) / name
            try:
                text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
            except OSError:
                continue
            if not (_WS_SOURCE_RE if node else _HINT_RE).search(text):
                continue
            rel = path.relative_to(project_root).as_posix()
            if node:
                found_node = _node_findings(rel, text)
                if found_node is not None:
                    scanned.add(rel)
                    findings.extend(found_node)
                continue
            if not _in_scope(rel, text):
                continue
            try:
                tree = parse_python(text, path)
            except (SyntaxError, ValueError):
                continue
            with refusing_overflow(path):
                found = walk_tree(_analyse, tree, rel, text)
                scanned.add(rel)
                findings.extend(found)
    return findings, scanned


__all__ = ["RULE", "RULE_NODE", "scan"]
