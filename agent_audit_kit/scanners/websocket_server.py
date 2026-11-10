"""AAK-WEBSOCKET-SERVER-001: a Python `websockets` server for MCP, model or policy traffic left open.

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

What the rule reads, and where it stops, is in the registry's limitations.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, SOURCE_MAX_BYTES, make_finding, parse_python, read_text_capped, refusing_overflow, walk_tree

RULE = "AAK-WEBSOCKET-SERVER-001"

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
_ORIGIN_READ_RE = re.compile(r"""["']origin["']|\.origin\b""", re.I)
_AUTH_RE = re.compile(r"authorization|basic_auth|api_key|apikey|bearer|\btoken\b|\bauth\b", re.I)
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


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Report `websockets` servers for MCP, model or policy traffic with open defaults.

    Args:
        project_root: The root directory of the project.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = Path(dirpath) / name
            try:
                text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
            except OSError:
                continue
            if not _HINT_RE.search(text):
                continue
            rel = path.relative_to(project_root).as_posix()
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


__all__ = ["RULE", "scan"]
