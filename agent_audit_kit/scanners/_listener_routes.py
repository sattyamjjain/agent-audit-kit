"""State-changing routes an MCP server's HTTP listener serves beside its MCP endpoint (AAK-DNS-REBIND-003).

The MCP SDKs check the `Host` of a request to the MCP endpoint itself: the Python SDK's
transport security, the TypeScript transport's `allowedHosts`. A server that registers
other routes on the same listener gets nothing from that check. jupyter-mcp-server before
1.0.3 (CVE-2026-77359) validated Host and Origin on the MCP endpoint, while `PUT /api/connect` and
`DELETE /api/stop`, FastMCP `custom_route` routes on the same app, checked neither: a page
whose name was rebound to the listener replaced the runtime and document URLs and stopped
the kernel. Loopback is no defence, since rebinding is how a page reaches loopback.

This module reads, per file, the routes that take POST, PUT, PATCH or DELETE and what
covers them:

* a Host or Origin read anywhere in the file outside a comment, which is taken to check
  every route;
* in Python, a `TrustedHostMiddleware` with an `allowed_hosts` that is not `["*"]` (its
  default), applied to the app that serves the route. Applied to the MCP app
  (`streamable_http_app()`, `sse_app()`, `http_app()`) it covers that app's own
  `custom_route` routes and nothing outside it; applied to any other app it covers every
  route in the file;
* in TS/JS, an `X.use(...)` middleware whose name speaks of a host or an origin
  (`hostHeaderValidation`, `localhostOriginValidation`; never `cors`), for the routes under
  its path, and an app made by the SDK's `createMcpExpressApp`, which applies both checks
  unless it is told to bind every interface without `allowedHosts`;
* a credential read on the route: its registration and its handler, by the markers
  AAK-WEBSOCKET-SERVER-001 reads (`CREDENTIAL_RE`), and in TS/JS a middleware whose name
  speaks of one, on the route or `use`d over its path.

Each credential question is a binary search over one pass of the file
(`_helpers.PatternSpans`), so a file of many routes costs one read.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any

from ._helpers import PatternSpans
from ._http_routes import CodeIndex, find_calls, is_mcp_endpoint_path

# The markers AAK-WEBSOCKET-SERVER-001 takes for a credential, and for an Origin read.
CREDENTIAL_RE = re.compile(r"authorization|basic_auth|api_key|apikey|bearer|\btoken\b|\bauth\b", re.I)
ORIGIN_READ_RE = re.compile(r"""["']origin["']|\.origin\b""", re.I)

STATE_CHANGING = ("POST", "PUT", "PATCH", "DELETE")

# The MCP transport's own paths (an `mcp` segment, `sse`, `messages`): the SDK's check, or
# AAK-DNS-REBIND-001, answers for them.
_TRANSPORT_SEGMENTS = frozenset({"sse", "message", "messages"})


@dataclass(frozen=True)
class OpenRoute:
    """A state-changing route nothing in its file covers."""

    methods: tuple[str, ...]
    path: str
    line: int

    def label(self) -> str:
        return f"{'/'.join(self.methods)} {self.path}"


def _is_transport_path(path: str) -> bool:
    segments = [s for s in path.split("/") if s]
    return is_mcp_endpoint_path(path) or bool(segments) and segments[-1].lower() in _TRANSPORT_SEGMENTS


# ---------------------------------------------------------------------------
# Python: FastMCP custom_route, Starlette, FastAPI, Flask
# ---------------------------------------------------------------------------

# A Host or Origin read: the header by name, Starlette's `request.url.hostname`, which it
# builds from the Host header, WSGI's `HTTP_HOST`, Django's `get_host()`, Flask's
# `request.host` and `request.origin`.
PY_HEADER_READ_RE = re.compile(
    r"""["']origin["']"""
    r"""|\bheaders\s*(?:\.\s*get\s*\(\s*|\[\s*)b?["']host["']"""
    r"""|\.\s*url\s*\.\s*(?:hostname|netloc)\b"""
    r"""|\bHTTP_(?:HOST|ORIGIN)\b"""
    r"""|\.\s*get_host\s*\("""
    r"""|\brequest\s*\.\s*(?:host|host_url|origin)\b""",
    re.IGNORECASE,
)
# Worth parsing for: a route registration of some kind.
PY_ROUTE_HINT_RE = re.compile(
    r"\b(?:custom_route|Route|add_api_route|add_url_rule|add_route)\s*\("
    r"|\.\s*(?:post|put|patch|delete|route|api_route)\s*\("
)
_PY_METHOD_DECORATORS = {"post": ("POST",), "put": ("PUT",), "patch": ("PATCH",), "delete": ("DELETE",)}
# Decorators and calls that take a `methods` list, and the position it may take.
_PY_LISTED_DECORATORS = {"route": None, "api_route": None, "custom_route": 1}
_PY_LISTED_CALLS = {"Route": None, "add_api_route": None, "add_url_rule": None, "add_route": 2}
_MCP_APP_CALLS = frozenset({"streamable_http_app", "sse_app", "http_app"})
_OUTER, _MCP = "outer", "mcp"
_NEWLINE_RE = re.compile(r"\n")


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _literal_methods(value: ast.expr | None) -> tuple[str, ...] | None:
    """The upper-cased methods of a literal list, tuple or set; None for anything else."""
    if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return None
    methods: list[str] = []
    for item in value.elts:
        if not (isinstance(item, ast.Constant) and isinstance(item.value, str)):
            return None
        methods.append(item.value.upper())
    return tuple(methods)


def _route_path(call: ast.Call) -> str | None:
    for value in [*call.args[:1], *(kw.value for kw in call.keywords if kw.arg in ("path", "rule"))]:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
    return None


def _registered_methods(call: ast.Call, position: int | None) -> tuple[str, ...] | None:
    """The methods a registration takes: its `methods` keyword, or the argument at
    `position`; GET (every framework's default) when it names none, None when the
    list is not a literal."""
    value = _keyword(call, "methods")
    if value is None and position is not None and len(call.args) > position:
        value = call.args[position]
    return ("GET",) if value is None else _literal_methods(value)


def _endpoint_name(call: ast.Call, name: str) -> str | None:
    value = _keyword(call, "endpoint") or _keyword(call, "view_func")
    if value is None:
        index = 2 if name == "add_url_rule" else 1
        value = call.args[index] if len(call.args) > index else None
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        return value.attr
    return None


@dataclass(frozen=True)
class _PyRegistration:
    methods: tuple[str, ...]
    path: str
    kind: str
    call: ast.Call
    handler: ast.AST | None
    handler_name: str | None


def _py_registration(call: ast.Call, handler: ast.AST | None) -> _PyRegistration | None:
    """A decorator call (with the function it decorates) or a registration call, when
    it registers a state-changing route on a literal path that is not the transport's."""
    name = _call_name(call)
    if handler is not None and isinstance(call.func, ast.Attribute) and name in _PY_METHOD_DECORATORS:
        methods: tuple[str, ...] | None = _PY_METHOD_DECORATORS[name]
    elif handler is not None and isinstance(call.func, ast.Attribute) and name in _PY_LISTED_DECORATORS:
        methods = _registered_methods(call, _PY_LISTED_DECORATORS[name])
    elif handler is None and name in _PY_LISTED_CALLS:
        methods = _registered_methods(call, _PY_LISTED_CALLS[name])
    else:
        return None
    state = tuple(m for m in (methods or ()) if m in STATE_CHANGING)
    path = _route_path(call)
    if not state or path is None or _is_transport_path(path):
        return None
    kind = _MCP if name == "custom_route" else _OUTER
    handler_name = None if handler is not None else _endpoint_name(call, name)
    return _PyRegistration(state, path, kind, call, handler, handler_name)


def _app_kind(value: ast.expr | None) -> str:
    """Whether an expression is the MCP server's own app or another one."""
    return _MCP if isinstance(value, ast.Call) and _call_name(value) in _MCP_APP_CALLS else _OUTER


def _names_trusted_host(value: ast.expr | None) -> bool:
    if isinstance(value, ast.Attribute):
        return value.attr == "TrustedHostMiddleware"
    return isinstance(value, ast.Name) and value.id == "TrustedHostMiddleware"


def _allows_named_hosts(call: ast.Call) -> bool:
    """Whether `allowed_hosts=` names hosts. Left out it is `["*"]`, every host, as is a
    literal list of nothing but `*`; a list that is not a literal is taken to name some."""
    value = _keyword(call, "allowed_hosts")
    if value is None:
        return False
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return any(not (isinstance(item, ast.Constant) and item.value == "*") for item in value.elts)
    return True


class _PyIndex:
    """One pass over a module: route registrations, functions by name, and the apps a
    TrustedHostMiddleware is applied to. A name is resolved in the scope it is assigned
    in (each function, lambda and class body is its own), so `app` assigned from
    `super().streamable_http_app()` inside an override and `app = Starlette(...)` at the
    top of the module are told apart."""

    def __init__(self, tree: ast.Module) -> None:
        self.registrations: list[_PyRegistration] = []
        self.functions: dict[str, ast.AST] = {}
        self.guarded: set[str] = set()
        bound: dict[tuple[int, str], str] = {}
        applied: list[tuple[int, ast.expr | None, ast.Call]] = []
        in_mcp_app: set[int] = set()
        stack: list[tuple[ast.AST, int]] = [(tree, 0)]
        while stack:
            node, scope = stack.pop()
            inner = scope
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)
                for deco in node.decorator_list:
                    if isinstance(deco, ast.Call):
                        self._add(_py_registration(deco, node))
                inner = id(node)
            elif isinstance(node, (ast.Lambda, ast.ClassDef)):
                inner = id(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        bound[(scope, target.id)] = _app_kind(node.value)
            elif isinstance(node, ast.Call):
                self._add(_py_registration(node, None))
                self._middleware(node, scope, applied, in_mcp_app)
            for child in ast.iter_child_nodes(node):
                stack.append((child, inner))
        for scope, app, call in applied:
            if app is None:
                kind = _MCP if id(call) in in_mcp_app else _OUTER
            elif isinstance(app, ast.Name):
                kind = bound.get((scope, app.id), _OUTER)
            else:
                kind = _app_kind(app)
            self.guarded.add(kind)

    def _add(self, registration: _PyRegistration | None) -> None:
        if registration is not None:
            self.registrations.append(registration)

    @staticmethod
    def _middleware(call: ast.Call, scope: int, applied: list[tuple[int, ast.expr | None, ast.Call]],
                    in_mcp_app: set[int]) -> None:
        """Record a TrustedHostMiddleware that names hosts, with what it is applied to:
        `app.add_middleware(TrustedHostMiddleware, ...)` the receiver,
        `TrustedHostMiddleware(app, ...)` its first argument, and
        `Middleware(TrustedHostMiddleware, ...)` the app whose `middleware=` holds it,
        the MCP app when that is `http_app(middleware=[...])`, any other app otherwise."""
        name = _call_name(call)
        if name == "add_middleware" and isinstance(call.func, ast.Attribute):
            if call.args and _names_trusted_host(call.args[0]) and _allows_named_hosts(call):
                applied.append((scope, call.func.value, call))
        elif name == "TrustedHostMiddleware":
            target = call.args[0] if call.args else _keyword(call, "app")
            if _allows_named_hosts(call):
                # With no app named, the call itself stands in: not the MCP app's.
                applied.append((scope, target if target is not None else call, call))
        elif name == "Middleware":
            if call.args and _names_trusted_host(call.args[0]) and _allows_named_hosts(call):
                applied.append((scope, None, call))
        if name in _MCP_APP_CALLS:
            listed = _keyword(call, "middleware")
            if isinstance(listed, (ast.List, ast.Tuple)):
                in_mcp_app.update(id(item) for item in listed.elts)


class _Lines:
    """Where each line of a text starts, to turn an AST node's lines into a range of the
    text. Whole lines: an AST column counts UTF-8 bytes, not characters."""

    def __init__(self, text: str) -> None:
        self._starts = [0, *(m.end() for m in _NEWLINE_RE.finditer(text))]
        self._length = len(text)

    def span(self, node: ast.AST) -> tuple[int, int]:
        first = getattr(node, "lineno", 1)
        last = getattr(node, "end_lineno", None) or first
        start = self._starts[min(first, len(self._starts)) - 1]
        end = self._starts[last] if last < len(self._starts) else self._length
        return start, end


def py_open_routes(tree: ast.Module, text: str, header_text: str) -> list[OpenRoute]:
    """The state-changing routes in a parsed Python file that nothing in it covers.

    Args:
        tree: The parsed module.
        text: Its source, for the route and handler ranges.
        header_text: The source with comments taken out, read for a Host or Origin read.

    Returns:
        The routes, in source order.
    """
    if PY_HEADER_READ_RE.search(header_text):
        return []
    index = _PyIndex(tree)
    if _OUTER in index.guarded:
        return []
    lines = _Lines(text)
    credentials = PatternSpans((CREDENTIAL_RE,), text)
    routes: list[OpenRoute] = []
    for reg in index.registrations:
        if reg.kind in index.guarded:
            continue
        handler = reg.handler
        if handler is None and reg.handler_name is not None:
            handler = index.functions.get(reg.handler_name)
        if credentials.within(*lines.span(reg.call)):
            continue
        if handler is not None and credentials.within(*lines.span(handler)):
            continue
        routes.append(OpenRoute(reg.methods, reg.path, reg.call.lineno))
    return sorted(routes, key=lambda r: (r.line, r.path))


# ---------------------------------------------------------------------------
# TS/JS: Express, Fastify, Hono
# ---------------------------------------------------------------------------

_JS_HEADER_READ_RE = re.compile(
    r"""["']origin["']"""
    r"""|\.\s*origin\b"""
    r"""|\bheaders\s*(?:\.\s*host\b|\[\s*["']host["']\s*\])"""
    r"""|\.\s*(?:get|header)\s*\(\s*["']host["']"""
    r"""|\b(?:req|request)\s*\.\s*(?:hostname|host)\b""",
    re.IGNORECASE,
)
# `const { origin, host } = req.headers`: the braces are matched first, each `{` read at
# most 200 characters on, and their names after.
_JS_HEADERS_DESTRUCTURE_RE = re.compile(r"\{([^{}]{0,200})\}\s*=\s*[\w$.]{0,80}\bheaders\b")
_HOST_OR_ORIGIN_RE = re.compile(r"\b(?:origin|host)\b", re.IGNORECASE)


def js_reads_host_or_origin(text: str) -> bool:
    """Whether TS/JS source reads the Host or the Origin of a request."""
    if _JS_HEADER_READ_RE.search(text):
        return True
    return any(_HOST_OR_ORIGIN_RE.search(m.group(1)) for m in _JS_HEADERS_DESTRUCTURE_RE.finditer(text))
_JS_ROUTE_HEAD_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\.\s*(post|put|patch|delete|all|use)\s*\("
)
# `const app = express()`, `let router = express.Router()`, `const app = new Hono()`.
_JS_BIND_RE = re.compile(
    r"(?<![\w$.])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]{0,120})?=\s*(?:await\s+)?"
    r"(?:new\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\("
)
_JS_APP_FACTORIES = frozenset({
    "express", "express.Router", "Router", "fastify", "Fastify", "Hono", "polka", "createMcpExpressApp",
})
# Receivers taken for an app or router without a binding in the file.
_JS_APP_NAMES = frozenset({"app", "router", "server", "fastify", "hono", "api"})
_JS_LEAD_RE = re.compile(r"(?:new\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)")
_WORD_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
_HOST_WORDS = frozenset({"host", "hosts", "origin", "origins"})
_CREDENTIAL_WORDS = frozenset({
    "auth", "authz", "authn", "authorization", "authorize", "authorized", "authenticate", "authenticated",
    "authentication", "bearer", "token", "jwt", "passport", "credential", "credentials", "apikey",
})
_EVERY_INTERFACE_RE = re.compile(r"""["'](?:0\.0\.0\.0|::)["']""")
_NAME_WINDOW = 200
_ARGS_WINDOW = 2000


def _words(identifier: str) -> set[str]:
    return {w.lower() for w in _WORD_RE.findall(identifier)}


def _names_credential(identifier: str) -> bool:
    words = _words(identifier)
    return bool(words & _CREDENTIAL_WORDS) or {"api", "key"} <= words


def _lead(index: CodeIndex, span: tuple[int, int]) -> str:
    start, end = span
    m = _JS_LEAD_RE.match(index.text, start, min(end, start + _NAME_WINDOW))
    return m.group(1) if m else ""


def _app_bindings(index: CodeIndex) -> tuple[set[str], set[str]]:
    """Names bound to an app or router, and those of them `createMcpExpressApp` made
    with its Host and Origin checks on."""
    apps: set[str] = set()
    checked: set[str] = set()
    text = index.text
    for m in _JS_BIND_RE.finditer(text):
        factory = m.group(2)
        if factory not in _JS_APP_FACTORIES or not index.in_code(m.start()):
            continue
        apps.add(m.group(1))
        if factory == "createMcpExpressApp":
            spans = index.args(m.end() - 1) or []
            options = text[spans[0][0]:min(spans[0][1], spans[0][0] + _ARGS_WINDOW)] if spans else ""
            if not (_EVERY_INTERFACE_RE.search(options) and "allowedHosts" not in options):
                checked.add(m.group(1))
    return apps, checked


class _Mounts:
    """The paths middleware is `use`d over, as a tree of path segments, to ask whether
    one covers a route in the length of the route's path: Express mounts `/api` over
    `/api` and `/api/x`, not `/apix`, and None (no path) over everything. Checking each
    route against each path in turn grew with their product."""

    _END = ""

    def __init__(self) -> None:
        self._root: dict[str, dict[str, Any]] = {}
        self._everything = False

    def add(self, path: str | None) -> None:
        if path is None:
            self._everything = True
            return
        node = self._root
        for segment in (s for s in path.split("/") if s):
            node = node.setdefault(segment, {})
        node[self._END] = {}

    def cover(self, path: str) -> bool:
        if self._everything:
            return True
        node = self._root
        if self._END in node:
            return True
        for segment in (s for s in path.split("/") if s):
            below = node.get(segment)
            if below is None:
                return False
            node = below
            if self._END in node:
                return True
        return False


def js_open_routes(text: str, header_text: str) -> list[OpenRoute]:
    """The state-changing routes in a TS/JS file that nothing in it covers.

    Args:
        text: The source.
        header_text: The source with comments taken out, read for a Host or Origin read.

    Returns:
        The routes, in source order.
    """
    if js_reads_host_or_origin(header_text):
        return []
    index = CodeIndex(text)
    apps, checked = _app_bindings(index)
    host_scopes = _Mounts()
    auth_scopes = _Mounts()
    pending: list[tuple[str, str, int, list[tuple[int, int]]]] = []
    for call in find_calls(index, _JS_ROUTE_HEAD_RE):
        receiver = call.receiver.rpartition(".")[2]
        if call.receiver not in apps and receiver not in _JS_APP_NAMES:
            continue
        spans = [s for s in call.args if s[0] < s[1]]
        if not spans:
            continue
        path = index.string_literal(*spans[0])
        if call.method == "use":
            for lead in (_lead(index, s) for s in (spans[1:] if path is not None else spans)):
                if lead.rpartition(".")[2].lower() != "cors" and _words(lead) & _HOST_WORDS:
                    host_scopes.add(path)
                if _names_credential(lead):
                    auth_scopes.add(path)
            continue
        if path is None or len(spans) < 2 or call.receiver in checked or _is_transport_path(path):
            continue
        pending.append((call.method.upper(), path, call.start, spans))
    if not pending:
        return []
    credentials = PatternSpans((CREDENTIAL_RE,), text)
    routes: list[OpenRoute] = []
    for method, path, start, spans in pending:
        if host_scopes.cover(path) or auth_scopes.cover(path):
            continue
        if any(_names_credential(_lead(index, s)) for s in spans[1:-1]):
            continue
        if credentials.within(spans[1][0], spans[-1][1]):
            continue
        methods = STATE_CHANGING if method == "ALL" else (method,)
        routes.append(OpenRoute(methods, path, index.line_of(start)))
    return routes


__all__ = [
    "CREDENTIAL_RE", "ORIGIN_READ_RE", "OpenRoute", "PY_HEADER_READ_RE", "PY_ROUTE_HINT_RE", "STATE_CHANGING",
    "js_reads_host_or_origin", "js_open_routes", "py_open_routes",
]
