"""MCP route rules: twin-route asymmetry (AAK-MCPWN-001), one handler on an
authenticated and an unauthenticated route (AAK-MCP-020), and a lookup keyed on
the caller's input that is answered before the auth check (AAK-MCP-019).

CVE-2026-33032 / MCPwn (nginx-ui, CVSS 9.8, KEV-listed 2026-04-13) was
caused by two routes sharing a handler but only one being wrapped in an
auth middleware. AAK-MCPWN-001 detects that shape by path — "one MCP route
is authed, its twin isn't" — across three stacks:

- **Go / Gin**: `router.POST("/mcp", AuthRequired(), h)` vs
  `router.POST("/mcp_message", h)`.
- **Python / FastAPI**: `@app.post("/mcp")` with `Depends(auth)` vs
  `@app.post("/mcp_message")` without.
- **Node / Express**: `app.post("/mcp", authMw, h)` vs
  `app.post("/mcp_message", h)`.

Gin and Express routes are read with the bracket reader in `_http_routes`, so
a route's middleware is every argument between its path and its handler; a
FastAPI route is its decorators up to the `def`. False-positive rate stays
low because we only fire when two routes matching the MCP endpoint pattern
live in the same file and one has a recognised auth marker while the other
doesn't. AAK-MCP-020, further down, pairs routes by the handler they reach
instead of by their paths, and AAK-MCP-019 reads the order of a Go handler's
own statements.

References:
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-33032
- VulnCheck KEV 2026-04-13.
- Rapid7 ETR:
  https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/
- Picus MCPwn writeup:
  https://www.picussecurity.com/resource/blog/cve-2026-33032-mcpwn-how-a-missing-middleware-call-in-nginx-ui-hands-attackers-full-web-server-takeover
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, in_skip_dir
from agent_audit_kit.scanners._http_routes import (
    GO_TEST_SERVER_RE,
    TEST_FILE_RE,
    Call,
    CodeIndex,
    GoHandler,
    find_calls,
    go_handlers,
    is_mcp_endpoint_path,
)


_SCAN_EXTS = {".go", ".py", ".ts", ".tsx", ".js", ".mjs"}
_MAX_FILE_BYTES = 512_000

# Canonical MCP endpoint shapes. We match the quoted path literal,
# captured once so the caller can extract it for reporting.
_MCP_ROUTE_RE = re.compile(
    r"""["']
        (?P<route>/mcp(?:[_\-/](?:messages?|invoke|tool|msg))?)
        ["']""",
    re.VERBOSE,
)

# Auth-middleware heuristics. We're intentionally broad — the cost of a
# missing marker is a FP on the safe side; the cost of too narrow is a
# false-negative on an MCPwn clone.
_AUTH_MARKERS = (
    # Go / Gin / chi
    "AuthRequired",
    "RequireAuth",
    "Auth(",
    "Authenticator",
    "MustAuth",
    "jwt.",
    "JwtAuth",
    "Protected",
    # Python / FastAPI / Starlette
    "Depends(auth)",
    "Depends(get_current_user)",
    "Depends(verify_token)",
    "Depends(require_auth)",
    "Depends(current_user)",
    "require_auth",
    "@requires",
    "HTTPBearer",
    "OAuth2PasswordBearer",
    # Node / Express / Koa
    "authMw",
    "requireAuth",
    "ensureAuthenticated",
    "passport.authenticate",
    "jwtMiddleware",
    "jwt_middleware",
    "authenticate(",
)


@dataclass(frozen=True)
class _RouteHit:
    route: str
    line: int
    line_text: str
    has_auth: bool


# ---------------------------------------------------------------------------
# Language-specific route extractors
# ---------------------------------------------------------------------------


# Routes are read through the shared bracket reader (`_http_routes.CodeIndex`),
# so a route's middleware is every argument between its path and its handler.
# The patterns this replaced read each route's arguments only to the first `)`:
# on nginx-ui's router, the file CVE-2026-33032 was found in, `r.Any("/mcp",
# middleware.IPWhiteList(), middleware.AuthRequired(), func(c *gin.Context) {...})`
# read as far as `middleware.IPWhiteList(`, neither route looked authenticated,
# and the rule named for that CVE was silent on it. The handler, the last
# argument, is still read only to its first `)`, as before, so an auth wrapper
# (`requireAuth(h)`) still counts and an inline handler's body does not.
#
# Each argument is read for at most `_MARKER_WINDOW` characters: a middleware
# name is short, and nested route calls would otherwise reread the text below
# them once per level. The heads start at a word run (`(?<!\w)`), so a long word
# with no `.` after it is read once, not once per character.
_GIN_HEAD_RE = re.compile(r"(?<!\w)(\w+)\.(Handle|POST|GET|PUT|DELETE|PATCH|Any)\s*\(")
_GIN_GROUP_HEAD_RE = re.compile(r"(?<!\w)(\w+)\s*:=\s*\w+\.Group\s*\(")
_EXPRESS_HEAD_RE = re.compile(r"(?<!\w)(\w+)\.(post|get|put|patch|delete|use|all)\s*\(")
_MCP_ROUTE_VALUE_RE = re.compile(r"/mcp(?:[_\-/](?:messages?|invoke|tool|msg))?")
_METHOD_LITERAL_RE = re.compile(r'"[A-Z]+"')
_MARKER_WINDOW = 200


def _route_parts(index: CodeIndex, spans: list[tuple[int, int]]) -> list[str]:
    """The text read for auth markers: each middleware argument, and the
    handler (the last argument) up to its first `)`."""
    text = index.text
    parts = [text[s:min(e, s + _MARKER_WINDOW)] for s, e in spans[:-1]]
    start, end = spans[-1]
    end = min(end, start + _MARKER_WINDOW)
    close = text.find(")", start, end)
    parts.append(text[start:close if close >= 0 else end])
    return parts


def _route_hits(index: CodeIndex, go: bool) -> list[_RouteHit]:
    """MCP routes registered with Gin (`go`) or Express-style calls. A Gin path
    is a double-quoted literal, an Express one a single- or double-quoted one."""
    text = index.text
    quotes = '"' if go else "\"'"
    hits: list[_RouteHit] = []
    for call in find_calls(index, _GIN_HEAD_RE if go else _EXPRESS_HEAD_RE):
        spans = [s for s in call.args if s[0] < s[1]]
        if go and spans and _METHOD_LITERAL_RE.fullmatch(text[spans[0][0]:spans[0][1]]):
            spans = spans[1:]
        if len(spans) < 2 or text[spans[0][0]] not in quotes:
            continue
        route = index.string_literal(*spans[0])
        if route is None or not _MCP_ROUTE_VALUE_RE.fullmatch(route):
            continue
        parts = _route_parts(index, spans[1:])
        has_auth = any(marker in part for part in parts for marker in _AUTH_MARKERS)
        shown = text[spans[1][0]:min(spans[-1][1], spans[1][0] + _MARKER_WINDOW)]
        hits.append(_RouteHit(route, index.line_of(call.start), shown, has_auth))
    return hits


def _extract_gin(text: str) -> list[_RouteHit]:
    return _route_hits(CodeIndex(text, go=True), go=True)


_FASTAPI_ROUTE_RE = re.compile(
    r"""@\w+\.(?:post|get|put|patch|delete|api_route)\s*\(
        \s*"(?P<route>/mcp(?:[_\-/](?:messages?|invoke|tool|msg))?)"
    """,
    re.VERBOSE,
)
_DEF_HEAD_RE = re.compile(r"(?:async\s+)?def\s+\w+\(")
# A newline whose next line opens a `def`.
_DEF_LINE_RE = re.compile(r"\n(?=[^\S\n]*(?:async\s+)?def\s+\w+\()")
# A `)` that only whitespace separates from the end of its line.
_CLOSE_AT_EOL_RE = re.compile(r"\)(?=[^\S\n]*\n)")
_WHITESPACE_RE = re.compile(r"\s*")


def _skip_whitespace(text: str, at: int) -> int:
    m = _WHITESPACE_RE.match(text, at)
    return m.end() if m else at


def _def_end(text: str, at: int, last_close: int) -> int | None:
    """End of `(?:async\\s+)?def\\s+\\w+\\([^)]*\\)` at ``at``, or None."""
    m = _DEF_HEAD_RE.match(text, at)
    if m is None or m.end() > last_close:
        return None
    return text.find(")", m.end()) + 1


def _last_def_line(text: str, last_close: int) -> tuple[int, int | None]:
    """The last newline after which a `def` opens and closes, and that
    `def`'s end; (-1, None) when there is none."""
    newline = -1
    for m in _DEF_LINE_RE.finditer(text, 0, last_close + 1):
        newline = m.start()
    if newline < 0:
        return -1, None
    return newline, _def_end(text, _skip_whitespace(text, newline + 1), last_close)


def _fastapi_routes(text: str) -> Iterator[tuple[int, int, str]]:
    """(start, end, route) of each MCP route decorator with the `def` it
    decorates: the matches of the DOTALL pattern this scanner used,

        @\\w+\\.(?:post|get|...)\\s*\\(\\s*"(?P<route>/mcp...)"
        .*?\\)\\s*\\n (?:\\s*@.*\\n)* \\s*(?:async\\s+)?def\\s+\\w+\\([^)]*\\)

    found without its backtracking. The decorator ends at the first `)` at
    the end of a line that a `def` follows, or an `@` line when a later line
    opens a `def`: with DOTALL, `(?:\\s*@.*\\n)*` ran from that `@` to the
    last such line in the file, and tried every split of the lines between
    before it gave up, so 26 repeated decorators with no `def` after them
    took 8.7 seconds, 30 took 144, and each added line doubled it. Where a
    decorator ends depends only on that `)`, not on the decorator that
    reached it, so once one finds no end, none after it can.
    """
    last_close = text.rfind(")")
    last_def: tuple[int, int | None] | None = None
    pos = 0
    while True:
        head = _FASTAPI_ROUTE_RE.search(text, pos)
        if head is None:
            return
        end = None
        for close in _CLOSE_AT_EOL_RE.finditer(text, head.end()):
            after = _skip_whitespace(text, close.end())
            if not text.startswith("@", after):
                end = _def_end(text, after, last_close)
            else:
                if last_def is None:
                    last_def = _last_def_line(text, last_close)
                if last_def[0] > after:
                    end = last_def[1]
            if end is not None:
                break
        if end is None:
            return
        yield head.start(), end, head.group("route")
        pos = end


def _extract_fastapi(text: str) -> list[_RouteHit]:
    hits: list[_RouteHit] = []
    lineno, counted = 1, 0
    for start, end, route in _fastapi_routes(text):
        block = text[start:end]
        has_auth = any(marker in block for marker in _AUTH_MARKERS)
        lineno += text.count("\n", counted, start)
        counted = start
        hits.append(_RouteHit(route, lineno, block.splitlines()[0], has_auth))
    return hits


def _extract_express(text: str) -> list[_RouteHit]:
    return _route_hits(CodeIndex(text), go=False)


def _normalize_pair(route: str) -> str:
    """Collapse '/mcp', '/mcp_message', '/mcp-messages', '/mcp/invoke' etc.
    into one canonical bucket so twin-asymmetry detection is stable."""
    base = route.rstrip("/")
    if base == "/mcp":
        return "mcp"
    return "mcp-surface"


# ---------------------------------------------------------------------------
# Pair-wise asymmetry check
# ---------------------------------------------------------------------------


def _asymmetry_findings(
    hits: list[_RouteHit],
    rel_path: str,
    text: str,
) -> list[Finding]:
    """Fire AAK-MCPWN-001 for every unauthenticated MCP route in a file
    that also has an authenticated twin — the CVE-2026-33032 shape."""
    findings: list[Finding] = []
    if not hits:
        return findings
    auths = {h.route for h in hits if h.has_auth}
    # Authenticated anchors can be '/mcp' itself or any other MCP route
    # that has auth; any SIBLING MCP route without auth is the bug.
    has_any_authed = bool(auths)
    if not has_any_authed:
        return findings
    for hit in hits:
        if hit.has_auth:
            continue
        if hit.route in auths:
            continue
        findings.append(
            make_finding(
                "AAK-MCPWN-001",
                rel_path,
                f"MCP route {hit.route!r} has no auth middleware while a "
                f"sibling route ({sorted(auths)[0]!r}) is authenticated — "
                f"CVE-2026-33032 (MCPwn) shape.",
                line_number=hit.line,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# File dispatch
# ---------------------------------------------------------------------------


def _iter_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SCAN_EXTS:
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(path.relative_to(project_root))
    suffix = path.suffix.lower()
    go = suffix == ".go"
    index: CodeIndex | None = None
    findings: list[Finding] = []
    # Cheap short-circuit: AAK-MCPWN-001 needs the file to mention /mcp.
    if "/mcp" in text:
        if suffix == ".py":
            return _asymmetry_findings(_extract_fastapi(text), rel, text)
        index = CodeIndex(text, go=go)
        findings = _mcpwn_findings(index, go, rel)
    if suffix != ".py" and _reads_shared_handlers(rel, text, go):
        index = index or CodeIndex(text, go=go)
        findings.extend(_shared_handler_findings(index, rel, {f.line_number for f in findings if f.line_number}))
    if go and _reads_lookup_order(rel, text):
        index = index or CodeIndex(text, go=True)
        findings.extend(_lookup_before_auth_findings(index, rel))
    return findings


def _mcpwn_findings(index: CodeIndex, go: bool, rel: str) -> list[Finding]:
    hits = _route_hits(index, go)
    if not hits:
        return []

    # We deliberately do NOT widen the window to surrounding lines here.
    # A naive window pass turns every /mcp_message hit into has_auth=True
    # whenever its twin /mcp appears within ~5 lines — exactly the
    # MCPwn shape we want to detect. Gin's `router.Group("/x", mw)`
    # pattern is handled separately below.
    if go:
        group_prefixes = _gin_grouped_auth_prefixes(index)
        if group_prefixes:
            for i, hit in enumerate(hits):
                if hit.has_auth:
                    continue
                if any(
                    hit.route.startswith(prefix.rstrip("/")) or prefix == "/"
                    for prefix in group_prefixes
                ):
                    hits[i] = _RouteHit(hit.route, hit.line, hit.line_text, True)

    return _asymmetry_findings(hits, rel, index.text)


def _gin_grouped_auth_prefixes(index: CodeIndex) -> list[str]:
    """Return URL prefixes declared by a `g := router.Group(prefix, mw...)`
    call whose middleware arguments contain one of our auth markers.

    Catches the group form of a fix:

        mcpGroup := router.Group("/", AuthRequired())
        mcpGroup.POST("/mcp", h)
        mcpGroup.POST("/mcp_message", h)

    which is safe and should not fire AAK-MCPWN-001.
    """
    text = index.text
    prefixes: list[str] = []
    for m in _GIN_GROUP_HEAD_RE.finditer(text):
        if not index.in_code(m.start()):
            continue
        spans = [s for s in index.args(m.end() - 1) or [] if s[0] < s[1]]
        if len(spans) < 2 or text[spans[0][0]] != '"':
            continue
        prefix = index.string_literal(*spans[0])
        if prefix is None:
            continue
        parts = [text[s:min(e, s + _MARKER_WINDOW)] for s, e in spans[1:]]
        if any(marker in part for part in parts for marker in _AUTH_MARKERS):
            prefixes.append(prefix or "/")
    return prefixes


# ---------------------------------------------------------------------------
# AAK-MCP-020: one handler, two routes, authentication on only one of them
# ---------------------------------------------------------------------------
#
# AAK-MCPWN-001 above pairs routes by path: an MCP-looking path with no auth
# marker next to one with. What made nginx-ui exploitable was that both routes
# ran the same handler, `mcp.ServeHTTP(c)`, and only one carried
# `middleware.AuthRequired()`. This check pairs routes by what they reach
# instead: the same handler value, or inline handlers whose only statement is
# the same delegate call, registered on two routes in the same block, one with
# an authentication middleware (or wrapper) and one with none. The
# unauthenticated route then serves every tool its twin protects, whatever the
# two paths are called.
#
# Each condition is there because the corpus showed its absence firing on safe
# code:
#   - same block, different (method, path): the TypeScript SDK's example server,
#     copied widely, registers `app.post('/mcp', authMiddleware, h)` in an `if`
#     and `app.post('/mcp', h)` in its `else`;
#   - the unauthenticated route carries no middleware the check cannot name
#     (auth, or a known body parser, CORS, logger or rate limiter): an unknown
#     `checkKey` may well be the authentication;
#   - not covered by scope auth: `app.use('/mcp', auth)`, `r.Use(auth)`, a Gin
#     or echo group made with auth, or the mux handed to an auth wrapper,
#     wherever it appears in the file, since a route ordering argument is the
#     kind of reasoning a text check gets wrong;
#   - one of the two paths is an MCP endpoint, or an SSE/message path in a
#     file that builds an MCP server.
# A route AAK-MCPWN-001 already reports is left to it: two findings on one line
# would be one defect twice, and that rule is the one named for the CVE.

_MCP020 = "AAK-MCP-020"

_JS_ROUTE_HEAD_RE = re.compile(
    r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\("
)
_GO_SHARED_HEAD_RE = re.compile(
    r"(?<![\w.])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.("
    r"GET|POST|PUT|PATCH|DELETE|Any|Handle|HandleFunc|Get|Post|Put|Patch|Delete|Method|MethodFunc|Use|Group"
    r")\s*\("
)
_GO_GROUP_ASSIGN_RE = re.compile(r"(?<!\w)([A-Za-z_]\w*)\s*:?=\s*$")
# How far before a `.Group(` call its assignment (`g := r.Group(...)`) is looked
# for; gofmt writes it a few characters before. Searching the whole line before
# every call made a line of `g := r.Group();` calls quadratic: 128 KB took 13
# seconds.
_GROUP_ASSIGN_WINDOW = 200
_CALL_HEAD_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
_JS_ASYNC_RE = re.compile(r"async\b\s*")
_JS_FUNCTION_RE = re.compile(r"function\b\s*\*?\s*(?:[A-Za-z_$][\w$]*\s*)?(?=\()")
_JS_ARROW_PARAM_RE = re.compile(r"[A-Za-z_$][\w$]*\s*=>")
_GO_FUNC_LITERAL_RE = re.compile(r"func\s*(?=\()")
_BLANK_RE = re.compile(r"\s*")
_BIND_SUFFIX_RE = re.compile(r"\.bind\([^()]*\)$")
_SPACE_RE = re.compile(r"\s+")
_LEADING_KEYWORD_RE = re.compile(r"(?:return|await)\b\s*")
_DOTTED_RE = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")
_MCP_SERVER_HINT_RE = re.compile(
    r"modelcontextprotocol|McpServer|StreamableHTTPServerTransport|SSEServerTransport|mcp-go|"
    r"mcp\.NewServer|server\.NewMCPServer|FastMCP",
)
_SSE_PATH_RE = re.compile(r"/(?:sse|messages?|rpc)/?$", re.IGNORECASE)

_NOT_AUTH_RE = re.compile(
    r"(?:optional|skip|no|public|bypass|allow|maybe|soft)[-_]?auth|auth[-_]?(?:optional|skip|bypass)|unauth|csrf",
    re.IGNORECASE,
)
_AUTH_WORD_RE = re.compile(
    r"auth|jwt|bearer|token|api[-_]?key|passport|clerk|login|signature|hmac|protect|guard|permission"
    r"|scope|require[-_]?user",
    re.IGNORECASE,
)
_BENIGN_MW_RE = re.compile(
    r"^(?:express\.(?:json|raw|text|urlencoded)|bodyParser\.\w+|json|cors|helmet|compression|morgan"
    r"|cookieParser|gin\.Logger|gin\.Recovery|middleware\.(?:Logger|Recoverer|RequestID|RealIP|Recover|CORS\w*))\b"
    r"|rate[-_]?limit|limiter|throttle|logger|logging|requestlog|metrics|tracing|timeout"
    # An IP allowlist or an Origin check is not authentication: nginx-ui's
    # unauthenticated `/mcp_message` carried `middleware.IPWhiteList()`, and an
    # empty list let everyone in (AAK-MCP-012).
    r"|ip[-_]?(?:white|allow)[-_]?list|ipfilter|origin",
    re.IGNORECASE,
)
_GO_TRANSPARENT = frozenset({"http.HandlerFunc", "gin.WrapH", "gin.WrapF", "echo.WrapHandler", "http.StripPrefix"})


# A middleware or handler name is short; a longer argument is an inline function
# or a nested call, read no further than this so nested calls cost linear time.
_NAME_WINDOW = 200


def _classify(text: str) -> str:
    """'auth', 'benign' or 'unknown' for one middleware argument."""
    compact = _SPACE_RE.sub("", text[:_NAME_WINDOW])
    if _NOT_AUTH_RE.search(compact):
        return "unknown"
    if _AUTH_WORD_RE.search(compact):
        return "auth"
    if _BENIGN_MW_RE.search(compact):
        return "benign"
    return "unknown"


@dataclass(frozen=True)
class _Reg:
    """One route registration, reduced to what the pairing needs."""

    receiver: str
    method: str
    path: str
    handler: str | None
    auth: str | None
    unknown: bool
    block: int
    start: int
    line: int
    handler_at: int


_PARAM_NAME_RE = re.compile(r"\s*([A-Za-z_$][\w$]*)")


def _param_names(index: CodeIndex, start: int, end: int) -> set[str]:
    """Names declared in the parameter list ``start:end`` (destructuring skipped)."""
    text = index.text
    names: set[str] = set()
    bounds = [start] + [c for c in index.commas.get(start - 1, []) if c < end] + [end]
    for a, b in zip(bounds, bounds[1:]):
        m = _PARAM_NAME_RE.match(text, a + (1 if a != start else 0), b)
        if m is not None:
            names.add(m.group(1))
    return names


def _delegate(index: CodeIndex, start: int, end: int, params: set[str]) -> str | None:
    """`delegate:<callee>` when the code in ``start:end`` is one call statement
    (optionally awaited or returned) that hands the request on: some argument
    is one of ``params``, and the callee is not a method of one of them, so
    `res.json({...})` in two health checks is not one shared handler."""
    text = index.text
    pos = start
    while pos < end and text[pos].isspace():
        pos += 1
    while end > pos and (text[end - 1].isspace() or text[end - 1] == ";"):
        end -= 1
    keyword = _LEADING_KEYWORD_RE.match(text, pos, end)
    while keyword is not None and keyword.end() > pos:
        pos = keyword.end()
        keyword = _LEADING_KEYWORD_RE.match(text, pos, end)
    callee = _DOTTED_RE.match(text, pos, end)
    if callee is None or callee.group().split(".", 1)[0] in params:
        return None
    paren = callee.end()
    while paren < end and text[paren].isspace():
        paren += 1
    if paren >= end or text[paren] != "(" or index.close.get(paren) != end - 1:
        return None
    for s, e in index.args(paren) or []:
        arg = _DOTTED_RE.match(text, s, e)
        if arg is not None and arg.group().split(".", 1)[0] in params:
            return "delegate:" + callee.group()
    return None


def _skip_blank(text: str, pos: int, end: int) -> int:
    m = _BLANK_RE.match(text, pos, end)
    return m.end() if m else pos


def _inline_body(
    index: CodeIndex, start: int, end: int, go: bool,
) -> tuple[bool, tuple[int, int] | None, set[str]]:
    """(is an inline function, its body span, its parameter names) for the
    argument ``start:end``.

    Arrows and `function` expressions in TS/JS, func literals in Go. An arrow
    with an expression body (`(c) => transport.handleRequest(c)`) has that
    expression as its body. A literal whose brackets do not close is inline
    with no body to read. An arrow's `=>`, and a function's `{`, are looked for
    within `_NAME_WINDOW` characters of its parameter list, where they stand
    (a return type comes between): searching to the end of the argument read
    the routes nested in it once per level, 5.8 seconds of CPU at 511 KB.
    """
    text = index.text
    pos = _skip_blank(text, start, end)
    params: set[str] = set()
    if go:
        lit = _GO_FUNC_LITERAL_RE.match(text, pos, end)
        if lit is None:
            return False, None, params
        close = index.close.get(lit.end())
        if close is not None:
            params = _param_names(index, lit.end() + 1, close)
    else:
        a = _JS_ASYNC_RE.match(text, pos, end)
        if a is not None:
            pos = a.end()
        fn = _JS_FUNCTION_RE.match(text, pos, end)
        if fn is not None:
            close = index.close.get(fn.end())
            if close is not None:
                params = _param_names(index, fn.end() + 1, close)
        else:
            if text.startswith("(", pos):
                close = index.close.get(pos)
                if close is None or close >= end:
                    return False, None, params
                arrow = text.find("=>", close, min(end, close + _NAME_WINDOW))
                between = text[close + 1:arrow] if arrow >= 0 else ""
                if arrow < 0 or any(c in between for c in "({;"):
                    return False, None, params
                params = _param_names(index, pos + 1, close)
                pos = arrow + 2
            else:
                param = _JS_ARROW_PARAM_RE.match(text, pos, end)
                if param is None:
                    return False, None, params
                params = {param.group()[:-2].strip()}
                pos = param.end()
            pos = _skip_blank(text, pos, end)
            if not text.startswith("{", pos):
                return True, (pos, end), params
            body_close = index.close.get(pos)
            return True, ((pos + 1, body_close) if body_close is not None else None), params
    if close is None:
        return True, None, params
    brace = text.find("{", close, min(end, close + _NAME_WINDOW))
    body_close = index.close.get(brace) if brace >= 0 else None
    return True, ((brace + 1, body_close) if body_close is not None else None), params


def _handler_identity(index: CodeIndex, start: int, end: int, go: bool) -> tuple[str | None, str | None]:
    """(identity, auth wrapper) of a handler argument.

    An inline handler is identified by its delegate call, and is not comparable
    when it does more than that. `auth(h)` and `withAuth(h)` are the handler
    `h` behind an auth wrapper; `http.HandlerFunc(h)` and `gin.WrapH(h)` are
    `h`; `this.h.bind(this)` is `this.h`. Any other call stays as written, so
    two routes that both pass `asyncHandler(h)` still match each other.
    """
    text = index.text
    inline, body, params = _inline_body(index, start, end, go)
    if inline:
        return (_delegate(index, *body, params) if body else None), None
    if end - start > _NAME_WINDOW:
        return None, None
    # Each step unwraps one call and leaves a shorter span, so the loop ends.
    wrapper: str | None = None
    while True:
        callee = _DOTTED_RE.match(text, start, end)
        if callee is None or callee.end() >= end or text[callee.end()] != "(":
            break
        paren = callee.end()
        if index.close.get(paren) != end - 1:
            break
        spans = index.args(paren) or []
        name = callee.group()
        if name in _GO_TRANSPARENT and spans:
            start, end = spans[-1]
            continue
        if len(spans) == 1 and _classify(name) == "auth":
            wrapper = name
            start, end = spans[0]
            continue
        break
    ident = _BIND_SUFFIX_RE.sub("", _SPACE_RE.sub("", text[start:end]))
    return (ident or None), wrapper


_Scope = tuple[str, "str | None", str]


def _js_registrations(index: CodeIndex) -> tuple[list[_Reg], list[_Scope]]:
    """Routes, and scope auth as (receiver, path prefix or None, middleware).

    `app.use(auth)` covers every route on `app`, `app.use('/mcp', auth)` every
    route under `/mcp`, and `app.use('/api', auth, router)` every route on
    `router`. Scope auth counts wherever it sits in the file: whether it runs
    before a route depends on registration order, which is not worth guessing.
    """
    text = index.text
    regs: list[_Reg] = []
    scopes: list[_Scope] = []
    for call in find_calls(index, _JS_ROUTE_HEAD_RE):
        spans = [s for s in call.args if s[0] < s[1]]
        if not spans:
            continue
        path = index.string_literal(*spans[0])
        if call.method == "use":
            rest = spans[1:] if path is not None else spans
            names = [text[s:min(e, s + _NAME_WINDOW)].strip() for s, e in rest]
            auth = next((n for n in names if _classify(n) == "auth"), None)
            if auth is not None:
                scopes.append((call.receiver, path, auth))
                scopes.extend((n, None, auth) for n in names if n != auth and _DOTTED_RE.fullmatch(n))
            continue
        if path is None or len(spans) < 2:
            continue
        handler, wrapper = _handler_identity(index, *spans[-1], go=False)
        middleware = [text[s:min(e, s + _NAME_WINDOW)] for s, e in spans[1:-1]]
        regs.append(_reg(call.receiver, call.method.upper(), path, handler, wrapper, middleware, call, index, spans[-1][0]))
    return regs, scopes


def _reg(
    receiver: str, method: str, path: str, handler: str | None, wrapper: str | None,
    middleware: list[str], call: Call, index: CodeIndex, handler_at: int,
) -> _Reg:
    kinds = [_classify(m) for m in middleware]
    auth = wrapper or next((m for m, k in zip(middleware, kinds) if k == "auth"), None)
    return _Reg(
        receiver, method, path, handler, auth, "unknown" in kinds,
        index.block_of.get(call.paren, -1), call.start, index.line_of(call.start), handler_at,
    )


_GO_METHOD_LITERALS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


def _go_registrations(index: CodeIndex, echo: bool) -> tuple[list[_Reg], list[_Scope]]:
    """Routes and scope auth for gin, echo, chi and net/http.

    gin takes (path, middleware..., handler), echo (path, handler,
    middleware...), chi and net/http (path, handler) with middleware as
    wrappers. Scope auth: `r.Use(auth)`, a group made with auth (`g :=
    r.Group("/x", auth)`, and the groups made from it), and a mux handed to an
    auth wrapper anywhere in the file (`http.ListenAndServe(addr, auth(mux))`).
    """
    text = index.text
    regs: list[_Reg] = []
    scopes: list[_Scope] = []
    parents: dict[str, str] = {}
    for call in find_calls(index, _GO_SHARED_HEAD_RE):
        spans = [s for s in call.args if s[0] < s[1]]
        if call.method in ("Use", "Group"):
            rest = spans[1:] if call.method == "Group" else spans
            auth = next((text[s:e] for s, e in rest if e - s <= _NAME_WINDOW and _classify(text[s:e]) == "auth"), None)
            target = call.receiver
            if call.method == "Group":
                window = max(0, call.start - _GROUP_ASSIGN_WINDOW)
                line_start = max(window, text.rfind("\n", window, call.start) + 1)
                assigned = _GO_GROUP_ASSIGN_RE.search(text, line_start, call.start)
                if assigned is None:
                    continue
                target = assigned.group(1)
                parents[target] = call.receiver
            if auth is not None:
                scopes.append((target, None, auth))
            continue
        if call.method in ("Method", "MethodFunc", "Handle") and spans and (
            index.string_literal(*spans[0]) in _GO_METHOD_LITERALS
        ):
            spans = spans[1:]
        path = index.string_literal(*spans[0]) if spans else None
        if path is None or len(spans) < 2:
            continue
        if echo:
            handler_span, middleware_spans = spans[1], spans[2:]
        else:
            handler_span, middleware_spans = spans[-1], spans[1:-1]
        handler, wrapper = _handler_identity(index, *handler_span, go=True)
        method = call.method.upper() if call.method not in ("Handle", "HandleFunc", "Any") else "ANY"
        middleware = [text[s:min(e, s + _NAME_WINDOW)] for s, e in middleware_spans]
        regs.append(_reg(call.receiver, method, path, handler, wrapper, middleware, call, index, handler_span[0]))
    for m in _CALL_HEAD_RE.finditer(text):
        if not index.in_code(m.start()) or _classify(m.group(1)) != "auth":
            continue
        for s, e in index.args(m.end() - 1) or []:
            if e - s <= _NAME_WINDOW and _DOTTED_RE.fullmatch(text[s:e]):
                scopes.append((text[s:e], None, m.group(1)))
    scopes.extend(_inherited_group_auth(scopes, parents))
    return regs, scopes


def _inherited_group_auth(scopes: list[_Scope], parents: dict[str, str]) -> list[_Scope]:
    """The groups made, at any depth, from a router or group with scope auth,
    each with that auth. Each group's chain of parents is walked until it meets
    an authenticated receiver, a group already resolved, or a cycle
    (`g := g.Group(...)`), and every group on the way takes the answer, so each
    is resolved once. Passing auth down a fixed four levels reported a route
    five groups below an authenticated one."""
    authed = {receiver: auth for receiver, _prefix, auth in scopes}
    resolved: dict[str, str | None] = {}
    for group in parents:
        chain: list[str] = []
        on_chain: set[str] = set()
        node = group
        while node not in resolved and node not in authed and node in parents and node not in on_chain:
            chain.append(node)
            on_chain.add(node)
            node = parents[node]
        auth = resolved[node] if node in resolved else authed.get(node)
        for g in chain:
            resolved[g] = auth
    return [(g, None, auth) for g, auth in resolved.items() if auth is not None]


class _Scopes:
    """Scope auth, indexed by receiver, so a route is checked in time linear in
    its path rather than against every scope in the file.

    A scope with no prefix, or one that strips to nothing (`app.use("/*",
    auth)`), covers its receiver whole. Any other covers a route whose path is
    the prefix or continues it past a `/`; the prefixes of one receiver sit in
    a character trie, walked once along the route's path.
    """

    def __init__(self, scopes: list[_Scope]) -> None:
        self._whole: set[str] = set()
        self._tries: dict[str, dict[str, Any]] = {}
        for receiver, prefix, _auth in scopes:
            base = None if prefix is None else prefix.rstrip("*").rstrip("/")
            if not base:
                self._whole.add(receiver)
                continue
            node = self._tries.setdefault(receiver, {})
            for ch in base:
                node = node.setdefault(ch, {})
            node[""] = True

    def cover(self, reg: _Reg) -> bool:
        if reg.receiver in self._whole:
            return True
        node: dict[str, Any] | None = self._tries.get(reg.receiver)
        if node is None:
            return False
        for ch in reg.path:
            if ch == "/" and "" in node:
                return True
            node = node.get(ch)
            if node is None:
                return False
        return "" in node


class _Twins:
    """The first of a group's authenticated routes and the first after it on
    another (method, path): between them, the first twin for any route."""

    def __init__(self, routes: list[_Reg]) -> None:
        self._first = routes[0] if routes else None
        key = (routes[0].method, routes[0].path) if routes else None
        self._other = next((r for r in routes if (r.method, r.path) != key), None)

    def twin_for(self, reg: _Reg) -> _Reg | None:
        if self._first is None or (self._first.method, self._first.path) != (reg.method, reg.path):
            return self._first
        return self._other


def _shared_handler_findings(index: CodeIndex, rel: str, mcpwn_lines: set[int]) -> list[Finding]:
    """AAK-MCP-020 in one file, in time linear in its routes.

    Each open route takes the first authenticated route of its group on another
    (method, path), where at least one of the two is an MCP endpoint. Searching
    the group's authenticated routes for each open one took 6.6 seconds on
    8,300 routes of one handler; the first such route is one of two fixed
    candidates (`_Twins`), among all of them or among those on an MCP endpoint.
    """
    text = index.text
    go = rel.endswith(".go")
    if go:
        regs, scopes = _go_registrations(index, echo='"github.com/labstack/echo' in text)
    else:
        regs, scopes = _js_registrations(index)
    covered = _Scopes(scopes)
    server_file = bool(_MCP_SERVER_HINT_RE.search(text))
    mcp_paths: dict[str, bool] = {}

    def mcp_side(path: str) -> bool:
        if path not in mcp_paths:
            mcp_paths[path] = is_mcp_endpoint_path(path) or bool(server_file and _SSE_PATH_RE.search(path))
        return mcp_paths[path]

    groups: dict[tuple[str, int], list[_Reg]] = {}
    for reg in regs:
        if reg.handler is not None:
            groups.setdefault((reg.handler, reg.block), []).append(reg)
    findings: list[Finding] = []
    for (handler, _block), members in groups.items():
        authed = [r for r in members if r.auth is not None]
        if not authed:
            continue
        any_twin = _Twins(authed)
        mcp_twin = _Twins([r for r in authed if mcp_side(r.path)])
        for open_reg in members:
            if open_reg.auth is not None or open_reg.unknown or open_reg.line in mcpwn_lines:
                continue
            if covered.cover(open_reg):
                continue
            twin = (any_twin if mcp_side(open_reg.path) else mcp_twin).twin_for(open_reg)
            if twin is None:
                continue
            findings.append(make_finding(
                _MCP020,
                rel,
                f"{open_reg.method} {open_reg.path!r} runs {_named(handler.split(':', 1)[-1], 'the shared handler')} "
                f"with no authentication, while {twin.method} {twin.path!r} (line {twin.line}) runs the same "
                f"handler behind {_named(twin.auth or '', 'an inline middleware')}",
                line_number=open_reg.line,
            ))
    return findings


def _named(code: str, otherwise: str) -> str:
    """How the evidence names a middleware or a handler: its name, with `()` or
    `(...)` for a call, and never its arguments, which can hold a credential
    (`gin.BasicAuth(gin.Accounts{"admin": "<password>"})` and express-basic-auth
    carried the password into every output). ``otherwise`` describes code that
    does not start with a name, such as an inline function: an `async` arrow
    or a `function` expression is one too, not a call to `async(...)`."""
    code = code.strip()
    name = _DOTTED_RE.match(code)
    if name is None or name.group() in ("async", "function"):
        return otherwise
    rest = code[name.end():].lstrip()
    if not rest:
        return f"`{name.group()[:80]}`"
    if rest.startswith("("):
        args = "()" if rest[1:].lstrip().startswith(")") else "(...)"
        return f"`{name.group()[:80]}{args}`"
    return otherwise


def _reads_shared_handlers(rel: str, text: str, go: bool) -> bool:
    """Whether AAK-MCP-020 reads this file: not a test file or a Go file that
    starts an `httptest` server, and it mentions MCP and registers a route."""
    if TEST_FILE_RE.search(Path(rel).as_posix()) or "mcp" not in text.lower():
        return False
    if go:
        return bool(_GO_SHARED_HEAD_RE.search(text)) and not GO_TEST_SERVER_RE.search(text)
    return bool(_JS_ROUTE_HEAD_RE.search(text))


# ---------------------------------------------------------------------------
# AAK-MCP-019: a lookup keyed on the caller's input, answered before the auth check
# ---------------------------------------------------------------------------
#
# The rule claims work done before the authentication check. The corpus held
# one shape of it, and this check reads only that shape: a Go MCP handler looks
# something up by what the caller sent (a path, query or form parameter),
# answers a miss with "not found" in the very next statement, and only later
# checks the caller's credential and answers 401 or 403. A caller with no
# credential tells the two answers apart and learns which names exist, and the
# lookup runs for anyone. SUSE/suse-ai-up's uniproxy is the real case: six REST
# MCP endpoints look the adapter up by the name in the path, answer 404 for an
# unknown one, and only then check that adapter's authentication.
#
# Each condition is there because a broader reading fired on safe code:
#   - the lookup's key comes from the request: `config.Get()` before a token
#     check reads the server's own settings (oawbz/filemanager);
#   - the gate calls a function named for authentication with the request: a
#     forwarding proxy that relays its upstream's 401 checks no credential of
#     the caller's (SUSE's own proxy.go);
#   - the handler is registered in the same file, on a route with no auth
#     middleware or wrapper and no group or router-wide auth: behind
#     middleware, the lookup runs after authentication.
# Only the handler's own statements are read (nested blocks are skipped), and
# each `if` is read for a bounded window, so nested handlers cost linear time.

_MCP019 = "AAK-MCP-019"
# A mention of MCP: the name, or a method only MCP has. `jsonrpc` is not one: a
# JSON-RPC wallet API is not an MCP server.
_MCP_MENTION_RE = re.compile(r"mcp|tools/(?:call|list)", re.IGNORECASE)
_NOT_FOUND_RE = re.compile(r"StatusNotFound|\b404\b|\bNotFound\(")
_DENIED_RE = re.compile(r"StatusUnauthorized|StatusForbidden|\b40[13]\b")
# A request value read by name: gin and echo `c.Param("id")`, `c.Query(...)`,
# net/http `r.PathValue(...)`, `r.URL.Query().Get(...)`, gorilla `mux.Vars(r)`,
# chi `chi.URLParam(r, ...)`. The receiver must be the handler's request.
_INPUT_READ_WORDS = (
    ".Param(", ".Query(", ".DefaultQuery(", ".PostForm(", ".QueryParam(", ".FormValue(", ".PathValue(",
    ".URL.Query()", "mux.Vars(", "chi.URLParam(", ".Params.ByName(",
)
_INPUT_CALL = (
    r"(?:(\w+)\.(?:Param|Query|DefaultQuery|PostForm|QueryParam|FormValue|PathValue|Params\.ByName"
    r"|URL\.Query\(\)\.Get)\(|(?:mux\.Vars|chi\.URLParam)\(\s*(\w+))"
)
_INPUT_ASSIGN_RE = re.compile(r"(?<![\w.])(\w+)\s*:?=\s*" + _INPUT_CALL)
_INPUT_EXPR_RE = re.compile(r"(?<![\w.])" + _INPUT_CALL)
_LOOKUP_VERB_RE = re.compile(
    r"Get|GetBy\w*|Find\w*|Lookup\w*|Load\w*|Fetch\w*|Read\w*|Query\w*|First|Retrieve\w*|Resolve\w*"
)
# A call on a receiver (`store.Get(`): a bare function call is not a lookup here.
_METHOD_CALL_RE = re.compile(r"(?<![\w.])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*\(")
_GO_CALL_RE = re.compile(r"(?<![\w.])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(")
_IF_LINE_RE = re.compile(r"[ \t]*(?:\}[ \t]*else[ \t]+)?(if)\b")
_WORD_RE = re.compile(r"\w+")
_GATE_AUTH_RE = re.compile(r"auth|credential|token|api_?key|bearer|permission|signature|jwt", re.IGNORECASE)
_NOT_LOOKUP_ROOTS = frozenset({
    "bytes", "context", "errors", "filepath", "fmt", "http", "io", "json", "log", "math", "os", "path",
    "regexp", "sort", "strconv", "strings", "sync", "time", "url",
})
# An `if` header is short, and an `if` is read for its first 1,000 characters:
# a gate's auth call and its 401 or 403, a miss's not-found answer and its
# `return`. Searching a whole block let nested handlers, each in the block of
# the one around it, read the file once per level.
_IF_HEADER_WINDOW = 400
_IF_WINDOW = 1000
_LINE_WINDOW = 200


@dataclass(frozen=True)
class _If:
    at: int
    block: int
    close: int


def _own_statements(index: CodeIndex, body: int, end: int) -> tuple[list[tuple[int, int]], dict[int, int]]:
    """The text ranges of a body's own statements, and its nested blocks
    (outermost only) as {open: close}: everything outside them."""
    text = index.text
    ranges: list[tuple[int, int]] = []
    blocks: dict[int, int] = {}
    start = search = body + 1
    while search < end:
        brace = text.find("{", search, end)
        if brace < 0:
            break
        close = index.close.get(brace)
        if close is None or close > end or not index.in_code(brace):
            search = brace + 1
            continue
        ranges.append((start, brace))
        blocks[brace] = close
        start = search = close + 1
    ranges.append((start, end))
    return ranges, blocks


def _own_ifs(index: CodeIndex, blocks: dict[int, int]) -> list[_If]:
    """Each `if` among the body's own statements, with its block: a nested
    block whose line opens with `if` (gofmt puts the `{` on the `if`'s line)."""
    text = index.text
    ifs: list[_If] = []
    for block, close in blocks.items():
        line_start = text.rfind("\n", max(0, block - _IF_HEADER_WINDOW), block) + 1
        head = _IF_LINE_RE.match(text, line_start, block) if line_start else None
        if head is not None and index.in_code(head.start(1)):
            ifs.append(_If(head.start(1), block, close))
    return ifs


def _input_key(index: CodeIndex, paren: int, inputs: set[str], request: str) -> str | None:
    """The argument of the call at ``paren`` that the caller supplied, if any."""
    text = index.text
    for s, e in index.args(paren) or []:
        e = min(e, s + _NAME_WINDOW)
        root = _DOTTED_RE.match(text, s, e)
        if root is not None and root.group().split(".", 1)[0] in inputs:
            return root.group()
        expr = _INPUT_EXPR_RE.search(text, s, e)
        if expr is not None and request in (expr.group(1), expr.group(2)):
            return _input_read(index, expr)
    return None


def _input_read(index: CodeIndex, expr: re.Match[str]) -> str:
    """The request read an argument holds, as the evidence shows it:
    `c.Param("name")`, keeping one short string argument and showing any other
    as `(...)`. The rest of the argument stays out of the evidence: quoting it
    whole put a signing key passed beside the caller's input
    (`sign(c.Param("name"), "<key>")`) into every output. A read with more
    than one argument is `(...)` before its arguments are listed: listing
    them once per lookup that reaches the read was quadratic in a read of
    250,000 arguments under 33 nested lookups."""
    text = index.text
    paren = expr.end() - 1 if expr.group(1) is not None else text.index("(", expr.start())
    callee = text[expr.start():paren]
    if index.commas.get(paren):
        return f"{callee}(...)"
    args = index.args(paren) or []
    if len(args) == 1:
        literal = index.string_literal(*args[0])
        if literal is not None and len(literal) <= 40:
            return f"{callee}({text[args[0][0]:args[0][1]]})"
    return f"{callee}(...)"


def _miss_answer(
    index: CodeIndex, start: int, paren: int, ifs: list[_If], ats: list[int], by_at: dict[int, int],
) -> int | None:
    """The index in ``ifs`` of the `if` that answers the lookup at ``start``
    with "not found": the `if` whose header holds the lookup, or the one on
    the next line that tests a name the lookup assigned."""
    text = index.text
    pos = bisect_right(ats, start) - 1
    if pos >= 0 and ifs[pos].block > start:
        found = pos
    else:
        close = index.close.get(paren)
        line_start = text.rfind("\n", max(0, start - _LINE_WINDOW), start) + 1
        if close is None or not line_start:
            return None
        newline = text.find("\n", close, close + _LINE_WINDOW)
        if newline < 0 or text[close + 1:newline].strip():
            return None
        nxt = by_at.get(_skip_blank(text, newline, min(len(text), newline + _LINE_WINDOW)))
        if nxt is None:
            return None
        assigned = set(_WORD_RE.findall(text, line_start, start))
        if not assigned & set(_WORD_RE.findall(text, ifs[nxt].at, ifs[nxt].block)):
            return None
        found = nxt
    branch = ifs[found]
    window = min(branch.close, branch.at + _IF_WINDOW)
    if not _NOT_FOUND_RE.search(text, branch.block, window) or text.find("return", branch.block, window) < 0:
        return None
    return found


def _is_gate(index: CodeIndex, branch: _If, request: str) -> bool:
    """An `if` that calls a function named for authentication with the request
    (or a value read from it) and answers 401 or 403."""
    text = index.text
    window = min(branch.close, branch.at + _IF_WINDOW)
    if not _DENIED_RE.search(text, branch.block, window):
        return False
    for m in _GO_CALL_RE.finditer(text, branch.at, window):
        if not _GATE_AUTH_RE.search(m.group(1)) or _NOT_AUTH_RE.search(m.group(1)):
            continue
        for s, e in index.args(m.end() - 1) or []:
            arg = _DOTTED_RE.match(text, s, min(e, s + _NAME_WINDOW))
            if arg is not None and arg.group().split(".", 1)[0] == request:
                return True
    return False


def _lookup_before_auth(index: CodeIndex, handler: GoHandler) -> tuple[int, str, str, int, int] | None:
    """(offset, lookup, key, not-found line, gate line) of the first lookup in
    the handler that the caller's input keys and that is answered before any
    authentication gate."""
    text = index.text
    ranges, blocks = _own_statements(index, handler.body_start, handler.body_end)
    ifs = _own_ifs(index, blocks)
    if not ifs:
        return None
    ats = [branch.at for branch in ifs]
    by_at = {at: i for i, at in enumerate(ats)}
    inputs = {
        m.group(1)
        for a, b in ranges
        for m in _INPUT_ASSIGN_RE.finditer(text, a, b)
        if handler.request in (m.group(2), m.group(3))
    }
    first_gate: int | None = None
    checked = 0
    for a, b in ranges:
        for m in _METHOD_CALL_RE.finditer(text, a, b):
            callee = m.group(1)
            root, _, verb = callee.rpartition(".")
            first = root.split(".", 1)[0]
            if first in _NOT_LOOKUP_ROOTS or first == handler.request or not _LOOKUP_VERB_RE.fullmatch(verb):
                continue
            if not index.in_code(m.start()):
                continue
            paren = m.end() - 1
            key = _input_key(index, paren, inputs, handler.request)
            if key is None:
                continue
            miss = _miss_answer(index, m.start(), paren, ifs, ats, by_at)
            if miss is None:
                continue
            while first_gate is None and checked < len(ifs):
                if _is_gate(index, ifs[checked], handler.request):
                    first_gate = checked
                checked += 1
            if first_gate is None or first_gate <= miss:
                return None
            return (m.start(), callee, key, index.line_of(ifs[miss].at), index.line_of(ifs[first_gate].at))
    return None


def _lookup_before_auth_findings(index: CodeIndex, rel: str) -> list[Finding]:
    text = index.text
    regs, scopes = _go_registrations(index, echo='"github.com/labstack/echo' in text)
    covered = _Scopes(scopes)
    by_name: dict[str, list[_Reg]] = {}
    by_at: dict[int, list[_Reg]] = {}
    for reg in regs:
        if reg.handler is not None:
            by_name.setdefault(_handler_name(reg.handler), []).append(reg)
        by_at.setdefault(reg.handler_at, []).append(reg)
    # Whether every route naming a handler is open, decided once per name: Go
    # methods on different receivers share names (every `ServeHTTP`), and
    # checking a name's routes for each method of that name made 8,500 methods
    # named `h` take 6.5 seconds.
    open_names = {name: _all_open(routes, covered) for name, routes in by_name.items()}
    mentions = [m.start() for m in _MCP_MENTION_RE.finditer(text)]
    findings: list[Finding] = []
    for handler in go_handlers(index):
        if handler.name is None:
            routes = by_at.get(handler.start, [])
            if not _all_open(routes, covered):
                continue
        elif not open_names.get(handler.name):
            continue
        near = bisect_right(mentions, handler.body_end) - bisect_right(mentions, handler.body_start)
        if not near and not (handler.name and _MCP_MENTION_RE.search(handler.name)):
            continue
        found = _lookup_before_auth(index, handler)
        if found is None:
            continue
        offset, lookup, key, miss_line, gate_line = found
        label = handler.name or f"the handler for {by_at[handler.start][0].method} {by_at[handler.start][0].path!r}"
        findings.append(make_finding(
            _MCP019,
            rel,
            f"{label} looks up `{lookup}` by the caller's `{key[:60]}` and answers not found "
            f"(line {miss_line}) before it checks the caller's credential (line {gate_line}), so a "
            "caller with no credential learns which names exist",
            line_number=index.line_of(offset),
        ))
    return findings


def _handler_name(identity: str) -> str:
    """The name a route's handler has where it is defined: the last part of a
    method value or a call through a receiver (`s.listMCPTools`,
    `delegate:h.listMCPTools`), as AAK-MCP-016 matches a handler by any word of
    its route. Keyed as written, a struct-based server's routes reached no
    handler at all."""
    identity = identity.split(":", 1)[-1]
    return identity.rsplit(".", 1)[-1] if _DOTTED_RE.fullmatch(identity) else identity


def _all_open(routes: list[_Reg], covered: _Scopes) -> bool:
    """At least one route, and none with auth on it or on its router."""
    return bool(routes) and not any(r.auth is not None or covered.cover(r) for r in routes)


def _reads_lookup_order(rel: str, text: str) -> bool:
    """Whether AAK-MCP-019 reads this Go file."""
    if TEST_FILE_RE.search(Path(rel).as_posix()) or GO_TEST_SERVER_RE.search(text):
        return False
    if not _MCP_MENTION_RE.search(text) or not any(word in text for word in _INPUT_READ_WORDS):
        return False
    return bool(_NOT_FOUND_RE.search(text)) and bool(_DENIED_RE.search(text))


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned


# find_line_number is imported but unused; keep the import for parity with
# other scanners in the package.
_ = find_line_number
