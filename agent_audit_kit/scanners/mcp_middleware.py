"""MCP route rules: twin-route asymmetry (AAK-MCPWN-001) and one handler on an
authenticated and an unauthenticated route (AAK-MCP-020).

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
doesn't. AAK-MCP-020, at the end of this module, pairs routes by the handler
they reach instead of by their paths.

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
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, in_skip_dir
from agent_audit_kit.scanners._http_routes import (
    GO_TEST_SERVER_RE,
    TEST_FILE_RE,
    Call,
    CodeIndex,
    find_calls,
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
    with no body to read.
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
                arrow = text.find("=>", close, end)
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
    brace = text.find("{", close, end)
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
    wrapper: str | None = None
    for _ in range(4):
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
        regs.append(_reg(call.receiver, call.method.upper(), path, handler, wrapper, middleware, call, index))
    return regs, scopes


def _reg(
    receiver: str, method: str, path: str, handler: str | None, wrapper: str | None,
    middleware: list[str], call: Call, index: CodeIndex,
) -> _Reg:
    kinds = [_classify(m) for m in middleware]
    auth = wrapper or next((m for m, k in zip(middleware, kinds) if k == "auth"), None)
    return _Reg(
        receiver, method, path, handler, auth, "unknown" in kinds,
        index.block_of.get(call.paren, -1), call.start, index.line_of(call.start),
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
                line_start = text.rfind("\n", 0, call.start) + 1
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
        regs.append(_reg(call.receiver, method, path, handler, wrapper, middleware, call, index))
    for m in _CALL_HEAD_RE.finditer(text):
        if not index.in_code(m.start()) or _classify(m.group(1)) != "auth":
            continue
        for s, e in index.args(m.end() - 1) or []:
            if e - s <= _NAME_WINDOW and _DOTTED_RE.fullmatch(text[s:e]):
                scopes.append((text[s:e], None, m.group(1)))
    for _ in range(4):
        authed = {receiver: auth for receiver, _prefix, auth in scopes}
        inherited = [(g, None, authed[p]) for g, p in parents.items() if p in authed and g not in authed]
        if not inherited:
            break
        scopes.extend(inherited)
    return regs, scopes


def _covered(reg: _Reg, scopes: list[_Scope]) -> bool:
    for receiver, prefix, _auth in scopes:
        if receiver != reg.receiver:
            continue
        if prefix is None:
            return True
        base = prefix.rstrip("*").rstrip("/")
        if not base or reg.path == base or reg.path.startswith(base + "/"):
            return True
    return False


def _shared_handler_findings(index: CodeIndex, rel: str, mcpwn_lines: set[int]) -> list[Finding]:
    text = index.text
    go = rel.endswith(".go")
    if go:
        regs, scopes = _go_registrations(index, echo='"github.com/labstack/echo' in text)
    else:
        regs, scopes = _js_registrations(index)
    server_file = bool(_MCP_SERVER_HINT_RE.search(text))
    groups: dict[tuple[str, int], list[_Reg]] = {}
    for reg in regs:
        if reg.handler is not None:
            groups.setdefault((reg.handler, reg.block), []).append(reg)
    findings: list[Finding] = []
    for (handler, _block), members in groups.items():
        authed = [r for r in members if r.auth is not None]
        if not authed:
            continue
        for open_reg in members:
            if open_reg.auth is not None or open_reg.unknown or open_reg.line in mcpwn_lines:
                continue
            if _covered(open_reg, scopes):
                continue
            twin = next((
                t for t in authed
                if (t.method, t.path) != (open_reg.method, open_reg.path)
                and any(
                    is_mcp_endpoint_path(p) or (server_file and _SSE_PATH_RE.search(p))
                    for p in (t.path, open_reg.path)
                )
            ), None)
            if twin is None:
                continue
            shown = handler.split(":", 1)[-1] if handler.startswith("delegate:") else handler
            findings.append(make_finding(
                _MCP020,
                rel,
                f"{open_reg.method} {open_reg.path!r} runs `{shown[:80]}` with no authentication, "
                f"while {twin.method} {twin.path!r} (line {twin.line}) runs the same handler "
                f"behind `{_SPACE_RE.sub(' ', twin.auth or '')[:60]}`",
                line_number=open_reg.line,
            ))
    return findings


def _reads_shared_handlers(rel: str, text: str, go: bool) -> bool:
    """Whether AAK-MCP-020 reads this file: not a test file or a Go file that
    starts an `httptest` server, and it mentions MCP and registers a route."""
    if TEST_FILE_RE.search(Path(rel).as_posix()) or "mcp" not in text.lower():
        return False
    if go:
        return bool(_GO_SHARED_HEAD_RE.search(text)) and not GO_TEST_SERVER_RE.search(text)
    return bool(_JS_ROUTE_HEAD_RE.search(text))


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
