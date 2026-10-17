"""MCPwn twin-route middleware-asymmetry scanner (AAK-MCPWN-001).

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
doesn't.

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
from agent_audit_kit.scanners._http_routes import CodeIndex, find_calls


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
    # Cheap short-circuit: file must at least mention /mcp.
    if "/mcp" not in text:
        return []
    rel = str(path.relative_to(project_root))
    suffix = path.suffix.lower()
    if suffix == ".py":
        return _asymmetry_findings(_extract_fastapi(text), rel, text)
    go = suffix == ".go"
    return _mcpwn_findings(CodeIndex(text, go=go), go, rel)


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
