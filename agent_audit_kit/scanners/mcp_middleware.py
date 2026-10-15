"""MCPwn twin-route middleware-asymmetry scanner (AAK-MCPWN-001).

CVE-2026-33032 / MCPwn (nginx-ui, CVSS 9.8, KEV-listed 2026-04-13) was
caused by two routes sharing a handler but only one being wrapped in an
auth middleware. We detect that shape — "one route is authed, its twin
isn't" — across three stacks:

- **Go / Gin**: `router.POST("/mcp", AuthRequired(), h)` vs
  `router.POST("/mcp_message", h)`.
- **Python / FastAPI**: `@app.post("/mcp")` with `Depends(auth)` vs
  `@app.post("/mcp_message")` without.
- **Node / Express**: `app.post("/mcp", authMw, h)` vs
  `app.post("/mcp_message", h)`.

The detection is pragmatic (regex, not full AST): the shape is shallow
enough that a tree-sitter pass would buy little. False-positive rate
stays low because we only fire when two routes matching the MCP endpoint
pattern live in the same file and one has a recognised auth marker while
the other doesn't.

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


# The Gin, Express and group patterns start at a word run. A start inside the
# run reads the same run to the same end, so it fails wherever the run's first
# character failed; `(?<!\w)` keeps the matches and stops a long word with no
# `.` after it from being read once per character (20,000 characters took 1.05
# seconds, and the time grew with the square of the run). Each also reads its
# arguments to a `)`, so they run only up to the last `)` in the file: past it
# no match can end, and every call there read on to the end of the file.
_GIN_LINE_RE = re.compile(
    r"""(?<!\w)(?P<router>\w+)\.(?:Handle|POST|GET|PUT|DELETE|PATCH|Any)\s*\(
        \s*(?:"[A-Z]+"\s*,\s*)?                # optional HTTP method literal
        "(?P<route>/mcp(?:[_\-/](?:messages?|invoke|tool|msg))?)"
        \s*,\s*(?P<mw_and_handler>[^)]+)\)""",
    re.VERBOSE,
)


def _extract_gin(text: str) -> list[_RouteHit]:
    hits: list[_RouteHit] = []
    lineno, counted = 1, 0
    for m in _GIN_LINE_RE.finditer(text, 0, text.rfind(")") + 1):
        mw_segment = m.group("mw_and_handler")
        has_auth = any(marker in mw_segment for marker in _AUTH_MARKERS)
        line_text = text[m.start(): m.end()]
        lineno += text.count("\n", counted, m.start())
        counted = m.start()
        hits.append(_RouteHit(m.group("route"), lineno, line_text, has_auth))
    return hits


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


_EXPRESS_HEAD_RE = re.compile(
    r"""(?<!\w)(?P<app>\w+)\.(?:post|get|put|patch|delete|use|all)\s*\(
        \s*["'](?P<route>/mcp(?:[_\-/](?:messages?|invoke|tool|msg))?)["']
        \s*,(?P<pad>\s*)""",
    re.VERBOSE,
)


def _express_routes(text: str) -> Iterator[tuple[int, str, str]]:
    """(start, route, middleware and handler) of each Express MCP route: the
    matches of `<head>\\s*,\\s*(?P<mw_and_handler>[^;]+?)\\)`.

    The arguments run to the first `)` that no `;` precedes. A call with a `;`
    first fails, and so does every call between it and that `;`, which the
    pattern read to the same `;` once per call. Backing off the whitespace
    after the comma rescues only `, )`, which keeps the last space.
    """
    end = text.rfind(")") + 1
    pos = 0
    while True:
        m = _EXPRESS_HEAD_RE.search(text, pos, end)
        if m is None:
            return
        args = m.end()
        semi = text.find(";", args, end)
        stop = semi if semi >= 0 else end
        close = text.find(")", args + 1, stop)
        if close >= 0:
            yield m.start(), m.group("route"), text[args:close]
            pos = close + 1
        elif m.group("pad") and text.startswith(")", args):
            yield m.start(), m.group("route"), text[args - 1:args]
            pos = args + 1
        elif semi >= 0:
            pos = semi + 1
        else:
            return


def _extract_express(text: str) -> list[_RouteHit]:
    hits: list[_RouteHit] = []
    lineno, counted = 1, 0
    for start, route, mw_segment in _express_routes(text):
        has_auth = any(marker in mw_segment for marker in _AUTH_MARKERS)
        lineno += text.count("\n", counted, start)
        counted = start
        hits.append(_RouteHit(route, lineno, mw_segment, has_auth))
    return hits


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
    if suffix == ".go":
        hits = _extract_gin(text)
    elif suffix == ".py":
        hits = _extract_fastapi(text)
    else:
        hits = _extract_express(text)
    if not hits:
        return []

    # We deliberately do NOT widen the window to surrounding lines here.
    # A naive window pass turns every /mcp_message hit into has_auth=True
    # whenever its twin /mcp appears within ~5 lines — exactly the
    # MCPwn shape we want to detect. Gin's `router.Group("/x", mw)`
    # pattern is handled separately below.
    if suffix == ".go":
        group_prefixes = _gin_grouped_auth_prefixes(text)
        if group_prefixes:
            for i, hit in enumerate(hits):
                if hit.has_auth:
                    continue
                if any(
                    hit.route.startswith(prefix.rstrip("/")) or prefix == "/"
                    for prefix in group_prefixes
                ):
                    hits[i] = _RouteHit(hit.route, hit.line, hit.line_text, True)

    return _asymmetry_findings(hits, rel, text)


_GIN_GROUP_AUTHED_RE = re.compile(
    r"""(?<!\w)(?P<varname>\w+)\s*:=\s*\w+\.Group\s*\(\s*
        "(?P<prefix>[^"]*)"\s*,\s*(?P<mw>[^)]+)\)""",
    re.VERBOSE,
)


def _gin_grouped_auth_prefixes(text: str) -> list[str]:
    """Return URL prefixes declared by a `router.Group(prefix, mw)`
    call whose middleware argument contains one of our auth markers.

    Catches the nginx-ui 2.3.4 patched shape:

        mcpGroup := router.Group("/", AuthRequired())
        mcpGroup.POST("/mcp", h)
        mcpGroup.POST("/mcp_message", h)

    which is safe and should not fire AAK-MCPWN-001.
    """
    prefixes: list[str] = []
    for m in _GIN_GROUP_AUTHED_RE.finditer(text, 0, text.rfind(")") + 1):
        mw = m.group("mw")
        if any(marker in mw for marker in _AUTH_MARKERS):
            prefixes.append(m.group("prefix") or "/")
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
