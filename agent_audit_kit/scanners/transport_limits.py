"""Transport-layer resource-limit checks.

Home of AAK-MCPFRAME-001 — mcp-framework < 0.2.22 HTTP body-size DoS
(CVE-2026-39313). Two detections:

1. Pin-check on `package.json` for `mcp-framework` at any version below
   0.2.22 (and `next-ai-draw-io` below 0.4.15, AAK-NEXT-AI-DRAW-001). It took
   the first number of the range, so `"<0.2.22"`, which admits only affected
   releases, read as the fix and was silent; it is now read as the CVE pin
   table reads it (`_dependency_pins`).
2. Pattern-check on `.ts` / `.js` / `.mjs` / `.tsx` files where a
   readRequestBody-style chunk-concat accumulates body bytes into a
   string without consulting a `Content-Length` guard or a
   `maxMessageSize`-style cap. Separate pass so custom transports
   written on top of upstream SDKs still get flagged.
"""

from __future__ import annotations

import ast
import re
from bisect import bisect_left, bisect_right
from pathlib import Path
from typing import Iterable

from agent_audit_kit.models import Finding

from ._dependency_pins import DependencyPin, pinned_dependency, read_manifest
from ._helpers import (
    SOURCE_MAX_BYTES,
    blank_js_comments,
    find_line_number,
    in_skip_dir,
    make_finding,
    parse_python,
    read_text_capped,
    sub_comments,
)
from ._http_routes import (
    CodeIndex,
    GO_TEST_SERVER_RE,
    GoHandler,
    GoRoute,
    MCP_HANDSHAKE,
    MCP_METHODS,
    TEST_FILE_RE,
    go_handlers,
    go_routes,
    is_mcp_endpoint_path,
    py_routes,
)

_MCPFRAME_PATCHED = (0, 2, 22)
_NEXT_AI_DRAW_PATCHED = (0, 4, 15)

# An unreadable spec (`latest`, `*`, a local directory, a git reference to a
# commit or a branch) is reported, as the first-number reader always reported one.
_MCPFRAME_PIN = DependencyPin(("mcp-framework",), _MCPFRAME_PATCHED, ecosystem="js", report_unversioned=True)
_NEXT_AI_DRAW_PIN = DependencyPin(("next-ai-draw-io",), _NEXT_AI_DRAW_PATCHED, ecosystem="js",
                                  report_unversioned=True)

_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")

# Readable loosely: any `.on('data', ...)` or `for await (... of req)`
# block that concatenates into a string or an array without a running
# size guard. Deliberately literal so false positives don't explode.
#
# The handler arm read `[^)]*` up to the next `)` from every `req.on('data',`,
# so a file of them with no `)` read the rest of the file once per occurrence
# and stalled the scan. It now looks for that `)` within a fixed window. In a
# real handler it comes within a few characters (`(chunk) =>`, `function
# (chunk)`, `onData)`): at most 36 on 88,502 TS/JS files, so 1,024 changes no
# answer there and keeps the read per occurrence fixed.
_BODY_CONCAT_RE = re.compile(
    r"""
    (?:
        req\.on\(\s*['"]data['"]\s*,[^)]{0,1024}\)\s*  # req.on('data', handler)
      | for\s+await\s*\(\s*const\s+\w+\s+of\s+req(?:\.body)?\s*\)  # for await
    )
    """,
    re.VERBOSE,
)

# The `+=` arm used to end in `\s*;`, so a reader written without semicolons
# (StandardJS, or `{ body += chunk.toString() }`) was silent while
# `chunks.push(chunk)` in the same style was reported. It now ends at whatever
# ends the statement there: a `;`, a line break, or the `}` or `)` that closes
# the handler. The `.toString(...)` arguments are one character class rather
# than `[^)]*`, which read on to the next `)` from every `.toString(` and made a
# file of them quadratic. It is matched against the code with comments blanked
# (a comment after the statement hid its line break, and a commented-out one
# counted), and each name stands on its own, a leading underscore allowed
# (`this._body`), so `metadata += chunk` is not `data += chunk`.
_STR_ACCUMULATE_RE = re.compile(
    r"""
    (?:
        (?<![\w$])_?(?:body|data|buf|chunks)\s*\+=\s*\w+(?:\.toString\([\w'".,\s-]*\))?[ \t]*(?:[;})\r\n]|$)  # body += chunk
      | (?<![\w$])_?(?:body|data|buf|chunks)\.push\s*\(\s*\w+\s*\)                    # chunks.push(chunk)
    )
    """,
    re.VERBOSE,
)

_SIZE_GUARD_RE = re.compile(
    r"""
    (?:
        headers\s*\[\s*['"]content-length['"]    # req.headers['content-length']
      | maxMessageSize                           # upstream config
      | maxBodySize                              # express/fastify idiom
      | bodyLimit                                # fastify
      | limits?\s*:\s*\{\s*fileSize              # multer-style
      | \b(total|length|size)\s*[><]=?\s*\d+     # if (total > N)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_LINE_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
_LINE_ONLY_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE | re.DOTALL)


def _strip_comments(text: str) -> str:
    return sub_comments(_LINE_COMMENT_RE, _LINE_ONLY_COMMENT_RE, text)


def _check_package_json(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    pkg = project_root / "package.json"
    if not pkg.is_file():
        return findings
    rel = str(pkg.relative_to(project_root))
    scanned.add(rel)
    manifest = read_manifest(pkg)
    if manifest is None:
        return findings
    for rule_id, pin, name, tail in (
        ("AAK-MCPFRAME-001", _MCPFRAME_PIN, "mcp-framework",
         "CVE-2026-39313 HTTP-body DoS is patched in 0.2.22."),
        ("AAK-NEXT-AI-DRAW-001", _NEXT_AI_DRAW_PIN, "next-ai-draw-io",
         "CVE-2026-40608 body-accumulation DoS is patched in 0.4.15."),
    ):
        hit = pinned_dependency(manifest, pin)
        if hit is not None:
            # No line, as before: giving package.json findings one re-keys
            # their code-scanning alerts.
            findings.append(make_finding(
                rule_id, rel, f"{name} referenced as {hit.quote(f' in {hit.declaration.section}')} — {tail}",
            ))
    return findings


def _check_body_accumulation(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _JS_EXTS:
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
        except OSError:
            continue
        if "readRequestBody" not in text and not _BODY_CONCAT_RE.search(text):
            continue
        if not _STR_ACCUMULATE_RE.search(blank_js_comments(text)):
            continue
        # Check for size guard in code (not comments) — the documented
        # safe pattern. Strip // and /* */ comments so "no Content-Length
        # guard" in a fixture comment doesn't spuriously suppress.
        stripped = _strip_comments(text)
        if _SIZE_GUARD_RE.search(stripped):
            continue
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-MCPFRAME-001",
            rel,
            "HTTP body chunks accumulated without a Content-Length or "
            "maxMessageSize guard — CVE-2026-39313 shape.",
            line_number=find_line_number(text, "data")
            or find_line_number(text, "req"),
        ))
    return findings


# ---------------------------------------------------------------------------
# AAK-MCP-016: an MCP endpoint that reads the whole request body, unbounded
# ---------------------------------------------------------------------------
#
# AAK-MCPFRAME-001 above reads one shape, TS/JS chunks concatenated off
# `req.on('data')`, and the SDK pins (AAK-MCP-SDK-CVE-2026-52869-001,
# AAK-MCP-JAVASDK-CVE-2026-108395-001) read versions. Neither sees a server
# that parses the JSON-RPC body itself in a framework that sets no limit,
# which is how most hand-written MCP endpoints in Go and Python read it: Go's
# net/http, gin, echo and chi, Starlette (so FastAPI) and Flask all hand the
# handler a body of any size. `io.ReadAll(r.Body)`, `json.NewDecoder(r.Body)`,
# `c.ShouldBindJSON(...)`, `await request.json()` and `request.get_json()` then
# hold all of it in memory, and the tool arguments in it go on to the model.
#
# A read is reported only inside a handler that serves MCP: one registered on a
# route whose path names `mcp`, or one whose body names a method only MCP has
# (`"tools/call"`, `"resources/read"`, ...; `"initialize"` is a language
# server's handshake too). A handler named for MCP is not enough: an admin API
# that binds MCP settings reads a body too. Any limit silences it,
# however it is written, because a limit the check does not understand should
# cost a missed finding, not a false one: `http.MaxBytesReader` or
# `io.LimitReader` in the handler, a Content-Length test, in Python a length
# test on what was read (the body is already in memory then, but the developer
# chose a size; Go reads no such test), and anywhere in the project
# `http.MaxBytesHandler`, a `.Body =` reassignment through a limiting reader,
# echo's `BodyLimit`, chi's `RequestSize`, gin's size limiter, Flask's
# `MAX_CONTENT_LENGTH` or a Starlette middleware that names a body size.
# Frameworks with a default limit (Express's body parsers, Fastify, aiohttp,
# Django, Quart, Fiber) are not read: a Python file that imports one is skipped,
# even when it only uses it as a client. Test files serve no endpoint.

_MCP016 = "AAK-MCP-016"
_MCP016_MAX_BYTES = 1_000_000
# An MCP method the handler dispatches on: `case "tools/call":`, `== "tools/list"`,
# a dispatch-table key. The same literal as a value (`Method: "tools/list"`) is
# a request the handler sends to a server as a client, not one it serves.
_MCP_METHOD_NAMES = "(?:" + "|".join(map(re.escape, sorted(MCP_METHODS))) + ")"
_HANDSHAKE_NAMES = "(?:" + "|".join(map(re.escape, sorted(MCP_HANDSHAKE))) + ")"


def _go_dispatch_re(names: str) -> re.Pattern[str]:
    # `[^:\n]{0,160}`, not `*`: from every `case` on a long line with no colon the
    # unbounded form read to the end of the line, so the line cost its square.
    return re.compile(rf'\bcase[ \t]+[^:\n]{{0,160}}"{names}"|[!=]=\s*"{names}"|"{names}"\s*(?:[!=]=|:)')


_GO_MCP_DISPATCH_RE = _go_dispatch_re(_MCP_METHOD_NAMES)
_GO_HANDSHAKE_DISPATCH_RE = _go_dispatch_re(_HANDSHAKE_NAMES)
# A method only MCP has, named anywhere in the file: what lets the handshake count.
_GO_MCP_LITERAL_RE = re.compile(rf'"{_MCP_METHOD_NAMES}"')
_WORD_RE = re.compile(r"[A-Za-z_]\w*")
_WORD_RUN_RE = re.compile(r"\w+")
# `match` cases (3.10+); the 3.9 AST has none, and an empty tuple matches nothing.
_MATCH_VALUE: tuple[type, ...] = tuple(t for t in (getattr(ast, "MatchValue", None),) if t is not None)
_GO_PROJECT_CAP_RE = re.compile(
    r"\bMaxBytesHandler\s*\(|\bMaxBytesReader\s*\(|\bBodyLimit\s*\(|\bRequestSize\s*\(|\bRequestSizeLimiter\s*\("
    r"|\.Body\s*=\s*(?:\w+\.)?(?:LimitReader|NopCloser\s*\(\s*(?:\w+\.)?LimitReader)\s*\("
    # A Content-Length test that answers 413 (a size-limit middleware).
    r"|ContentLength\s*>[^\n{]{1,80}\{[^}]{0,300}?(?:StatusRequestEntityTooLarge|\b413\b)"
)
# The whole-body reads of each kind of handler, with the request's name
# captured: one sweep per kind finds the reads of every handler of that kind.
_GO_READS = {
    "nethttp": re.compile(r"\b(?:io|ioutil)\.ReadAll\(\s*(\w+)\.Body\s*\)|\bjson\.NewDecoder\(\s*(\w+)\.Body\s*\)"),
    "gin": re.compile(
        r"\b(\w+)\.(?:ShouldBindJSON|BindJSON|ShouldBind|Bind|ShouldBindBodyWith|GetRawData)\s*\("
        r"|\b(?:io|ioutil)\.ReadAll\(\s*(\w+)\.Request\.Body\s*\)|\bjson\.NewDecoder\(\s*(\w+)\.Request\.Body\s*\)"
    ),
    "echo": re.compile(
        r"\b(\w+)\.Bind\s*\("
        r"|\b(?:io|ioutil)\.ReadAll\(\s*(\w+)\.Request\(\)\.Body\s*\)|\bjson\.NewDecoder\(\s*(\w+)\.Request\(\)\.Body\s*\)"
    ),
}
# Any of the reads above, before the handler that makes them is known: a file
# without one is not indexed.
_GO_ANY_READ_RE = re.compile(
    r"\b(?:io|ioutil)\.ReadAll\(|\bjson\.NewDecoder\(|\.(?:ShouldBindJSON|BindJSON|ShouldBind|Bind|ShouldBindBodyWith|GetRawData)\s*\("
)
_PY_ANY_READ_RE = re.compile(r"\.(?:json|body)\s*\(\s*\)|\bget_json\b|\bget_data\b|\brequest\.(?:json|data)\b")
# A limit in the handler: a limiting reader, or the request's Content-Length
# (`r.ContentLength`, `c.Request.ContentLength`, `c.Request().ContentLength`).
_GO_LIMIT_CALL_RE = re.compile(r"\bLimitReader\s*\(|\bMaxBytesReader\s*\(")
_GO_CONTENT_LENGTH_RE = re.compile(r"\.ContentLength\b")

# What `parse_python` raises on a file it cannot build a tree for: a syntax
# error, or a source nested too deep to parse, which it refuses (raised as a
# SyntaxError) and before 3.11 parses where it cannot crash the process. The
# file is skipped; letting one escape lost every finding of the scan.
_PY_PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)
# Flask's (Werkzeug's) limit, set in code or config.
_PY_PROJECT_CAP_RE = re.compile(r"\bMAX_CONTENT_LENGTH\b|\bmax_content_length\b")
# A file that may hold a size-limiting middleware, before parsing it.
_PY_MIDDLEWARE_HINT_RE = re.compile(r"middleware|before_request|__call__")
# A middleware installed by class name, often from a library:
# `app.add_middleware(LimitUploadSize, max_upload_size=...)`.
_PY_ADD_MIDDLEWARE_RE = re.compile(r"\b(?:add_middleware|Middleware)\(\s*([A-Za-z_][\w.]*)")
_PY_SIZE_HINT_RE = re.compile(r"\b413\b|content[-_]length|TOO_LARGE|too large", re.IGNORECASE)
# `^[ \t]*`, not `^\s*`: `\s` crosses newlines, so from every line start of a run
# of blank lines the pattern reread the rest of the run.
_PY_STARLETTE_RE = re.compile(r"^[ \t]*(?:from|import)[ \t]+(?:fastapi|starlette)\b", re.MULTILINE)
_PY_FLASK_RE = re.compile(r"^[ \t]*from[ \t]+flask[ \t]+import\b[^\n]*\brequest\b", re.MULTILINE)
_PY_OTHER_FRAMEWORK_RE = re.compile(
    r"^[ \t]*(?:from|import)[ \t]+(?:quart|aiohttp|sanic|litestar|django|tornado|falcon|bottle)\b", re.MULTILINE
)


# Every alternative of each project-limit pattern contains one of these words.
_CAP_WORDS = {
    _GO_PROJECT_CAP_RE.pattern: ("MaxBytes", "BodyLimit", "RequestSize", ".Body", "ContentLength"),
    _PY_PROJECT_CAP_RE.pattern: ("MAX_CONTENT_LENGTH", "max_content_length"),
}


def _project_files(project_root: Path, suffix: str) -> list[Path]:
    out: list[Path] = []
    for path in project_root.rglob(f"*{suffix}"):
        if not path.is_file() or in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > _MCP016_MAX_BYTES:
                continue
        except OSError:
            continue
        out.append(path)
    return out


def _read_texts(paths: list[Path], project_root: Path) -> list[tuple[Path, str, str]]:
    """(path, path relative to the root, text) of each readable file."""
    texts: list[tuple[Path, str, str]] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        texts.append((path, path.relative_to(project_root).as_posix(), text))
    return texts


def _project_capped(texts: list[tuple[Path, str, str]], cap_re: re.Pattern[str]) -> bool:
    """A body-size limit anywhere in the project's own (non-test) code.

    Project-wide on purpose: the limit is usually set where the server is
    built (`http.MaxBytesHandler(mux, n)` in main.go, `MAX_CONTENT_LENGTH` in
    the app factory, a Starlette middleware), not beside the handler, and which
    handler it wraps is not worth guessing. A limit in a test configures no
    server. A name alone is not a limit: `MAX_BODY_CHARS` that truncates a log
    line, or `io.LimitReader(r.Body, n)` in some other handler, said nothing
    about the MCP route and silenced 29 real findings in the design sample.
    """
    words = _CAP_WORDS[cap_re.pattern]
    for path, rel, text in texts:
        if TEST_FILE_RE.search(rel):
            continue
        # Each pattern needs one of its words: a file without any is not searched.
        if any(w in text for w in words) and cap_re.search(text):
            return True
        if path.suffix == ".py" and _py_size_middleware(text, path):
            return True
    return False


def _py_size_middleware(text: str, path: Path) -> bool:
    """A Starlette/FastAPI middleware or Flask `before_request` hook that checks
    a body size: `@app.middleware("http")`, a class with `dispatch(...,
    call_next)` or an ASGI `__call__(self, scope, receive, send)`, whose own
    code answers 413 or compares a Content-Length or a body length."""
    if "iddleware(" in text and any(
        _names_body_limit(m.group(1).rsplit(".", 1)[-1]) for m in _PY_ADD_MIDDLEWARE_RE.finditer(text)
    ):
        return True
    if not (_PY_MIDDLEWARE_HINT_RE.search(text) and _PY_SIZE_HINT_RE.search(text)):
        return False
    try:
        tree = parse_python(text, path)
    except _PY_PARSE_ERRORS:
        return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_middleware(node) and _checks_size(node):
            return True
        if isinstance(node, ast.ClassDef) and _names_body_limit(node.name) and any(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_middleware(item) for item in node.body
        ):
            return True
    return False


def _names_body_limit(name: str) -> bool:
    """`BodyLimitMiddleware`, `BodySizeLimitMiddleware`, `ContentSizeLimitMiddleware`."""
    low = name.lower()
    return any(w in low for w in ("body", "content", "upload", "payload")) and any(
        w in low for w in ("limit", "size", "max")
    )


_ORDERING = (ast.Gt, ast.GtE, ast.Lt, ast.LtE)


def _is_middleware(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    params = [a.arg for a in func.args.args]
    if func.name == "dispatch" and "call_next" in params:
        return True
    if func.name == "__call__" and params[:4] == ["self", "scope", "receive", "send"]:
        return True
    for deco in func.decorator_list:
        target = deco.func if isinstance(deco, ast.Call) else deco
        if isinstance(target, ast.Attribute) and target.attr in ("middleware", "before_request"):
            return True
    return False


def _checks_size(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in _own_nodes(func):
        if isinstance(node, ast.Constant) and node.value == 413:
            return True
        if isinstance(node, ast.Call):
            callee = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if "too_large" in callee.lower() or "toolarge" in callee.lower():
                return True
        if isinstance(node, ast.Attribute) and node.attr in (
            "HTTP_413_REQUEST_ENTITY_TOO_LARGE", "HTTP_413_CONTENT_TOO_LARGE", "REQUEST_ENTITY_TOO_LARGE",
        ):
            return True
        # An ordering test on the Content-Length value; `"content-length" in
        # request.headers` is a logging middleware asking whether there is one.
        if isinstance(node, ast.Compare) and all(isinstance(op, _ORDERING) for op in node.ops) and any(
            isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes))
            and n.value.lower() in ("content-length", b"content-length")
            for side in [node.left, *node.comparators] for n in ast.walk(side)
        ):
            return True
    return False


def _check_unbounded_go(project_root: Path, scanned: set[str]) -> list[Finding]:
    texts = _read_texts(_project_files(project_root, ".go"), project_root)
    if _project_capped(texts, _GO_PROJECT_CAP_RE):
        return []
    findings: list[Finding] = []
    for _path, rel, text in texts:
        if TEST_FILE_RE.search(rel) or not _GO_ANY_READ_RE.search(text):
            continue
        if "httptest" in text and GO_TEST_SERVER_RE.search(text):
            continue
        scanned.add(rel)
        index = CodeIndex(text, go=True)
        handlers = go_handlers(index)
        if not handlers:
            continue
        findings.extend(_unbounded_go_reads(index, handlers, rel))
    return findings


def _unbounded_go_reads(index: CodeIndex, handlers: list[GoHandler], rel: str) -> list[Finding]:
    """AAK-MCP-016 in one Go file, in time linear in it.

    A handler's body holds every handler nested in it, and a file can register
    thousands of handlers, so nothing here reads a body, or the route table,
    once per handler: the reads, the MCP methods, the limits and the
    limit-helper calls are each found once in the file and looked up by
    offset, and the routes are indexed by the handler they name. Searching
    each body whole took 29 seconds on 4,000 nested handlers, and searching
    every route for each handler's name 3.4 seconds on 4,000 handlers with a
    route each.
    """
    text = index.text
    routes = _McpRoutes([r for r in go_routes(index) if is_mcp_endpoint_path(r.path)], text)
    dispatch = _Offsets(m.start() for m in _GO_MCP_DISPATCH_RE.finditer(text))
    names_mcp = _GO_MCP_LITERAL_RE.search(text) is not None
    handshake = _Offsets(m.start() for m in _GO_HANDSHAKE_DISPATCH_RE.finditer(text)) if names_mcp else _Offsets(())
    # Limits are found once per file, and only when a read reaches the check.
    helpers: _Offsets | None = None
    limits = _Offsets(())
    caps: dict[str, _Offsets] = {}
    findings: list[Finding] = []
    reported: set[int] = set()
    reads = _innermost_reads(text, handlers)
    for pos in sorted(reads):
        handler, m = reads[pos]
        if not index.in_code(pos) or id(handler) in reported:
            continue
        route = routes.path_for(handler)
        if route is None and not (
            dispatch.any_in(handler.body_start, handler.body_end)
            or handshake.any_in(handler.body_start, handler.body_end)
        ):
            continue
        if helpers is None:
            helpers = _Offsets(_limit_helper_calls(text))
            limits = _Offsets(c.start() for c in _GO_LIMIT_CALL_RE.finditer(text))
            caps = {name: _Offsets(at) for name, at in _content_length_reads(text).items()}
        cap = caps.get(handler.request)
        if (
            limits.any_in(handler.body_start, handler.body_end)
            or cap is not None and cap.any_in(handler.body_start, handler.body_end)
            or helpers.any_in(handler.body_start, pos)
        ):
            continue
        reported.add(id(handler))
        where = f"route {route!r}" if route else "a handler that serves MCP methods"
        findings.append(make_finding(
            _MCP016,
            rel,
            f"{handler.name or 'func literal'} ({where}) reads the request body with "
            f"`{m.group(0)}` and nothing limits its size: no http.MaxBytesReader, "
            "io.LimitReader or Content-Length check here, and no body-size middleware "
            "in the project",
            line_number=index.line_of(pos),
        ))
    return findings


class _Offsets:
    """Sorted offsets, for "is there one in [start, end)" in logarithmic time."""

    def __init__(self, offsets: Iterable[int]) -> None:
        self._offsets = sorted(offsets)

    def any_in(self, start: int, end: int) -> bool:
        i = bisect_left(self._offsets, start)
        return i < len(self._offsets) and self._offsets[i] < end


class _OpenBodies:
    """The handlers of one kind and request name whose bodies are open at a
    point, for points visited in order: each handler is pushed and popped once."""

    def __init__(self, group: list[GoHandler]) -> None:
        self._group = sorted(group, key=lambda h: h.body_start)
        self._next = 0
        self._stack: list[GoHandler] = []

    def innermost(self, start: int, end: int) -> GoHandler | None:
        """The innermost handler whose body holds ``start:end``."""
        group, stack = self._group, self._stack
        while self._next < len(group) and group[self._next].body_start < start:
            while stack and stack[-1].body_end <= group[self._next].body_start:
                stack.pop()
            stack.append(group[self._next])
            self._next += 1
        while stack and stack[-1].body_end < end:
            stack.pop()
        return stack[-1] if stack else None


def _innermost_reads(text: str, handlers: list[GoHandler]) -> dict[int, tuple[GoHandler, re.Match[str]]]:
    """Each body read, with the innermost handler whose own reads it is.

    A read belongs to a handler of its kind whose request it names
    (`io.ReadAll(r.Body)` in a handler whose request is `r`). Each kind is
    swept once, its pattern capturing the name, and each (kind, name) keeps
    the bodies open at the read; the innermost handler of any kind wins, as
    when every body was searched on its own. One pattern per request name,
    swept from its first handler on, made a file of handlers with distinct
    request names quadratic: 4,000 of them (452 KB) took 27 seconds.
    """
    groups: dict[tuple[str, str], list[GoHandler]] = {}
    for handler in handlers:
        groups.setdefault((handler.kind, handler.request), []).append(handler)
    open_bodies = {key: _OpenBodies(group) for key, group in groups.items()}
    reads: dict[int, tuple[GoHandler, re.Match[str]]] = {}
    for kind in sorted({kind for kind, _name in groups}):
        for m in _GO_READS[kind].finditer(text):
            name = next(g for g in m.groups() if g is not None)
            bodies = open_bodies.get((kind, name))
            innermost = bodies.innermost(m.start(), m.end()) if bodies is not None else None
            if innermost is None:
                continue
            held = reads.get(m.start())
            if held is None or held[0].body_start < innermost.body_start:
                reads[m.start()] = (innermost, m)
    return reads


def _content_length_reads(text: str) -> dict[str, list[int]]:
    """Where `<name>.ContentLength`, `<name>.Request.ContentLength` or
    `<name>.Request().ContentLength` starts, by name, found once for every
    handler. A name is a whole word: `xr.ContentLength` is not `r`'s. Reading
    back from each `.ContentLength` gives both names of
    `c.Request.ContentLength` (`c`, and a request named `Request`), as a
    pattern per request name did."""
    found: dict[str, list[int]] = {}
    for m in _GO_CONTENT_LENGTH_RE.finditer(text):
        for suffix in ("", ".Request", ".Request()"):
            stop = m.start() - len(suffix)
            if suffix and not text.startswith(suffix, stop):
                continue
            start = stop
            while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
                start -= 1
            if start < stop:
                found.setdefault(text[start:stop], []).append(start)
    return found


def _limit_helper_calls(text: str) -> list[int]:
    """Offsets of calls such as `limitRequestBody(w, r, max)`.

    Read word by word rather than with one pattern: `\\w*limit\\w*body` over a
    long word with many `limit`s and no `body` backtracks with its square.
    """
    calls: list[int] = []
    for m in _WORD_RE.finditer(text):
        low = m.group().lower()
        limited = "limit" in low or "max" in low
        if limited and ("body" in low or "size" in low) and text.startswith("(", m.end()):
            calls.append(m.start())
    return calls


class _McpRoutes:
    """The MCP route a Go handler is registered on, in this file.

    A func literal is registered by the route whose arguments hold it, and a
    named handler by the first route whose arguments name it as a word. A route
    nested in another route's arguments comes after it in the file, so the
    first route that holds a literal or names a handler is always an outermost
    one: only the outermost argument spans are kept, and their words read once.
    """

    def __init__(self, routes: list[GoRoute], text: str) -> None:
        spans = sorted(
            ((s, e, i) for i, route in enumerate(routes) for s, e in route.arg_spans if s < e),
            key=lambda span: (span[0], -span[1]),
        )
        outer: list[tuple[int, int, int]] = []
        for span in spans:
            if not outer or span[0] >= outer[-1][1]:
                outer.append(span)
        self._outer = outer
        self._starts = [s for s, _e, _i in outer]
        self._paths = [route.path for route in routes]
        self._named: dict[str, str] = {}
        for s, e, i in sorted(outer, key=lambda span: (span[2], span[0])):
            for word in _WORD_RUN_RE.finditer(text, s, e):
                self._named.setdefault(word.group(), self._paths[i])

    def path_for(self, handler: GoHandler) -> str | None:
        if handler.name is not None:
            return self._named.get(handler.name)
        i = bisect_right(self._starts, handler.start) - 1
        if i >= 0 and handler.start < self._outer[i][1]:
            return self._paths[self._outer[i][2]]
        return None


def _check_unbounded_python(project_root: Path, scanned: set[str]) -> list[Finding]:
    texts = _read_texts(_project_files(project_root, ".py"), project_root)
    if _project_capped(texts, _PY_PROJECT_CAP_RE):
        return []
    findings: list[Finding] = []
    for path, rel, text in texts:
        if TEST_FILE_RE.search(rel) or not _PY_ANY_READ_RE.search(text) or _PY_OTHER_FRAMEWORK_RE.search(text):
            continue
        starlette = bool(_PY_STARLETTE_RE.search(text))
        flask = bool(_PY_FLASK_RE.search(text))
        if starlette == flask:
            continue
        scanned.add(rel)
        try:
            tree = parse_python(text, path)
        except _PY_PARSE_ERRORS:
            continue
        routes = py_routes(tree)
        if not routes:
            continue
        names_mcp: bool | None = None
        # The MCP route each name is registered on, once per name: listing and
        # testing a name's routes for every function of that name made 10,000
        # FastAPI functions named `h` take 32 seconds.
        mcp_paths = {
            name: next((r.path for r in regs if r.path is not None and is_mcp_endpoint_path(r.path)), None)
            for name, regs in routes.items()
        }
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name not in routes:
                continue
            mcp_path = mcp_paths[node.name]
            if mcp_path is None and not _py_dispatches_on(node, MCP_METHODS):
                if not _py_dispatches_on(node, MCP_HANDSHAKE):
                    continue
                if names_mcp is None:
                    names_mcp = any(
                        isinstance(n, ast.Constant) and n.value in MCP_METHODS for n in ast.walk(tree)
                    )
                if not names_mcp:
                    continue
            read = _py_body_read(node, flask)
            if read is None or _py_handler_capped(node, read[0]):
                continue
            where = f"route {mcp_path!r}" if mcp_path else "a handler that serves MCP methods"
            framework = "Flask, with MAX_CONTENT_LENGTH unset," if flask else "Starlette"
            findings.append(make_finding(
                _MCP016,
                rel,
                f"{node.name} ({where}) reads the request body with `{read[1]}`; {framework} sets "
                "no size limit, and there is no Content-Length or length check here or "
                "body-size middleware in the project",
                line_number=read[0],
            ))
    return findings


def _own_nodes(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    """Nodes of ``func``'s body, not those of functions or classes nested in it."""
    out: list[ast.AST] = []
    stack: list[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        out.append(node)
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                stack.append(child)
    return out


def _py_dispatches_on(func: ast.FunctionDef | ast.AsyncFunctionDef, methods: frozenset[str]) -> bool:
    """True when ``func`` dispatches on one of ``methods``: compares one,
    matches a `case` on one, or keys a dispatch table by one. A method as a dict
    value (`{"method": "tools/list"}`) is a request it sends as a client."""
    for node in _own_nodes(func):
        values: list[ast.AST] = []
        if isinstance(node, ast.Compare):
            values = [node.left, *node.comparators]
            for side in node.comparators:
                if isinstance(side, (ast.Tuple, ast.List, ast.Set)):
                    values.extend(side.elts)
        elif isinstance(node, ast.Dict):
            values = [k for k in node.keys if k is not None]
        elif isinstance(node, _MATCH_VALUE):
            values = [getattr(node, "value", None) or node]
        if any(isinstance(v, ast.Constant) and v.value in methods for v in values):
            return True
    return False


def _py_request_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names: set[str] = set()
    for arg in func.args.posonlyargs + func.args.args + func.args.kwonlyargs:
        ann = arg.annotation
        ann_name = ann.id if isinstance(ann, ast.Name) else ann.attr if isinstance(ann, ast.Attribute) else ""
        if ann_name == "Request" or arg.arg in ("request", "req"):
            names.add(arg.arg)
    return names


def _py_body_read(func: ast.FunctionDef | ast.AsyncFunctionDef, flask: bool) -> tuple[int, str] | None:
    """(line, source) of the first whole-body read in ``func``'s own body."""
    reads: list[tuple[int, str]] = []
    if flask:
        for node in _own_nodes(func):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "request"
                and node.attr in ("get_json", "get_data", "json", "data")
            ):
                suffix = "()" if node.attr.startswith("get_") else ""
                reads.append((node.lineno, f"request.{node.attr}{suffix}"))
    else:
        params = _py_request_params(func)
        for node in _own_nodes(func):
            if (
                isinstance(node, ast.Await)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and isinstance(node.value.func.value, ast.Name)
                and node.value.func.value.id in params
                and node.value.func.attr in ("json", "body")
            ):
                reads.append((node.lineno, f"await {node.value.func.value.id}.{node.value.func.attr}()"))
    return min(reads) if reads else None


def _py_handler_capped(func: ast.FunctionDef | ast.AsyncFunctionDef, read_line: int) -> bool:
    """A size check in the handler: a Content-Length read, a length test, or a
    call such as `body_exceeds_limit(request)` before the read."""
    for node in _own_nodes(func):
        if isinstance(node, ast.Call) and getattr(node, "lineno", read_line) <= read_line:
            func_node = node.func
            name = func_node.attr if isinstance(func_node, ast.Attribute) else getattr(func_node, "id", "")
            low = name.lower()
            if ("limit" in low or "max" in low or "exceed" in low) and ("body" in low or "size" in low):
                return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.lower() in (
            "content-length", "content_length",
        ):
            return True
        if isinstance(node, ast.Attribute) and node.attr == "content_length":
            return True
        if isinstance(node, ast.Compare):
            for side in [node.left, *node.comparators]:
                if isinstance(side, ast.Call) and isinstance(side.func, ast.Name) and side.func.id == "len":
                    return True
    return False


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_package_json(project_root, scanned))
    findings.extend(_check_body_accumulation(project_root, scanned))
    findings.extend(_check_unbounded_go(project_root, scanned))
    findings.extend(_check_unbounded_python(project_root, scanned))
    return findings, scanned
