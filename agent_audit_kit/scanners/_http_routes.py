"""HTTP handlers and route registrations read out of Go, TS/JS and Python source.

AAK-MCP-016, AAK-MCP-020 and AAK-MCPWN-001 all start from the same question:
which routes does this file register, with what middleware, and which handler
does each reach? A route's arguments hold nested calls, arrow functions and func
literals, so where one argument ends depends on bracket nesting, and a `[^)]*`
stops at the first `)` it meets. AAK-MCPWN-001's Gin pattern did exactly that:
it read `r.Any("/mcp", middleware.IPWhiteList(), middleware.AuthRequired(), ...)`
as far as `middleware.IPWhiteList(`, never saw `AuthRequired()`, and was silent
on the nginx-ui router CVE-2026-33032 was found in.

`CodeIndex` reads a Go or TS/JS file once instead: every bracket's partner and
the commas directly inside each `(`, skipping strings and comments, in time
linear in the file. A closer whose kind is not open anywhere is ignored, and one
that closes a deeper opener of its kind pops the openers above it, each opener
once, so a stray bracket (a regex literal, JSX text) costs one pass, not a
rescan. Python is read with `ast`.
"""

from __future__ import annotations

import ast
import re
from bisect import bisect_right
from dataclasses import dataclass

# Strings, comments and the characters that shape argument lists; in TS/JS also a
# `/`, which may open a regex literal.
_TOKEN_RE = re.compile(r"""[()\[\]{},]|//|/\*|["'`]""")
_JS_TOKEN_RE = re.compile(r"""[()\[\]{},]|//|/\*|/|["'`]""")
# A regex literal is read up to a fixed window: escapes, classes (in which `/`
# does not close it), then flags. Each step jumps to the next character that
# matters, outside a class and inside one.
_REGEX_STOP_RE = re.compile(r"[/\\\[\n]")
_CLASS_STOP_RE = re.compile(r"[\[\]\\\n]")
_REGEX_FLAGS_RE = re.compile(r"[A-Za-z]*")
_REGEX_WINDOW = 512
# A `/` after one of these starts an expression, so it opens a regex literal:
# the previous token, a character before it, or a keyword.
_REGEX_AFTER_TOKENS = frozenset("([{},/")
_REGEX_AFTER_CHARS = frozenset("(,=:[!&|?{};")
_REGEX_AFTER_WORDS = frozenset({
    "return", "typeof", "case", "in", "of", "new", "delete", "void", "throw", "instanceof", "yield", "await",
    "else", "do",
})
# A literal up to where it closes or gives up: it is closed when the next
# character is its own quote. Each pattern reads one way only (an escape is a
# backslash and the character after it), so where it stops does not depend on
# backtracking.
_DQ_BODY_RE = re.compile(r'"(?:[^"\\\n]|\\.)*')
_SQ_BODY_RE = re.compile(r"'(?:[^'\\\n]|\\.)*")
_JS_TEMPLATE_BODY_RE = re.compile(r"`(?:[^`\\]|\\.)*", re.DOTALL)
_GO_RAW_BODY_RE = re.compile(r"`[^`]*")
_NEWLINE_RE = re.compile(r"\n")
_OPENERS = {")": "(", "]": "[", "}": "{"}


# Test files, Go test-helper packages (`mcptest/`, `ssetest/`, as `httptest/`) and
# mock or fake servers (`mock_mcp_server.py`, `fakemcp/`, `ch21_fakemcp.go`)
# serve no real endpoint.
TEST_FILE_RE = re.compile(
    r"(?:^|/)(?!latest/)(?:[a-z0-9]*tests?|testdata|e2e|__tests__|testutils?|testhelpers?|testsupport)/"
    r"|(?:^|/)(?:mock|fake)[^/]*(?:/|$)|[-_](?:mock|fake)[^/]*(?:/|$)"
    r"|_test\.go$|(?:^|/)test_[^/]*\.py$|_test\.py$|(?:^|/)conftest\.py$",
    re.IGNORECASE,
)
# A Go file that starts an `httptest` server is a test double wherever it lives
# (a grading harness's fake MCP peer). `httptest.NewRecorder()` alone is not:
# production code uses it to capture a handler's response.
GO_TEST_SERVER_RE = re.compile(r"\bhttptest\.New(?:TLS|Unstarted)?Server\(")
# Methods only MCP has, and the handshake it shares with a language server. A
# handler that dispatches on `initialize` or its `initialized` notification
# serves MCP only in a file that names one of the others too: VS Code LSP
# endpoints over JSON-RPC answer `initialize` (endomorphosis/ipfs_kit_py has a
# dozen), while an MCP server that handles the handshake in its HTTP handler
# usually dispatches the rest in a function beside it.
MCP_METHODS = frozenset({
    "tools/call", "tools/list", "resources/list", "resources/read", "prompts/list", "prompts/get",
})
MCP_HANDSHAKE = frozenset({"initialize", "notifications/initialized"})
# A route that receives MCP traffic: a segment ending in `mcp`, then nothing, a
# path parameter, a transport tail or an MCP method spelled as a path
# (`/mcp`, `/api/v1/mcp`, `/tunnel/{id}/mcp`, `/mcp/message`, `/mcp/tools/call`).
# `/api/mcp/workflows/<id>` and `/api/admin/mcp-keys/create` are an MCP
# server's own admin API and are not read.
_MCP_SEGMENT_RE = re.compile(r"[\w.-]*mcp|mcp[_-](?:messages?|rpc|jsonrpc|sse|stream|http)", re.IGNORECASE)
_MCP_TAIL_RE = re.compile(
    r"v\d+|(?:v\d+/)?(?:messages?|sse|rpc|jsonrpc|stream|streamable|initialize|notifications?|call(?:/[^/]+)?"
    r"|tools/(?:call|list)|resources/(?:read|list)|prompts/(?:get|list)|\{[^/]*\}|:\w+|<[^/]*>)",
    re.IGNORECASE,
)


# A segment before the MCP one that makes it settings, not traffic: `/api/config/mcp`.
_ADMIN_SEGMENTS = frozenset({"config", "configs", "configuration", "settings", "setting", "admin", "preferences"})


def is_mcp_endpoint_path(path: str) -> bool:
    segments = [s for s in path.rsplit(" ", 1)[-1].split("/") if s]
    for i, segment in enumerate(segments):
        if _MCP_SEGMENT_RE.fullmatch(segment):
            if any(s.lower() in _ADMIN_SEGMENTS for s in segments[:i]):
                return False
            rest = "/".join(segments[i + 1:])
            if not rest or _MCP_TAIL_RE.fullmatch(rest):
                return True
    return False


class _RegexReader:
    """Where the TS/JS regex literal opened by a `/` ends, with each character
    read a bounded number of times however many `/` share it.

    A read walks from stop to stop: past a `\\` and the character it escapes,
    past a class (`[...]`, in which `/` does not close the literal), to the `/`
    that closes it, or to the end of the line, where it gives up. Where a walk
    goes from a point depends on that point alone, not on the `/` it started
    from, so every point a walk passes keeps where it closed: a later walk that
    reaches one stops there. Classes are kept the same way. A `[` inside a class
    is a literal character there, but a walk that lands on it reads a class
    that ends where the outer one does, since both readings stand at the
    character after it, so each `[` a class read passes keeps that class's end.
    Before this, each `/` after a `[` of a long run of closed classes read the
    whole window again, 512 characters per `/`.

    The window still decides: a literal ends only if its `/` closes within
    `_REGEX_WINDOW` characters, so a walk keeps where it closed and each read
    compares that with its own window. A literal that does not close on its
    line within the window is division after all.
    """

    def __init__(self, text: str) -> None:
        self._text = text
        # Walk point -> the `/` the walk from it closes at, or -1.
        self._closes: dict[int, int] = {}
        # A `[` -> the position after the `]` that closes its class, or -1.
        self._classes: dict[int, int] = {}

    def end(self, at: int) -> int | None:
        """The end of the literal whose `/` is at ``at``, flags included, or None."""
        text = self._text
        limit = min(len(text), at + _REGEX_WINDOW)
        close = self._walk(at + 1)
        if close < 0 or close >= limit:
            return None
        flags = _REGEX_FLAGS_RE.match(text, close + 1, limit)
        return flags.end() if flags else close + 1

    def _walk(self, point: int) -> int:
        text = self._text
        passed: list[int] = []
        while True:
            known = self._closes.get(point)
            if known is not None:
                close = known
                break
            passed.append(point)
            stop = _REGEX_STOP_RE.search(text, point)
            if stop is None or stop.group() == "\n":
                close = -1
                break
            at = stop.start()
            if stop.group() == "/":
                close = at
                break
            if stop.group() == "\\":
                if at + 1 >= len(text) or text[at + 1] == "\n":
                    close = -1
                    break
                point = at + 2
                continue
            point = self._class_end(at)
            if point < 0:
                close = -1
                break
        for p in passed:
            self._closes[p] = close
        return close

    def _class_end(self, bracket: int) -> int:
        known = self._classes.get(bracket)
        if known is not None:
            return known
        text = self._text
        inside = [bracket]
        pos = bracket + 1
        while True:
            stop = _CLASS_STOP_RE.search(text, pos)
            if stop is None or stop.group() == "\n":
                end = -1
                break
            at = stop.start()
            if stop.group() == "]":
                end = at + 1
                break
            if stop.group() == "\\":
                if at + 1 >= len(text) or text[at + 1] == "\n":
                    end = -1
                    break
                if text[at + 1] == "[":
                    inside.append(at + 1)
                pos = at + 2
                continue
            known = self._classes.get(at)
            if known is not None:
                end = known
                break
            inside.append(at)
            pos = at + 1
        for p in inside:
            self._classes[p] = end
        return end


class CodeIndex:
    """Bracket partners, top-level commas and string spans of one Go or TS/JS file."""

    def __init__(self, text: str, go: bool = False) -> None:
        self.text = text
        self.close: dict[int, int] = {}
        self.commas: dict[int, list[int]] = {}
        # The innermost `{` open at each `(`: two calls with the same entry sit
        # in one block, so an `if` branch and its `else` are told apart.
        self.block_of: dict[int, int] = {}
        self._mask_starts: list[int] = []
        self._mask_ends: list[int] = []
        self._strings: dict[int, int] = {}
        self._newlines = [m.start() for m in _NEWLINE_RE.finditer(text)]
        bodies = {'"': _DQ_BODY_RE, "'": _SQ_BODY_RE, "`": _GO_RAW_BODY_RE if go else _JS_TEMPLATE_BODY_RE}
        token_re = _TOKEN_RE if go else _JS_TOKEN_RE
        stack: list[tuple[str, int]] = []
        braces: list[int] = []
        open_count = {"(": 0, "[": 0, "{": 0}
        # The last token that is not a comment, and where it ends: whether a
        # `/` opens a regex literal depends on what precedes it.
        prev_tok, prev_end = "", 0
        regex = _RegexReader(text)
        # Per quote, where a literal that never closed gave up. Every quote of
        # that kind before it is an escaped one inside that literal, and a
        # literal opened there reads on from it with the same escapes, so it
        # gives up at the same place: it is skipped without reading again.
        # Retrying each one read to the end of the line, or of the file for a
        # template, once per escaped quote.
        given_up = {'"': 0, "'": 0, "`": 0}
        pos = 0
        n = len(text)
        while pos < n:
            m = token_re.search(text, pos)
            if m is None:
                break
            tok, at = m.group(), m.start()
            if tok == "//":
                end = text.find("\n", at)
                end = n if end < 0 else end
                self._mask(at, end)
                pos = end
                continue
            if tok == "/*":
                end = text.find("*/", at + 2)
                end = n if end < 0 else end + 2
                self._mask(at, end)
                pos = end
                continue
            if tok == "/":
                literal = regex.end(at) if self._opens_regex(at, prev_tok, prev_end) else None
                if literal is not None:
                    self._mask(at, literal)
                    prev_tok, prev_end = "re", literal
                else:
                    prev_tok, prev_end = "/", at + 1
                pos = prev_end
                continue
            if tok in "\"'`":
                if at < given_up[tok]:
                    pos = at + 1
                    continue
                body = bodies[tok].match(text, at)
                end = body.end() if body is not None else n
                if end >= n or text[end] != tok:
                    given_up[tok] = end
                    pos = at + 1
                    continue
                end += 1
                self._mask(at, end)
                self._strings[at] = end
                prev_tok, prev_end = "str", end
                pos = end
                continue
            prev_tok, prev_end = tok, at + 1
            pos = at + 1
            if tok in "([{":
                stack.append((tok, at))
                open_count[tok] += 1
                if tok == "(":
                    self.commas[at] = []
                    self.block_of[at] = braces[-1] if braces else -1
                elif tok == "{":
                    braces.append(at)
            elif tok == ",":
                if stack and stack[-1][0] == "(":
                    self.commas[stack[-1][1]].append(at)
            else:
                want = _OPENERS[tok]
                if not open_count[want]:
                    continue
                while stack:
                    kind, start = stack.pop()
                    open_count[kind] -= 1
                    if kind == "{":
                        braces.pop()
                    if kind == want:
                        self.close[start] = at
                        break

    def _opens_regex(self, at: int, prev_tok: str, prev_end: int) -> bool:
        """Whether the `/` at ``at`` starts an expression, and so a regex literal.

        Read backwards to what precedes it, past blanks and comments, no
        further than the previous token: one of `_REGEX_AFTER_CHARS`, `=>`, a
        keyword of `_REGEX_AFTER_WORDS`, a previous token of
        `_REGEX_AFTER_TOKENS`, or the start of the file opens one. After a
        name, a number, `)`, `]` or a string it is division (`a / b`, `x[i] /
        2`, `f() / g()`), on the next line too: JS inserts no semicolon before
        a `/`, and a formatter breaks a long division with the `/` first on
        the new line. A literal that does not close on its line is division
        after all. Each stretch between tokens is read back once, so the file
        costs one pass.
        """
        text = self.text
        q = at - 1
        k = len(self._mask_starts) - 1
        while q >= prev_end:
            if k >= 0 and self._mask_ends[k] == q + 1 and self._mask_starts[k] >= prev_end:
                q = self._mask_starts[k] - 1
                k -= 1
            elif text[q].isspace():
                q -= 1
            else:
                break
        if q < prev_end:
            return not prev_tok or prev_tok in _REGEX_AFTER_TOKENS
        ch = text[q]
        if ch in _REGEX_AFTER_CHARS or ch == ">" and text[q - 1:q] == "=":
            return True
        if not (ch.isalnum() or ch in "_$"):
            return False
        start = q
        while start > prev_end and (text[start - 1].isalnum() or text[start - 1] in "_$"):
            start -= 1
        return text[start:q + 1] in _REGEX_AFTER_WORDS

    def _mask(self, start: int, end: int) -> None:
        self._mask_starts.append(start)
        self._mask_ends.append(end)

    def in_code(self, pos: int) -> bool:
        """False when ``pos`` sits inside a string or a comment."""
        i = bisect_right(self._mask_starts, pos) - 1
        return i < 0 or pos >= self._mask_ends[i]

    def line_of(self, pos: int) -> int:
        return bisect_right(self._newlines, pos - 1) + 1

    def args(self, paren: int) -> list[tuple[int, int]] | None:
        """Spans of the top-level arguments of the call whose `(` is at ``paren``,
        trimmed of blanks; None when the `(` is never closed."""
        close = self.close.get(paren)
        if close is None:
            return None
        bounds = [paren] + self.commas.get(paren, []) + [close]
        spans: list[tuple[int, int]] = []
        text = self.text
        for a, b in zip(bounds, bounds[1:]):
            s, e = a + 1, b
            while s < e and text[s].isspace():
                s += 1
            while e > s and text[e - 1].isspace():
                e -= 1
            spans.append((s, e))
        if len(spans) == 1 and spans[0][0] == spans[0][1]:
            return []
        return spans

    def string_literal(self, start: int, end: int) -> str | None:
        """The value of a plain string literal spanning exactly ``start:end``."""
        if self._strings.get(start) != end:
            return None
        body = self.text[start + 1:end - 1]
        if self.text[start] == "`" and "${" in body:
            return None
        return body


@dataclass(frozen=True)
class Call:
    """One call to ``receiver.method(...)``: its arguments as text and spans."""

    receiver: str
    method: str
    start: int
    paren: int
    args: tuple[tuple[int, int], ...]


def find_calls(index: CodeIndex, head: re.Pattern[str]) -> list[Call]:
    """Every ``head`` match outside strings and comments whose `(` closes.

    ``head`` must end at the opening `(` and capture the receiver and the
    method as groups 1 and 2.
    """
    calls: list[Call] = []
    for m in head.finditer(index.text):
        if not index.in_code(m.start()):
            continue
        paren = m.end() - 1
        spans = index.args(paren)
        if spans is None:
            continue
        calls.append(Call(m.group(1), m.group(2), m.start(), paren, tuple(spans)))
    return calls


# ---------------------------------------------------------------------------
# Go: HTTP handler functions
# ---------------------------------------------------------------------------

_GO_FUNC_RE = re.compile(r"(?<![\w.])func\b")
_GO_IDENT_RE = re.compile(r"[ \t]*([A-Za-z_]\w*)[ \t]*(?=\()")
_GO_BLANKS_RE = re.compile(r"[ \t]*")
# The request a handler receives: net/http's `*http.Request`, gin's
# `*gin.Context`, echo's `echo.Context`.
_GO_REQUEST_PARAM_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s+(\*\s*http\.Request|\*\s*gin\.Context|echo\.Context)\b"
)
_GO_KINDS = {"http": "nethttp", "gin": "gin", "echo": "echo"}


@dataclass(frozen=True)
class GoHandler:
    """A Go function or function literal that receives an HTTP request."""

    name: str | None
    kind: str
    request: str
    start: int
    body_start: int
    body_end: int


def go_handlers(index: CodeIndex) -> list[GoHandler]:
    """Every `func` whose parameters take an HTTP request, with its body span.

    A method's receiver list and a literal's parameter list both follow
    `func` directly, so a name after the first `(...)` means it was a
    receiver. gofmt opens a body on the signature's own line, so the first
    `{` before the end of that line, past any parenthesised result list, is
    the body; a `func` type with no body there is skipped.
    """
    text = index.text
    handlers: list[GoHandler] = []
    for m in _GO_FUNC_RE.finditer(text):
        if not index.in_code(m.start()):
            continue
        blank = _GO_BLANKS_RE.match(text, m.end())
        pos = blank.end() if blank else m.end()
        name: str | None = None
        if text.startswith("(", pos):
            first = index.close.get(pos)
            if first is None:
                continue
            after = _GO_IDENT_RE.match(text, first + 1)
            if after is not None:
                name = after.group(1)
                params_open = after.end()
            else:
                params_open = pos
        else:
            ident = _GO_IDENT_RE.match(text, pos)
            if ident is None:
                continue
            name = ident.group(1)
            params_open = ident.end()
        params_close = index.close.get(params_open)
        if params_close is None:
            continue
        param = _GO_REQUEST_PARAM_RE.search(text, params_open, params_close)
        if param is None:
            continue
        body = _go_body_open(index, params_close + 1)
        if body is None:
            continue
        kind = _GO_KINDS[param.group(2).lstrip("*").strip().split(".")[0]]
        handlers.append(GoHandler(name, kind, param.group(1), m.start(), body, index.close[body]))
    return handlers


def _go_body_open(index: CodeIndex, pos: int) -> int | None:
    text = index.text
    end = text.find("\n", pos)
    end = len(text) if end < 0 else end
    while pos < end:
        ch = text[pos]
        if ch == "{":
            return pos if pos in index.close else None
        if ch == "(":
            close = index.close.get(pos)
            if close is None:
                return None
            pos = close + 1
            continue
        if ch in ",;=":
            return None
        pos += 1
    return None


# ---------------------------------------------------------------------------
# Go: route registrations
# ---------------------------------------------------------------------------

# net/http and chi take (path, handler); gin takes (path, handlers...); echo
# takes (path, handler, middleware...). The handler is matched by name, so the
# argument order matters only for which argument is the handler.
_GO_ROUTE_HEAD_RE = re.compile(
    r"(?<![\w.])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.("
    r"HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE|Any|Get|Post|Put|Patch|Delete|Method|MethodFunc"
    r")\s*\("
)


@dataclass(frozen=True)
class GoRoute:
    receiver: str
    method: str
    path: str
    args: tuple[str, ...]
    start: int
    arg_spans: tuple[tuple[int, int], ...]


def go_routes(index: CodeIndex) -> list[GoRoute]:
    """Route registrations whose path is a string literal."""
    text = index.text
    routes: list[GoRoute] = []
    for call in find_calls(index, _GO_ROUTE_HEAD_RE):
        spans = list(call.args)
        if call.method in ("Method", "MethodFunc") and spans:
            spans = spans[1:]
        if len(spans) < 2:
            continue
        path = index.string_literal(*spans[0])
        if path is None:
            continue
        routes.append(GoRoute(
            call.receiver, call.method, path, tuple(text[s:e] for s, e in spans[1:]), call.start,
            tuple(spans[1:]),
        ))
    return routes


# ---------------------------------------------------------------------------
# Python: route-registered functions (FastAPI, Starlette, Flask)
# ---------------------------------------------------------------------------

_PY_ROUTE_DECORATORS = frozenset({"get", "post", "put", "patch", "delete", "api_route", "route", "websocket"})
_PY_ROUTE_CALLS = frozenset({"Route", "add_api_route", "add_route", "add_url_rule", "WebSocketRoute"})


@dataclass(frozen=True)
class PyRoute:
    """One way a function is reached over HTTP."""

    path: str | None
    line: int
    node: ast.Call


def py_routes(tree: ast.AST) -> dict[str, list[PyRoute]]:
    """Route registrations keyed by the name of the function they reach.

    Decorators (`@app.post("/mcp")`, `@bp.route(...)`) key on the function they
    decorate; `Route("/mcp", endpoint=f)`, `add_api_route("/mcp", f)` and
    `add_url_rule("/mcp", view_func=f)` key on the name (or `self.<name>`) they
    pass. A path that is not a string literal is kept as None.
    """
    found: dict[str, list[PyRoute]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for deco in node.decorator_list:
                if (
                    isinstance(deco, ast.Call)
                    and isinstance(deco.func, ast.Attribute)
                    and deco.func.attr in _PY_ROUTE_DECORATORS
                ):
                    found.setdefault(node.name, []).append(PyRoute(_py_path(deco), deco.lineno, deco))
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            if name not in _PY_ROUTE_CALLS:
                continue
            target = _py_endpoint_arg(node, name)
            if target is not None:
                found.setdefault(target, []).append(PyRoute(_py_path(node), node.lineno, node))
    return found


def _py_path(call: ast.Call) -> str | None:
    candidates: list[ast.expr] = list(call.args[:1])
    candidates += [kw.value for kw in call.keywords if kw.arg in ("path", "rule")]
    for value in candidates:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
    return None


def _py_endpoint_arg(call: ast.Call, name: str) -> str | None:
    """The function name a registration call routes to."""
    value: ast.expr | None = None
    for kw in call.keywords:
        if kw.arg in ("endpoint", "view_func"):
            value = kw.value
    if value is None:
        index = 2 if name == "add_url_rule" else 1
        if len(call.args) > index:
            value = call.args[index]
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        return value.attr
    return None
