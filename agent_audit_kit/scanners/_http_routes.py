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
the commas directly inside each `(`, skipping strings, comments, TS/JS regex
literals and template text (a template's `${...}` is read as code), in time
linear in the file. A closer whose kind is not open anywhere is ignored, and one
that closes a deeper opener of its kind pops the openers above it, each opener
once, so a stray bracket (JSX text) costs one pass, not a rescan. Python is
read with `ast`.
"""

from __future__ import annotations

import ast
import re
from bisect import bisect_left, bisect_right
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
# the previous token (`if)` is the `)` closing an `if`, `while`, `for` or
# `with` header, after which a statement starts), a character before it, or a
# keyword that is not a property (`.in`).
_REGEX_AFTER_TOKENS = frozenset({"(", "[", "{", "}", ",", "/", "if)"})
_REGEX_AFTER_CHARS = frozenset("(,=:[!&|?{};+-*%<>~^")
_REGEX_AFTER_WORDS = frozenset({
    "return", "typeof", "case", "in", "of", "new", "delete", "void", "throw", "instanceof", "yield", "await",
    "else", "do", "default",
})
_HEADER_WORDS = frozenset({"if", "while", "for", "with"})
# A `{` after one of these, after an operator, or after a `(`, `[` or `,` opens
# an expression (an object literal, a JSX container), whose `}` a `/` divides.
_EXPRESSION_WORDS = frozenset({
    "return", "typeof", "case", "in", "of", "new", "delete", "void", "throw", "instanceof", "yield", "await",
    "default",
})
_EXPRESSION_CHARS = frozenset("=:?!&|+-*%<>~^")
# A literal up to where it closes or gives up: it is closed when the next
# character is its own quote. Each pattern reads one way only (an escape is a
# backslash and the character after it), so where it stops does not depend on
# backtracking.
_DQ_BODY_RE = re.compile(r'"(?:[^"\\\n]|\\.)*')
_SQ_BODY_RE = re.compile(r"'(?:[^'\\\n]|\\.)*")
_GO_RAW_BODY_RE = re.compile(r"`[^`]*")
# A TS/JS template's text, up to its closing backtick or a `${` that opens a
# substitution, whose code the reader reads as code until the `}` that closes it.
_JS_TEMPLATE_TEXT_RE = re.compile(r"(?:[^`\\$]|\\.|\$(?!\{))*", re.DOTALL)
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
    """Whether a route path receives MCP traffic: an `mcp` segment with no
    settings segment before it, then nothing or a transport tail.

    The path is read once. A tail spans at most three segments
    (`v1/tools/call`), so only an `mcp` segment among the last four can end the
    path; an earlier one matters only because a settings segment before it rules
    the path out. Rescanning the segments before every `mcp` segment and
    rejoining those after it made a path of repeated `/mcp` quadratic: 100 KB
    took about 30 seconds.
    """
    segments = [s for s in path.rsplit(" ", 1)[-1].split("/") if s]
    settings = False
    last = len(segments) - 1
    for i, segment in enumerate(segments):
        if _MCP_SEGMENT_RE.fullmatch(segment):
            if settings:
                return False
            if last - i <= 3:
                rest = "/".join(segments[i + 1:])
                if not rest or _MCP_TAIL_RE.fullmatch(rest):
                    return True
        elif segment.lower() in _ADMIN_SEGMENTS:
            settings = True
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
        _Scan(self, go).run()

    def _preceding(self, at: int, prev_end: int) -> tuple[int, int]:
        """What comes before ``at``, read back past blanks and comments no further
        than ``prev_end``, the end of the previous token: the position of the
        character found (below ``prev_end`` when there is none), and where the
        name ending there starts (one past it when that character is not part of
        a name). Each stretch between tokens is read back once per token, so the
        file costs one pass."""
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
        start = q + 1
        while start > prev_end and (text[start - 1].isalnum() or text[start - 1] in "_$"):
            start -= 1
        return q, start

    def _word(self, q: int, start: int, words: frozenset[str]) -> bool:
        """Whether the name at ``start:q + 1`` is one of ``words`` and not a
        property: `stats.in / 2` divides."""
        return start <= q and self.text[start:q + 1] in words and self.text[start - 1:start] != "."

    def _opens_regex(self, at: int, prev_tok: str, prev_end: int) -> bool:
        """Whether the `/` at ``at`` starts an expression, and so a regex literal.

        It does after one of `_REGEX_AFTER_CHARS` (an operator or punctuation),
        a keyword of `_REGEX_AFTER_WORDS`, a previous token of
        `_REGEX_AFTER_TOKENS` (a block's `}`, the `)` of an `if (...)` header),
        or at the start of the file. After a name, a number, `)`, `]`, an
        object literal's `}`, `++`, `--` or a string it is division (`a / b`,
        `x[i] / 2`, `f() / g()`, `i++ / 2`), on the next line too: JS inserts no
        semicolon before a `/`, and a formatter breaks a long division with the
        `/` first on the new line. A `/` straight after `<` closes a JSX tag
        (`</p>`); a formatter puts a blank between `<` and the regex it
        compares. A literal that does not close on its line is division after
        all.
        """
        q, start = self._preceding(at, prev_end)
        if q < prev_end:
            return not prev_tok or prev_tok in _REGEX_AFTER_TOKENS
        ch = self.text[q]
        if ch in "+-":
            return self.text[q - 1:q] != ch
        if ch == "<":
            return q < at - 1
        if ch in _REGEX_AFTER_CHARS:
            return True
        return self._word(q, start, _REGEX_AFTER_WORDS)

    def _opens_expression(self, at: int, prev_tok: str, prev_end: int, in_expression: bool) -> bool:
        """Whether the `{` at ``at`` opens an expression, an object literal or a
        JSX container, rather than a block: after an operator (but `=> {` opens
        a body), a `(`, `[`, `,` or a `/` that divides, an expression keyword, or
        a `{` that is itself an expression. Anything else is a block."""
        q, start = self._preceding(at, prev_end)
        if q < prev_end:
            return prev_tok in ("(", "[", ",", "/") or prev_tok == "{" and in_expression
        ch = self.text[q]
        if ch == ">":
            return self.text[q - 1:q] != "="
        if ch in _EXPRESSION_CHARS:
            return True
        return self._word(q, start, _EXPRESSION_WORDS)

    def _opens_header(self, at: int, prev_end: int) -> bool:
        """Whether the `(` at ``at`` opens an `if`, `while`, `for` or `with` header."""
        q, start = self._preceding(at, prev_end)
        return q >= prev_end and self._word(q, start, _HEADER_WORDS)

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


class _Scan:
    """One pass over a file, filling in a `CodeIndex`: the reader's state."""

    def __init__(self, index: CodeIndex, go: bool) -> None:
        self.index = index
        self.text = index.text
        self.go = go
        self.bodies = {'"': _DQ_BODY_RE, "'": _SQ_BODY_RE, "`": _GO_RAW_BODY_RE}
        self.token_re = _TOKEN_RE if go else _JS_TOKEN_RE
        self.stack: list[tuple[str, int]] = []
        self.braces: list[int] = []
        self.open_count = {"(": 0, "[": 0, "{": 0}
        # The last token that is not a comment, and where it ends: whether a
        # `/` opens a regex literal depends on what precedes it.
        self.prev_tok, self.prev_end = "", 0
        self.regex = _RegexReader(index.text)
        # Per quote, where a literal that never closed gave up. Every quote of
        # that kind before it is an escaped one inside that literal, and a
        # literal opened there reads on from it with the same escapes, so it
        # gives up at the same place: it is skipped without reading again.
        # Retrying each one read to the end of the line, or of the file for a
        # template, once per escaped quote.
        self.given_up = {'"': 0, "'": 0, "`": 0}
        # TS/JS only: the `{` that open an expression, the `(` that open an
        # `if`/`while`/`for`/`with` header, and the `{` of each `${`.
        self.expressions: set[int] = set()
        self.headers: set[int] = set()
        self.substitutions: set[int] = set()

    def run(self) -> None:
        text, n = self.text, len(self.text)
        pos = 0
        while pos < n:
            m = self.token_re.search(text, pos)
            if m is None:
                break
            tok, at = m.group(), m.start()
            if tok in ("//", "/*"):
                pos = self._comment(tok, at)
            elif tok == "/":
                pos = self._slash(at)
            elif tok == "`" and not self.go:
                pos = at + 1 if at < self.given_up["`"] else self._template(at, at + 1, opening=True)
            elif tok in ('"', "'", "`"):
                pos = self._string(tok, at)
            elif tok in ("(", "[", "{"):
                pos = self._open(tok, at)
            elif tok == ",":
                self.prev_tok, self.prev_end = tok, at + 1
                if self.stack and self.stack[-1][0] == "(":
                    self.index.commas[self.stack[-1][1]].append(at)
                pos = at + 1
            else:
                pos = self._close(tok, at)

    def _comment(self, tok: str, at: int) -> int:
        text = self.text
        if tok == "//":
            end = text.find("\n", at)
            end = len(text) if end < 0 else end
        else:
            end = text.find("*/", at + 2)
            end = len(text) if end < 0 else end + 2
        self.index._mask(at, end)
        return end

    def _slash(self, at: int) -> int:
        literal = self.regex.end(at) if self.index._opens_regex(at, self.prev_tok, self.prev_end) else None
        if literal is not None:
            self.index._mask(at, literal)
            self.prev_tok, self.prev_end = "re", literal
        else:
            self.prev_tok, self.prev_end = "/", at + 1
        return self.prev_end

    def _string(self, tok: str, at: int) -> int:
        text = self.text
        if at < self.given_up[tok]:
            return at + 1
        body = self.bodies[tok].match(text, at)
        end = body.end() if body is not None else len(text)
        if end >= len(text) or text[end] != tok:
            self.given_up[tok] = end
            return at + 1
        end += 1
        self.index._mask(at, end)
        self.index._strings[at] = end
        self.prev_tok, self.prev_end = "str", end
        return end

    def _template(self, start: int, pos: int, opening: bool) -> int:
        """Template text from ``pos`` to its closing backtick or the next `${`.

        ``start`` is the opening backtick, or the `}` that closed a
        substitution. A `${` opens a `{` that the reader closes as code; its `}`
        comes back here. Text that never closes is no template: like a string,
        the code after the backtick (or the `}`) is read as code, and since no
        backtick or `${` of its own stands before where it gave up, any backtick
        before that point is an escaped one and gives up there too. So does text
        after a `}` before that point: the reading that gave up stood after that
        `}` as well and read on from there the same way. Reading it again made k
        nested `${`, closed by k `}`, read the rest of the file k times.
        """
        if not opening and pos < self.given_up["`"]:
            return start + 1
        text = self.text
        match = _JS_TEMPLATE_TEXT_RE.match(text, pos)
        stop = match.end() if match is not None else len(text)
        if stop < len(text) and text[stop] == "`":
            self.index._mask(start, stop + 1)
            if opening:
                self.index._strings[start] = stop + 1
            self.prev_tok, self.prev_end = "str", stop + 1
            return stop + 1
        if text.startswith("${", stop):
            self.index._mask(start, stop + 2)
            self.substitutions.add(stop + 1)
            self._push("{", stop + 1)
            self.prev_tok, self.prev_end = "{", stop + 2
            return stop + 2
        self.given_up["`"] = stop
        return start + 1

    def _open(self, tok: str, at: int) -> int:
        if not self.go:
            if tok == "(" and self.index._opens_header(at, self.prev_end):
                self.headers.add(at)
            elif tok == "{" and self.index._opens_expression(
                at, self.prev_tok, self.prev_end, bool(self.braces) and self.braces[-1] in self.expressions,
            ):
                self.expressions.add(at)
        self.prev_tok, self.prev_end = tok, at + 1
        self._push(tok, at)
        return at + 1

    def _push(self, tok: str, at: int) -> None:
        self.stack.append((tok, at))
        self.open_count[tok] += 1
        if tok == "(":
            self.index.commas[at] = []
            self.index.block_of[at] = self.braces[-1] if self.braces else -1
        elif tok == "{":
            self.braces.append(at)

    def _close(self, tok: str, at: int) -> int:
        """A closer whose kind is not open anywhere is ignored, and one that
        closes a deeper opener of its kind pops the openers above it."""
        self.prev_tok, self.prev_end = tok, at + 1
        want = _OPENERS[tok]
        if not self.open_count[want]:
            return at + 1
        start = -1
        while self.stack:
            kind, start = self.stack.pop()
            self.open_count[kind] -= 1
            if kind == "{":
                self.braces.pop()
            if kind == want:
                self.index.close[start] = at
                break
        if start in self.substitutions:
            return self._template(at, at + 1, opening=False)
        if start in self.headers:
            self.prev_tok = "if)"
        elif start in self.expressions:
            self.prev_tok = ")"
        return at + 1


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
    # Request parameters are found once and looked up per `func`: searching
    # each parameter list on its own read the func types nested in it again,
    # so nested func types (`func(cb func(x func(...)))`) were quadratic, 24
    # seconds at 128 KB. A parameter holds no bracket, so none straddles a
    # list's `(` or `)`, and the first one past the `(` is the one a search of
    # the list finds.
    params = list(_GO_REQUEST_PARAM_RE.finditer(text))
    param_starts = [p.start() for p in params]
    # Where each signature walk ended, kept for the points it passed just after
    # a `)` that closes a `(`: see `_go_body_open`.
    walked: dict[int, int] = {}
    closes = {close for start, close in index.close.items() if text[start] == "("}
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
        i = bisect_left(param_starts, params_open)
        if i == len(params) or param_starts[i] >= params_close:
            continue
        param = params[i]
        body = _go_body_open(index, params_close + 1, walked, closes)
        if body is None:
            continue
        kind = _GO_KINDS[param.group(2).lstrip("*").strip().split(".")[0]]
        handlers.append(GoHandler(name, kind, param.group(1), m.start(), body, index.close[body]))
    return handlers


def _go_body_open(index: CodeIndex, pos: int, walked: dict[int, int], closes: set[int]) -> int | None:
    """The `{` that opens the body of the signature whose parameter list ends
    just before ``pos``: the walk to the end of the line steps over bracketed
    groups (a result list) and gives up at `,`, `;`, `=` or a `(` that never
    closes.

    The walk from a point on a line always ends the same way, so ``walked``
    keeps its end, as an offset or -1 for none, for each point it passed just
    after a `)` that closes a `(` (the offsets in ``closes``), and a later walk
    stops at the first such point. Those are the only points where two walks
    meet: a walk lands on a point another one passed either where it starts,
    just after its parameter list's `)`, or where one of the two jumped a
    group and the other stepped onto it, just after the group's `)`. So each
    character is walked once. Walking every signature to the line end on its
    own stepped past every func literal after it on that line: 10,700
    bodiless literals on one 256 KB line took 26 seconds. A `)` that closes
    nothing is not kept, since no two walks meet after one: keeping every
    point after a run of them, behind one func literal, held 99.5 MB at 999
    KB. The line end comes from the newline offsets by bisection; searching
    the text for it from every literal read the rest of the line once each as
    well (84,000 on one 4 MB line took 8.6 seconds).
    """
    text = index.text
    i = bisect_left(index._newlines, pos)
    end = index._newlines[i] if i < len(index._newlines) else len(text)
    passed: list[int] = []
    found = -1
    while pos < end:
        if text[pos - 1] == ")" and pos - 1 in closes:
            known = walked.get(pos)
            if known is not None:
                found = known
                break
            passed.append(pos)
        ch = text[pos]
        if ch == "{":
            found = pos if pos in index.close else -1
            break
        if ch == "(":
            close = index.close.get(pos)
            if close is None:
                break
            pos = close + 1
            continue
        if ch in ",;=":
            break
        pos += 1
    for point in passed:
        walked[point] = found
    return found if found >= 0 else None


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
    """A route registration: its path, and the spans of the arguments after it.

    Spans, not text: an inline handler's arguments hold every route nested in
    it, and copying each route's text was quadratic in memory (23,000 nested
    routes copied 11.6 GB).
    """

    receiver: str
    method: str
    path: str
    start: int
    arg_spans: tuple[tuple[int, int], ...]


def go_routes(index: CodeIndex) -> list[GoRoute]:
    """Route registrations whose path is a string literal."""
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
        routes.append(GoRoute(call.receiver, call.method, path, call.start, tuple(spans[1:])))
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
