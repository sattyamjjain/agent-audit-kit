"""Reachability helpers for the SSRF pattern scanner.

`ssrf_patterns` used to decide file-wide: if the word `fetch` appeared anywhere
and a user-input marker appeared anywhere, it reported CRITICAL. Neither had to
be code, related, or near each other — a match inside a comment, a rule title or
a regex literal counted. That produced findings like "loopback address reachable
from MCP tool" on the scanner's own detection pattern (#593).

This module answers the question the finding text actually claims: does the URL
argument of an outbound HTTP call derive from caller-controlled input, and does a
private or metadata address actually reach one of those calls?

Two backends, both dependency-free:

  * Python — `ast`. Call sites are real Call nodes; the URL argument is traced
    back through assignments, f-strings and simple concatenation.
  * TS/JS — comment-stripped def-use. No parser is available, so this is a
    narrower approximation: it finds call sites, extracts the argument
    expression, and resolves single-hop assignments of the names in it.

Both are strictly more conservative than the old file-wide matching, so this can
only remove findings, never add them.
"""

from __future__ import annotations

import ast
import re
from typing import Callable, Iterator, NamedTuple

from agent_audit_kit.scanners._helpers import blank_js_comments

# Callees that perform an outbound request.
_PY_FETCH_CALLEES = (
    "requests.get", "requests.post", "requests.put", "requests.delete", "requests.head",
    "requests.request", "urllib.request.urlopen", "httpx.get", "httpx.post", "httpx.put",
    "httpx.delete", "httpx.request", "httpx.stream", "session.get", "session.post",
    "client.get", "client.post", "aiohttp.request",
)
# A call site and its first argument, read without backtracking. The argument is
# everything up to the first `,`, `)` or `;` (at most 200 characters before the
# closer's leading whitespace), and the call counts only when a `,` or `)` closes
# it; `_js_fetch_calls` drops the trailing whitespace and applies that test.
# This is exactly what `\s*(?P<arg>[^;]{0,200}?)\s*[,)]` returned, but that form
# re-read every whitespace run once per character before it, so a call followed
# by a long run with no closer grew with the square of the run: "fetch(" and
# 8,000 spaces took 32 seconds.
_JS_FETCH_RE = re.compile(
    r"\b(?P<callee>fetch|axios\.(?:get|post|put|delete|request)|axios|got|node_fetch|"
    r"superagent\.(?:get|post))\s*\(\s*(?P<arg>[^,);]{0,200})(?P<close>\s*[,)])?",
)

# Caller-controlled sources.
_PY_USER_ROOTS = frozenset({
    "input", "args", "params", "kwargs", "request", "req", "event", "tool_input",
    "arguments", "payload", "body", "query",
})
_JS_USER_RE = re.compile(
    r"\b(?:req\.query|req\.body|req\.params|request\.json|event\.body|tool_input|"
    r"arguments|params\[|args\[|input)\b"
)

_PRIVATE_ADDR_RE = re.compile(
    r"(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1|169\.254\.169\.254|metadata\.google\.internal|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)",
    re.IGNORECASE,
)

# `const x = ...` / `let x = ...` / `x = ...`. The old one-piece pattern,
# `(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,200})`, began an
# attempt at every character of a long word or blank run and read to its end
# (a hex blob in an ordinary JS file), so 40,000 characters took 7.2 seconds and
# the time grew with the square. A match now starts only where one could first
# succeed: at the start of a blank run (the name after it is read whole), at the
# start of a word run, past any leading digits (a leading `const` / `let` / `var`
# is dropped from the name, as before, so `;variable=1` still records `iable`),
# or at one of those words that ends a run. Every other start failed for the
# same reason as one of these. `_JS_ASSIGN_AT_RE` is the old attempt, tried once
# where a 200-character right-hand side stopped inside a run, the one place the
# old pattern restarted mid-run. The table is the same as before.
_JS_ASSIGN_RE = re.compile(
    r"(?:(?<!\s)\s+|(?<![\w$])[^\W_A-Za-z]*(?:(?:const|let|var)\s*)?|(?:const|let|var)(?![\w$])\s*)"
    r"([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,200})"
)
_JS_ASSIGN_AT_RE = re.compile(r"[^\W_A-Za-z]*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,200})")
_JS_WORD_RE = re.compile(r"[\w$]")


class Reach(NamedTuple):
    """What an outbound call site was found to reach."""
    callee: str
    line: int
    tainted: bool          # URL argument derives from caller-controlled input
    private_addr: str | None   # private/metadata address reaching this call


def strip_comments(text: str, is_python: bool) -> str:
    """Remove comments only. String literals are kept: a real metadata URL lives
    in one, so blanking literals would delete the true positives along with the
    prose."""
    if is_python:
        # `#` inside a string would be mangled by a naive strip, so use the
        # tokenizer's view via ast when the file parses, else leave it alone.
        return text
    return blank_js_comments(text)


# ---------------------------------------------------------------------------
# Python backend
# ---------------------------------------------------------------------------

def _py_callee_name(node: ast.AST) -> str:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _py_is_fetch(name: str) -> bool:
    if name in _PY_FETCH_CALLEES:
        return True
    # `self.session.get(...)`, `_client.post(...)` — match on the tail.
    tail = ".".join(name.split(".")[-2:])
    return tail in _PY_FETCH_CALLEES


def _py_names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _py_roots_in(node: ast.AST) -> set[str]:
    """Root identifiers referenced, including the base of attribute/subscript chains."""
    roots = _py_names_in(node)
    for sub in ast.walk(node):
        if isinstance(sub, (ast.Attribute, ast.Subscript)):
            cur: ast.AST = sub
            while isinstance(cur, (ast.Attribute, ast.Subscript)):
                cur = cur.value
            if isinstance(cur, ast.Name):
                roots.add(cur.id)
    return roots


def _py_is_user_expr(node: ast.AST) -> bool:
    return bool(_py_roots_in(node) & _PY_USER_ROOTS)


def _py_literal_strings(node: ast.AST) -> list[str]:
    return [
        n.value for n in ast.walk(node)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


# Both backends read four levels of assignments below a call's argument: a
# Python expression at depth 4 is still checked, and a TS/JS piece at depth 3 is
# still expanded (its right-hand sides, at depth 4, are read but not expanded).
_PY_MAX_DEPTH = 4
_JS_MAX_DEPTH = 3


def _py_reach(
    assigns: dict[str, list[ast.AST]],
) -> tuple[Callable[[ast.AST], bool], Callable[[ast.AST], str | None]]:
    """Whether an expression derives from caller input, and the first private
    address that reaches it, through up to four levels of assignments.

    Both used to walk the assignment graph afresh for every name at every
    level: each step tried every name an expression mentions and every
    expression that name was assigned, four levels down, with nothing
    remembered. Names assigned from each other multiplied: twenty names that
    each read all twenty took a second for one call, growing with the fifth
    power of the fan-out, and every call site paid again. A depth bound stops a
    cycle; it does not stop that.

    The answer for an expression at a given depth never changes within a file,
    so each (expression, depth) and each (name, depth) is worked out once. The
    order is the old one (names in the set's order, a name's assignments in
    source order), so the address reported is the one the old walk reached
    first."""
    expr_tainted: dict[tuple[int, int], bool] = {}
    name_tainted: dict[tuple[str, int], bool] = {}
    expr_addr: dict[tuple[int, int], str | None] = {}
    name_addr: dict[tuple[str, int], str | None] = {}
    names: dict[int, set[str]] = {}

    def names_in(node: ast.AST) -> set[str]:
        found = names.get(id(node))
        if found is None:
            found = names[id(node)] = _py_names_in(node)
        return found

    def tainted(node: ast.AST, depth: int = 0) -> bool:
        if depth > _PY_MAX_DEPTH:
            return False
        key = (id(node), depth)
        hit = expr_tainted.get(key)
        if hit is None:
            hit = expr_tainted[key] = _py_is_user_expr(node) or any(
                assigned_tainted(name, depth + 1) for name in names_in(node)
            )
        return hit

    def assigned_tainted(name: str, depth: int) -> bool:
        key = (name, depth)
        hit = name_tainted.get(key)
        if hit is None:
            hit = name_tainted[key] = any(tainted(rhs, depth) for rhs in assigns.get(name, []))
        return hit

    def addr_reaching(node: ast.AST, depth: int = 0) -> str | None:
        if depth > _PY_MAX_DEPTH:
            return None
        key = (id(node), depth)
        if key not in expr_addr:
            found = _py_addr_here(node)
            if found is None:
                for name in names_in(node):
                    found = assigned_addr(name, depth + 1)
                    if found:
                        break
            expr_addr[key] = found
        return expr_addr[key]

    def assigned_addr(name: str, depth: int) -> str | None:
        key = (name, depth)
        if key not in name_addr:
            found = None
            for rhs in assigns.get(name, []):
                found = addr_reaching(rhs, depth)
                if found:
                    break
            name_addr[key] = found
        return name_addr[key]

    return tainted, addr_reaching


def _py_addr_here(node: ast.AST) -> str | None:
    """The first private address in the string literals of ``node`` itself."""
    for lit in _py_literal_strings(node):
        m = _PRIVATE_ADDR_RE.search(lit)
        if m:
            return m.group(0).lower()
    return None


def analyze_python(text: str) -> list[Reach]:
    """Outbound call sites in a Python source, with what each one reaches."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []

    # name -> assigned expressions (all of them; any tainted assignment taints).
    assigns: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigns.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            assigns.setdefault(node.target.id, []).append(node.value)

    tainted, addr_reaching = _py_reach(assigns)

    out: list[Reach] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _py_callee_name(node.func)
        if not _py_is_fetch(name):
            continue
        url_arg: ast.AST | None = node.args[0] if node.args else None
        if url_arg is None:
            for kw in node.keywords:
                if kw.arg in ("url", "uri"):
                    url_arg = kw.value
                    break
        if url_arg is None:
            continue
        out.append(Reach(
            callee=name,
            line=getattr(node, "lineno", 0),
            tainted=tainted(url_arg),
            private_addr=addr_reaching(url_arg),
        ))
    return out


# ---------------------------------------------------------------------------
# TS / JS backend
# ---------------------------------------------------------------------------

def analyze_js(text: str) -> list[Reach]:
    """Outbound call sites in TS/JS, via comment-stripped single-hop def-use."""
    code = strip_comments(text, is_python=False)

    # name -> RHS text, for `const x = ...` / `let x = ...` / `x = ...`
    assigns: dict[str, str] = {}
    for name, rhs in _js_assignments(code):
        assigns.setdefault(name, rhs)

    reach = _js_reach(assigns)
    results: list[Reach] = []
    # Lines are counted on from the previous call: counted from the top for
    # every call, 450 KB of `fetch(a);` lines took 4 seconds.
    line, counted = 1, 0
    for callee, arg, start in _js_fetch_calls(code):
        line += code.count("\n", counted, start)
        counted = start
        tainted, addr = reach(arg, 0)
        results.append(Reach(callee=callee, line=line, tainted=tainted, private_addr=addr))
    return results


_JS_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")


def _js_reach(assigns: dict[str, str]) -> Callable[[str, int], tuple[bool, str | None]]:
    """Whether an argument derives from caller input, and the first private
    address that reaches it, through up to four levels of assignments.

    This used to build the text: the argument, then each name in it replaced
    by its right-hand side, then each name in those, four levels down, all
    joined with spaces, and then search it. Nothing was remembered, so names
    assigned from each other multiplied: twenty-four names that each read all
    twenty-four, and one `fetch` reading them all, built 1.4 seconds of text,
    growing with the fourth power of the fan-out, and every call built it again
    (ten calls in a 3 KB file took 11 seconds). The depth bound stops a cycle;
    it does not stop that.

    Neither pattern can match across the space between two pieces of that text,
    so the joined text matches the user-input pattern exactly when one of its
    pieces does, and its first private address is the first in the first piece,
    in the old order, that has one. Each (piece, depth) is worked out once."""
    memo: dict[tuple[str, int], tuple[bool, str | None]] = {}
    names: dict[str, set[str]] = {}

    def visit(expr: str, depth: int) -> tuple[bool, str | None]:
        key = (expr, depth)
        hit = memo.get(key)
        if hit is not None:
            return hit
        tainted = bool(_JS_USER_RE.search(expr))
        m = _PRIVATE_ADDR_RE.search(expr)
        addr = m.group(0).lower() if m else None
        if depth <= _JS_MAX_DEPTH:
            idents = names.get(expr)
            if idents is None:
                # The old order: a set built from the names in source order.
                idents = names[expr] = set(_JS_IDENT_RE.findall(expr))
            for name in idents:
                rhs = assigns.get(name)
                if rhs and rhs.strip() != name:
                    below_tainted, below_addr = visit(rhs, depth + 1)
                    tainted = tainted or below_tainted
                    if addr is None:
                        addr = below_addr
        memo[key] = (tainted, addr)
        return tainted, addr

    return visit


def _js_assignments(code: str) -> Iterator[tuple[str, str]]:
    """``(name, right-hand side)`` pairs in the order ``finditer`` over the old
    one-piece pattern found them (see `_JS_ASSIGN_RE`)."""
    pos = 0
    while True:
        m = None
        if 0 < pos < len(code) and _same_run(code[pos - 1], code[pos]):
            m = _JS_ASSIGN_AT_RE.match(code, pos)
        if m is None:
            m = _JS_ASSIGN_RE.search(code, pos)
        if m is None:
            return
        yield m.group(1), m.group(2)
        pos = m.end()


def _same_run(a: str, b: str) -> bool:
    """Both blanks, or both word characters: a right-hand side cut there."""
    if a.isspace():
        return b.isspace()
    return bool(_JS_WORD_RE.match(a)) and bool(_JS_WORD_RE.match(b))


def _js_fetch_calls(code: str) -> Iterator[tuple[str, str, int]]:
    """``(callee, first argument, offset)`` for each outbound call, in the order
    and with the overlap rules of ``finditer`` over the old one-piece pattern: a
    call that is not closed is skipped and the search resumes one character
    later, and a closed one resumes after its closer."""
    pos = 0
    while True:
        m = _JS_FETCH_RE.search(code, pos)
        if m is None:
            return
        if m.group("close") is None:
            pos = m.start() + 1
            continue
        yield m.group("callee"), m.group("arg").rstrip(), m.start()
        pos = m.end()


def analyze(text: str, is_python: bool) -> list[Reach]:
    return analyze_python(text) if is_python else analyze_js(text)
