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
from typing import NamedTuple, Optional

# Callees that perform an outbound request.
_PY_FETCH_CALLEES = (
    "requests.get", "requests.post", "requests.put", "requests.delete", "requests.head",
    "requests.request", "urllib.request.urlopen", "httpx.get", "httpx.post", "httpx.put",
    "httpx.delete", "httpx.request", "httpx.stream", "session.get", "session.post",
    "client.get", "client.post", "aiohttp.request",
)
_JS_FETCH_RE = re.compile(
    r"\b(?P<callee>fetch|axios\.(?:get|post|put|delete|request)|axios|got|node_fetch|"
    r"superagent\.(?:get|post))\s*\(\s*(?P<arg>[^;]{0,200}?)\s*[,)]",
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

_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


class Reach(NamedTuple):
    """What an outbound call site was found to reach."""
    callee: str
    line: int
    tainted: bool          # URL argument derives from caller-controlled input
    private_addr: Optional[str]   # private/metadata address reaching this call


def _blank_preserving_layout(text: str, pattern: re.Pattern[str]) -> str:
    """Replace matches with spaces, keeping newlines so offsets and line numbers hold."""
    def repl(m: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in m.group(0))
    return pattern.sub(repl, text)


def strip_comments(text: str, is_python: bool) -> str:
    """Remove comments only. String literals are kept: a real metadata URL lives
    in one, so blanking literals would delete the true positives along with the
    prose."""
    if is_python:
        # `#` inside a string would be mangled by a naive strip, so use the
        # tokenizer's view via ast when the file parses, else leave it alone.
        return text
    return _blank_preserving_layout(
        _blank_preserving_layout(text, _TS_BLOCK_COMMENT_RE), _TS_LINE_COMMENT_RE
    )


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

    def tainted(node: ast.AST, depth: int = 0) -> bool:
        if depth > 4:
            return False
        if _py_is_user_expr(node):
            return True
        for name in _py_names_in(node):
            for rhs in assigns.get(name, []):
                if tainted(rhs, depth + 1):
                    return True
        return False

    def addr_reaching(node: ast.AST, depth: int = 0) -> Optional[str]:
        if depth > 4:
            return None
        for lit in _py_literal_strings(node):
            m = _PRIVATE_ADDR_RE.search(lit)
            if m:
                return m.group(0).lower()
        for name in _py_names_in(node):
            for rhs in assigns.get(name, []):
                found = addr_reaching(rhs, depth + 1)
                if found:
                    return found
        return None

    out: list[Reach] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _py_callee_name(node.func)
        if not _py_is_fetch(name):
            continue
        url_arg: Optional[ast.AST] = node.args[0] if node.args else None
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
    for m in re.finditer(r"(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,200})", code):
        assigns.setdefault(m.group(1), m.group(2))

    def resolve(expr: str, depth: int = 0) -> str:
        """Inline single-hop assignments of the identifiers in expr."""
        if depth > 3:
            return expr
        out = expr
        for name in set(re.findall(r"[A-Za-z_$][\w$]*", expr)):
            rhs = assigns.get(name)
            if rhs and rhs.strip() != name:
                out += " " + resolve(rhs, depth + 1)
        return out

    results: list[Reach] = []
    for m in _JS_FETCH_RE.finditer(code):
        arg = m.group("arg") or ""
        expanded = resolve(arg)
        addr = _PRIVATE_ADDR_RE.search(expanded)
        results.append(Reach(
            callee=m.group("callee"),
            line=code.count("\n", 0, m.start()) + 1,
            tainted=bool(_JS_USER_RE.search(expanded)),
            private_addr=addr.group(0).lower() if addr else None,
        ))
    return results


def analyze(text: str, is_python: bool) -> list[Reach]:
    return analyze_python(text) if is_python else analyze_js(text)
