"""Reachability helpers for the SSRF pattern scanner.

`ssrf_patterns` used to decide file-wide: if the word `fetch` appeared anywhere
and a user-input marker appeared anywhere, it reported CRITICAL. Neither had to
be code, related, or near each other — a match inside a comment, a rule title or
a regex literal counted. That produced findings like "loopback address reachable
from MCP tool" on the scanner's own detection pattern (#593).

This module answers the question the finding text actually claims: can the
caller of a tool set the host an outbound HTTP call connects to, and does a
private or metadata address actually reach one of those calls?

Two backends, both dependency-free:

  * Python — `ast`. Call sites are real Call nodes. Caller input is the
    parameters of the tool function the call sits in (`_CallerInput`), traced
    through assignments, f-strings, concatenation and formatting to the URL's
    host.
  * TS/JS — comment-stripped def-use. No parser is available, so this is a
    narrower approximation: it finds call sites, extracts the argument
    expression, and resolves single-hop assignments of the names in it.

The TS/JS backend is strictly more conservative than the old file-wide
matching. The Python one also reads a tool's own parameters, which the old name
list missed (`def fetch(url: str)`), and no longer reads a name outside a tool.
"""

from __future__ import annotations

import ast
import ipaddress
import re
from typing import Callable, Iterator, NamedTuple

from agent_audit_kit.scanners._helpers import blank_js_comments, host_ip, url_readings
from agent_audit_kit.scanners.taint_analysis import (
    _get_param_names,
    _is_call_tool_handler,
    _is_tool_function,
)

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

# Caller-controlled sources in TS/JS. Python reads a tool's parameters instead
# (see `_CallerInput`).
_JS_USER_RE = re.compile(
    r"\b(?:req\.query|req\.body|req\.params|request\.json|event\.body|tool_input|"
    r"arguments|params\[|args\[|input)\b"
)

# The private and metadata addresses AAK-SSRF-002 and -003 report, judged by
# value: 127.0.0.1, 0.0.0.0, ::1, 169.254.169.254, 10/8, 172.16/12 and
# 192.168/16, and the names localhost and metadata.google.internal.
#
# They were one regex searched anywhere in a string, with no boundary, so
# `http://110.1.2.3/` read as 10.1.2.3, `http://[2001:db8::1]/` as ::1 and
# `notlocalhost.example.com` as localhost, and AAK-SSRF-002 (HIGH) named an
# address the code does not contain. It also knew each address in one spelling,
# so `http://0xa9fea9fe/`, which Node and the resolver behind curl both read as
# 169.254.169.254, reached no rule. A URL's host is now read the way the client
# reads it (`_helpers.url_readings`, every reading counts), and a string that is
# not a URL counts when it is a host written plainly (see `_bare_host`).
_PRIVATE_V4_NETS = tuple(
    ipaddress.IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_PRIVATE_ADDRESSES = frozenset(
    ipaddress.ip_address(addr) for addr in ("127.0.0.1", "0.0.0.0", "::1", "169.254.169.254")
)
_PRIVATE_NAMES = frozenset({"localhost", "metadata.google.internal"})
#: Where a host written without a scheme ends.
_BARE_HOST_END_RE = re.compile(r"[/\\?#]")
#: The contents of a JS string or template literal, closed or not, read once:
#: a quote's body cannot contain its own quote unescaped, so every match ends at
#: the first one, and an unclosed literal ends at the line's or text's end.
_JS_LITERAL_RE = re.compile(
    r"'((?:[^'\\\n]|\\.)*)'?|\"((?:[^\"\\\n]|\\.)*)\"?|`((?:[^`\\]|\\[\s\S])*)`?"
)
#: A template literal's `${...}`, which is code, not text.
_JS_TEMPLATE_HOLE_RE = re.compile(r"\$\{[^}]*\}?")

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
    tainted: bool          # caller input can set the URL's host
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


def _private_address(text: str) -> str | None:
    """The first private or metadata address a string literal names, or None.

    Each whitespace-separated word is read as a URL when it has a scheme, and
    every reading of its host counts: `http://evil.example\\@10.0.0.5/` is
    10.0.0.5 to httpx, which dials it. A word holding `://` without a URL
    scheme in front (an f-string piece such as `://169.254.169.254/`, or
    `gopher://127.0.0.1:6379/`) is read from its `://`. Any other word counts
    when it is a host written plainly (`_bare_host`). The address comes back
    in its usual form, so `http://0xa9fea9fe/` gives 169.254.169.254.
    """
    for word in text.split():
        if "." not in word and ":" not in word and "localhost" not in word.lower():
            continue  # no URL, address or private name: skip the parse
        readings = url_readings(word)
        if not readings and "://" in word:
            readings = url_readings("http" + word[word.index("://"):])
        if readings:
            hosts = [reading.host for reading in readings]
        elif "://" in word:
            continue
        else:
            hosts = [_bare_host(word)]
        for host in hosts:
            label = _private_label(host)
            if label is not None:
                return label
    return None


def _bare_host(word: str) -> str:
    """The host a word that is not a URL starts with: `127.0.0.1`,
    `localhost:9000`, `169.254.169.254/latest`, `[::1]:8080` or `::1`.

    Read this way, an address has to be written out: four decimal numbers or an
    IPv6 address, which is all `host_ip` accepts. A URL parser also reads
    `10.1`, `0x7f.1` and `2130706433` as addresses, but without a scheme saying
    the string is a URL they are as often a version or a count, so `"10.2.1"`
    in a path is not 10.2.0.1.
    """
    end = _BARE_HOST_END_RE.search(word)
    authority = (word if end is None else word[:end.start()]).rpartition("@")[2]
    if authority.startswith("["):
        return authority[1:authority.find("]")] if "]" in authority else ""
    if authority.count(":") > 1:
        return authority  # an IPv6 address written without brackets
    return authority.partition(":")[0].lower()


def _private_label(host: str) -> str | None:
    """`host` as AAK-SSRF-002 and -003 name it, when it is one of theirs.

    A name under `.localhost` counts as localhost, as RFC 6761 reserves it for
    loopback and the old substring search read it.
    """
    name = host.rstrip(".")
    if name in _PRIVATE_NAMES or name.endswith(".localhost"):
        return name
    address = host_ip(name)
    if address is None:
        return None
    if address in _PRIVATE_ADDRESSES:
        return str(address)
    if isinstance(address, ipaddress.IPv4Address) and any(address in net for net in _PRIVATE_V4_NETS):
        return str(address)
    return None


def _js_private_address(expr: str) -> str | None:
    """`_private_address` over the string and template literals of a piece of
    JS, in order. Code is not text: the old search over the whole piece read
    `fetch(localhostUrl)` as a request to localhost."""
    for match in _JS_LITERAL_RE.finditer(expr):
        single, double, template = match.groups()
        if template is not None:
            body = _JS_TEMPLATE_HOLE_RE.sub(" ", template)
        else:
            body = single if single is not None else double or ""
        label = _private_address(body)
        if label is not None:
            return label
    return None


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


def _py_addr_reach(assigns: dict[str, list[ast.AST]]) -> Callable[[ast.AST], str | None]:
    """The first private address that reaches an expression, through up to four
    levels of assignments.

    The walk used to start afresh for every name at every level: each step
    tried every name an expression mentions and every expression that name was
    assigned, four levels down, with nothing remembered. Names assigned from
    each other multiplied: twenty names that each read all twenty took a second
    for one call, growing with the fifth power of the fan-out, and every call
    site paid again. A depth bound stops a cycle; it does not stop that.

    The answer for an expression at a given depth never changes within a file,
    so each (expression, depth) and each (name, depth) is worked out once. The
    order is the old one (names in the set's order, a name's assignments in
    source order), so the address reported is the one the old walk reached
    first."""
    expr_addr: dict[tuple[int, int], str | None] = {}
    name_addr: dict[tuple[str, int], str | None] = {}
    names: dict[int, set[str]] = {}

    def names_in(node: ast.AST) -> set[str]:
        found = names.get(id(node))
        if found is None:
            found = names[id(node)] = _py_names_in(node)
        return found

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

    return addr_reaching


def _py_addr_here(node: ast.AST) -> str | None:
    """The first private address in the string literals of ``node`` itself."""
    for lit in _py_literal_strings(node):
        label = _private_address(lit)
        if label is not None:
            return label
    return None


# ---- Caller input: a tool's parameters --------------------------------------
#
# Caller input was a list of names (`input`, `args`, `params`, `kwargs`,
# `request`, `req`, `event`, `tool_input`, `arguments`, `payload`, `body`,
# `query`) matched anywhere in the file. A tool's own `url` parameter was not on
# it, so `@mcp.tool() def fetch(url: str): return requests.get(url).text`
# reached neither AAK-SSRF-001 nor -005, while any function with a parameter
# called `query` counted, and so did a module-level `request`. Caller input is
# now what taint_analysis takes it to be: the parameters of a function it reads
# as a tool (`@tool`, `@mcp.tool`, `@server.tool`, ...) or as a low-level
# `@<server>.call_tool()` handler, less a `Context` the framework fills in
# (`_injected_params`), inside that function and its closures, and the locals
# bound from them there.
#
# A parameter reaching the URL is not enough on its own. A tool that calls one
# fixed API with the caller's values in the path or the query,
# `f"https://api.github.com/repos/{owner}/{repo}"`, is how most MCP servers are
# written, and it sends nothing to a host the caller chooses. So a URL counts
# when caller input can set its host (`_CallerInput.sets_host`).

#: Where an authority ends: WHATWG also stops at a backslash.
_AUTHORITY_END_RE = re.compile(r"[/\\?#]")
#: Text the code does not spell out (a configured base URL, `self.base`, a call).
_UNKNOWN = "\x00"
#: How much of a URL's leading text is read: no host is longer.
_PREFIX_CAP = 512
#: How deeply nested expressions are followed inside one assignment level.
#: Real URL expressions nest a few levels; the bound keeps a crafted file from
#: exhausting the interpreter's stack.
_PY_MAX_NEST = 40


#: Functions that return a URL built from the arguments they are given, so
#: caller input in an argument is in the URL: `str(url)`, `urljoin(BASE, path)`
#: (`path` replaces the base when it is absolute), the quoting helpers,
#: `urlunparse`/`urlunsplit` over their parts, and the URL and request objects
#: of urllib, requests, httpx and yarl (`Request(url)`, `httpx.URL(url)`).
_PASS_THROUGH = frozenset({
    "str", "urljoin", "quote", "quote_plus", "unquote", "unquote_plus", "requote_uri",
    "urlunparse", "urlunsplit", "URL", "Request",
})


def _authority_closed(prefix: str) -> bool:
    """Whether the leading text of a URL has ended its authority, so that
    nothing after it can change the host.

    `prefix` is the URL's text up to a caller-controlled piece, each piece the
    code does not spell out written as `_UNKNOWN`. The authority has ended once
    `/`, `?`, `#` or `\\` follows at least one character of it, counted after
    the `://` when the text has one (`https://api.example.com/`) and from the
    start otherwise (`{BASE}/items/`, `api.example.com/`). A path that starts
    with one `/` (for a client holding a `base_url`) has no authority to change,
    and nor does a leading piece the code does not spell out, which is a base
    URL with its own host. Until then the caller's text can still name the
    host: `https://` + host, `"https://api.example.com"` + `@evil.example` or
    `.evil.example`, or `http://localhost:` + a port and an `@`.
    """
    if prefix.startswith("/") and not prefix.startswith("//"):
        return True
    scheme = prefix.find("://")
    if prefix.startswith(_UNKNOWN) and scheme < 0:
        # A base the code does not spell out (`{BASE}`, `os.getenv(...)`,
        # `self.base_url`) is taken to carry its own host: it is how a client
        # is pointed at its one API (`FHIR_SERVER_BASE + endpoint`, the base
        # read from the environment). AAK-SSRF-001's limitation names the
        # base without a trailing `/` that this lets through.
        return True
    authority = prefix[scheme + 3:] if scheme >= 0 else prefix
    end = _AUTHORITY_END_RE.search(authority)
    return end is not None and end.start() > 0


def _str_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_join(node: ast.AST) -> tuple[str, list[ast.expr]] | None:
    """``(separator, items)`` for `"/".join([a, b])` over a literal list."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    sep = _str_constant(node.func.value)
    if node.func.attr != "join" or sep is None or len(node.args) != 1 or node.keywords:
        return None
    items = node.args[0]
    return (sep, list(items.elts)) if isinstance(items, (ast.List, ast.Tuple)) else None


def _is_built(node: ast.AST) -> bool:
    """An f-string, a `+` or a literal `.join`: a URL put together from pieces."""
    return (
        isinstance(node, ast.JoinedStr)
        or (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add))
        or _literal_join(node) is not None
    )


def _pieces(node: ast.AST) -> list[str | ast.AST]:
    """A built string as the literal text and expressions it joins, in order:
    an f-string's parts, a `+` chain flattened left to right (with an explicit
    stack, as a chain can be thousands long), and a literal `.join` with its
    separator between the items."""
    out: list[str | ast.AST] = []
    stack: list[str | ast.AST] = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            out.append(cur)
            continue
        joined = _literal_join(cur)
        if joined is not None:
            sep, items = joined
            for index in range(len(items) - 1, -1, -1):
                stack.append(items[index])
                if index:
                    stack.append(sep)
        elif isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Add):
            stack.extend((cur.right, cur.left))
        elif isinstance(cur, ast.JoinedStr):
            stack.extend(reversed(cur.values))
        elif isinstance(cur, ast.FormattedValue):
            out.append(cur.value)
        else:
            text = _str_constant(cur)
            out.append(cur if text is None else text)
    return out


#: The annotations of parameters a framework fills in, not the caller: FastMCP's
#: `Context` (`ctx: Context`, whose `request_context.lifespan_context` holds the
#: server's own API client) and LangChain's `RunnableConfig`.
_INJECTED_ANNOTATIONS = frozenset({"Context", "RunnableConfig"})


def _injected_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """The parameters of `func` annotated as one `_INJECTED_ANNOTATIONS` names,
    written bare, dotted, subscripted (`Context[ServerSession, None]`) or as a
    string."""
    names: set[str] = set()
    for arg in func.args.posonlyargs + func.args.args + func.args.kwonlyargs:
        annotation = arg.annotation
        if isinstance(annotation, ast.Subscript):
            annotation = annotation.value
        if annotation is None:
            continue
        text = _str_constant(annotation)
        name = text.partition("[")[0] if text is not None else _py_callee_name(annotation)
        if name.rpartition(".")[2] in _INJECTED_ANNOTATIONS:
            names.add(arg.arg)
    return names


class _CallerInput:
    """One tool function's caller input: what it is, and whether it can set the
    host of a URL built in that function."""

    def __init__(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        module_assigns: dict[str, list[ast.AST]],
    ) -> None:
        self.params = _get_param_names(func) - _injected_params(func)
        # name -> what it is bound to here: `=`, an annotated `=` and `:=` ...
        self.values: dict[str, list[ast.AST]] = {}
        # ... and the iterable a `for` or a comprehension takes it from, whose
        # every element is the caller's when the iterable is.
        self.elements: dict[str, list[ast.AST]] = {}
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.values.setdefault(target.id, []).append(node.value)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and isinstance(node.target, ast.Name):
                if node.value is not None:
                    self.values.setdefault(node.target.id, []).append(node.value)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                if isinstance(node.target, ast.Name):
                    self.elements.setdefault(node.target.id, []).append(node.iter)
        self.module_assigns = module_assigns
        self._sets: dict[tuple[int, int], bool] = {}
        self._text: dict[tuple[int, int], str] = {}

    def sets_host(self, node: ast.AST, depth: int = 0, nest: int = 0) -> bool:
        """Whether caller input can set the host of the URL `node` evaluates to.

        It can when the URL is caller input as a whole (a parameter, an item or
        attribute read from one, a method called on one or a URL function given
        one, a local bound from one), or when the URL is built (an f-string,
        `+`, a literal `.join`, `%`, `.format`, `.replace`) and a piece of caller
        input comes before the text the code wrote has ended the authority
        (`_authority_closed`). Each (expression, depth) is worked out
        once, as `_py_addr_reach` does, so names that read each other do not
        multiply the work.
        """
        if depth > _PY_MAX_DEPTH or nest > _PY_MAX_NEST:
            return False
        key = (id(node), depth)
        hit = self._sets.get(key)
        if hit is None:
            hit = self._sets[key] = self._sets_host(node, depth, nest)
        return hit

    def _sets_host(self, node: ast.AST, depth: int, nest: int) -> bool:
        # Read and attribute chains can be thousands long, so the parts of one
        # expression are walked with a stack; only a built URL, or a name's
        # binding one assignment down, is a call of its own.
        stack = [node]
        while stack:
            cur = stack.pop()
            if isinstance(cur, ast.Name):
                if cur.id in self.params:
                    return True
                bound = self.values.get(cur.id, []) + self.elements.get(cur.id, [])
                if any(self.sets_host(rhs, depth + 1, nest + 1) for rhs in bound):
                    return True
            elif isinstance(cur, (ast.Subscript, ast.Attribute, ast.Starred, ast.Await, ast.NamedExpr)):
                # `URLS[region]` reads a URL the code fixed: only the container counts.
                stack.append(cur.value)
            elif _is_built(cur):
                if self._built_sets_host(_pieces(cur), depth, nest + 1):
                    return True
            elif isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Mod) and _str_constant(cur.left) is not None:
                if not _authority_closed(str(_str_constant(cur.left)).partition("%")[0]):
                    # `"%s://%s/" % (scheme, host)` and `"%(host)s" % {...}` format each value.
                    if isinstance(cur.right, ast.Tuple):
                        stack.extend(cur.right.elts)
                    elif isinstance(cur.right, ast.Dict):
                        stack.extend(value for value in cur.right.values if value is not None)
                    else:
                        stack.append(cur.right)
            elif isinstance(cur, ast.BinOp):
                stack.extend((cur.left, cur.right))
            elif isinstance(cur, ast.Call):
                stack.extend(self._call_operands(cur, depth, nest))
            elif isinstance(cur, ast.IfExp):
                stack.extend((cur.body, cur.orelse))
            elif isinstance(cur, ast.BoolOp):
                stack.extend(cur.values)
        return False

    def _call_operands(self, call: ast.Call, depth: int, nest: int) -> list[ast.AST]:
        """The parts of a call that can carry caller input into the URL it
        returns, read as `_PASS_THROUGH` says.

        A method passes its receiver on (`url.strip()`, `arguments.get("url")`,
        `params["url"].lower()`), and its arguments only where they become part
        of the result: a `.format` and a `.replace` are read for where they put
        them (a `"/".join([...])` of a literal list is read as the text it
        builds, see `_pieces`), and `.get(key, default)` passes its default but
        not its key. A function passes its arguments on only when it is one
        that returns a URL built from them (`_PASS_THROUGH`); any other one is
        taken to return what it builds, so a helper that puts the caller's
        values on a host it fixes (`self._url(path)`, `make_link(owner)`) is not
        read as a caller's URL, and nor is what a search or an API returns.
        """
        func = call.func
        name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
        if name in _PASS_THROUGH:
            operands: list[ast.AST] = []
            for arg in call.args:
                operands.extend(arg.elts if isinstance(arg, (ast.Tuple, ast.List)) else [arg])
            operands.extend(kw.value for kw in call.keywords if kw.arg in ("url", "uri"))
            return operands
        if not isinstance(func, ast.Attribute):
            return []
        receiver = func.value
        if name == "format":
            template = self._spelled(receiver, depth, nest + 1)
            if _authority_closed(template.partition("{")[0]):
                return [receiver]
            return [receiver, *call.args, *(kw.value for kw in call.keywords)]
        if name == "replace" and len(call.args) >= 2:
            template = self._spelled(receiver, depth, nest + 1)
            old = self._spelled(call.args[0], depth, nest + 1)
            if old and _UNKNOWN not in old and old in template and _authority_closed(template[:template.index(old)]):
                return [receiver]
            return [receiver, call.args[1]]
        if name == "get":
            return [receiver, *call.args[1:], *(kw.value for kw in call.keywords if kw.arg == "default")]
        if name == "join" and call.args:
            return [receiver, call.args[0]]
        return [receiver]

    def _built_sets_host(self, pieces: list[str | ast.AST], depth: int, nest: int) -> bool:
        prefix = ""
        for piece in pieces:
            if _authority_closed(prefix):
                return False
            if isinstance(piece, str):
                prefix = (prefix + piece)[:_PREFIX_CAP]
            elif self.sets_host(piece, depth, nest):
                return True
            else:
                prefix = (prefix + self._spelled(piece, depth, nest))[:_PREFIX_CAP]
        return False

    def _spelled(self, node: ast.AST, depth: int, nest: int) -> str:
        """The text a piece holds, as far as the code spells it out, with
        `_UNKNOWN` for the rest: a string constant, a name bound to one value
        here or in the module (`BASE = "https://api.example.com"`), and the
        built forms `sets_host` reads."""
        if depth > _PY_MAX_DEPTH or nest > _PY_MAX_NEST:
            return _UNKNOWN
        key = (id(node), depth)
        text = self._text.get(key)
        if text is None:
            text = self._text[key] = self._spell(node, depth, nest)[:_PREFIX_CAP]
        return text

    def _spell(self, node: ast.AST, depth: int, nest: int) -> str:
        constant = _str_constant(node)
        if constant is not None:
            return constant
        if isinstance(node, ast.Name):
            if node.id in self.params or node.id in self.elements:
                return _UNKNOWN
            bound = self.values.get(node.id) or self.module_assigns.get(node.id, [])
            return self._spelled(bound[0], depth + 1, nest + 1) if len(bound) == 1 else _UNKNOWN
        if _is_built(node):
            text = ""
            for piece in _pieces(node):
                text += piece if isinstance(piece, str) else self._spelled(piece, depth, nest + 1)
                if len(text) >= _PREFIX_CAP:
                    break
            return text
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and _str_constant(node.left) is not None:
            return str(_str_constant(node.left)).partition("%")[0] + _UNKNOWN
        func = node.func if isinstance(node, ast.Call) else None
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return self._spelled(func.value, depth, nest + 1).partition("{")[0] + _UNKNOWN
        return _UNKNOWN


def _caller_inputs(tree: ast.AST, assigns: dict[str, list[ast.AST]]) -> dict[int, list[_CallerInput]]:
    """id(call) -> the caller input of each tool function the call sits in."""
    around: dict[int, list[_CallerInput]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not (_is_tool_function(node) or _is_call_tool_handler(node)):
            continue
        scope = _CallerInput(node, assigns)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                around.setdefault(id(sub), []).append(scope)
    return around


def analyze_python(text: str) -> list[Reach]:
    """Outbound call sites in a Python source, with what each one reaches."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []

    # name -> assigned expressions, file-wide, for the address walk and for
    # spelling out a module-level constant such as a base URL.
    assigns: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigns.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            assigns.setdefault(node.target.id, []).append(node.value)

    addr_reaching = _py_addr_reach(assigns)
    caller_inputs = _caller_inputs(tree, assigns)

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
            tainted=any(scope.sets_host(url_arg) for scope in caller_inputs.get(id(node), [])),
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
        addr = _js_private_address(expr)
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
