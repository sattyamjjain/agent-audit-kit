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
import string
from typing import Callable, Iterable, Iterator, NamedTuple

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
    "session.request", "client.get", "client.post", "client.request", "client.stream",
    "aiohttp.request",
)
# The callees above whose last name is one of these take the HTTP method first
# and the URL second, or as `url=`: `requests.request`, `httpx.request`,
# `httpx.stream`, `aiohttp.request`, and a requests or aiohttp session's or an
# httpx client's `.request` and `.stream`. The URL used to be read from the first
# positional argument everywhere, so the method was taken for it:
# `requests.request("GET", url)` never carried the caller's URL, and
# `requests.request(method, FIXED)` reported a caller's method as one.
_PY_METHOD_FIRST = frozenset({"request", "stream"})
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
#: Punctuation a host written without a scheme sits between in prose and lists
#: (`hosts: localhost, 10.0.0.5,`, `(127.0.0.1)`). Not `[` or `]`, which bracket
#: an IPv6 host, and not `=` or `&`, after which a query value is not the URL's
#: host.
_BARE_HOST_PUNCT_RE = re.compile(r"[,;()<>{}\"'`|]+")
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
    when it is a host written plainly (`_bare_host`), after the punctuation
    around it is split off: the old search found `localhost` in
    `hosts: localhost, 10.0.0.5,` and 127.0.0.1 in `(127.0.0.1)`. The address
    comes back in its usual form, so `http://0xa9fea9fe/` gives 169.254.169.254.
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
            hosts = [_bare_host(part) for part in _BARE_HOST_PUNCT_RE.split(word) if part]
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

#: Where every reader ends an authority. WHATWG also ends one at a backslash,
#: but curl, httpx and urlsplit keep it inside, so after `https://api.example.com\\`
#: the caller can still write `@evil.example`. A host is taken as fixed only
#: when every reading agrees (#1019).
_AUTHORITY_END_RE = re.compile(r"[/?#]")
#: Text the code does not spell out (a configured base URL, `self.base`, a call).
_UNKNOWN = "\x00"
#: How much of a URL's leading text is read: no host is longer.
_PREFIX_CAP = 512
#: How deeply nested expressions are followed inside one assignment level.
#: Real URL expressions nest a few levels; the bound keeps a crafted file from
#: exhausting the interpreter's stack.
_PY_MAX_NEST = 40
#: How many pieces of one built URL are read. Its host is in the first few; the
#: bound keeps a crafted run of empty pieces from costing more than this.
_PIECE_CAP = 256


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
    `/`, `?` or `#` follows at least one character of it, counted after the
    `://` when the text has one (`https://api.example.com/`), after a leading
    `//` (scheme-relative), and from the start otherwise (`api.example.com/`).
    A path that starts with one `/` and a segment (`/items/`, for a client
    holding a `base_url`) has no authority to change, and nor does a leading
    piece the code does not spell out, which is a base URL with its own host.
    Until then the caller's text can still name the host: `https://` + host,
    `"https://api.example.com"` + `@evil.example` or `.evil.example`,
    `http://localhost:` + a port and an `@`, or `/` + `/evil.example/x`.
    """
    if prefix[:1] in ("/", "\\") and prefix[1:2] not in ("/", "\\"):
        # A path on the client's base URL holds its host once the first segment
        # has begun. A bare `/` does not: the caller can write the second one,
        # and `urljoin(BASE, "/" + "/evil.example/x")` is https://evil.example/x.
        return len(prefix) > 1
    scheme = prefix.find("://")
    if prefix.startswith(_UNKNOWN) and scheme < 0:
        # A base the code does not spell out (`{BASE}`, `os.getenv(...)`,
        # `self.base_url`) is taken to carry its own host: it is how a client
        # is pointed at its one API (`FHIR_SERVER_BASE + endpoint`, the base
        # read from the environment). AAK-SSRF-001's limitation names the
        # base without a trailing `/` that this lets through.
        return True
    if scheme >= 0:
        authority = prefix[scheme + 3:]
    elif prefix[:1] in ("/", "\\"):
        authority = prefix[2:]  # scheme-relative: `//host/...`
    else:
        authority = prefix
    end = _AUTHORITY_END_RE.search(authority)
    return end is not None and end.start() > 0


def _str_constant(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_join(
    node: ast.AST, lists: Callable[[str], list[ast.expr] | None] | None = None
) -> tuple[str, list[ast.expr]] | None:
    """``(separator, items)`` for `"/".join([a, b])` over a literal list, or over
    a name `lists` reads back to one (`parts = ["https://", host]`, then
    `"".join(parts)`)."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    sep = _str_constant(node.func.value)
    if node.func.attr != "join" or sep is None or len(node.args) != 1 or node.keywords:
        return None
    items = node.args[0]
    if isinstance(items, ast.Name) and lists is not None:
        elts = lists(items.id)
        return None if elts is None else (sep, elts)
    return (sep, list(items.elts)) if isinstance(items, (ast.List, ast.Tuple)) else None


def _is_built(node: ast.AST, lists: Callable[[str], list[ast.expr] | None] | None = None) -> bool:
    """An f-string, a `+` or a literal `.join`: a URL put together from pieces."""
    return (
        isinstance(node, ast.JoinedStr)
        or (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add))
        or _literal_join(node, lists) is not None
    )


def _joined_name(node: ast.AST) -> str | None:
    """The name a `"sep".join(name)` reads its items from."""
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join"
            and len(node.args) == 1 and isinstance(node.args[0], ast.Name)):
        return node.args[0].id
    return None


def _pieces(
    node: ast.AST, lists: Callable[[str], list[ast.expr] | None] | None = None
) -> Iterator[str | ast.AST]:
    """A built string as the literal text and expressions it joins, in order:
    an f-string's parts, a `+` chain flattened left to right (with an explicit
    stack, as a chain can be thousands long), and a literal `.join` with its
    separator between the items, read lazily so a caller can stop once the
    host is settled, and never more than `_PIECE_CAP` of them.

    A named list is expanded once per URL. A join that comes back to a list
    already read reads as text the code does not spell out: `parts =
    ["https://", "".join(parts)]` looped for ever when every join was expanded
    again, and thirty lists that each join the one before twice would have
    read 2**30 pieces."""
    expanded: set[str] = set()
    stack: list[str | ast.AST] = [node]
    count = 0
    while stack:
        if count >= _PIECE_CAP:
            yield _UNKNOWN
            return
        cur = stack.pop()
        if isinstance(cur, str):
            count += 1
            yield cur
            continue
        name = _joined_name(cur) if lists is not None else None
        if name is not None:
            if name in expanded:
                count += 1
                yield _UNKNOWN
                continue
            expanded.add(name)
        joined = _literal_join(cur, lists)
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
        else:
            count += 1
            if isinstance(cur, ast.FormattedValue):
                yield cur.value
            else:
                text = _str_constant(cur)
                yield cur if text is None else text


#: A `%` conversion: an optional `(key)`, flags, width and precision in one
#: class, then the conversion letter. The key stops at the next `(` or `%`, and
#: the flag run at the next `%`, so a crafted template is read in linear time.
_PERCENT_FIELD_RE = re.compile(r"%(?:\(([^()%]*)\))?[-#0 +*.\d]*([A-Za-z%])")


def _percent_pieces(template: str, values: ast.expr) -> list[str | ast.AST]:
    """`template % values` as the text and the values it puts in each field, in
    order. A tuple fills the fields by position and a dict literal by `(key)`.
    Any other operand is the value of a positional field and the mapping a
    keyed one reads, so `"https://%(host)s/" % arguments` puts
    `arguments["host"]` in the host; a dict literal's `**` entries and entries
    under a computed key may fill a key it does not write out. A field nothing
    fills reads as text the code does not spell out."""
    positional: list[ast.expr] = []
    keyed: dict[str, ast.expr] = {}
    mapping: ast.expr | None = None
    if isinstance(values, ast.Tuple):
        positional = list(values.elts)
    elif isinstance(values, ast.Dict):
        others: list[ast.expr] = []
        for dict_key, dict_value in zip(values.keys, values.values):
            name = _str_constant(dict_key) if dict_key is not None else None
            if name is None:
                others.append(dict_value)
            else:
                keyed[name] = dict_value
        if others:
            mapping = others[0] if len(others) == 1 else ast.Tuple(elts=others, ctx=ast.Load())
    else:
        positional = [values]
        mapping = values
    pieces: list[str | ast.AST] = []
    pos = index = 0
    for field in _PERCENT_FIELD_RE.finditer(template):
        pieces.append(template[pos:field.start()])
        pos = field.end()
        field_key: str | None = field.group(1)
        if field.group(2) == "%" and field_key is None:
            pieces.append("%")
            continue
        filled: ast.expr | None
        if field_key is not None:
            filled = keyed.get(field_key, mapping)
        else:
            filled = positional[index] if index < len(positional) else None
            index += 1
        pieces.append(_UNKNOWN if filled is None else filled)
    pieces.append(template[pos:])
    return pieces


def _format_pieces(template: str, call: ast.Call) -> list[str | ast.AST] | None:
    """`template.format(...)` as the text and the argument each field takes, in
    order (`{}`, `{0}`, `{host}`, `{0.netloc}`), or None when the arguments are
    unpacked (`*args`, `**kwargs`) or the template does not parse."""
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(kw.arg is None for kw in call.keywords):
        return None
    try:
        fields = list(string.Formatter().parse(template))
    except ValueError:
        return None
    keywords = {kw.arg: kw.value for kw in call.keywords if kw.arg is not None}
    pieces: list[str | ast.AST] = []
    auto = 0
    for literal, name, _spec, _conversion in fields:
        pieces.append(literal)
        if name is None:
            continue
        head = name.partition(".")[0].partition("[")[0]
        value: ast.expr | None
        if head == "":
            value = call.args[auto] if auto < len(call.args) else None
            auto += 1
        elif head.isdigit():
            value = call.args[int(head)] if int(head) < len(call.args) else None
        else:
            value = keywords.get(head)
        pieces.append(_UNKNOWN if value is None else value)
    return pieces


#: The annotations of parameters a framework fills in, not the caller: FastMCP's
#: `Context` (`ctx: Context`, whose `request_context.lifespan_context` holds the
#: server's own API client), LangChain's `RunnableConfig`, and the OpenAI Agents
#: SDK's `RunContextWrapper` and `ToolContext`.
_INJECTED_ANNOTATIONS = frozenset({"Context", "RunnableConfig", "RunContextWrapper", "ToolContext"})


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


def _collect_bindings(
    root: ast.AST, values: dict[str, list[ast.AST]], parts: dict[str, list[ast.AST]]
) -> None:
    """The names `root` binds, in source order: into `values` what a name is
    bound to, into `parts` what it holds a part of.

    `=`, an annotated `=` and `:=` bind a name to their value. `x += y` extends
    the binding above it in place, so `url = "https://"` then `url += host` is
    one binding, `"https://" + host`: a chain is judged once, as one URL, and a
    base built that way is spelled out. Each `+=` used to add a binding of its
    own over the whole value before it, and every one was judged in full, so
    4,000 lines took 4 seconds, growing with the square. With nothing bound
    above it, `x += y` binds `x` itself combined with `y`. A name an unpacking
    assignment, a `for` or a comprehension binds holds a part of the value it
    is given (`host, _, port = target.partition(":")`).
    """
    nodes = [
        n for n in ast.walk(root)
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr,
                          ast.For, ast.AsyncFor, ast.comprehension))
    ]
    nodes.sort(key=_position)
    last: dict[str, ast.expr] = {}
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                _bind(target, node.value, values, parts, last)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            if node.value is not None:
                _bind(node.target, node.value, values, parts, last)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                name = node.target.id
                before = last.get(name)
                bound = values.setdefault(name, [])
                if before is not None and bound and bound[-1] is before:
                    combined = ast.BinOp(left=before, op=node.op, right=node.value)
                    bound[-1] = combined
                else:
                    combined = ast.BinOp(left=ast.Name(id=name, ctx=ast.Load()), op=node.op, right=node.value)
                    bound.append(combined)
                last[name] = combined
        else:
            _bind_parts(node.target, node.iter, parts, last)


def _position(node: ast.AST) -> tuple[int, int]:
    anchor = node.target if isinstance(node, ast.comprehension) else node
    return getattr(anchor, "lineno", 0), getattr(anchor, "col_offset", 0)


def _bind(
    target: ast.AST,
    value: ast.expr,
    values: dict[str, list[ast.AST]],
    parts: dict[str, list[ast.AST]],
    last: dict[str, ast.expr],
) -> None:
    if isinstance(target, ast.Name):
        values.setdefault(target.id, []).append(value)
        last[target.id] = value
    else:
        _bind_parts(target, value, parts, last)


def _bind_parts(
    target: ast.AST, value: ast.expr, parts: dict[str, list[ast.AST]], last: dict[str, ast.expr]
) -> None:
    """Each name a target list unpacks into (`a, (b, *c) = value`). An attribute
    or item target (`self.host, port = value`) binds no local."""
    stack = [target]
    while stack:
        cur = stack.pop()
        if isinstance(cur, ast.Name):
            parts.setdefault(cur.id, []).append(value)
            last.pop(cur.id, None)
        elif isinstance(cur, (ast.Tuple, ast.List)):
            stack.extend(cur.elts)
        elif isinstance(cur, ast.Starred):
            stack.append(cur.value)


class _CallerInput:
    """One tool function's caller input: what it is, and whether it can set the
    host of a URL built in that function."""

    def __init__(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        module_values: dict[str, list[ast.AST]],
        module_parts: dict[str, list[ast.AST]],
        only: frozenset[str] | None = None,
    ) -> None:
        self.params = _get_param_names(func) - _injected_params(func)
        if only is not None:
            self.params &= only
        # name -> what it is bound to here: `=`, an annotated `=`, `:=`, and an
        # augmented `+=` read as the value before it plus the operand ...
        self.values: dict[str, list[ast.AST]] = {}
        # ... and what it holds a part of: the iterable of a `for` or a
        # comprehension, and the value an unpacking assignment splits, whose
        # every part is the caller's when the whole is.
        self.elements: dict[str, list[ast.AST]] = {}
        _collect_bindings(func, self.values, self.elements)
        # The same, file-wide, for a name this function does not bind.
        self.module_values = module_values
        self.module_parts = module_parts
        self._sets: dict[tuple[int, int], bool] = {}
        self._text: dict[tuple[int, int], str] = {}

    def _bound(self, name: str) -> list[ast.AST]:
        """What `name` is bound to here, or else in the file. A name the file
        unpacks or loops over holds a part of a value, not the value: none."""
        local = self.values.get(name)
        if local:
            return local
        if name in self.module_parts:
            return []
        return self.module_values.get(name, [])

    def _list_of(self, name: str) -> list[ast.expr] | None:
        """The items of the list or tuple literal `name` is bound to, once."""
        bound = self._bound(name)
        if len(bound) == 1 and isinstance(bound[0], (ast.List, ast.Tuple)):
            return list(bound[0].elts)
        return None

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
            # Reached again while it is being worked out, an expression adds
            # nothing to its own answer: the cycle ends here.
            self._sets[key] = False
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
            elif _is_built(cur, self._list_of):
                if self._built_sets_host(_pieces(cur, self._list_of), depth, nest + 1):
                    return True
            elif isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Mod):
                # A template the caller hands over is theirs whatever it holds;
                # otherwise each value is read where its field puts it, so in
                # `"%s/v2/%s" % (BASE, repo)` the caller's `repo` is in the path.
                stack.append(cur.left)
                template = self._spelled(cur.left, depth, nest + 1)
                if self._built_sets_host(_percent_pieces(template, cur.right), depth, nest + 1):
                    return True
            elif isinstance(cur, (ast.List, ast.Tuple, ast.Set)):
                # The pieces of a URL a `.join` or a URL function has not been
                # read as text: any of them can be the host.
                stack.extend(cur.elts)
            elif isinstance(cur, ast.BinOp):
                stack.extend((cur.left, cur.right))
            elif isinstance(cur, ast.Call):
                func = cur.func
                pieces = None
                if isinstance(func, ast.Attribute) and func.attr == "format":
                    pieces = _format_pieces(self._spelled(func.value, depth, nest + 1), cur)
                    if pieces is not None:
                        # The template itself may be the caller's.
                        stack.append(func.value)
                if pieces is None:
                    stack.extend(self._call_operands(cur, depth, nest))
                elif self._built_sets_host(pieces, depth, nest + 1):
                    return True
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

    def _built_sets_host(self, pieces: Iterable[str | ast.AST], depth: int, nest: int) -> bool:
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
            self._text[key] = _UNKNOWN  # spelling it again while spelling it ends the cycle
            text = self._text[key] = self._spell(node, depth, nest)[:_PREFIX_CAP]
        return text

    def _spell(self, node: ast.AST, depth: int, nest: int) -> str:
        constant = _str_constant(node)
        if constant is not None:
            return constant
        if isinstance(node, ast.Name):
            if node.id in self.params or node.id in self.elements:
                return _UNKNOWN
            bound = self._bound(node.id)
            return self._spelled(bound[0], depth + 1, nest + 1) if len(bound) == 1 else _UNKNOWN
        if _is_built(node, self._list_of):
            text = ""
            for piece in _pieces(node, self._list_of):
                text += piece if isinstance(piece, str) else self._spelled(piece, depth, nest + 1)
                if len(text) >= _PREFIX_CAP:
                    break
            return text
        pieces: list[str | ast.AST] | None = None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            pieces = _percent_pieces(self._spelled(node.left, depth, nest + 1), node.right)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            pieces = _format_pieces(self._spelled(node.func.value, depth, nest + 1), node)
        if pieces is None:
            return _UNKNOWN
        text = ""
        for piece in pieces:
            text += piece if isinstance(piece, str) else self._spelled(piece, depth, nest + 1)
            if len(text) >= _PREFIX_CAP:
                break
        return text


def _registered_tools(tree: ast.AST) -> set[str]:
    """Names of functions the file registers as tools by a call rather than a
    decorator: passed to `add_tool(...)` (FastMCP, the MCP SDK), handed over as
    `func=` (`StructuredTool.from_function(func=fetch)`, LangChain's
    `Tool(name, func=fetch, ...)`) or as `from_function`'s first argument."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _py_callee_name(node.func).rpartition(".")[2]
        given = [kw.value for kw in node.keywords if kw.arg == "func"]
        if callee in ("add_tool", "from_function") and node.args:
            given.append(node.args[0])
        if callee == "add_tool":
            given.extend(kw.value for kw in node.keywords if kw.arg in ("fn", "function", "tool"))
        names.update(item.id for item in given if isinstance(item, ast.Name))
    return names


def _is_function_tool(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Decorated `@function_tool`, the OpenAI Agents SDK's tool decorator,
    bare or called (`@function_tool(name_override=...)`)."""
    for decorator in func.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if _py_callee_name(target).rpartition(".")[2] == "function_tool":
            return True
    return False


#: The base a class-based tool extends (LangChain's and CrewAI's `BaseTool`),
#: and the methods it runs the caller's input through.
_TOOL_CLASS_BASE = "BaseTool"
_TOOL_CLASS_METHODS = frozenset({"_run", "_arun"})
#: The parameters of a `call_tool` method that are the caller's: the names the
#: old list held. A client's bridge takes the server it was configured with
#: too (`call_tool(self, server, tool_name, arguments)`), which is not.
_CALL_TOOL_INPUTS = frozenset({
    "input", "args", "params", "kwargs", "request", "req", "event", "tool_input", "arguments", "payload",
    "body", "query",
})


def _class_tool_methods(tree: ast.AST) -> set[int]:
    """ids of the `_run` and `_arun` methods of the file's `BaseTool`
    subclasses (`class Fetch(BaseTool)`, `class Fetch(tools.BaseTool)`)."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if not any(_py_callee_name(base).rpartition(".")[2] == _TOOL_CLASS_BASE for base in node.bases):
            continue
        found.update(
            id(item) for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in _TOOL_CLASS_METHODS
        )
    return found


def _caller_inputs(tree: ast.AST) -> dict[int, list[_CallerInput]]:
    """id(call) -> the caller input of each tool function the call sits in.

    A tool is what taint_analysis reads as one, a function decorated
    `@function_tool`, one the file registers by a call (`_registered_tools`),
    a `BaseTool` subclass's `_run` or `_arun`, or a function or method called
    `call_tool`, the shape a low-level server or a dispatcher written as a
    class takes (`async def call_tool(self, name, arguments)`), whose caller
    input is only its `arguments` and the other `_CALL_TOOL_INPUTS`. Without
    these, `mcp.add_tool(fetch)`, the OpenAI Agents SDK's tools, LangChain's
    and CrewAI's class tools and a class's `call_tool` had no caller input,
    where the old name list fired on them when the parameter was called
    `query`, `params` or `arguments`.
    """
    registered = _registered_tools(tree)
    class_tools = _class_tool_methods(tree)
    module_values: dict[str, list[ast.AST]] = {}
    module_parts: dict[str, list[ast.AST]] = {}
    _collect_bindings(tree, module_values, module_parts)
    around: dict[int, list[_CallerInput]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        only: frozenset[str] | None = None
        if not (_is_tool_function(node) or _is_call_tool_handler(node) or _is_function_tool(node)
                or node.name in registered or id(node) in class_tools):
            if node.name != "call_tool":
                continue
            only = _CALL_TOOL_INPUTS
        scope = _CallerInput(node, module_values, module_parts, only)
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

    # name -> assigned expressions, file-wide, for the address walk: `=` and an
    # annotated `=` only. Reading the loop, unpacking and `+=` bindings the host
    # test reads as well added two real loopback calls on the two code-search
    # samples and one false one (a login URL that took a probe loop's address
    # four names away), too small a gain for the noise.
    assigns: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigns.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            assigns.setdefault(node.target.id, []).append(node.value)

    addr_reaching = _py_addr_reach(assigns)
    caller_inputs = _caller_inputs(tree)

    out: list[Reach] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _py_callee_name(node.func)
        if not _py_is_fetch(name):
            continue
        position = 1 if name.rpartition(".")[2] in _PY_METHOD_FIRST else 0
        url_arg: ast.AST | None = node.args[position] if len(node.args) > position else None
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
