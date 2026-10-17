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
    parameters of the tool function the call sits in, read through the scopes
    around it (`_Scope`), traced through assignments, f-strings, concatenation
    and formatting to the URL's host.
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
from typing import Any, Callable, Iterable, Iterator, NamedTuple

from agent_audit_kit.scanners._helpers import (
    blank_js_comments,
    host_ip,
    parse_python,
    url_readings,
)
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
# (see `_Scope`).
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
# when caller input can set its host (`_Scope.sets_host`).

#: Where every reader ends an authority. WHATWG also ends one at a backslash,
#: but curl, httpx and urlsplit keep it inside, so after `https://api.example.com\\`
#: the caller can still write `@evil.example`. A host is taken as fixed only
#: when every reading agrees (#1019).
_AUTHORITY_END_RE = re.compile(r"[/?#]")
#: A scheme and its colon with at most one `/` or `\` after them (`https:`,
#: `https:/`): text a URL passes through on its way to `https://`, written in
#: pieces as `"/".join(["https:", "", host])` writes it. No authority has begun.
_SCHEME_LEAD_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[/\\]?")
#: Text the code does not spell out (a configured base URL, `self.base`, a call).
_UNKNOWN = "\x00"
#: How much of a URL's leading text is read: no host is longer.
_PREFIX_CAP = 512
#: How deeply nested expressions are followed inside one assignment level.
#: Real URL expressions nest a few levels; the bound keeps a crafted file from
#: exhausting the interpreter's stack.
_PY_MAX_NEST = 40
#: How many pieces of one built URL are read. Its host is in the first few; the
#: bound keeps a crafted run of empty pieces from costing more than this. A list
#: joined by name is one piece of the URL that joins it, and is read to its own
#: `_PIECE_CAP` pieces (`_Scope._joined_sets_host`).
_PIECE_CAP = 256
#: How many fields of a `%` or `.format` template are read; the rest of it is
#: text the code does not spell out. A template a name holds is read again at
#: every use, so a template of 255 fields read at 20,414 call sites took 9
#: seconds; its host is in the first few fields.
_FIELD_CAP = 16


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
    `http://localhost:` + a port and an `@`, or `/` + `/evil.example/x`. A
    scheme with one slash after it (`https:/`) has no authority yet: read as
    a host and a path, it hid the caller's host in
    `"/".join(["https:", "", host])`.
    """
    if _SCHEME_LEAD_RE.fullmatch(prefix):
        return False
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


def _join_parts(node: ast.AST) -> tuple[str, ast.expr] | None:
    """``(separator, items)`` for `"sep".join(items)` with a constant separator."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    sep = _str_constant(node.func.value)
    if node.func.attr != "join" or sep is None or len(node.args) != 1 or node.keywords:
        return None
    return sep, node.args[0]


def _literal_join(node: ast.AST) -> tuple[str, list[ast.expr]] | None:
    """``(separator, items)`` for `"/".join([a, b])` over a literal list or tuple."""
    joined = _join_parts(node)
    if joined is None or not isinstance(joined[1], (ast.List, ast.Tuple)):
        return None
    return joined[0], joined[1].elts


def _named_join(node: ast.AST) -> tuple[str, str] | None:
    """``(separator, name)`` for `"".join(parts)`, a join over a name."""
    joined = _join_parts(node)
    if joined is None or not isinstance(joined[1], ast.Name):
        return None
    return joined[0], joined[1].id


def _is_built(node: ast.AST) -> bool:
    """An f-string, a `+` or a literal `.join`: a URL put together from pieces
    the expression itself writes."""
    return (
        isinstance(node, ast.JoinedStr)
        or (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add))
        or _literal_join(node) is not None
    )


#: The characters of a join's separator the authority test reads one by one:
#: the end of an authority (`/`, `?`, `#`), a backslash, a scheme's `:`, `@`
#: and text the code does not spell out. Any other character is read only as
#: a letter, as one of the rest of a scheme's characters, or as neither.
_SEPARATOR_OTHER_RE = re.compile(r"[^A-Za-z0-9+.\-:/?#\\@\x00]")
_SEPARATOR_KINDS = str.maketrans(string.ascii_letters + string.digits + "+.-", "a" * 52 + "0" * 13)
#: A separator `_pieces` passes through as itself, so the text between the
#: separators of a join can be read once for every separator it is joined with.
_SEPARATOR = "".join(["\x00", "separator"])


def _separator_class(sep: str) -> str:
    """A join's separator as far as the authority test can tell, a character
    for each of its own: `:`, `/`, `?`, `#`, `\\`, `@` and text the code does
    not spell out as themselves, a letter as `a`, a digit, `+`, `.` or `-` as
    `0`, and anything else as a space. Two separators of one class leave the
    authority open, or end it, at the same pieces of a join: the test reads a
    character only for whether it is one of those marks, whether it can start
    a scheme and whether it can carry one on.

    The class used to be the separator's length alone, when it held none of
    the marks. A letter carries a scheme on and a space breaks it, so
    `"s".join(["http", ":/" + host])`, which is `https:/` and the caller's
    host, and `" ".join(...)` of the same list, which is no URL, shared one
    verdict, as did `"s"` and `"1"` before `":/" + host`, a digit being no
    start of a scheme, and whichever join was read first decided the other."""
    return _SEPARATOR_OTHER_RE.sub(" ", sep).translate(_SEPARATOR_KINDS)


class _Run(NamedTuple):
    """The items of a joined list still to read, from `start`, with the
    separator between them. `_pieces` keeps one of these on its stack rather
    than every item, so a reader that settles the host early reads no more."""
    items: list[ast.expr]
    start: int
    sep: str


def _pieces(root: ast.AST | _Run) -> Iterator[str | ast.AST]:
    """A built string as the literal text and expressions it joins, in order:
    an f-string's parts, a `+` chain flattened left to right (with an explicit
    stack, as a chain can be thousands long), and a literal `.join` with its
    separator between the items, read lazily so a caller can stop once the
    host is settled, and never more than `_PIECE_CAP` of them. `root` is an
    expression, or a `_Run` over a list's items.

    A join over a name is one piece, which the reader judges and spells once
    per list (`_Scope._joined_sets_host`), the way it reads a name. It
    used to be read out item by item into every URL that joined it, so a list
    of 39,000 items joined by 10,000 fetches took 16 seconds, 8,000 lists that
    each joined the next took 60, and a list that joined itself had to be
    stopped with a record of the lists each URL had read."""
    stack: list[str | ast.AST | _Run] = [root]
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
        if isinstance(cur, _Run):
            if cur.start + 1 < len(cur.items):
                stack.append(_Run(cur.items, cur.start + 1, cur.sep))
                stack.append(cur.sep)
            if cur.start < len(cur.items):
                stack.append(cur.items[cur.start])
            continue
        joined = _literal_join(cur)
        if joined is not None:
            stack.append(_Run(joined[1], 0, joined[0]))
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


def _is_dict_display(node: ast.AST) -> bool:
    """A dict literal or a `dict(...)` call: a mapping written out in place."""
    return isinstance(node, ast.Dict) or (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict"
    )


def _dict_entries(node: ast.AST) -> list[tuple[str | None, ast.expr]]:
    """``(key, value)`` for each entry of a dict literal or a `dict(...)` call,
    in order, with None for a key the code does not write out: a `**` entry,
    a computed key, or the mapping or pairs `dict(...)` is given."""
    if isinstance(node, ast.Dict):
        return [(_str_constant(key) if key is not None else None, value) for key, value in zip(node.keys, node.values)]
    if isinstance(node, ast.Call):
        return [(None, arg) for arg in node.args] + [(kw.arg, kw.value) for kw in node.keywords]
    return []


def _template_lead(template: str) -> str:
    """The text of a `string.Template` before its first placeholder, with
    `$$` read as the `$` it writes."""
    lead: list[str] = []
    pos = 0
    while True:
        at = template.find("$", pos)
        if at < 0:
            lead.append(template[pos:])
            return "".join(lead)
        lead.append(template[pos:at])
        if template[at + 1:at + 2] != "$":
            return "".join(lead)
        lead.append("$")
        pos = at + 2


def _percent_pieces(
    template: str,
    values: ast.expr,
    mapping: Callable[[ast.expr], tuple[dict[str, ast.expr], ast.expr | None]],
) -> list[str | ast.AST]:
    """`template % values` as the text and the values it puts in each field, in
    order. A tuple fills the fields by position, and a keyed field reads what
    `mapping` finds in the operand: the entries it writes out by key, and what
    any other key may come from (a dict literal's `**` entries and entries
    under a computed key, or the operand itself). Any operand but a tuple or a
    dict literal is the value of a positional field too, so `"https://%(host)s/"
    % arguments` puts `arguments["host"]` in the host. A field nothing fills
    reads as text the code does not spell out, and so does the template after
    its `_FIELD_CAP`th field."""
    positional: list[ast.expr] = []
    keyed: dict[str, ast.expr] = {}
    rest: ast.expr | None = None
    if isinstance(values, ast.Tuple):
        positional = list(values.elts)
    else:
        keyed, rest = mapping(values)
        if not isinstance(values, ast.Dict):
            positional = [values]
    pieces: list[str | ast.AST] = []
    pos = index = 0
    for number, field in enumerate(_PERCENT_FIELD_RE.finditer(template)):
        pieces.append(template[pos:field.start()])
        if number == _FIELD_CAP:
            pieces.append(_UNKNOWN)
            return pieces
        pos = field.end()
        field_key: str | None = field.group(1)
        if field.group(2) == "%" and field_key is None:
            pieces.append("%")
            continue
        filled: ast.expr | None
        if field_key is not None:
            filled = keyed.get(field_key, rest)
        else:
            filled = positional[index] if index < len(positional) else None
            index += 1
        pieces.append(_UNKNOWN if filled is None else filled)
    pieces.append(template[pos:])
    return pieces


def _format_pieces(template: str, call: ast.Call) -> list[str | ast.AST] | None:
    """`template.format(...)` as the text and the argument each field takes, in
    order (`{}`, `{0}`, `{host}`, `{0.netloc}`), or None when the arguments are
    unpacked (`*args`, `**kwargs`) or the template does not parse. The template
    after its `_FIELD_CAP`th field, an escaped `{{` or `}}` counting as one,
    reads as text the code does not spell out."""
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(kw.arg is None for kw in call.keywords):
        return None
    try:
        fields = list(string.Formatter().parse(template))
    except ValueError:
        return None
    keywords = {kw.arg: kw.value for kw in call.keywords if kw.arg is not None}
    pieces: list[str | ast.AST] = []
    auto = 0
    for number, (literal, name, _spec, _conversion) in enumerate(fields):
        pieces.append(literal)
        if number == _FIELD_CAP:
            if name is not None or number + 1 < len(fields):
                pieces.append(_UNKNOWN)
            return pieces
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


#: The statements and expressions that bind a name in the scope they sit in,
#: with a function's parameters and a comprehension's own `for`, which binds
#: in the comprehension (`_scopes`). An import, a `def` or `class`, a `with`
#: or `except` target, a `match` capture, a `del` and an annotation without a
#: value bind in Python too, and are not read: the same name around them is
#: read instead.
_BINDING_NODES = (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _parameters(args: ast.arguments) -> set[str]:
    """Every name a function's or a lambda's parameters bind, `self` too."""
    names = {arg.arg for arg in args.posonlyargs + args.args + args.kwonlyargs}
    names.update(arg.arg for arg in (args.vararg, args.kwarg) if arg is not None)
    return names


def _outer_parts(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef) -> list[ast.AST]:
    """The parts of a definition that run in the scope around it: decorators,
    defaults, annotations, a class's bases and keywords."""
    if isinstance(node, ast.ClassDef):
        return [*node.decorator_list, *node.bases, *(kw.value for kw in node.keywords)]
    args = node.args
    parts: list[ast.AST] = [*args.defaults, *(default for default in args.kw_defaults if default is not None)]
    if isinstance(node, ast.Lambda):
        return parts
    every = [*args.posonlyargs, *args.args, *args.kwonlyargs, *(a for a in (args.vararg, args.kwarg) if a)]
    parts.extend(arg.annotation for arg in every if arg.annotation is not None)
    return [*node.decorator_list, *parts, *([node.returns] if node.returns else [])]


def _bind_nodes(
    pairs: list[tuple[ast.AST, frozenset[str] | None]],
    values: dict[str, list[ast.AST]],
    parts: dict[str, list[ast.AST]],
) -> None:
    """Record the bindings of each node, in source order, of the names its
    `frozenset` allows (any name for None)."""
    pairs.sort(key=lambda pair: _position(pair[0]))
    last: dict[str, ast.expr] = {}
    for node, allowed in pairs:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                _bind(target, node.value, values, parts, last, allowed)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            if node.value is not None:
                _bind(node.target, node.value, values, parts, last, allowed)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and (allowed is None or node.target.id in allowed):
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
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            _bind_parts(node.target, node.iter, parts, last, allowed)


def _position(node: ast.AST) -> tuple[int, int]:
    anchor = node.target if isinstance(node, ast.comprehension) else node
    return getattr(anchor, "lineno", 0), getattr(anchor, "col_offset", 0)


def _bind(
    target: ast.AST,
    value: ast.expr,
    values: dict[str, list[ast.AST]],
    parts: dict[str, list[ast.AST]],
    last: dict[str, ast.expr],
    allowed: frozenset[str] | None = None,
) -> None:
    if isinstance(target, ast.Name):
        if allowed is None or target.id in allowed:
            values.setdefault(target.id, []).append(value)
            last[target.id] = value
    else:
        _bind_parts(target, value, parts, last, allowed)


def _bind_parts(
    target: ast.AST,
    value: ast.expr,
    parts: dict[str, list[ast.AST]],
    last: dict[str, ast.expr],
    allowed: frozenset[str] | None = None,
) -> None:
    """Each name a target list unpacks into (`a, (b, *c) = value`). An attribute
    or item target (`self.host, port = value`) binds no local."""
    stack = [target]
    while stack:
        cur = stack.pop()
        if isinstance(cur, ast.Name):
            if allowed is None or cur.id in allowed:
                parts.setdefault(cur.id, []).append(value)
                last.pop(cur.id, None)
        elif isinstance(cur, (ast.Tuple, ast.List)):
            stack.extend(cur.elts)
        elif isinstance(cur, ast.Starred):
            stack.append(cur.value)


class _Foreign(ast.expr):
    """A value bound in one scope and read in another: a `global` or `nonlocal`
    write, a `:=` inside a comprehension (which binds in the scope around it),
    a comprehension's first iterable (which runs in the scope around it) and a
    dict comprehension's key. It is read in `scope`, the scope that evaluates
    it, where the names in it are that scope's."""

    _fields = ()

    def __init__(self, value: ast.AST, scope: _Scope) -> None:
        super().__init__()
        self.value = value
        self.scope = scope


#: The memo tables a scope makes on first use (`_Scope.__getattr__`): most of
#: a file's scopes, a comprehension's or a handler's, are never read.
_TABLES: dict[str, Callable[[], Any]] = {
    name: dict for name in (
        "_owners", "_sets", "_name_sets", "_joined_sets", "_joined_callers", "_keys_sets", "_text",
        "_segments", "_mappings", "_cut_memo",
    )
}
_TABLES["_either"] = set


class _Scope:
    """A module, function, lambda, class or comprehension: the names it binds,
    and, in a tool, which of its parameters are the caller's input. Whether
    caller input can set the host of a URL is worked out in the scope that
    evaluates it, and a name is read in the scope that binds it, the way
    Python reads it for the bindings this reads (an assignment, augmented or
    annotated with a value, a `for`, a comprehension, a `:=`, a parameter,
    and `global` and `nonlocal`): the scope's own, then the functions around
    it, never a class body from inside a function in it, then the module. A
    name only an import, a `def` or `class`, a `with` or `except` target, a
    `match` capture, a `del` or a bare annotation binds is not the scope's
    own.

    A scope holds only what it binds and points at the scope around it, so a
    name costs a walk up that chain once per scope that reads it. Each tool
    nested in another used to copy the enclosing tool's parameters and names,
    so one tool holding 7,700 handlers beside 30,800 names took 18 seconds,
    and 2,000 handlers that each fetch held 437 MB. Only enclosing tools were
    handed on, so a tool registered inside `create_server()` or
    `register(mcp)` read that function's `SCHEME` as unbound. A function,
    class, comprehension or lambda inside a tool landed its names in the
    tool's scope, so a helper's local `BASE` hid the module's from the tool.

    The module's scope is read through one of these too, holding no caller
    input of its own, and what it spells, and how it judges a list joined by
    name, is worked out once for the whole file. Each tool used to spell the
    file's bindings again in a scope of its own, so a module-level `+=` chain
    read by 4,368 tools took 24 seconds, and a binding fanning out to 128
    names of 128 names, read by 2,000 tools, 42."""

    _owners: dict[str, _Scope]
    _sets: dict[tuple[int, int], bool]
    _name_sets: dict[tuple[str, int], bool]
    _joined_sets: dict[tuple[str, str, int], bool]
    _joined_callers: dict[tuple[str, int], bool]
    _keys_sets: dict[tuple[str, int], bool]
    _text: dict[tuple[int, int], str]
    _segments: dict[tuple[str, int], list[str]]
    _mappings: dict[int, tuple[ast.expr, dict[str, ast.expr], ast.expr | None]]
    # ids of the tuples `_mapping` makes for a key's value or what can replace
    # it, whose parts are judged one by one, each once
    _either: set[int]
    _cut_memo: dict[tuple[int, Any], tuple[int, Any]]

    def __init__(self, node: ast.AST, parent: _Scope | None, params: set[str], caller: set[str]) -> None:
        self.node = node
        self.parent = parent
        self.module: _Scope = parent.module if parent is not None else self
        self.is_class = isinstance(node, ast.ClassDef)
        self.is_comprehension = isinstance(node, _COMPREHENSIONS)
        # Every name the parameters bind, which hides the same name around the
        # scope, and the ones the caller fills in: a tool's, less what a
        # framework fills in.
        self.params = params
        self.caller = caller
        # name -> what it is bound to here: `=`, an annotated `=`, `:=`, and an
        # augmented `+=` read as the value before it plus the operand ...
        self.values: dict[str, list[ast.AST]] = {}
        # ... and what it holds a part of: the iterable of a `for` or a
        # comprehension, and the value an unpacking assignment splits, whose
        # every part is the caller's when the whole is.
        self.elements: dict[str, list[ast.AST]] = {}
        # name -> "global" or "nonlocal", as the scope declares it
        self.declared: dict[str, str] = {}
        # A dict comprehension's key, read in this scope (`_iterated`), and,
        # shared by every scope in the file, id(comprehension) -> its scope.
        self.key: ast.expr | None = None
        self.inner: dict[int, _Scope] = parent.inner if parent is not None else {}
        # Whether the scope sits in a tool, so the calls in it are judged, and
        # whether any caller input can reach a URL it evaluates (`_scopes`).
        self.in_tool = False
        self.reaches = False
        # How many times the nesting bound has stopped a read, counted across
        # every scope in the file, and what was worked out under such a stop,
        # kept per depth of nesting (`_remember`).
        self._cuts: list[int] = parent._cuts if parent is not None else [0]

    def __getattr__(self, name: str) -> Any:
        make = _TABLES.get(name)
        if make is None:
            raise AttributeError(name)
        table = make()
        setattr(self, name, table)
        return table

    def _owner(self, name: str) -> _Scope:
        """The scope whose binding of `name` this one reads, found once per
        name: its own, for a parameter, a loop or unpacking name or a name it
        binds in a form `_BINDING_NODES` lists; for a name it declares
        `global`, the module's; else the nearest function, lambda or
        comprehension around it that has it, passing over a class body and a
        function that declares the name `nonlocal`, and stopping at one that
        declares it `global`; else the module's. A tool's parameter used to
        fall through to a module binding of the same name, so `def
        fetch(params)` joining `params` read a module list called `params`."""
        owner = self._owners.get(name)
        if owner is None:
            owner = self._owners[name] = self._find_owner(name)
        return owner

    def _find_owner(self, name: str) -> _Scope:
        scope = self
        while scope.parent is not None:
            if scope is self or not scope.is_class:
                declared = scope.declared.get(name)
                if declared == "global":
                    return self.module
                if declared is None and (name in scope.params or name in scope.values or name in scope.elements):
                    return scope
            scope = scope.parent
        return scope

    def _bound(self, name: str) -> list[ast.AST]:
        """What `name` is bound to in the scope that owns it. A name the module
        unpacks or loops over holds a part of a value, not the value: none."""
        owner = self._owner(name)
        if owner is not self:
            return owner._bound(name)
        if self.parent is None and name in self.elements:
            return []
        return self.values.get(name, [])

    def _inner(self, node: ast.AST) -> _Scope:
        """The scope of a comprehension `node`, where its element is read."""
        return self.inner.get(id(node), self)

    def _list_of(self, name: str) -> list[ast.expr] | None:
        """The items of the list or tuple literal `name` is bound to, once. The
        items are the literal's own, never copied: every join of the list used
        to copy them twice."""
        bound = self._bound(name)
        if len(bound) == 1 and isinstance(bound[0], (ast.List, ast.Tuple)):
            return bound[0].elts
        return None

    def sets_host(self, node: ast.AST, depth: int = 0, nest: int = 0) -> bool:
        """Whether caller input can set the host of the URL `node` evaluates to.

        It can when the URL is caller input as a whole (a parameter, an item or
        attribute read from one, a method called on one or a URL function given
        one, a local bound from one), or when the URL is built (an f-string,
        `+`, a literal `.join`, `%`, `.format`, `.replace`) and a piece of caller
        input comes before the text the code wrote has ended the authority
        (`_authority_closed`). Each (expression, depth), each (name, depth) and
        each (list joined by name, depth) is worked out once, as
        `_py_addr_reach` does, so names that read each other do not multiply
        the work. A scope no caller input can reach has none to find.
        """
        if not self.reaches or depth > _PY_MAX_DEPTH:
            return False
        if nest > _PY_MAX_NEST:
            return bool(self._cut(False))
        key = (id(node), depth)
        hit = self._sets.get(key)
        if hit is None:
            # Reached again while it is being worked out, an expression adds
            # nothing to its own answer: the cycle ends here.
            hit = self._remember(self._sets, key, nest, False, lambda: self._sets_host(node, depth, nest))
        return hit

    def _remember(self, table: dict[Any, Any], key: Any, nest: int, pending: Any, work: Callable[[], Any]) -> Any:
        """`work()`, kept in `table` under `key`, which holds `pending` while it
        is worked out so that a cycle back to it ends.

        The tables key on an expression or a name and its depth, not on how
        deeply it is nested, while the nesting bound (`_PY_MAX_NEST`) stops a
        read 40 levels down. A result worked out under such a stop was kept
        and handed to every later read: `u = p` first read 40 levels deep
        cleared `requests.get(u)`, and a module base spelled 37 levels deep in
        one tool cleared `BASE + host` in another. A result is kept in `table`
        only when no stop fired under it; otherwise it is kept with the depth
        of nesting it was worked out at, handed only to a read at that depth
        or deeper, and whatever reads it is marked the same way. A deeper read
        would stop at least as soon, so it gets an answer that read no less of
        the code, as one no stop touched is handed to every read.

        It was kept for its own depth alone, so a name read at 38 depths, each
        reading a name past the bound, was worked out 38 times: 255 such names
        took 6 seconds, where they now take 1.5."""
        cut_key = (id(table), key)
        kept = self._cut_memo.get(cut_key)
        if kept is not None and kept[0] <= nest:
            self._cuts[0] += 1
            return kept[1]
        cuts = self._cuts[0]
        table[key] = pending
        value = work()
        if self._cuts[0] == cuts:
            table[key] = value
        else:
            del table[key]
            self._cut_memo[cut_key] = (nest, value)
        return value

    def _cut(self, value: Any) -> Any:
        """`value`, from a read the nesting bound stopped, counted so that
        nothing worked out from it is kept for another depth of nesting."""
        self._cuts[0] += 1
        return value

    def _sets_host(self, node: ast.AST, depth: int, nest: int) -> bool:
        # Read and attribute chains can be thousands long, so the parts of one
        # expression are walked with a stack; only a built URL, a name's
        # binding one assignment down, or a list joined by name is a call of
        # its own.
        stack = [node]
        while stack:
            cur = stack.pop()
            if isinstance(cur, ast.Name):
                owner = self._owner(cur.id)
                if cur.id in owner.caller or owner._name_sets_host(cur.id, depth, nest):
                    return True
            elif isinstance(cur, _Foreign):
                if cur.scope.sets_host(cur.value, depth, nest + 1):
                    return True
            elif isinstance(cur, (ast.Subscript, ast.Attribute, ast.Starred, ast.Await, ast.NamedExpr)):
                # `URLS[region]` reads a URL the code fixed: only the container counts.
                stack.append(cur.value)
            elif _is_built(cur):
                if self._built_sets_host(_pieces(cur), depth, nest + 1):
                    return True
            elif isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Mod):
                # A template the caller hands over is theirs whatever it holds;
                # otherwise each value is read where its field puts it, so in
                # `"%s/v2/%s" % (BASE, repo)` the caller's `repo` is in the path.
                stack.append(cur.left)
                template = self._spelled(cur.left, depth, nest + 1)
                if self._built_sets_host(_percent_pieces(template, cur.right, self._mapping), depth, nest + 1):
                    return True
            elif isinstance(cur, (ast.List, ast.Tuple, ast.Set)):
                if id(cur) in self._either:
                    # A key's value or the entries that can replace it: each
                    # is judged once, however many keys a mapping has.
                    if any(self.sets_host(part, depth, nest + 1) for part in cur.elts):
                        return True
                else:
                    # The pieces of a URL a `.join` or a URL function has not
                    # been read as text: any of them can be the host.
                    stack.extend(cur.elts)
            elif isinstance(cur, ast.Dict):
                # A mapping a template reads, or a `**` hands over, whole: any
                # of its values can be the host, as can any value of a mapping
                # it unpacks (`{**arguments}`).
                stack.extend(cur.values)
            elif isinstance(cur, ast.DictComp):
                if self._inner(cur).sets_host(cur.value, depth, nest + 1):
                    return True
            elif isinstance(cur, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
                # Each element is what `elt` reads in the comprehension's
                # scope, its loop names holding parts of what they iterate:
                # `[u.strip() for u in urls]`.
                if self._inner(cur).sets_host(cur.elt, depth, nest + 1):
                    return True
            elif isinstance(cur, ast.BinOp):
                stack.extend((cur.left, cur.right))
            elif isinstance(cur, ast.Call):
                joined = self._joined_list(cur)
                if joined is not None:
                    if self._joined_sets_host(joined[0], joined[1], depth, nest):
                        return True
                    continue
                func = cur.func
                mapping = self._joined_mapping(cur)
                if mapping is not None and isinstance(func, ast.Attribute):
                    # Joining a mapping held in a name joins its keys, judged
                    # once per name and depth; the separator is read here.
                    if self._mapping_keys_set_host(mapping, depth, nest):
                        return True
                    stack.append(func.value)
                    continue
                if isinstance(func, ast.Attribute) and func.attr in ("substitute", "safe_substitute"):
                    reader = self._template(func.value, depth)
                    if reader is not None:
                        # A `string.Template` fills `$host` or `${host}` from
                        # its mapping and keywords, as `.format(**m)` fills
                        # `{host}`. Its text is judged and spelled by the scope
                        # that binds it, once: walked again at every call, a
                        # module template took 59 s for 7,923 substitutions.
                        owner, source, level = reader
                        if owner.sets_host(source, level, nest + 1):
                            return True
                        if not _authority_closed(_template_lead(owner._spelled(source, level, nest + 1))):
                            stack.extend(cur.args)
                            stack.extend(kw.value for kw in cur.keywords)
                        continue
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

    def _name_sets_host(self, name: str, depth: int, nest: int) -> bool:
        """Whether something `name` is bound to in this scope, the one that owns
        it, can set the host, worked out once per name and depth.

        Every read of a name used to loop over all of its bindings, each read a
        node of its own: a name bound n times and read n times cost n squared,
        so `url = url + part` 24,000 times, each binding reading `url` again,
        took more than six minutes. Which binding a read sees is not told
        apart, so the answer is the same for every read of the name at one
        depth. A name reached again while it is being worked out adds nothing
        to its own answer."""
        key = (name, depth)
        hit = self._name_sets.get(key)
        if hit is None:
            bound = self.values.get(name, []) + self.elements.get(name, [])
            hit = self._remember(self._name_sets, key, nest, False, lambda: any(
                self.sets_host(rhs, depth + 1, nest + 1) for rhs in bound
            ))
        return hit

    def _joined_list(self, node: ast.AST) -> tuple[str, str] | None:
        """``(separator, name)`` when `node` joins a list or tuple literal that
        a name is bound to (`parts = ["https://", host]`, `"".join(parts)`)."""
        joined = _named_join(node)
        if joined is None or self._list_of(joined[1]) is None:
            return None
        return joined

    def _joined_sets_host(self, sep: str, name: str, depth: int, nest: int) -> bool:
        """Whether caller input can set the host of `sep.join(name)`, read as a
        URL of its own, its items at this depth, once per list, separator and
        depth, in the scope that binds the list. A join reached again while it
        is being worked out, a list that joins itself, adds nothing to its own
        answer.

        The list used to be read out into each URL that joined it, so in
        `BASE + "".join(parts)` its pieces followed the base's. A join is now
        judged like a name, on its own, so a list whose text starts with a bare
        `/` (`parts = ["/", path]`) leaves a host open after a base that has no
        `/` of its own. Lists joined inside one another are read a call per
        list, so past forty of them (`_PY_MAX_NEST`) the rest reads as text the
        code does not spell out."""
        owner = self._owner(name)
        if owner is not self:
            return owner._joined_sets_host(sep, name, depth, nest)
        if not self.reaches or depth > _PY_MAX_DEPTH:
            return False
        if nest > _PY_MAX_NEST:
            return bool(self._cut(False))
        key = (_separator_class(sep), name, depth)
        hit = self._joined_sets.get(key)
        if hit is None:
            hit = self._remember(
                self._joined_sets, key, nest, False, lambda: self._joined_list_sets_host(sep, name, depth, nest)
            )
        return hit

    def _joined_list_sets_host(self, sep: str, name: str, depth: int, nest: int) -> bool:
        """`_joined_sets_host`'s work, past its checks and its memo."""
        if not self._joined_has_caller(name, depth, nest):
            return False
        items = self._list_of(name) or []
        return self._built_sets_host(_pieces(_Run(items, 0, sep)), depth, nest + 1)

    def _joined_has_caller(self, name: str, depth: int, nest: int) -> bool:
        """Whether any piece `"sep".join(name)` reads, within `_PIECE_CAP`, is
        one caller input can set, once per list and depth. A join with none
        holds no caller input whatever its separator, so a list of 301 fixed
        items joined with 12,855 separators is read once, not once per
        separator (9.9 s)."""
        key = (name, depth)
        hit = self._joined_callers.get(key)
        if hit is None:
            items = self._list_of(name) or []
            hit = self._remember(self._joined_callers, key, nest, False, lambda: any(
                self.sets_host(piece, depth, nest + 1)
                for piece in _pieces(_Run(items, 0, _SEPARATOR)) if not isinstance(piece, str)
            ))
        return hit

    def _joined_text(self, sep: str, name: str, depth: int, nest: int) -> str:
        """The text `sep.join(name)` spells: the text between its separators,
        worked out once per list and depth (`_joined_segments`), joined with
        this one, by the scope that binds the list."""
        owner = self._owner(name)
        if owner is not self:
            return owner._joined_text(sep, name, depth, nest)
        if depth > _PY_MAX_DEPTH:
            return _UNKNOWN
        if nest > _PY_MAX_NEST:
            return str(self._cut(_UNKNOWN))
        return sep.join(self._joined_segments(name, depth, nest))

    def _joined_segments(self, name: str, depth: int, nest: int) -> list[str]:
        """The text of the pieces between the separators of `"sep".join(name)`,
        read until it holds `_PREFIX_CAP` characters, which the separators only
        add to. A list that joins itself spells that join as text the code
        does not spell out."""
        key = (name, depth)
        segments = self._segments.get(key)
        if segments is None:
            segments = self._remember(
                self._segments, key, nest, [_UNKNOWN], lambda: self._read_segments(name, depth, nest)
            )
        return segments

    def _read_segments(self, name: str, depth: int, nest: int) -> list[str]:
        """`_joined_segments`' work, past its memo."""
        items = self._list_of(name) or []
        segments = [""]
        length = 0
        for piece in _pieces(_Run(items, 0, _SEPARATOR)):
            if piece is _SEPARATOR:
                segments.append("")
                continue
            text = piece if isinstance(piece, str) else self._spelled(piece, depth, nest + 1)
            segments[-1] += text
            length += len(text)
            if length >= _PREFIX_CAP:
                break
        return segments

    def _mapping(self, node: ast.expr) -> tuple[dict[str, ast.expr], ast.expr | None]:
        """What a keyed `%` field can read in `node`: the entries a dict literal
        or a `dict(...)` call writes out under a constant key, and the
        expression any other key may come from, its `**` entries, entries under
        a computed key and the mapping `dict(...)` copies read together, or
        None when it has none of those. A key written before such an entry may
        take its value from those entries instead, so `{"host": FIXED,
        **arguments}` lets the caller set the host and `{**arguments, "host":
        FIXED}` does not. A name bound once here to such a mapping (`params =
        {"host": arguments["host"]}`) is read as it; any other operand is all
        of that expression.

        Two or more such entries are read as one tuple made here, and the tuple
        is kept for as long as this scope's verdicts are. They are remembered
        by an expression's id, and a tuple made afresh for each template and
        dropped once read handed its id to the next one: in a tool with
        `{**A, **B}` in one template and `{**B, **arguments}` in the next, the
        second was read as the first and lost the caller's host."""
        target: ast.expr = node
        reader: _Scope = self
        if isinstance(node, ast.Name):
            owner = self._owner(node.id)
            bound = [] if node.id in owner.params or node.id in owner.elements else owner.values.get(node.id, [])
            if len(bound) == 1 and isinstance(bound[0], (ast.Dict, ast.Call)) and _is_dict_display(bound[0]):
                # A mapping a function around this one holds is read there.
                target, reader = bound[0], owner
        if not _is_dict_display(target):
            return {}, node
        hit = self._mappings.get(id(target))
        if hit is None:
            keyed: dict[str, ast.expr] = {}
            replaceable: list[str] = []
            others: list[ast.expr] = []
            # Read back to front, so the last value written under a key wins,
            # and a key knows whether an entry without a constant key follows
            # it (`{"host": FIXED, **arguments}`) and can replace its value.
            for key, value in reversed(_dict_entries(target)):
                if reader is not self:
                    value = _Foreign(value, reader)
                if key is None:
                    others.append(value)
                elif key not in keyed:
                    keyed[key] = value
                    if others:
                        replaceable.append(key)
            others.reverse()
            rest: ast.expr | None = None
            if len(others) == 1:
                rest = others[0]
            elif others:
                rest = ast.Tuple(elts=others, ctx=ast.Load())
            if rest is not None:
                for key in replaceable:
                    either = ast.Tuple(elts=[keyed[key], rest], ctx=ast.Load())
                    self._either.add(id(either))
                    keyed[key] = either
            hit = self._mappings[id(target)] = (target, keyed, rest)
        return hit[1], hit[2]

    def _template(self, node: ast.AST, depth: int) -> tuple[_Scope, ast.AST, int] | None:
        """For a `string.Template`: the scope that reads its text, the text, and
        the depth to read it at. `Template(text)` or `string.Template(text)`
        written in place is read here, at this depth; one bound once to a name
        is read by the scope that binds the name, one level down, so a module
        template is the module's, with no caller input in it."""
        owner, level = self, depth
        if isinstance(node, ast.Name):
            owner = self._owner(node.id)
            if node.id in owner.params or node.id in owner.elements:
                return None
            bound = owner._bound(node.id)
            if len(bound) != 1:
                return None
            node, level = bound[0], depth + 1
        if isinstance(node, ast.Call) and node.args and _py_callee_name(node.func).rpartition(".")[2] == "Template":
            return owner, node.args[0], level
        return None

    def _joined_mapping(self, node: ast.AST) -> str | None:
        """The name `node` joins (`sep.join(name)`), when the scope that owns the
        name binds it once to a dict literal or comprehension or a `dict(...)`
        call."""
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join"):
            return None
        if len(node.args) != 1 or node.keywords or not isinstance(node.args[0], ast.Name):
            return None
        name = node.args[0].id
        owner = self._owner(name)
        if name in owner.params or name in owner.elements:
            return None
        bound = owner.values.get(name, [])
        if len(bound) == 1 and (isinstance(bound[0], ast.DictComp) or _is_dict_display(bound[0])):
            return name
        return None

    def _mapping_keys_set_host(self, name: str, depth: int, nest: int) -> bool:
        """Whether a key of the mapping `name` is bound to, or a mapping it
        unpacks or copies, can set the host, worked out once per name and
        depth. The keys were read again at every join: a dict of 23,070 keys
        joined at 7,690 fetches took 189 s. They are read in the scope that
        binds the mapping."""
        owner = self._owner(name)
        if owner is not self:
            return owner._mapping_keys_set_host(name, depth, nest)
        key = (name, depth)
        hit = self._keys_sets.get(key)
        if hit is None:
            binding = self.values[name][0]
            hit = self._remember(self._keys_sets, key, nest, False, lambda: any(
                self.sets_host(part, depth, nest + 1) for part in self._iterated(binding)
            ))
        return hit

    def _iterated(self, node: ast.AST) -> list[ast.AST]:
        """What iterating `node` yields, to read: a mapping yields its keys, so a
        dict literal or comprehension, or a `dict(...)` call, gives its keys and
        the mappings it unpacks or copies, never its values, a comprehension's
        key read in the comprehension's scope; anything else is read whole."""
        if isinstance(node, ast.DictComp):
            inner = self._inner(node)
            return [inner.key if inner.key is not None else node.key]
        if isinstance(node, ast.Dict):
            return [key if key is not None else value for key, value in zip(node.keys, node.values)]
        if _is_dict_display(node) and isinstance(node, ast.Call):
            return list(node.args)
        return [node]

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
        if isinstance(func, ast.Name) and func.id == "dict":
            # `dict(arguments)`, `dict(host=h)`: a mapping holding what it is given.
            return [*call.args, *(kw.value for kw in call.keywords)]
        if not isinstance(func, ast.Attribute):
            return []
        receiver = func.value
        if name in ("format", "format_map"):
            # `.format_map(m)` reads its mapping as `.format(**m)` does.
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
            return [receiver, *self._iterated(call.args[0])]
        return [receiver]

    def _built_sets_host(self, pieces: Iterable[str | ast.AST], depth: int, nest: int) -> bool:
        prefix = ""
        open_prefix = None  # the text last found to leave the authority open
        for piece in pieces:
            if prefix != open_prefix:
                if _authority_closed(prefix):
                    return False
                open_prefix = prefix
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
        if depth > _PY_MAX_DEPTH:
            return _UNKNOWN
        if nest > _PY_MAX_NEST:
            return str(self._cut(_UNKNOWN))
        key = (id(node), depth)
        text = self._text.get(key)
        if text is None:
            # spelling it again while spelling it ends the cycle
            text = self._remember(self._text, key, nest, _UNKNOWN, lambda: self._spell(node, depth, nest)[:_PREFIX_CAP])
        return text

    def _spell(self, node: ast.AST, depth: int, nest: int) -> str:
        constant = _str_constant(node)
        if constant is not None:
            return constant
        if isinstance(node, ast.Name):
            owner = self._owner(node.id)
            if node.id in owner.params or node.id in owner.elements:
                return _UNKNOWN
            bound = owner._bound(node.id)
            return owner._spelled(bound[0], depth + 1, nest + 1) if len(bound) == 1 else _UNKNOWN
        if isinstance(node, _Foreign):
            return node.scope._spelled(node.value, depth, nest + 1)
        joined = self._joined_list(node)
        if joined is not None:
            return self._joined_text(joined[0], joined[1], depth, nest)
        if _is_built(node):
            return self._spell_pieces(_pieces(node), depth, nest + 1)
        pieces: list[str | ast.AST] | None = None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            pieces = _percent_pieces(self._spelled(node.left, depth, nest + 1), node.right, self._mapping)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            pieces = _format_pieces(self._spelled(node.func.value, depth, nest + 1), node)
        if pieces is None:
            return _UNKNOWN
        return self._spell_pieces(pieces, depth, nest + 1)

    def _spell_pieces(self, pieces: Iterable[str | ast.AST], depth: int, nest: int) -> str:
        """The text of a run of pieces, read to `_PREFIX_CAP` characters."""
        text = ""
        for piece in pieces:
            text += piece if isinstance(piece, str) else self._spelled(piece, depth, nest)
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


#: The bases a class-based tool extends, LangChain's and CrewAI's `BaseTool`
#: and LangChain's `StructuredTool`, and the methods it runs the caller's input
#: through: `_run` and `_arun`, which a tool writes, and `run` and `arun`,
#: which it may override.
_TOOL_CLASS_BASES = frozenset({"BaseTool", "StructuredTool"})
_TOOL_CLASS_METHODS = frozenset({"_run", "_arun", "run", "arun"})
#: The parameters of a `call_tool` method that are the caller's: the names the
#: old list held. A client's bridge takes the server it was configured with
#: too (`call_tool(self, server, tool_name, arguments)`), which is not.
_CALL_TOOL_INPUTS = frozenset({
    "input", "args", "params", "kwargs", "request", "req", "event", "tool_input", "arguments", "payload",
    "body", "query",
})


def _is_call_tool_name(name: str) -> bool:
    """`call_tool`, or a name ending in `_call_tool` (`handle_call_tool`, a
    client's `_call_tool`): the low-level server's handler and a dispatcher's
    method, written without the `@<server>.call_tool()` decorator."""
    return name == "call_tool" or name.endswith("_call_tool")


def _base_name(node: ast.AST) -> str:
    """The name a class base is written as: `Base`, `tools.Base`, with a
    subscript dropped (`BaseTool[dict]`). A tool base read through a module
    keeps only its last part, so `langchain.tools.BaseTool` is `BaseTool`."""
    if isinstance(node, ast.Subscript):
        node = node.value
    name = _py_callee_name(node)
    last = name.rpartition(".")[2]
    return last if last in _TOOL_CLASS_BASES else name


def _class_tool_methods(tree: ast.AST) -> set[int]:
    """ids of the tool methods of the file's class tools: the classes whose
    bases reach `BaseTool` or `StructuredTool`, named in place (`BaseTool`,
    `tools.BaseTool`, `BaseTool[dict]`), under a name the file imports or
    assigns it as (`from langchain.tools import BaseTool as LCTool`, `LCTool =
    tools.BaseTool`), or through classes the file defines (`class Search(Base)`
    with `class Base(BaseTool)`).

    Only a class whose own bases named `BaseTool` used to count, so an
    indirect subclass, a `StructuredTool` subclass and an aliased or
    subscripted base had no caller input, where the old name list fired on
    their `query`. A base another file defines is not followed. The names
    the file's classes and aliases build on are walked once, out from the
    tool bases, so classes that each extend the last cost no more than their
    number, and classes that extend each other end."""
    classes: list[ast.ClassDef] = []
    # a name -> the classes and aliases the file writes on top of it
    built_on: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            classes.append(node)
            for base in node.bases:
                built_on.setdefault(_base_name(base), []).append(node.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.asname:
                    built_on.setdefault(alias.name, []).append(alias.asname)
        elif isinstance(node, ast.Assign) and isinstance(node.value, (ast.Name, ast.Attribute)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    built_on.setdefault(_base_name(node.value), []).append(target.id)
    tool_names = set(_TOOL_CLASS_BASES)
    stack = list(_TOOL_CLASS_BASES)
    while stack:
        for name in built_on.get(stack.pop(), []):
            if name not in tool_names:
                tool_names.add(name)
                stack.append(name)
    found: set[int] = set()
    for node in classes:
        if any(_base_name(base) in tool_names for base in node.bases):
            found.update(
                id(item) for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in _TOOL_CLASS_METHODS
            )
    return found


def _tool_inputs(node: ast.AST, registered: set[str], class_tools: set[int]) -> set[str] | None:
    """The caller input of `node` when it is a tool function, else None.

    A tool is what taint_analysis reads as one, a function decorated
    `@function_tool`, one the file registers by a call (`_registered_tools`),
    a class tool's `_run`, `_arun`, `run` or `arun` (`_class_tool_methods`),
    or a function or method called `call_tool` or ending in `_call_tool`, the
    shape a low-level server or a dispatcher written as a class takes (`async
    def call_tool(self, name, arguments)`, `handle_call_tool`), whose caller
    input is only its `arguments` and the other `_CALL_TOOL_INPUTS`. Without
    these, `mcp.add_tool(fetch)`, the OpenAI Agents SDK's tools, LangChain's
    and CrewAI's class tools and a class's `call_tool` had no caller input,
    where the old name list fired on them when the parameter was called
    `query`, `params` or `arguments`. What a framework fills in is no caller
    input (`_injected_params`)."""
    if not isinstance(node, _FUNCTIONS):
        return None
    params = _get_param_names(node) - _injected_params(node)
    if (_is_tool_function(node) or _is_call_tool_handler(node) or _is_function_tool(node)
            or node.name in registered or id(node) in class_tools):
        return params
    if _is_call_tool_name(node.name):
        return params & _CALL_TOOL_INPUTS
    return None


def _nonlocal_owner(writer: _Scope, name: str) -> _Scope:
    """The function around `writer` whose `name` a `nonlocal` declaration in
    `writer` writes to: the nearest that binds it, past class bodies and the
    functions that declare it `nonlocal` too."""
    scope = writer.parent
    while scope is not None and scope.parent is not None:
        if not scope.is_class:
            declared = scope.declared.get(name)
            if declared == "global":
                break
            if declared is None and (name in scope.params or name in scope.values or name in scope.elements):
                return scope
        scope = scope.parent
    return writer.module


def _scopes(tree: ast.Module) -> dict[int, _Scope]:
    """id(call) -> the scope that reads the URL of each call inside a tool.

    The module and every function, lambda, class and comprehension in it is a
    scope (`_Scope`), chained to the scope around it, holding the names its
    own statements bind in a form this reads (`_BINDING_NODES`), its
    parameters and a comprehension's targets. A call is judged once, in the
    scope it sits in: the innermost function, lambda, class body or
    comprehension around it. It was judged in every enclosing tool's scope,
    each collecting every binding below it, so 97 nested tools around 4,252
    fetches took 10.6 s.

    Where Python binds a name somewhere other than the scope that writes it,
    so does this. A comprehension's first iterable runs in the scope around
    it, and its `:=` binds in the function around it. A `global` write binds
    the module's name and a `nonlocal` one the enclosing function's, each
    read in the function that writes it (`_Foreign`), so a nested tool that
    sets the enclosing tool's `url` from its own caller, or a tool that sets
    the module's base, reaches whatever fetches from it.
    """
    registered = _registered_tools(tree)
    class_tools = _class_tool_methods(tree)
    module = _Scope(tree, None, set(), set())
    scopes = [module]
    statements: dict[int, list[ast.AST]] = {id(module): []}
    walrus: list[tuple[_Scope, ast.NamedExpr]] = []
    calls: dict[int, _Scope] = {}
    stack: list[tuple[ast.AST, _Scope]] = [(child, module) for child in ast.iter_child_nodes(tree)]
    while stack:
        node, scope = stack.pop()
        if isinstance(node, (*_FUNCTIONS, ast.Lambda, ast.ClassDef)):
            caller = _tool_inputs(node, registered, class_tools)
            params = set() if isinstance(node, ast.ClassDef) else _parameters(node.args)
            inner = _Scope(node, scope, params, caller or set())
            inner.in_tool = scope.in_tool or caller is not None
            scopes.append(inner)
            statements[id(inner)] = []
            stack.extend((part, scope) for part in _outer_parts(node))
            stack.extend((part, inner) for part in ([node.body] if isinstance(node, ast.Lambda) else node.body))
            continue
        if isinstance(node, _COMPREHENSIONS):
            inner = _Scope(node, scope, set(), set())
            inner.in_tool = scope.in_tool
            scopes.append(inner)
            statements[id(inner)] = []
            module.inner[id(node)] = inner
            first, *rest = node.generators
            stack.append((first.iter, scope))
            _bind_parts(first.target, _Foreign(first.iter, scope), inner.elements, {})
            for generator in rest:
                _bind_parts(generator.target, generator.iter, inner.elements, {})
                stack.append((generator.iter, inner))
            for generator in node.generators:
                stack.extend((condition, inner) for condition in generator.ifs)
            if isinstance(node, ast.DictComp):
                inner.key = _Foreign(node.key, inner)
                stack.extend(((node.key, inner), (node.value, inner)))
            else:
                stack.append((node.elt, inner))
            continue
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            if scope.parent is not None:
                kind = "global" if isinstance(node, ast.Global) else "nonlocal"
                scope.declared.update(dict.fromkeys(node.names, kind))
        elif isinstance(node, ast.NamedExpr) and scope.is_comprehension:
            walrus.append((scope, node))
        elif isinstance(node, _BINDING_NODES):
            statements[id(scope)].append(node)
        elif isinstance(node, ast.Call) and scope.in_tool:
            calls[id(node)] = scope
        stack.extend((child, scope) for child in ast.iter_child_nodes(node))

    # Each scope's own bindings, in source order, then each `:=` inside a
    # comprehension, then the writes declared `global` or `nonlocal`, which
    # land where those declarations say, once every scope's own names are in.
    landings: list[tuple[_Scope, str, str, list[ast.AST]]] = []
    # id(writer) -> the scopes its writes land in, read in the writer
    writes: dict[int, list[_Scope]] = {}
    for scope in scopes:
        values: dict[str, list[ast.AST]] = {}
        elements: dict[str, list[ast.AST]] = {}
        _bind_nodes([(node, None) for node in statements[id(scope)]], values, elements)
        for table, bound in (("values", values), ("elements", elements)):
            for name, nodes in bound.items():
                if name in scope.declared:
                    landings.append((scope, name, table, nodes))
                else:
                    getattr(scope, table).setdefault(name, []).extend(nodes)
    for comprehension, node in walrus:
        home = comprehension
        while home.is_comprehension and home.parent is not None:
            home = home.parent
        name = node.target.id
        value: list[ast.AST] = [_Foreign(node.value, comprehension)]
        if name in home.declared:
            landings.append((home, name, "values", value))
        else:
            home.values.setdefault(name, []).extend(value)
            writes.setdefault(id(comprehension), []).append(home)
    for writer, name, table, nodes in landings:
        owner = module if writer.declared[name] == "global" else _nonlocal_owner(writer, name)
        wrapped = [node if isinstance(node, _Foreign) else _Foreign(node, writer) for node in nodes]
        getattr(owner, table).setdefault(name, []).extend(wrapped)
        writes.setdefault(id(writer), []).append(owner)

    # A scope reaches caller input through its own parameters, through the
    # scope around it, or through a write that lands in it from a scope that
    # reaches it, which may itself reach it only through another write. The
    # reach spreads from the scopes holding caller input along both kinds of
    # edge, each scope taken once, so it settles in time linear in the scopes
    # and the writes. Two passes counted one write, so a handler whose `u` a
    # helper set from a name a nested tool set read as reaching nothing.
    children: dict[int, list[_Scope]] = {}
    for scope in scopes:
        if scope.parent is not None:
            children.setdefault(id(scope.parent), []).append(scope)
    reached = [scope for scope in scopes if scope.caller]
    for scope in reached:
        scope.reaches = True
    while reached:
        scope = reached.pop()
        for later in (*children.get(id(scope), ()), *writes.get(id(scope), ())):
            if not later.reaches:
                later.reaches = True
                reached.append(later)
    return calls


def analyze_python(text: str) -> list[Reach]:
    """Outbound call sites in a Python source, with what each one reaches."""
    try:
        tree = parse_python(text, None)
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
    scopes = _scopes(tree)

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
            tainted=id(node) in scopes and scopes[id(node)].sets_host(url_arg),
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
