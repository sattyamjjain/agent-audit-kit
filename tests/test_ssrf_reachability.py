"""Reachability tests for ssrf_patterns (#593).

The rule used to decide file-wide: the word `fetch` anywhere plus a user-input
marker anywhere meant CRITICAL, with no requirement that either be code, be
related, or be near the other. Against AAK's own source that produced three
findings, all of them prose — a scanner description, a rule title, and the SSRF
scanner's own detection regex.

Each rule now hangs off a real outbound call site whose URL argument is traced.
The tests below are split into the two things that matter: prose must not fire,
and genuine data flow must still fire.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.scanners._ssrf_reach import analyze_js, analyze_python
from agent_audit_kit.scanners.ssrf_patterns import scan

# Every file must carry an MCP tool hint or the scanner skips it entirely.
_HINT = "from mcp.server.fastmcp import FastMCP\n"


def _ids(tmp_path: Path, name: str, body: str) -> set[str]:
    (tmp_path / name).write_text(_HINT + body, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


# --- the #593 reproduction --------------------------------------------------


def test_scanner_does_not_flag_its_own_source() -> None:
    """The regression that motivated this: AAK flagging its own detection patterns."""
    findings = scan(Path("agent_audit_kit"))[0]
    assert findings == [], (
        "ssrf_patterns fires on AAK's own source: "
        + ", ".join(f"{f.rule_id} {f.file_path}:{f.line_number}" for f in findings)
    )


def test_private_address_in_a_regex_literal_does_not_fire(tmp_path: Path) -> None:
    """The exact shape from ssrf_patterns.py:36 — a detection pattern, not a call."""
    body = (
        'import re\n'
        '_ADDR = re.compile(r"127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254")\n'
        'def check(text):\n'
        '    return bool(_ADDR.search(text))\n'
    )
    assert _ids(tmp_path, "patterns.py", body) == set()


def test_private_address_in_a_description_string_does_not_fire(tmp_path: Path) -> None:
    """The shape from engine.py:99 and builtin.py:451 — prose in a data structure."""
    body = (
        'SCANNERS = [\n'
        '    ("noauth", "Unauthenticated MCP server on 0.0.0.0 / wildcard CORS", []),\n'
        '    ("url", "MCP server URL points to localhost/internal network", []),\n'
        ']\n'
    )
    assert _ids(tmp_path, "registry.py", body) == set()


def test_user_input_and_fetch_in_the_same_file_but_unconnected(tmp_path: Path) -> None:
    """Both markers present, no flow between them — the old rule fired here."""
    body = (
        'import requests\n'
        'def log_request(request):\n'
        '    print(request.json)\n'
        'def health():\n'
        '    return requests.get("https://status.example.com/健康".encode().decode())\n'
    )
    ids = _ids(tmp_path, "svc.py", body)
    assert "AAK-SSRF-001" not in ids
    assert "AAK-SSRF-005" not in ids


# --- genuine flow must still fire ------------------------------------------


def test_direct_user_input_to_fetch_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        '@mcp.tool()\n'
        'def tool(request):\n'
        '    return requests.get(request.json["url"])\n'
    )
    ids = _ids(tmp_path, "tool.py", body)
    assert "AAK-SSRF-001" in ids
    assert "AAK-SSRF-005" in ids


def test_user_input_through_a_variable_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        '@mcp.tool()\n'
        'def tool(params):\n'
        '    target = params["endpoint"]\n'
        '    return requests.get(target)\n'
    )
    assert "AAK-SSRF-001" in _ids(tmp_path, "tool.py", body)


def test_user_input_through_an_fstring_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        '@mcp.tool()\n'
        'def tool(args):\n'
        '    host = args["host"]\n'
        '    return requests.get(f"https://{host}/v1/data")\n'
    )
    assert "AAK-SSRF-001" in _ids(tmp_path, "tool.py", body)


def test_metadata_address_reaching_a_call_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'def creds():\n'
        '    return requests.get("http://169.254.169.254/latest/meta-data/iam/")\n'
    )
    assert "AAK-SSRF-003" in _ids(tmp_path, "meta.py", body)


def test_metadata_address_via_a_variable_fires(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'METADATA = "http://169.254.169.254/latest/meta-data/"\n'
        'def creds():\n'
        '    return requests.get(METADATA)\n'
    )
    assert "AAK-SSRF-003" in _ids(tmp_path, "meta.py", body)


def test_allowlist_guard_clears_the_tainted_finding(tmp_path: Path) -> None:
    body = (
        'import requests\n'
        'ALLOWED_HOSTS = {"api.example.com"}\n'
        '@mcp.tool()\n'
        'def tool(params):\n'
        '    return requests.get(params["url"])\n'
    )
    assert "AAK-SSRF-005" not in _ids(tmp_path, "tool.py", body)


# --- a tool's parameters are caller input -----------------------------------
#
# Caller input was a list of names (`args`, `params`, `request`, `arguments`,
# ...) matched anywhere in the file, so `def fetch(url: str)` under
# `@mcp.tool()` scanned clean while any function with a parameter called `query`
# reported. The parameters of a tool function and of a low-level `call_tool`
# handler, found the way taint_analysis finds them, are caller input now, inside
# that function, and a URL counts when one of them can set its host.

_TOOL_PRELUDE = (
    "import httpx\n"
    "import requests\n"
    "import urllib.request\n"
    "from urllib.parse import urljoin\n"
    'BASE = "https://api.example.com"\n'
    'BASE_SLASH = "https://api.example.com/"\n'
    'REGIONS = {"eu": "https://eu.example.com"}\n'
    'TEMPLATE = "https://{host}/status"\n'
    'USER_URL = "https://api.example.com/users/[id]"\n'
    "import os\n"
)
_SSRF_RULES = {"AAK-SSRF-001", "AAK-SSRF-005"}


@pytest.mark.parametrize("body", [
    "def fetch(url: str) -> str:\n    return requests.get(url).text\n",
    "def fetch(url: str) -> str:\n    target = url.strip()\n    return requests.get(target).text\n",
    'def fetch(arguments: dict) -> str:\n    return requests.get(arguments["url"]).text\n',
    'def fetch(opts: dict) -> str:\n    return requests.get(opts.get("url")).text\n',
    'def status(host: str) -> str:\n    return requests.get(f"https://{host}/status").text\n',
    'def status(port: int) -> str:\n    return requests.get(f"http://localhost:{port}/status").text\n',
    "def proxy(path: str) -> str:\n    return requests.get(BASE + path).text\n",
    "def proxy(path: str) -> str:\n    return requests.get(urljoin(BASE, path)).text\n",
    "def proxy(url: str) -> str:\n    return requests.get(str(url).strip()).text\n",
    'def proxy(host: str) -> str:\n    return requests.get(TEMPLATE.replace("{host}", host)).text\n',
    'def proxy(host: str) -> str:\n    return requests.get("".join([host, "/status"])).text\n',
    'def proxy(base: str) -> str:\n    return requests.get("{}/status".format(base)).text\n',
    'def proxy(host: str) -> str:\n    return requests.get("http://%s/status" % (host,)).text\n',
    'def proxy(host: str) -> str:\n    return requests.get("http://%(h)s/status" % {"h": host}).text\n',
    "def fetch_all(urls: list[str]) -> list[str]:\n    return [requests.get(u).text for u in urls]\n",
    'def fetch_all(urls: list[str]) -> str:\n    for u in urls:\n        requests.get(u)\n    return ""\n',
    "def fetch(url: str) -> str:\n    def go() -> str:\n        return requests.get(url).text\n    return go()\n",
    "async def fetch(url: str) -> str:\n    async with httpx.AsyncClient() as client:\n"
    "        return (await client.get(url)).text\n",
    "def post(url: str) -> bytes:\n    req = urllib.request.Request(url, data=b'{}')\n"
    "    return urllib.request.urlopen(req).read()\n",
])
def test_a_tool_parameter_that_can_set_the_host_is_caller_input(tmp_path: Path, body: str) -> None:
    assert _SSRF_RULES <= _ids(tmp_path, "tool.py", _TOOL_PRELUDE + "@mcp.tool()\n" + body)


@pytest.mark.parametrize("body", [
    'def repo(owner: str, name: str) -> str:\n'
    '    return requests.get(f"https://api.github.com/repos/{owner}/{name}").text\n',
    'def item(item_id: str) -> str:\n    return requests.get(f"{BASE}/items/{item_id}").text\n',
    "def item(item_id: str) -> str:\n    return requests.get(BASE_SLASH + item_id).text\n",
    'def search(query: str) -> str:\n    return requests.get(f"{BASE}?q={query}").text\n',
    'def search(query: str) -> str:\n    return requests.get(BASE, params={"q": query}).text\n',
    'def user(name: str) -> str:\n    return requests.get("https://api.example.com/users/{}".format(name)).text\n',
    'def user(name: str) -> str:\n    return requests.get("https://api.example.com/users/%s" % name).text\n',
    "def pick(region: str) -> str:\n    return requests.get(REGIONS[region]).text\n",
    'def ingest(arguments: dict) -> str:\n    return requests.post(BASE + "/ingest", json=arguments).text\n',
    'def page(self, path: str) -> str:\n    return self.session.get(f"{self.base}/{path}").text\n',
    # A base the code does not spell out carries its own host.
    'def item(path: str) -> str:\n    return requests.get(os.getenv("API_BASE") + path).text\n',
    'def item(path: str) -> str:\n    return requests.get(self.base_url + path).text\n',
    # A key into a fixed table, a placeholder in a fixed path, a literal join.
    'def feed(topic: str) -> str:\n    return requests.get(REGIONS.get(topic, REGIONS["eu"])).text\n',
    'def user(uid: str) -> str:\n    return requests.get(USER_URL.replace("[id]", uid)).text\n',
    'def item(path: str) -> str:\n    return requests.get("/".join([BASE, path])).text\n',
    # What a helper or a search returns is not the caller's URL.
    "def repo(owner: str) -> str:\n    return requests.get(make_link(owner)).text\n",
    # The framework fills a `Context` in, and its lifespan state is the server's.
    'def item(ctx: Context, path: str) -> str:\n'
    '    return requests.get(ctx.request_context.lifespan_context["base_url"]).text\n',
    'def item(ctx: "Context[ServerSession, None]") -> str:\n'
    '    return requests.get(ctx.request_context.lifespan_context["base_url"]).text\n',
    "def first(query: str) -> str:\n    for link in search(query):\n        return requests.get(link).text\n",
    # A request's method and body are not its address.
    'def run(hook: str, method: str, body: bytes) -> bytes:\n'
    '    req = urllib.request.Request(f"{BASE}/hooks/{hook}", data=body, method=method.upper())\n'
    "    return urllib.request.urlopen(req).read()\n",
])
def test_a_tool_parameter_after_a_fixed_host_is_not_a_caller_url(tmp_path: Path, body: str) -> None:
    """The caller picks a path, a query or a key on a host the code fixed."""
    assert _ids(tmp_path, "tool.py", _TOOL_PRELUDE + "@mcp.tool()\n" + body) & _SSRF_RULES == set()


def test_a_call_tool_handler_s_arguments_are_caller_input(tmp_path: Path) -> None:
    body = (
        "@server.call_tool()\n"
        "async def handle(tool: str, payload: dict) -> list:\n"
        '    target = payload["url"]\n'
        "    async with httpx.AsyncClient() as client:\n"
        "        return [(await client.get(target)).text]\n"
    )
    assert _SSRF_RULES <= _ids(tmp_path, "server.py", _TOOL_PRELUDE + body)


@pytest.mark.parametrize("body", [
    # A parameter of a function that is no tool: its callers decide the URL.
    'def fetch_page(request):\n    return requests.get(request.json["url"]).text\n',
    'def fetch_page(url: str) -> str:\n    return requests.get(url).text\n',
    # A name from the old list outside any function.
    'url = request.args["url"]\nrequests.get(url)\n',
    # A FastMCP instance under another name is not read as a tool (as in AAK-TAINT-*).
    "@app.tool()\ndef fetch(url: str) -> str:\n    return requests.get(url).text\n",
])
def test_only_a_tool_s_parameters_are_caller_input(tmp_path: Path, body: str) -> None:
    assert _ids(tmp_path, "tool.py", _TOOL_PRELUDE + body) & _SSRF_RULES == set()


# --- a method-first call reads its URL second -------------------------------
#
# `requests.request(method, url)`, `httpx.request`, `httpx.stream`,
# `aiohttp.request` and a session's or client's `.request` take the HTTP method
# first. The URL was read from the first positional argument, so the method was
# taken for it: `requests.request("GET", url)` never carried the caller's URL,
# and `requests.request(method, FIXED)` reported a caller's method as one.


@pytest.mark.parametrize("call", [
    'requests.request("GET", url)',
    'requests.request("GET", url=url)',
    'requests.request(method="GET", url=url)',
    'httpx.request("POST", url)',
    'httpx.stream("GET", url)',
    'aiohttp.request("GET", url)',
    'session.request("GET", url)',
    'self.session.request("GET", url)',
    'client.request("GET", url)',
    'client.stream("GET", url)',
])
def test_a_method_first_call_reads_its_url_second(tmp_path: Path, call: str) -> None:
    body = f"@mcp.tool()\ndef fetch(url: str) -> object:\n    return {call}\n"
    assert _SSRF_RULES <= _ids(tmp_path, "tool.py", _TOOL_PRELUDE + body)


@pytest.mark.parametrize("call", [
    'requests.request(method, "https://api.example.com/v1/items")',
    'httpx.request(method, BASE + "/items")',
    'session.request(method, url=f"{BASE}/items")',
    'client.stream(method, "https://api.example.com/v1/items")',
])
def test_a_caller_s_method_is_not_a_url(tmp_path: Path, call: str) -> None:
    body = f"@mcp.tool()\ndef call(method: str) -> object:\n    return {call}\n"
    assert _ids(tmp_path, "tool.py", _TOOL_PRELUDE + body) & _SSRF_RULES == set()


def test_an_address_in_a_method_first_call_is_read(tmp_path: Path) -> None:
    body = (
        "import requests\n"
        "def creds() -> str:\n"
        '    return requests.request("GET", "http://169.254.169.254/latest/meta-data/").text\n'
    )
    assert "AAK-SSRF-003" in _ids(tmp_path, "meta.py", body)


# --- a `@tool` decorator alone marks the file -------------------------------
#
# The gate wrote `\b(@tool|...)\b`. A word boundary before `@` needs a word
# character in front of it, so a file whose only marker was a `@tool` decorator
# (LangChain's, or a framework's that re-exports it) was never read.


@pytest.mark.parametrize(("decorator", "read"), [
    ("@tool", True),
    ("@tool()", True),
    ('@tool("identity")', True),
    ("@toolbox", False),
    ("@tools.register", False),
])
def test_a_tool_decorator_alone_marks_the_file(tmp_path: Path, decorator: str, read: bool) -> None:
    (tmp_path / "tools.py").write_text(
        "import requests\n\n\n"
        f"{decorator}\n"
        "def identity() -> str:\n"
        '    return requests.get("http://169.254.169.254/latest/meta-data/").text\n',
        encoding="utf-8",
    )
    assert ("AAK-SSRF-003" in {f.rule_id for f in scan(tmp_path)[0]}) is read


def test_a_tool_file_with_no_other_marker_reports_its_caller_url(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "import requests\n"
        "from langchain_core.tools import tool\n\n\n"
        "@tool\n"
        "def fetch(tool_input):\n"
        '    url = tool_input["url"]\n'
        "    return requests.get(url).text\n",
        encoding="utf-8",
    )
    ids = {f.rule_id for f in scan(tmp_path)[0]}
    assert {"AAK-SSRF-001", "AAK-SSRF-005"} <= ids


# --- backend units ----------------------------------------------------------


def test_python_backend_ignores_calls_that_are_not_fetches() -> None:
    sites = analyze_python('import os\ndef f(request):\n    os.getenv(request.json["k"])\n')
    assert sites == []


def test_python_backend_survives_a_syntax_error() -> None:
    """A file that does not parse must yield nothing, not raise."""
    assert analyze_python("def broken(:\n  pass\n") == []


def test_js_backend_resolves_a_single_hop() -> None:
    sites = analyze_js('const target = req.query.url;\nfetch(target);\n')
    assert sites and sites[0].tainted


def test_js_backend_ignores_a_commented_call() -> None:
    sites = analyze_js('// fetch(req.query.url)\nconst x = 1;\n')
    assert all(not s.tainted for s in sites)


@pytest.mark.parametrize("addr", ["127.0.0.1", "169.254.169.254", "192.168.1.5"])
def test_python_backend_finds_private_addresses_in_the_url_arg(addr: str) -> None:
    sites = analyze_python(f'import requests\nrequests.get("http://{addr}/x")\n')
    assert sites and sites[0].private_addr == addr


# --- an address is the host a client reads ----------------------------------
#
# The private-address pattern was searched anywhere in a string with no
# boundary, so `110.1.2.3` read as 10.1.2.3, `2001:db8::1` as ::1 and
# `notlocalhost.example.com` as localhost, and AAK-SSRF-002 (HIGH) named an
# address the code does not contain. It knew each address in one spelling, so
# `http://0xa9fea9fe/`, 169.254.169.254 to Node and to the resolver behind curl,
# reached no rule.

_ADDRESS_RULES = {"AAK-SSRF-002", "AAK-SSRF-003"}


def _status_ids(tmp_path: Path, url: str, ext: str = "py") -> list[tuple[str, str]]:
    if ext == "py":
        body = f'import requests\ndef status() -> str:\n    return requests.get("{url}").text\n'
        (tmp_path / "tool.py").write_text(_HINT + body, encoding="utf-8")
    else:
        (tmp_path / "tool.ts").write_text(_TS_HEAD + f'export const status = () => fetch("{url}");\n', encoding="utf-8")
    return [(f.rule_id, f.evidence) for f in scan(tmp_path)[0] if f.rule_id in _ADDRESS_RULES]


@pytest.mark.parametrize("ext", ["py", "ts"])
@pytest.mark.parametrize("url", [
    "http://110.1.2.3/health",
    "http://[2001:db8::1]/health",
    "https://notlocalhost.example.com/health",
    "https://localhost.example.com/health",
    "http://10.1.2.3.example.com/health",
    "http://172.32.0.1/health",
    "http://192.169.0.1/health",
    "http://8.8.8.8/health",
])
def test_a_public_host_is_not_a_private_address(tmp_path: Path, url: str, ext: str) -> None:
    assert _status_ids(tmp_path, url, ext) == []


@pytest.mark.parametrize("ext", ["py", "ts"])
@pytest.mark.parametrize(("url", "rule_id", "address"), [
    ("http://0xa9fea9fe/latest/meta-data/", "AAK-SSRF-003", "169.254.169.254"),
    ("http://2852039166/latest/meta-data/", "AAK-SSRF-003", "169.254.169.254"),
    ("http://169.254.43518/latest/meta-data/", "AAK-SSRF-003", "169.254.169.254"),
    ("http://0251.0376.0251.0376/latest/meta-data/", "AAK-SSRF-003", "169.254.169.254"),
    ("http://[::ffff:169.254.169.254]/latest/meta-data/", "AAK-SSRF-003", "169.254.169.254"),
    ("http://METADATA.google.internal./computeMetadata/v1/", "AAK-SSRF-003", "metadata.google.internal"),
    ("http://0x7f.1:9000/admin", "AAK-SSRF-002", "127.0.0.1"),
    ("http://2130706433:9000/admin", "AAK-SSRF-002", "127.0.0.1"),
    ("http://[0:0:0:0:0:0:0:1]:9000/admin", "AAK-SSRF-002", "::1"),
    ("http://LOCALHOST.:9000/admin", "AAK-SSRF-002", "localhost"),
    ("http://dev.localhost:3000/admin", "AAK-SSRF-002", "dev.localhost"),
    ("http://10.1:9000/admin", "AAK-SSRF-002", "10.0.0.1"),
    ("http://0/admin", "AAK-SSRF-002", "0.0.0.0"),
    # evil.example to Node and requests, 10.0.0.5 to httpx and curl
    ("http://evil.example\\\\@10.0.0.5/admin", "AAK-SSRF-002", "10.0.0.5"),
])
def test_an_address_counts_in_any_spelling_a_client_reads(
    tmp_path: Path, url: str, rule_id: str, address: str, ext: str
) -> None:
    hits = _status_ids(tmp_path, url, ext)
    assert [rule for rule, _ in hits] == [rule_id]
    assert f": {address} via " in hits[0][1]


@pytest.mark.parametrize(("literal", "address"), [
    ("127.0.0.1", "127.0.0.1"),
    ("localhost:9000", "localhost"),
    ("169.254.169.254/latest/meta-data/", "169.254.169.254"),
    ("[::1]:8080", "::1"),
    ("::1", "::1"),
    ("10.2.1.4", "10.2.1.4"),
    # A string that is not a URL holds an address only when it is written out.
    ("10.2.1", None),
    ("2130706433", None),
    ("0x7f.1", None),
    ("notlocalhost", None),
    ("/v1/10.0.0.1", None),
])
def test_a_host_written_without_a_scheme(literal: str, address: str | None) -> None:
    sites = analyze_python(f'import requests\nHOST = "{literal}"\nrequests.get(f"http://{{HOST}}/x")\n')
    assert [s.private_addr for s in sites] == [address]


def test_js_code_is_not_read_as_an_address() -> None:
    """The old search read the whole argument, names and all."""
    assert [s.private_addr for s in analyze_js("fetch(localhostUrl);\n")] == [None]
    assert [s.private_addr for s in analyze_js("const target = `http://${host}:8080/x`;\nfetch(target);\n")] == [None]
    assert [s.private_addr for s in analyze_js("fetch(`http://localhost:${port}/x`);\n")] == ["localhost"]


@pytest.mark.parametrize("unit", ["'", '"', "`", "`${", "'\\", "http://", "a b ", "a.b ", "a:b ", "[::"])
def test_a_crafted_literal_reads_in_linear_time(tmp_path: Path, unit: str) -> None:
    """The address check reads every string a URL argument holds. 400 KB of the
    worst unit takes a fraction of a second; the bound is loose for slow runners."""
    body = unit * (400_000 // len(unit))
    started = time.perf_counter()
    analyze_js(f"const base = {body};\nfetch(base);\n")
    analyze_python(f"import requests\nrequests.get({body!r})\n")
    assert time.perf_counter() - started < 5.0


def test_python_backend_does_not_find_addresses_outside_a_call() -> None:
    sites = analyze_python('import requests\nDOC = "use 127.0.0.1 for local"\nrequests.get("https://a.example")\n')
    assert sites and sites[0].private_addr is None


# --- TS/JS: `//` inside a literal is not a comment ----------------------------
#
# The stripper was two regexes that did not know what a string is, so the `//` of
# every `http://` in a literal started a "comment" to the end of the line. The
# call lost its closing parenthesis and no call site was found: AAK-SSRF-002/003
# never saw a TS URL with a scheme, and 001/005 lost a caller-controlled host as
# soon as it followed `http://` in a template literal.

_TS_HEAD = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'export const server = new McpServer({ name: "fetcher", version: "1.0.0" });\n'
)


def _ts_ids(tmp_path: Path, body: str) -> set[str]:
    (tmp_path / "tool.ts").write_text(_TS_HEAD + body, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


@pytest.mark.parametrize(("body", "rule_id"), [
    ('export const role = () => fetch("http://169.254.169.254/latest/meta-data/");\n', "AAK-SSRF-003"),
    ("export const admin = () => fetch('http://localhost:9000/admin'); // admin port\n", "AAK-SSRF-002"),
    ("export const f = (req: any) => fetch(`http://${req.query.host}/status`);\n", "AAK-SSRF-001"),
    ("export const f = (req: any) => fetch(`http://${req.query.host}/status`);\n", "AAK-SSRF-005"),
    ('export const f = (req: any) => fetch("http://" + req.query.host + "/status");\n', "AAK-SSRF-001"),
    ('const META = "http://169.254.169.254/latest/meta-data/";\n'
     "export const role = () => fetch(META);\n", "AAK-SSRF-003"),
    # a regex literal holding `//` must not eat the rest of its line either
    ('const norm = (p: string) => p.replace(/\\/\\//g, "/"); '
     "export const f = (req: any) => fetch(req.query.url);\n", "AAK-SSRF-001"),
])
def test_a_ts_url_with_a_scheme_is_read(tmp_path: Path, body: str, rule_id: str) -> None:
    assert rule_id in _ts_ids(tmp_path, body)


@pytest.mark.parametrize("body", [
    '// return fetch("http://169.254.169.254/latest/meta-data/");\nexport const x = 1;\n',
    "/* fetch(req.query.url) */ export const y = 2;\n",
    "export const re = /[\"']/; // fetch(req.query.url)\nexport const z = 3;\n",
    "export const half = (a: number, b: number) => (a + b) / 2; // fetch(req.query.url)\n",
    "let n = 4;\nexport const q = n++ / 2; // fetch(req.query.url)\n",
])
def test_a_ts_comment_is_not_a_call(tmp_path: Path, body: str) -> None:
    assert _ts_ids(tmp_path, body) == set()


def test_ts_comment_stripping_keeps_literals_and_layout() -> None:
    from agent_audit_kit.scanners._ssrf_reach import strip_comments

    src = (
        'const a = "http://x.example/*y"; // one\n'
        "const b = `http://${ok ? `${h}` : 'z'}/p`; /* two\n"
        "three */ const c = /^https?:\\/\\//; // four\n"
    )
    out = strip_comments(src, is_python=False)
    assert len(out) == len(src) and out.count("\n") == src.count("\n")
    assert '"http://x.example/*y"' in out
    assert "`http://${ok ? `${h}` : 'z'}/p`" in out
    assert "/^https?:\\/\\//" in out
    assert not any(word in out for word in ("one", "two", "three", "four"))


@pytest.mark.parametrize("unit", ['"//" ', "`${`${a}`}` ", "a / b // c\n", "/[/]/ ", "'\\'' /* x */ "])
def test_ts_comment_stripping_is_linear(unit: str) -> None:
    """Every search resumes where the last one stopped. 400 KB of the worst unit
    took well under a tenth of a second; the bound is loose for slow runners."""
    import time

    from agent_audit_kit.scanners._ssrf_reach import strip_comments

    src = unit * (400_000 // len(unit))
    started = time.perf_counter()
    strip_comments(src, is_python=False)
    assert time.perf_counter() - started < 5.0


def _js_arg(length: int) -> str:
    """A call argument of exactly ``length`` characters that names a request field."""
    return "'" + "a" * (length - 18) + "' + req.query.url"


@pytest.mark.parametrize(("source", "sites"), [
    ("fetch( req.query.url   );\n", [("fetch", 1, True, None)]),
    # The argument is read up to 200 characters before the closer's blanks.
    ("fetch(" + _js_arg(200) + ");\n", [("fetch", 1, True, None)]),
    ("fetch(" + _js_arg(201) + ");\n", []),
    ("fetch(" + _js_arg(199) + " " * 500 + ");\n", [("fetch", 1, True, None)]),
    ("fetch(req.query.url; got(req.body.u);\n", [("got", 1, True, None)]),
    ("fetch(fetch(req.query.url));\n", [("fetch", 1, True, None)]),
    ("axios.get(req.body.target, { timeout: 5 });\n", [("axios.get", 1, True, None)]),
    ("const base = '169.254.169.254/latest';\nfetch(base);\n", [("fetch", 2, False, "169.254.169.254")]),
])
def test_js_backend_call_shapes_keep_their_result(source: str, sites: list[tuple[object, ...]]) -> None:
    assert [tuple(s) for s in analyze_js(source)] == sites


_CRAFTED_JS = {
    # A call with a long blank run and no closer re-read the run once per
    # character before it: "fetch(" and 8,000 blanks took 32 seconds.
    "call-blanks": "fetch(" + " " * 500_000,
    "calls": "fetch(" * 83_000,
    # Every unclosed `/*` read on to the end of the file.
    "open-comments": "/* a" * 125_000,
    # Every character of a long word began an assignment read to its end.
    "word": "a" * 500_000,
    "blanks": " " * 500_000 + "x",
}


@pytest.mark.parametrize("shape", sorted(_CRAFTED_JS))
def test_a_crafted_js_file_scans_in_linear_time(tmp_path: Path, shape: str) -> None:
    """Just under the scanner's 512,000-byte file cap, with the MCP hint. The
    bound is loose for slow CI runners; each takes a fraction of a second."""
    import time

    body = _CRAFTED_JS[shape]
    assert len(_HINT + body) < 512_000
    started = time.perf_counter()
    _ids(tmp_path, "server.ts", body)
    assert time.perf_counter() - started < 5.0


# --- the assignment walk is linear ------------------------------------------
#
# Both backends follow a URL argument through assignments a few levels deep.
# The walk remembered nothing, so names assigned from each other multiplied: the
# work grew with the fourth (TS/JS) or fifth (Python) power of how many names
# each right-hand side reads, and every call site paid again. Each test runs a
# crafted file at two sizes, best of three, and allows the larger 40 times the
# smaller's time for 10 times the work (the old walk needed 100 to 10,000 times)
# plus a fixed slack, under an absolute bound that is loose for slow CI runners.


def _seconds(run: Callable[[], object]) -> float:
    """Best of three, so one descheduled run cannot fail a timing test."""
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


def _grows_linearly(small: Callable[[], object], large: Callable[[], object]) -> None:
    """``large`` does ten times the work of ``small``."""
    t_small, t_large = _seconds(small), _seconds(large)
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def _fanout_js(names: int, calls: int) -> str:
    """Every name assigned from every name, and calls that read all of them.
    Twenty-four names and ten calls (3 KB) took 11 seconds."""
    every = "+".join(f"n{i}" for i in range(names))
    lines = [f"const n{i} = {every};\n" for i in range(names)]
    return "".join(lines) + f"fetch({every});\n" * calls


def _fanout_py(names: int, calls: int) -> str:
    """The Python shape: twenty names and one call took a second."""
    every = " + ".join(f"n{i}" for i in range(names))
    lines = [f"n{i} = {every}\n" for i in range(names)]
    return "import requests\n" + "".join(lines) + "requests.get(n0)\n" * calls


def _fanout_tool(names: int, calls: int) -> str:
    """The same inside a tool, where a parameter is caller input, so the
    caller-input walk reads every name as well as the address walk."""
    every = " + ".join(f"n{i}" for i in range(names))
    lines = [f"    n{i} = {every}\n" for i in range(names)]
    return "import requests\n@mcp.tool()\ndef t(request):\n" + "".join(lines) + "    requests.get(n0)\n" * calls


def test_names_assigned_from_each_other_resolve_in_linear_time() -> None:
    """Eight names to thirty (TS) or twenty-seven (Python) is ten times the
    text. The old walk grew with the fourth or fifth power of the fan-out, a
    few hundred times longer; on a real file (transformers' image_utils.py) it
    took 6.9 seconds."""
    assert 9.5 < len(_fanout_js(30, 4)) / len(_fanout_js(8, 4)) < 10.5
    assert 9.5 < len(_fanout_py(27, 4)) / len(_fanout_py(8, 4)) < 10.5
    assert 9.5 < len(_fanout_tool(29, 4)) / len(_fanout_tool(8, 4)) < 10.5
    _grows_linearly(lambda: analyze_js(_fanout_js(8, 4)), lambda: analyze_js(_fanout_js(30, 4)))
    _grows_linearly(lambda: analyze_python(_fanout_py(8, 4)), lambda: analyze_python(_fanout_py(27, 4)))
    _grows_linearly(lambda: analyze_python(_fanout_tool(8, 4)), lambda: analyze_python(_fanout_tool(29, 4)))


def test_a_deep_fanout_still_reaches_its_source() -> None:
    """The memo must not cut the walk short. The request field and the address
    sit four assignments below the call, the deepest the walk reads, behind
    names that all read each other. In Python the caller's value has to lead
    each piece it passes through, as it sets the host only from there:
    `top = n0 + ...`, `n0 = n11 + ...`, `n11 = src + ...`."""
    js = (
        _fanout_js(12, 0).replace("const n11 = ", "const n11 = src + ", 1)
        + "const src = req.query.url + '169.254.169.254';\n"
        + "const top = n0 + n5;\nfetch(top);\n"
    )
    assert [tuple(s)[2:] for s in analyze_js(js)] == [(True, "169.254.169.254")]
    py = (
        _fanout_tool(12, 0).replace("n0 = ", "n0 = n11 + ", 1).replace("n11 = ", "n11 = src + ", 1)
        + "    src = request.json['u'] + '169.254.169.254'\n"
        + "    top = n0 + n5\n    requests.get(top)\n"
    )
    assert [tuple(s)[2:] for s in analyze_python(py)] == [(True, "169.254.169.254")]
    # One more assignment between the call and the request field is past the walk.
    deeper = py.replace("    top = n0 + n5\n", "    top = mid + n5\n    mid = n0\n")
    assert [tuple(s)[2:] for s in analyze_python(deeper)] == [(False, "169.254.169.254")]


@pytest.mark.parametrize("arg", [
    "p" + ".a" * 4_000,                                   # an attribute chain
    "q" + "[0]" * 4_000,                                  # a read chain
    " if c else ".join(["'x'"] * 3_000) + " if c else p",  # a conditional chain
    " + ".join(["'x'"] * 2_000) + " + p",                 # a concatenation
    "f'" + "{c}x" * 10_000 + "{p}'",                      # an f-string of many parts
])
def test_a_crafted_tool_url_is_read_in_linear_time(arg: str) -> None:
    """The caller-input walk reads a tool's URL expression part by part. Chains
    thousands long are walked with a stack, not by recursion, so none of these
    can exhaust the interpreter's stack, and each takes a fraction of a second;
    the bound is loose for slow runners. Python 3.11's own parser refuses the
    deepest chains ("maximum recursion depth exceeded during ast construction"),
    before this code runs, so the case is skipped there."""
    import ast

    source = "import requests\n@mcp.tool()\ndef t(p):\n    requests.get(" + arg + ")\n"
    try:
        ast.parse(source)
    except RecursionError:
        pytest.skip("this interpreter's parser refuses an expression this deep")
    started = time.perf_counter()
    analyze_python(source)
    assert time.perf_counter() - started < 5.0


def test_a_cycle_of_assignments_terminates_with_its_finding() -> None:
    js = "let a = b + c;\nlet b = a;\nlet c = req.body.target;\nfetch(a);\n"
    assert [tuple(s) for s in analyze_js(js)] == [("fetch", 4, True, None)]
    py = "import requests\na = b + c\nb = a\nc = '127.0.0.1'\nrequests.get(a)\n"
    assert [tuple(s) for s in analyze_python(py)] == [("requests.get", 5, False, "127.0.0.1")]


def test_call_lines_are_counted_in_linear_time() -> None:
    """Each call's line was counted from the top of the file: 450 KB of
    `fetch(a);` lines took 4 seconds, growing with the square."""
    sites = analyze_js("fetch(a);\n" * 3)
    assert [s.line for s in sites] == [1, 2, 3]
    _grows_linearly(lambda: analyze_js("fetch(a);\n" * 4_500), lambda: analyze_js("fetch(a);\n" * 45_000))
