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

import ast
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.scanners._helpers import _PY_MAX_NESTING, python_nesting_bound
from agent_audit_kit.scanners._ssrf_reach import _format_pieces, _percent_pieces, analyze_js, analyze_python
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
    'PATH_T = "https://api.example.com/items/%s"\n'
    'HOST_T = "https://%s/status"\n'
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


# --- the host test, reviewed --------------------------------------------------
#
# Four ways a caller value sets the host that the first host test missed, a
# `%` template it misread, a backslash only WHATWG readers end an authority at,
# the registration forms that make a function a tool without a decorator
# taint_analysis knows, a bare host next to punctuation, a scheme assignment
# read as validation, and the address walk, which keeps its old bindings.


@pytest.mark.parametrize("body", [
    # A bare leading `/` lets the caller write the second one: `"/" +
    # "/evil.example/x"` is scheme-relative, and urljoin takes its host.
    'def proxy(path: str) -> str:\n    return requests.get(urljoin(BASE_SLASH, "/" + path)).text\n',
    'async def proxy(path: str) -> str:\n    async with httpx.AsyncClient(base_url=BASE) as client:\n'
    '        return (await client.get(f"/{path}")).text\n',
    # `+=` onto a scheme.
    'def proxy(host: str) -> str:\n    url = "https://"\n    url += host\n    url += "/x"\n'
    "    return requests.get(url).text\n",
    # A host read out of the caller's value by unpacking.
    'def proxy(target: str) -> str:\n    host, _, port = target.partition(":")\n'
    '    return requests.get(f"http://{host}:{port}/").text\n',
    'def proxy(pair: tuple) -> str:\n    (host, port) = pair\n    return requests.get(f"http://{host}:{port}/").text\n',
    # A list of pieces bound to a name and joined.
    'def proxy(host: str) -> str:\n    parts = ["https://", host, "/x"]\n    return requests.get("".join(parts)).text\n',
    # A name holding a `%` template that leaves the host open, and fields read
    # by position and by name.
    "def proxy(host: str) -> str:\n    return requests.get(HOST_T % host).text\n",
    'def proxy(scheme: str, path: str) -> str:\n    return requests.get("%s://api.example.com/%s" % (scheme, path)).text\n',
    'def proxy(host: str) -> str:\n    return requests.get("{}://{}/x".format("https", host)).text\n',
    'def proxy(host: str) -> str:\n    return requests.get("https://{h}/x".format(h=host)).text\n',
    # httpx, curl and urlsplit keep a backslash inside the authority, so the
    # caller can still write `@evil.example` after it.
    'def proxy(user: str) -> str:\n    return requests.get("https://api.example.com\\\\" + user).text\n',
    # A mapping the caller hands over fills keyed fields: `%(host)s` reads
    # `arguments["host"]`, as `{host}` does through `**arguments`.
    'def proxy(arguments: dict) -> str:\n    return requests.get("https://%(host)s/x" % arguments).text\n',
    'def proxy(arguments: dict) -> str:\n    return requests.get("https://%(host)s/x" % {**arguments}).text\n',
    'def proxy(arguments: dict) -> str:\n    return requests.get("https://{host}/x".format(**arguments)).text\n',
    'def proxy(arguments: dict) -> str:\n    return requests.get("https://{0[host]}/x".format(arguments)).text\n',
    # A base built with `+=` and no trailing `/`, here and at module level:
    # the caller's path still extends its host.
    'def proxy(path: str) -> str:\n    url = "https://"\n    url += "api.example.com"\n'
    "    return requests.get(url + path).text\n",
    'def proxy(path: str) -> str:\n    return requests.get(API_HOST + path).text\n'
    'API_HOST = "https://"\nAPI_HOST += "api.example.com"\n',
    # A scheme and its two slashes written apart: `https:/` has no authority
    # yet, so it does not end one.
    'def proxy(host: str) -> str:\n    return requests.get("/".join(["https:", "", host, "v1"])).text\n',
    'def proxy(host: str) -> str:\n    parts = ["https:", "", host, "v1"]\n    return requests.get("/".join(parts)).text\n',
    'def proxy(host: str) -> str:\n    return requests.get("https:/" + "/" + host).text\n',
    'def proxy(host: str) -> str:\n    return requests.get("https:" + "/" + "/" + host).text\n',
])
def test_the_host_test_reads_these_caller_hosts(tmp_path: Path, body: str) -> None:
    assert _SSRF_RULES <= _ids(tmp_path, "tool.py", _TOOL_PRELUDE + "@mcp.tool()\n" + body)


@pytest.mark.parametrize("body", [
    "def fetch(arguments: dict) -> str:\n    urls = [u.strip() for u in arguments['urls']]\n"
    "    return requests.get(urls[0]).text\n",
    "def fetch_many(urls: str) -> list:\n    targets = [u.strip() for u in urls.split(',')]\n"
    "    return [requests.get(t).text for t in targets]\n",
    "def fetch(query: list) -> str:\n    urls = {q.strip() for q in query}\n    for url in urls:\n"
    "        requests.get(url)\n    return ''\n",
    "def status(hosts: list) -> int:\n    targets = [f'https://{h}/status' for h in hosts]\n"
    "    return requests.get(targets[0]).status_code\n",
    "def fetch(urls: list) -> str:\n    for url in (u.strip() for u in urls):\n        requests.get(url)\n    return ''\n",
])
def test_a_comprehension_over_caller_input_holds_it(tmp_path: Path, body: str) -> None:
    """A list, set or generator comprehension holds what its element reads,
    as a dict comprehension holds its values: a local bound from one of the
    tool's parameters. Each was silent; the first fires on main too."""
    assert _SSRF_RULES <= _ids(tmp_path, "tool.py", _TOOL_PRELUDE + "@mcp.tool()\n" + body)


@pytest.mark.parametrize("body", [
    "def item(path: str) -> str:\n    return requests.get(PATH_T % path).text\n",
    # The caller's value fills a field after the host the code put first.
    'def item(repo: str) -> str:\n    return requests.get("%s/v2/%s" % (BASE, repo)).text\n',
    'def item(repo: str) -> str:\n    return requests.get("{}/v2/{}".format(BASE, repo)).text\n',
    'def item(path: str) -> str:\n    return requests.get("{base}/x/{p}".format(base=BASE, p=path)).text\n',
    'def item(path: str) -> str:\n    url = BASE_SLASH\n    url += path\n    return requests.get(url).text\n',
    # A module-level `+=` makes the base more than its first value.
    'def item(path: str) -> str:\n    return requests.get(API + path).text\nAPI = "https://"\nAPI += "api.example.com/"\n',
    'def item(path: str) -> str:\n    parts = [BASE, path]\n    return requests.get("/".join(parts)).text\n',
    'def item(path: str) -> str:\n    return requests.get(urljoin(BASE_SLASH, "/v1/" + path)).text\n',
    'def item(path: str) -> str:\n    return requests.get("https:/" + "/api.example.com/" + path).text\n',
    "def item(ids: list) -> int:\n    targets = [f'https://api.example.com/{i}' for i in ids]\n"
    "    return requests.get(targets[0]).status_code\n",
    # Keyed fields after a fixed host, and a mapping the code fixed.
    'def item(arguments: dict) -> str:\n    return requests.get("https://api.example.com/%(path)s" % arguments).text\n',
    'def item(path: str) -> str:\n    return requests.get("https://%(host)s/" % REGIONS + path).text\n',
])
def test_the_host_test_still_leaves_a_fixed_host_alone(tmp_path: Path, body: str) -> None:
    assert _ids(tmp_path, "tool.py", _TOOL_PRELUDE + "@mcp.tool()\n" + body) & _SSRF_RULES == set()


@pytest.mark.parametrize("registration", [
    "def fetch(url: str) -> str:\n    return requests.get(url).text\n\nmcp.add_tool(fetch)\n",
    "@function_tool\ndef fetch(url: str) -> str:\n    return requests.get(url).text\n",
    '@function_tool(name_override="fetch")\ndef fetch(url: str) -> str:\n    return requests.get(url).text\n',
    "def fetch(url: str) -> str:\n    return requests.get(url).text\n\nTOOL = StructuredTool.from_function(func=fetch)\n",
    'def fetch(url: str) -> str:\n    return requests.get(url).text\n\nTOOL = Tool(name="fetch", func=fetch, description="x")\n',
    # A tool written as a class: a LangChain or CrewAI `BaseTool` runs the
    # caller's input through `_run` or `_arun`, and a low-level server written
    # as a class, or a dispatcher, takes it in `call_tool`.
    "class Fetch(BaseTool):\n    name: str = 'fetch'\n    def _run(self, query: str) -> str:\n        return requests.get(query).text\n",
    "class Fetch(tools.BaseTool):\n    async def _arun(self, url: str) -> str:\n        return requests.get(url).text\n",
    "class Tools:\n    async def call_tool(self, name, arguments):\n        return requests.get(arguments['url']).text\n",
    "async def call_tool(name, arguments):\n    return requests.get(arguments['url']).text\n",
])
def test_a_function_registered_as_a_tool_is_one(tmp_path: Path, registration: str) -> None:
    """`mcp.add_tool(fetch)`, the OpenAI Agents SDK's `@function_tool`, a
    function handed to `func=` (`StructuredTool.from_function`, LangChain's
    `Tool`), a `BaseTool` subclass's `_run` and a `call_tool` method make a
    tool without a decorator taint_analysis knows. The old name list fired on
    the last two through `query` and `arguments`."""
    assert _SSRF_RULES <= _ids(tmp_path, "tool.py", _TOOL_PRELUDE + registration)


@pytest.mark.parametrize("registration", [
    # A class that reaches `BaseTool` or `StructuredTool` through the file's own
    # classes, an alias the file imports or assigns, or a subscripted base.
    "class Base(BaseTool):\n    pass\n\nclass Search(Base):\n"
    "    def _run(self, query: str) -> str:\n        return requests.get(query).text\n",
    "from langchain.tools import BaseTool as LCTool\n\nclass Search(LCTool):\n"
    "    def _run(self, query: str) -> str:\n        return requests.get(query).text\n",
    "LCTool = tools.BaseTool\n\nclass Search(LCTool):\n"
    "    def _run(self, query: str) -> str:\n        return requests.get(query).text\n",
    "class Search(StructuredTool):\n    def _run(self, query: str) -> str:\n        return requests.get(query).text\n",
    "class Search(BaseTool[dict]):\n    def _run(self, query: str) -> str:\n        return requests.get(query).text\n",
    "class Base(BaseTool[str]):\n    pass\n\nclass Search(Mixin, Base):\n"
    "    def _run(self, query: str) -> str:\n        return requests.get(query).text\n",
    # The public `run` and `arun` a class tool may override.
    "class Search(BaseTool):\n    def run(self, query: str) -> str:\n        return requests.get(query).text\n",
    "class Search(BaseTool):\n    async def arun(self, query: str) -> str:\n        return requests.get(query).text\n",
    # A `call_tool` handler under another name, undecorated.
    "async def handle_call_tool(name, arguments):\n    return requests.get(arguments['url']).text\n",
    "class Client:\n    async def _call_tool(self, name, arguments):\n        return requests.get(arguments['url']).text\n",
])
def test_a_class_tool_or_handler_however_the_file_names_it_is_one(tmp_path: Path, registration: str) -> None:
    """Each fired on main, through the old name list, and was silent once only
    a class whose own bases name `BaseTool` counted, and only `call_tool`."""
    assert _SSRF_RULES <= _ids(tmp_path, "tool.py", _TOOL_PRELUDE + registration)


@pytest.mark.parametrize("body", [
    "class Base:\n    pass\n\nclass Search(Base):\n    def _run(self, url: str) -> str:\n        return requests.get(url).text\n",
    # Classes that name each other end, and reach no tool.
    "class A(B):\n    pass\n\nclass B(A):\n    def _run(self, url: str) -> str:\n        return requests.get(url).text\n",
    "class Search(BaseTool):\n    def fetch(self, url: str) -> str:\n        return requests.get(url).text\n",
    "async def recall_tool(name, arguments):\n    return requests.get(arguments['url']).text\n",
    # A base another file defines is not followed.
    "from .base import ToolBase\n\nclass Search(ToolBase):\n"
    "    def _run(self, url: str) -> str:\n        return requests.get(url).text\n",
])
def test_a_class_or_function_that_reaches_no_tool_is_none(tmp_path: Path, body: str) -> None:
    assert _ids(tmp_path, "tool.py", _TOOL_PRELUDE + body) & _SSRF_RULES == set()


def test_class_tools_are_found_in_one_walk() -> None:
    """The classes that reach `BaseTool` are found by one walk out from the
    tool bases, so 15,000 classes that each extend the last are read in a
    fraction of a second, where a walk up from every class would take the
    square of that, and classes that extend each other end. In a child, so
    a loop fails here instead of hanging the run."""
    chain = "class C0(BaseTool):\n    pass\n" + "".join(
        f"class C{i}(C{i - 1}):\n    pass\n" for i in range(1, 15_000)
    )
    tools = (
        "class Search(C14999):\n    def _run(self, url: str) -> str:\n        return requests.get(url).text\n"
        "class A(B):\n    pass\n"
        "class B(A):\n    def _run(self, url: str) -> str:\n        return requests.get(url).text\n"
    )
    source = _CYCLE_HEAD + chain + tools
    assert len(source) < 512_000
    sites, seconds = _analyze_in_child(source, timeout=30)
    assert [site[2] for site in sorted(sites, key=lambda site: site[1])] == [True, False]
    assert seconds < 5.0


@pytest.mark.parametrize("source", [
    # A tool's parameter or loop name is the tool's, whatever the module binds.
    "params = ['https://api.example.com/', 'v1']\n"
    "@mcp.tool()\ndef fetch(params: list) -> str:\n    return requests.get(''.join(params)).text\n",
    "parts = ['https://api.example.com/', 'v1']\n"
    "@mcp.tool()\ndef fetch(parts: list) -> str:\n    return requests.get(''.join(parts)).text\n",
    "parts = ['https://api.example.com/']\n"
    "@mcp.tool()\ndef fetch(hosts: list) -> str:\n    for parts in hosts:\n        requests.get(''.join(parts))\n"
    "    return ''\n",
    # Another function's own names are not the module's.
    "SCHEME = 'https://'\n@mcp.tool()\ndef fetch(host: str) -> str:\n    return requests.get(SCHEME + host).text\n"
    "def unrelated() -> None:\n    for SCHEME in ('a', 'b'):\n        print(SCHEME)\n",
    "ROOT = 'https://'\n@mcp.tool()\ndef fetch(host: str) -> str:\n    return requests.get(ROOT + host).text\n"
    "def helper() -> str:\n    ROOT = 'https://api.example.com/'\n    return ROOT\n",
])
def test_a_name_is_read_in_the_scope_that_binds_it(tmp_path: Path, source: str) -> None:
    """Names resolved file-wide, through every function's bindings: a module
    list won over the tool's own parameter of that name, and another
    function's loop or local made a module binding unreadable. The first
    fires on main too."""
    assert _SSRF_RULES <= _ids(tmp_path, "tool.py", _TOOL_PRELUDE + source)


def test_a_global_a_function_extends_is_the_module_s(tmp_path: Path) -> None:
    """A function that declares a name `global` binds the module's name, so
    its `+=` still makes the base more than its first value."""
    source = (
        "ROOT = 'https://'\ndef configure() -> None:\n    global ROOT\n    ROOT += 'api.example.com/'\n"
        "@mcp.tool()\ndef fetch(path: str) -> str:\n    return requests.get(ROOT + path).text\n"
    )
    assert _ids(tmp_path, "tool.py", _TOOL_PRELUDE + source) & _SSRF_RULES == set()


def _nested(outer: str, inner: str) -> list[bool]:
    """The verdicts of a tool nested in a tool, with these bodies."""
    source = (
        _CYCLE_HEAD + "@mcp.tool()\ndef outer(host: str) -> str:\n" + outer
        + "    @mcp.tool()\n    def inner(path: str) -> str:\n" + inner + "    return ''\n"
    )
    return [site.tainted for site in analyze_python(source)]


def test_a_nested_tool_reads_the_enclosing_tools_names_as_a_closure_does() -> None:
    """A call inside nested tools is judged once, in one scope: the tools'
    parameters, and each name as the innermost of them that has it binds it.
    It used to be judged in every enclosing tool's scope, each holding only
    what that tool binds, so a nested tool read an enclosing tool's local as
    unbound and an enclosing tool's parameter even where the nested tool
    rebinds the name."""
    caller = "        return requests.get('https://' + host + '/' + path).text\n"
    assert _nested("", caller) == [True]
    # The enclosing tool's `base` is the nested tool's, as in a closure.
    assert _nested("    base = 'https://'\n", "        return requests.get(base + path).text\n") == [True]
    # A name the nested tool binds is its own.
    assert _nested(
        "    base = 'https://api.example.com/'\n",
        "        base = 'https://'\n        return requests.get(base + path).text\n",
    ) == [True]
    assert _nested("", "        host = 'api.example.com'\n        return requests.get('https://' + host + '/x').text\n") == [False]


@pytest.mark.parametrize(("source", "tainted"), [
    ("def create_server():\n    mcp = FastMCP('d')\n    SCHEME = 'https://'\n    @mcp.tool()\n"
     "    def fetch(arguments: dict) -> str:\n        return requests.get(SCHEME + arguments['host']).text\n"
     "    return mcp\n", True),
    ("def register(mcp):\n    URL_T = 'https://{host}/v1/items'\n    @mcp.tool()\n"
     "    def fetch(arguments: dict) -> str:\n        return requests.get(URL_T.format(host=arguments['host'])).text\n",
     True),
    ("def register(mcp):\n    URL_T = Template('https://$host/v1/items')\n    @mcp.tool()\n"
     "    def fetch(arguments: dict) -> str:\n        return requests.get(URL_T.substitute(arguments)).text\n", True),
    ("def register(mcp):\n    URL_T = 'https://%s/v1/items'\n    @mcp.tool()\n"
     "    def fetch(arguments: dict) -> str:\n        return requests.get(URL_T % arguments['host']).text\n", True),
    ("def main():\n    mcp = FastMCP('d')\n    scheme = 'https://'\n    @mcp.tool()\n"
     "    def fetch(host: str) -> str:\n        return requests.get(scheme + host + '/status').text\n    mcp.run()\n",
     True),
    # A host the function fixes keeps the caller's value in the path.
    ("def register(mcp):\n    BASE = 'https://api.example.com/v1/'\n    @mcp.tool()\n"
     "    def fetch(path: str) -> str:\n        return requests.get(BASE + path).text\n", False),
])
def test_a_tool_defined_inside_a_function_reads_that_function_s_names(source: str, tainted: bool) -> None:
    """A tool registered inside a function that is no tool (`create_server()`,
    `register(mcp)`, `main()`) reads that function's names, as a closure does.
    Only an enclosing tool's scope was handed on, so the factory's `SCHEME`
    read as unbound, the caller's host after it went unread, and the forms
    main reported went quiet."""
    sites = analyze_python(_CYCLE_HEAD + "from string import Template\n" + source)
    assert [site.tainted for site in sites] == [tainted]


@pytest.mark.parametrize("inner", [
    "    def helper() -> str:\n        BASE = 'https://api.example.com/'\n        return BASE\n",
    "    class Cfg:\n        BASE = 'https://api.example.com/'\n",
    "    seen = [BASE for BASE in ('a', 'b')]\n",
    "    make = lambda: (BASE := 'https://api.example.com/')\n",
])
def test_a_name_a_scope_inside_the_tool_binds_is_not_the_tool_s(inner: str) -> None:
    """A function, class, comprehension or lambda inside a tool binds its names
    in a scope of its own, so a nested helper's local, a class attribute, a
    comprehension's variable or a lambda's `:=` does not hide the module's
    `BASE` from the tool. Each landed in the tool's scope, giving `BASE` a
    second value the tool read as a base the code does not spell out."""
    source = (
        _CYCLE_HEAD + "BASE = 'https://'\n@mcp.tool()\ndef fetch(arguments: dict) -> str:\n" + inner
        + "    return requests.get(BASE + arguments['host']).text\n"
    )
    assert [site.tainted for site in analyze_python(source)] == [True]


@pytest.mark.parametrize(("helper", "call", "tainted"), [
    ("    def get(url: str) -> str:\n        return requests.get(url).text\n", "get('https://api.example.com/')", False),
    ("    get = lambda url: requests.get(url).text\n", "get('https://api.example.com/')", False),
    # Without a parameter of its own, the name is the tool's, as in a closure.
    ("    def get() -> str:\n        return requests.get(url).text\n", "get()", True),
])
def test_a_helper_inside_a_tool_reads_its_own_parameter_as_its_own(helper: str, call: str, tainted: bool) -> None:
    """A function or lambda inside a tool reads a parameter of its own as its
    own, even one called what the tool's is: what a helper is handed is not
    followed, as AAK-SSRF-001's limitation says. Its body was read in the
    tool's scope, where the name was the caller's, so a helper handed a fixed
    URL was reported."""
    source = _CYCLE_HEAD + "@mcp.tool()\ndef fetch(url: str) -> str:\n" + helper + f"    return {call}\n"
    assert [site.tainted for site in analyze_python(source)] == [tainted]


@pytest.mark.parametrize(("source", "tainted"), [
    # A nested tool's `nonlocal` write to the name the enclosing tool fetches.
    ("@mcp.tool()\ndef outer(arguments: dict) -> str:\n    url = 'https://api.example.com/'\n    @mcp.tool()\n"
     "    def inner(query: dict) -> str:\n        nonlocal url\n        url = query['url']\n        return ''\n"
     "    inner(arguments)\n    return requests.get(url).text\n", True),
    # A nested tool's `global` write to the module name the enclosing tool fetches.
    ("URL = 'https://api.example.com/'\n@mcp.tool()\ndef outer(arguments: dict) -> str:\n    @mcp.tool()\n"
     "    def inner(query: dict) -> str:\n        global URL\n        URL = query['url']\n        return ''\n"
     "    inner(arguments)\n    return requests.get(URL).text\n", True),
    # One tool sets the module's base from its caller; another fetches from it.
    ("BASE = 'https://api.example.com/'\n@mcp.tool()\ndef set_base(query: dict) -> str:\n    global BASE\n"
     "    BASE = query['base']\n    return 'ok'\n@mcp.tool()\ndef fetch(arguments: dict) -> str:\n"
     "    return requests.get(BASE + arguments['path']).text\n", True),
    # A function that is no tool sets it from its own parameter, no caller's.
    ("BASE = 'https://api.example.com/'\ndef configure(base: str) -> None:\n    global BASE\n    BASE = base\n"
     "@mcp.tool()\ndef fetch(path: str) -> str:\n    return requests.get(BASE + path).text\n", False),
])
def test_a_global_or_nonlocal_write_is_read_where_it_is_written(source: str, tainted: bool) -> None:
    """A `nonlocal` or `global` write binds the name in the scope that declares
    it, and its value is read in the function that writes it, where `query`
    is that tool's parameter. The write was kept in the writing function's
    scope, so the enclosing tool's `url` never saw it; a `global` write was
    the module's, read in the module's scope, where no name is the caller's."""
    sites = sorted(analyze_python(_CYCLE_HEAD + source), key=lambda site: site.line)
    assert sites[-1].tainted is tainted


def _write_through_write(decorator: str) -> str:
    """A handler with no caller input of its own whose `u` a helper sets from
    `v`, which a function beside the helper sets from its `arguments`."""
    return (
        _CYCLE_HEAD + "def run_call_tool(name):\n    u = 'https://api.example.com/'\n    def a():\n        v = 'x'\n"
        f"{decorator}        def w2(arguments: dict) -> str:\n            nonlocal v\n"
        "            v = arguments['host']\n            return ''\n"
        "        def w():\n            nonlocal u\n            u = 'https://' + v\n        return w2, w\n"
        "    a()\n    return requests.get(u + name).text\n"
    )


@pytest.mark.parametrize(("decorator", "tainted"), [("        @mcp.tool()\n", True), ("", False)])
def test_a_write_reaches_caller_input_through_another_write(decorator: str, tainted: bool) -> None:
    """Whether a scope can reach caller input at all is settled before any URL
    is read, and a scope no caller input reaches is not read. It reaches it
    through a write a scope that reaches it lands in it, and that writer may
    reach it only through another write: here the nested tool's `v` reaches
    `w`, whose `u` reaches the handler. Two passes counted one write, so the
    handler read as unreachable; the reach now spreads along every write and
    every scope around another until nothing new is reached. With no tool
    setting `v`, nothing reaches the handler."""
    sites = analyze_python(_write_through_write(decorator))
    assert [site.tainted for site in sites] == [tainted]


def _sibling_tools(tools: int, fetch: bool) -> str:
    """One tool that binds four names for each of `tools` handlers defined
    beside one another in it, each a `*_call_tool` function of its own."""
    names = [f"a{i}" for i in range(4 * tools)]
    body = "".join("    " + "=".join(names[i:i + 500]) + "=0\n" for i in range(0, len(names), 500))
    call = "requests.get(arguments)" if fetch else "pass"
    body += "".join(f"    def f{i}_call_tool(arguments):{call}\n" for i in range(tools))
    return _CYCLE_HEAD + "@mcp.tool()\ndef outer(p: str) -> str:\n" + body + "    return requests.get(p).text\n"


def _peak_in_child(source: str, timeout: float = 120) -> int:
    """The most memory analyze_python held at once for `source`, in bytes, from
    a child traced with tracemalloc."""
    code = (
        "import sys, tracemalloc\n"
        "from agent_audit_kit.scanners._ssrf_reach import analyze_python\n"
        "source = sys.stdin.read()\n"
        "tracemalloc.start()\n"
        "analyze_python(source)\n"
        "print(tracemalloc.get_traced_memory()[1])\n"
    )
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [str(_REPO_ROOT), os.environ.get("PYTHONPATH")])))
    proc = subprocess.run(
        [sys.executable, "-c", code], input=source, capture_output=True, text=True, timeout=timeout, env=env,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    return int(proc.stdout)


def test_tools_defined_side_by_side_are_read_in_linear_time() -> None:
    """Each nested tool's scope used to copy the enclosing tool's parameters
    and names, so one tool holding 7,700 handlers beside 30,800 names took 18
    seconds. A scope now holds its own names and reads the rest up the chain
    of scopes around it."""
    source = _sibling_tools(7_700, fetch=False)
    assert len(source) < 512_000
    sites, seconds = _analyze_in_child(source, timeout=60)
    assert [site[2] for site in sites] == [True]
    assert seconds < 5.0


def test_tools_defined_side_by_side_hold_no_copy_of_the_enclosing_names() -> None:
    """The copies stayed alive for every call, so 2,000 handlers that each
    fetch held 437 MB at once, and 3,000 held 1.28 GB."""
    assert _peak_in_child(_sibling_tools(2_000, fetch=True)) < 100_000_000


def test_a_function_passed_elsewhere_is_no_tool(tmp_path: Path) -> None:
    body = (
        "def fetch(url: str) -> str:\n    return requests.get(url).text\n\n"
        "RESULT = list(map(fetch, URLS))\n"
        "thread = threading.Thread(target=fetch, args=(BASE,))\n"
        "class Worker(threading.Thread):\n    def _run(self, url: str) -> str:\n        return requests.get(url).text\n"
    )
    assert _ids(tmp_path, "tool.py", _TOOL_PRELUDE + body) & _SSRF_RULES == set()


def test_a_call_tool_method_reads_only_the_caller_s_arguments(tmp_path: Path) -> None:
    """A `call_tool` method is often a client's bridge to a server it was
    configured with (`call_tool(self, server, tool_name, arguments)`): its
    caller input is `arguments` and the other names the old list held, not
    the server it is handed. Seen on a real Docker bridge, which fetched
    `f"http://127.0.0.1:{server.port}/"`."""
    body = (
        "class Bridge:\n    async def call_tool(self, server, tool_name, arguments):\n"
        "        return requests.post(f'http://127.0.0.1:{server.port}/', json=arguments).text\n"
    )
    assert _ids(tmp_path, "tool.py", _TOOL_PRELUDE + body) & _SSRF_RULES == set()


@pytest.mark.parametrize(("literal", "address"), [
    ("hosts: localhost, 10.0.0.5,", "localhost"),
    ("(127.0.0.1)", "127.0.0.1"),
    ("[::1],", "::1"),
    ("upstream=10.0.0.5", None),
])
def test_a_bare_host_next_to_punctuation(literal: str, address: str | None) -> None:
    """The old search found an address anywhere; reading a word as a host lost
    one glued to a comma or a parenthesis. A query value (`upstream=`) is not
    the URL's host, and stays unread."""
    sites = analyze_python(f'import requests\nHOST = "{literal}"\nrequests.get(f"http://{{HOST}}/x")\n')
    assert [s.private_addr for s in sites] == [address]


def test_another_function_s_loop_lends_a_call_no_address() -> None:
    """The address walk reads `=` and an annotated `=` only, as before.
    Reading the bindings the host test now reads (a `for`, an unpacking, `+=`)
    as well added two real loopback calls on the code-search samples and one
    false one of this shape, a login URL built from a parameter that took
    another function's probe loop address four names away: too small a gain
    for the noise."""
    source = (
        "import requests\n"
        "def login(server_url):\n"
        "    url = f'{server_url}/api/v1/login'\n"
        "    return requests.post(url)\n"
        "def probe():\n"
        "    for url in ['http://127.0.0.1:8237/health']:\n"
        "        print(url)\n"
    )
    assert [s.private_addr for s in analyze_python(source)] == [None]


@pytest.mark.parametrize(("check", "silenced"), [
    ('    scheme = "https"\n', False),
    ('    if parsed.scheme == "https":\n        pass\n', True),
    ('    if parsed.scheme != "https":\n        raise ValueError(url)\n', True),
])
def test_a_scheme_comparison_is_validation_and_an_assignment_is_not(
    tmp_path: Path, check: str, silenced: bool
) -> None:
    """The validation pattern read `scheme = "https"`, an assignment, as a check
    and silenced AAK-SSRF-001 for the whole file, while `parsed.scheme ==
    "https"` did not match it."""
    body = (
        "@mcp.tool()\ndef fetch(url: str) -> str:\n"
        "    parsed = urllib.parse.urlsplit(url)\n" + check + "    return requests.get(url).text\n"
    )
    ids = _ids(tmp_path, "tool.py", _TOOL_PRELUDE + body)
    assert ("AAK-SSRF-001" not in ids) is silenced
    assert "AAK-SSRF-005" in ids


# --- a binding that comes back to itself ends --------------------------------
#
# The host test follows a name to what it is bound to, a named list into the
# join that reads it, and a template into its fields. A binding that comes back
# to itself must end: a list that joined itself looped for ever inside one
# expansion, with no depth bound to stop it, and the engine has no scanner
# timeout. Each shape runs in a child process, so a regression fails here
# instead of hanging the run.

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CYCLE_HEAD = "import requests\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('d')\n"


def _analyze_in_child(source: str, timeout: float = 60) -> tuple[list[tuple[object, ...]], float]:
    """analyze_python's sites for `source` and its CPU time, from a child."""
    code = (
        "import json, sys, time\n"
        "from agent_audit_kit.scanners._ssrf_reach import analyze_python\n"
        "source = sys.stdin.read()\n"
        "started = time.process_time()\n"
        "sites = analyze_python(source)\n"
        "print(json.dumps([[list(s) for s in sites], time.process_time() - started]))\n"
    )
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [str(_REPO_ROOT), os.environ.get("PYTHONPATH")])))
    proc = subprocess.run(
        [sys.executable, "-c", code], input=source, capture_output=True, text=True, timeout=timeout, env=env,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    sites, seconds = json.loads(proc.stdout)
    return [tuple(site) for site in sites], seconds


_CYCLES = {
    # A list that joins itself, two lists that join each other, and the same
    # at module level, read through the file-wide bindings.
    "list-self": ("    parts = ['https://', ''.join(parts)]\n    return requests.get(''.join(parts)).text\n", False),
    "list-pair": ("    a = ['x', ''.join(b)]\n    b = ['y', ''.join(a)]\n    return requests.get(''.join(a)).text\n", False),
    "list-module": ("    return requests.get('/'.join(PARTS) + host).text\nPARTS = ['https://', '/'.join(PARTS)]\n", True),
    # A self-join reached again through a call each time, twice per level.
    "list-through-call": (
        "    parts = ['https://', str(''.join(parts)), str(''.join(parts))]\n"
        "    return requests.get(''.join(parts)).text\n", False),
    # Names bound to each other, with and without a caller value among them.
    "names": ("    a = b\n    b = a\n    return requests.get(a).text\n", False),
    "names-with-caller": ("    a = b\n    b = a\n    b = host\n    return requests.get(a).text\n", True),
    # `x += x`, after a value and with none before it.
    "augmented-self": ("    x = 'https://'\n    x += x\n    return requests.get(x).text\n", False),
    "augmented-param": ("    host += host\n    return requests.get(host).text\n", True),
    # f-strings and templates that read each other.
    "fstrings": ("    a = f'https://{b}'\n    b = f'{a}/x'\n    return requests.get(a).text\n", False),
    "percent": ("    t = 'https://%s' % t\n    return requests.get(t).text\n", False),
    "format": ("    t = '{}/x'.format(t)\n    return requests.get(t).text\n", False),
}


@pytest.mark.parametrize("shape", sorted(_CYCLES))
def test_a_binding_that_comes_back_to_itself_ends(shape: str) -> None:
    body, tainted = _CYCLES[shape]
    sites, seconds = _analyze_in_child(_CYCLE_HEAD + "@mcp.tool()\ndef f(host: str) -> str:\n" + body)
    assert [site[2] for site in sites] == [tainted]
    assert seconds < 2.0


def test_lists_that_each_join_the_last_twice_do_not_double() -> None:
    """Thirty lists, each joining the one before it twice: expanding every
    join again would read 2**30 pieces. A list is expanded once per URL."""
    lines = ["    l0 = ['https://']\n"] + [f"    l{i} = [''.join(l{i - 1}), ''.join(l{i - 1})]\n" for i in range(1, 31)]
    body = "".join(lines) + "    return requests.get(''.join(l30) + host).text\n"
    sites, seconds = _analyze_in_child(_CYCLE_HEAD + "@mcp.tool()\ndef f(host: str) -> str:\n" + body)
    assert len(sites) == 1
    assert seconds < 2.0


# --- a mapping the host test puts together is its own ------------------------
#
# A dict literal with two or more `**` entries fills a keyed field from any of
# them, so the host test reads those entries as one value it puts together.
# That value was made afresh for every template and dropped once read, while
# the host test remembers a verdict by an expression's id, and CPython hands a
# freed object's id to the next object made: a later template's mapping was
# read as an earlier one's. Fixed mappings first lost the caller's at the end,
# and a caller's first made a fixed one the caller's.

_TWO_MAPPINGS = "A = {'host': 'a.example.com'}\nB = {'host': 'b.example.com'}\n"


@pytest.mark.parametrize("mappings", [
    ["**A, **B", "**B, **A", "**A, **A", "**B, **arguments"],
    ["**A, **arguments", "**A, **B"],
    ["**A, **B", "**A, **arguments"] * 4,
    ["**A, **arguments", "**A, **B"] * 4,
])
def test_each_template_reads_its_own_merged_mapping(mappings: list[str]) -> None:
    sites = "".join(f"    requests.get('https://%(host)s/{i}' % {{{m}}})\n" for i, m in enumerate(mappings))
    source = _CYCLE_HEAD + _TWO_MAPPINGS + "@mcp.tool()\ndef proxy(arguments: dict) -> str:\n" + sites
    assert [s.tainted for s in analyze_python(source)] == ["arguments" in m for m in mappings]


# --- a caller's mapping, however it is written --------------------------------
#
# The old name list fired whenever a caller's name reached the URL, so it read
# a mapping in any spelling. The host test read only a mapping written in place
# (`% arguments`, `% {**arguments}`, `.format(**arguments)`): one held in a
# name, built by `dict(...)` or a comprehension, or read by `format_map` or a
# `string.Template` was silent.

_MAPPING_PRELUDE = _TOOL_PRELUDE + "import string\nfrom string import Template\n@mcp.tool()\n"


@pytest.mark.parametrize("body", [
    "def proxy(arguments: dict) -> str:\n    params = {'host': arguments['host']}\n"
    "    return requests.get('https://%(host)s/x' % params).text\n",
    "def proxy(arguments: dict) -> str:\n    params = {'host': arguments['host']}\n"
    "    return requests.get('https://{host}/x'.format(**params)).text\n",
    "def proxy(host: str) -> str:\n    params = {'host': host}\n    return requests.get('https://%(host)s/x' % params).text\n",
    "def proxy(arguments: dict) -> str:\n    return requests.get('https://%(host)s/x' % dict(arguments)).text\n",
    "def proxy(arguments: dict) -> str:\n"
    "    return requests.get('https://%(host)s/x' % dict(host=arguments['host'])).text\n",
    "def proxy(arguments: dict) -> str:\n"
    "    return requests.get('https://%(host)s/x' % {k: v for k, v in arguments.items()}).text\n",
    "def proxy(arguments: dict) -> str:\n    return requests.get('https://{host}/x'.format_map(arguments)).text\n",
    "def proxy(arguments: dict) -> str:\n"
    "    return requests.get(string.Template('https://$host/x').substitute(arguments)).text\n",
    "def proxy(host: str) -> str:\n    page = Template('https://${host}/x')\n"
    "    return requests.get(page.safe_substitute(host=host)).text\n",
    # A `**` written after a key can replace it.
    "def proxy(arguments: dict) -> str:\n"
    "    return requests.get('https://%(host)s/x' % {'host': 'api.example.com', **arguments}).text\n",
])
def test_a_caller_s_mapping_fills_the_host_however_it_is_written(tmp_path: Path, body: str) -> None:
    assert _SSRF_RULES <= _ids(tmp_path, "tool.py", _MAPPING_PRELUDE + body)


@pytest.mark.parametrize("body", [
    "def item(arguments: dict) -> str:\n    params = {'host': 'api.example.com'}\n"
    "    return requests.get('https://%(host)s/' % params + arguments['p']).text\n",
    "def item(arguments: dict) -> str:\n    params = {'host': 'api.example.com', 'path': arguments['p']}\n"
    "    return requests.get('https://%(host)s/%(path)s' % params).text\n",
    "def item(arguments: dict) -> str:\n    return requests.get(\n"
    "        'https://%(host)s/%(path)s' % dict(host='api.example.com', path=arguments['p'])).text\n",
    "def item(arguments: dict) -> str:\n    return requests.get('https://api.example.com/{path}'.format_map(arguments)).text\n",
    "def item(arguments: dict) -> str:\n"
    "    return requests.get(string.Template('https://api.example.com/$path').substitute(arguments)).text\n",
    "def item(path: str) -> str:\n    page = Template('https://api.example.com/$$/$path')\n"
    "    return requests.get(page.substitute(path=path)).text\n",
    # A key written after a `**` is the key's; one before it is replaced only
    # by what that `**` holds, not by the dict's other entries.
    "def item(arguments: dict) -> str:\n"
    "    return requests.get('https://%(host)s/x' % {**arguments, 'host': 'api.example.com'}).text\n",
    "def item(arguments: dict) -> str:\n    return requests.get(\n"
    "        'https://%(host)s/%(path)s' % {'host': 'api.example.com', 'path': arguments['p'], **REGIONS}).text\n",
])
def test_a_caller_s_mapping_after_a_fixed_host_is_not_a_caller_url(tmp_path: Path, body: str) -> None:
    assert _ids(tmp_path, "tool.py", _MAPPING_PRELUDE + body) & _SSRF_RULES == set()


@pytest.mark.parametrize(("mapping", "tainted"), [
    ("{'u': 'https://' + host}", False),
    ("{k: 'https://' + host for k in KEYS}", False),
    ("{host: 'x'}", True),
])
def test_a_joined_mapping_gives_its_keys(mapping: str, tainted: bool) -> None:
    """Iterating a mapping gives its keys, so `"".join(d)` holds the keys of
    `d`, never its values, however the host test reads a mapping elsewhere."""
    source = _TOOL_HEAD.replace("p: str", "host: str") + f"    d = {mapping}\n    return requests.get(''.join(d)).text\n"
    assert [s.tainted for s in analyze_python(source)] == [tainted]


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


@pytest.mark.parametrize("template", ["%(" * 50_000, "%" + "0" * 100_000, "{" * 100_000, "%s" * 50_000])
def test_a_crafted_template_is_read_in_linear_time(template: str) -> None:
    """A template is spelled out to `_PREFIX_CAP` characters, and the field
    readers stay linear without that cap: each `%` field's key and flag run
    stop at the next `%` or `(` (a key read up to the next `)` scanned to the
    end of the text from every `%(`), and `.format` templates go to
    `string.Formatter`. The bound is loose for slow runners."""
    call = ast.parse("t.format(p)", mode="eval").body
    assert isinstance(call, ast.Call)
    source = (
        "import requests\n@mcp.tool()\ndef t(p):\n"
        f"    requests.get({template!r} % (p,))\n    requests.get({template!r}.format(p))\n"
    )
    started = time.perf_counter()
    _percent_pieces(template, ast.Name(id="p", ctx=ast.Load()), lambda node: ({}, node))
    _format_pieces(template, call)
    analyze_python(source)
    assert time.perf_counter() - started < 5.0


def _augmented(lines: int) -> str:
    """`url += part` again and again inside a tool, none of it the caller's,
    so the whole chain is judged and its host never closes. Each `+=` bound
    a new value over the one before and every one was judged, flattened in
    full: 4,000 lines took 4 seconds, growing with the square."""
    return (
        "import requests\n@mcp.tool()\ndef t(host: str) -> str:\n    part = 'x'\n    url = 'https://'\n"
        + "    url += part\n" * lines + "    return requests.get(url).text\n"
    )


def test_an_augmented_chain_is_read_in_linear_time() -> None:
    assert 9.5 < len(_augmented(10_000)) / len(_augmented(1_000)) < 10.5
    assert [s.tainted for s in analyze_python(_augmented(3))] == [False]
    _grows_linearly(lambda: analyze_python(_augmented(1_000)), lambda: analyze_python(_augmented(10_000)))


# A name bound many times, or read at many places. Every read of a name looped
# over all of its bindings, once per read and depth, so a name bound n times and
# read n times cost n squared. `url = url + part` 4,000 times (84 KB) took 7
# seconds and 24,000 times (504 KB) more than six minutes.
_REBOUND = {
    "rebound": lambda n: "    part = 'x'\n    url = 'https://'\n" + "    url = url + part\n" * n,
    "augmented-rebound": lambda n: (
        "    part = 'x'\n    url = 'https://'\n" + "    url += part\n    url = url + part\n" * (n // 2)
    ),
    "loop-rebound": lambda n: "    url = 'https://'\n" + "    for url in [url]:\n        pass\n" * (n // 2),
    "read-often": lambda n: "    url = 'https://a/'\n" * (n // 2) + "    requests.get(url)\n" * (n // 2),
}
_REBOUND_LINES = {"rebound": 8_000, "augmented-rebound": 12_000, "loop-rebound": 12_000, "read-often": 22_000}


@pytest.mark.parametrize("shape", sorted(_REBOUND))
def test_a_name_bound_or_read_many_times_is_judged_once_per_depth(shape: str) -> None:
    body = _REBOUND[shape](_REBOUND_LINES[shape]) + "    return requests.get(url).text\n"
    source = _CYCLE_HEAD + "@mcp.tool()\ndef t(host: str) -> str:\n" + body
    assert len(source) < 512_000
    sites, seconds = _analyze_in_child(source, timeout=30)
    assert sites and not any(site[2] for site in sites)
    assert seconds < 5.0


# What a binding outside the tool spells, and what a list joined by name holds,
# were read again by every tool and at every call site, and a template a name
# holds was read to its end at every use. Each shape is just under the
# scanner's 512,000-byte cap, and took, before the fix: a module-level `+=`
# chain read by 4,368 tools 24 s, a list of 39,000 items joined by 10,188
# fetches 16 s (in the tool or at module level), 8,000 lists each joining the
# next 60 s, a list of 30,000 empty f-strings joined by 10,310 fetches 13 s, a
# binding fanning out to 128 names of 128 names read by 2,000 tools 42 s, and a
# 255-field template read by 20,414 fetches 9 s (`%`) or 17,599 fetches 7 s
# (`.format`). Each takes about a second now.


def _filled(head: str, unit: str) -> str:
    """`head`, then `unit` as often as fits under the scanner's file cap."""
    return head + unit * ((511_000 - len(head)) // len(unit))


_TOOL_HEAD = _CYCLE_HEAD + "@mcp.tool()\ndef t(p: str) -> str:\n"
_FANOUT = (
    "".join(f"M{i} = ''\n" for i in range(128))
    + "".join(f"N{i} = ''" + "".join(f" + M{j}" for j in range(128)) + "\n" for i in range(128))
    + "B0 = ''" + "".join(f" + N{i}" for i in range(128)) + "\n"
)
_SHARED: dict[str, tuple[Callable[[], str], bool]] = {
    "module-augmented-chain": (lambda: _filled(
        _CYCLE_HEAD + "BASE = 'https://'\n" + "BASE += 'a'\n" * 16_000,
        "@mcp.tool()\ndef t(p: str) -> str:\n    return requests.get(BASE + p).text\n"), True),
    "module-list": (lambda: _filled(
        _CYCLE_HEAD + "BIG = ['https://', 'api.example.com/', " + "'a', " * 39_000 + "]\n"
        "@mcp.tool()\ndef t(p: str) -> str:\n", "    requests.get(''.join(BIG))\n"), False),
    "local-list": (lambda: _filled(
        _TOOL_HEAD + "    big = ['https://', 'api.example.com/', " + "'a', " * 39_000 + "]\n",
        "    requests.get(''.join(big))\n"), False),
    "join-chain": (lambda: _filled(
        _TOOL_HEAD + "".join(f"    l{i} = [''.join(l{i + 1})]\n" for i in range(8_000)) + "    l8000 = ['https://']\n",
        "    requests.get(''.join(l0) + p)\n"), False),
    "empty-fstrings": (lambda: _filled(
        _TOOL_HEAD + "    big = ['https://', " + "f'', " * 30_000 + "]\n", "    requests.get(''.join(big) + p)\n"), True),
    "fanout": (lambda: _CYCLE_HEAD + _FANOUT + (
        "@mcp.tool()\ndef t(p: str) -> str:\n    return requests.get(B0 + p).text\n" * 2_000), True),
    "percent-template": (lambda: _filled(
        _CYCLE_HEAD + "T = 'x" + "%s" * 255 + "'\n@mcp.tool()\ndef t(p: str) -> str:\n",
        "    requests.get(T % ())\n"), False),
    "format-template": (lambda: _filled(
        _CYCLE_HEAD + "T = 'x" + "{}" * 255 + "'\n@mcp.tool()\ndef t(p: str) -> str:\n",
        "    requests.get(T.format())\n"), False),
    # 7,000 keys a `**` written after them can replace, each read by a fetch:
    # a key's value and the entries that can replace it are judged once each.
    "replaceable-keys": (lambda: _TOOL_HEAD.replace("p: str", "arguments: dict") + "    d = {"
        + "".join(f"'k{i}': 'a', " for i in range(7_000)) + "".join(f"**x{i}, " for i in range(7_000))
        + "**arguments}\n" + "".join(f"    requests.get('https://%(k{i})s/' % d)\n" for i in range(7_000)), True),
    # A dict of 23,070 keys joined by name at 7,690 fetches: joining a mapping
    # reads its keys, which were read again at every join.
    "dict-join": (lambda: _TOOL_HEAD + "    d = {" + "".join(f"'k{i}': 0, " for i in range(23_070)) + "}\n"
        + "    requests.get(''.join(d))\n" * 7_690, False),
    # A module `string.Template` made from an `or` of 23,769 names, substituted
    # at 7,923 fetches in one tool, and one of 13,554 names substituted by 4,518
    # tools: the template's text was walked again at every substitution.
    "template-one-tool": (lambda: _CYCLE_HEAD + "from string import Template\nT = Template("
        + " or ".join(f"x{i}" for i in range(23_769)) + ")\n@mcp.tool()\ndef t(p: str) -> str:\n"
        + "    requests.get(T.substitute(h=p))\n" * 7_923, False),
    "template-tools": (lambda: _CYCLE_HEAD + "from string import Template\nT = Template("
        + " or ".join(f"x{i}" for i in range(13_554)) + ")\n" + "".join(
            f"@mcp.tool()\ndef t{k}(p: str) -> str:\n    return requests.get(T.substitute(h=p)).text\n"
            for k in range(4_518)), False),
    # A list of 301 items joined by name with 12,855 different separators: it
    # was read out again for every separator, to its 256th piece, and spelled.
    "separators": (lambda: _TOOL_HEAD + "    parts = ['https://', " + "'a', " * 300 + "]\n" + "".join(
        f"    requests.get('{_separator(i)}'.join(parts) + p)\n" for i in range(12_855)), True),
    # 97 tools nested in one another, the innermost holding 4,252 fetches of an
    # open URL: every fetch was judged in every enclosing tool's scope.
    "nested-tools": (lambda: _CYCLE_HEAD + "".join(
        "\t" * level + "@mcp.tool()\n" + "\t" * level + f"def t{level}(p{level}: str) -> str:\n"
        for level in range(97)) + "\t" * 97 + "u = 'https://'" + " + 'a'" * 200 + "\n"
        + ("\t" * 97 + "requests.get(u + q)\n") * 4_252, False),
    # 255 names of 250 pieces each, all ending in one name nested 45 deep, so
    # past the nesting bound, and each read at 38 depths in its own fetch: a
    # verdict the bound cut was worked out again at every depth.
    "cut-names": (lambda: _TOOL_HEAD + "    D = " + _wrapped(45, "'a'") + "\n"
        + "".join(f"    K{k} = 'a'" + " + 'a'" * 248 + " + D\n" for k in range(255)) + "".join(
            "    requests.get('https://' + " + f"str(K{k} + " * 38 + "p" + ")" * 38 + ")\n" for k in range(255)), True),
}


def _separator(index: int) -> str:
    """The `index`th of the strings of letters and digits, shortest first."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    text = alphabet[index % len(alphabet)]
    index //= len(alphabet)
    while index:
        text += alphabet[index % len(alphabet)]
        index //= len(alphabet)
    return text


@pytest.mark.parametrize(("items", "open_sep", "closed_sep"), [
    # `https:/` and the caller's host, against `http :/`, which is no URL.
    ("'http', ':/' + host", "s", " "),
    # `s:/` and the caller's host, against `1:/`, whose scheme cannot start
    # with a digit.
    ("'', ':/' + host", "s", "1"),
])
@pytest.mark.parametrize("open_first", [True, False])
def test_a_join_is_judged_by_the_kind_of_each_separator_character(
    items: str, open_sep: str, closed_sep: str, open_first: bool
) -> None:
    """A join's verdict is kept for every separator the authority test cannot
    tell from it. That was any separator of the same length without a `:`,
    `/`, `?`, `#`, `\\` or `@`, so `"s"` and `" "`, or `"s"` and `"1"`, shared
    one verdict, and whichever join was read first decided the other: a
    false finding one way round, a missed host the other."""
    joins = [(open_sep, True), (closed_sep, False)]
    if not open_first:
        joins.reverse()
    body = f"    parts = [{items}]\n" + "".join(f"    requests.get({sep!r}.join(parts))\n" for sep, _ in joins)
    source = _TOOL_HEAD.replace("p: str", "host: str") + body + "    return ''\n"
    sites = sorted(analyze_python(source), key=lambda site: site.line)
    assert [site.tainted for site in sites] == [tainted for _, tainted in joins]


@pytest.mark.parametrize("shape", sorted(_SHARED))
def test_a_shared_binding_is_read_once_per_scope(shape: str) -> None:
    build, tainted = _SHARED[shape]
    source = build()
    assert len(source) < 512_000
    if sys.version_info < (3, 11) and python_nesting_bound(source) > _PY_MAX_NESTING:
        # Before 3.11 a source whose screen bound passes the limit is refused
        # unparsed, and the screen counts each `or` as a level: the template
        # shapes' chains of 13,554 and 23,769 names bound past it, though their
        # trees are five levels deep. A scan refuses such a file and reports it.
        pytest.skip("refused unparsed by the pre-3.11 screen")
    sites, seconds = _analyze_in_child(source, timeout=30)
    assert sites and all(site[2] is tainted for site in sites)
    assert seconds < 5.0


def _join_chain(lists: int) -> str:
    """A tool whose URL joins the first of `lists` lists that each join the next."""
    chain = "".join(f"    l{i} = [''.join(l{i + 1})]\n" for i in range(lists)) + f"    l{lists} = ['https://']\n"
    return _TOOL_HEAD + chain + "    return requests.get(''.join(l0) + p).text\n"


@pytest.mark.parametrize(("empty", "tainted"), [(254, True), (255, False)])
def test_a_built_url_is_read_to_its_256th_piece(empty: int, tainted: bool) -> None:
    """AAK-SSRF-001's limitation states the bound: with 254 empty pieces before
    `"https://" + host` the host is the 256th piece and is read, and with 255
    it is the 257th and is not."""
    url = "'' + " * empty + "'https://' + host"
    source = _TOOL_HEAD.replace("p: str", "host: str") + f"    return requests.get({url}).text\n"
    assert [s.tainted for s in analyze_python(source)] == [tainted]


@pytest.mark.parametrize(("empty", "tainted"), [(15, True), (16, False)])
@pytest.mark.parametrize("form", ["%", "format"])
def test_a_template_is_read_to_its_16th_field(form: str, empty: int, tainted: bool) -> None:
    """AAK-SSRF-001's limitation states the bound: with 15 fields filled with
    `''` before `https://` and the host's field, the host fills the 16th field
    and is read; with 16 it fills the 17th, and the template from there on is
    text the code does not spell out."""
    values = "'', " * empty + "host"
    if form == "%":
        url = "'" + "%s" * empty + "https://%s/' % (" + values + ")"
    else:
        url = "'" + "{}" * empty + "https://{}/'.format(" + values + ")"
    source = _TOOL_HEAD.replace("p: str", "host: str") + f"    return requests.get({url}).text\n"
    assert [s.tainted for s in analyze_python(source)] == [tainted]


def test_lists_joined_inside_one_another_are_read_forty_deep() -> None:
    """A list joined by name is judged and spelled once, the way a name is, a
    call per list, so lists that each join the next are read 39 lists below
    the one the URL joins; the 40th and those under it read as text the code
    does not spell out, which is taken to carry its own host. The 8,000-list
    chain above is one of those."""
    assert [s.tainted for s in analyze_python(_join_chain(39))] == [True]
    assert [s.tainted for s in analyze_python(_join_chain(40))] == [False]


def _built_inside(levels: int) -> str:
    """The caller's `host` in the innermost of `levels` URLs built one inside
    another: `'https://' + ('' + host + '').strip()` is two."""
    inner = "host"
    for _ in range(levels - 1):
        inner = f"('' + {inner} + '').strip()"
    return f"'https://' + {inner}"


@pytest.mark.parametrize(("levels", "tainted"), [(40, True), (41, False)])
def test_urls_built_inside_one_another_are_read_forty_deep(levels: int, tainted: bool) -> None:
    """Not only joined lists: each URL built inside another, here through a
    call on it, is read a level further down, and the reader stops 40 levels
    down, so the caller's host in the 40th is read and in the 41st reads as
    text the code does not spell out. AAK-SSRF-001's limitation states it."""
    source = _TOOL_HEAD.replace("p: str", "host: str") + f"    return requests.get({_built_inside(levels)}).text\n"
    assert [s.tainted for s in analyze_python(source)] == [tainted]


@pytest.mark.parametrize(("length", "tainted"), [(503, False), (504, True)])
def test_an_authority_is_read_to_its_512th_character(length: int, tainted: bool) -> None:
    """AAK-SSRF-001's limitation states the bound: a URL's text is read to its
    512th character. With the `/` that ends the authority as the 512th, the
    caller's value after it is in the path; a character later the `/` is not
    read, the authority reads as still open, and the value is taken for the
    host."""
    url = "'https://" + "a" * length + "/' + host"
    source = _TOOL_HEAD.replace("p: str", "host: str") + f"    return requests.get({url}).text\n"
    assert [s.tainted for s in analyze_python(source)] == [tainted]


@pytest.mark.parametrize(("length", "tainted"), [(502, True), (504, False)])
@pytest.mark.parametrize("form", ["%", "format"])
def test_a_template_field_after_its_512th_character_is_not_filled(form: str, length: int, tainted: bool) -> None:
    """The same bound in a `%` or `.format` template: with the host's field as
    the 511th and 512th characters of the template it is filled and read;
    starting at the 513th it is not filled, so the caller's host there is
    missed."""
    if form == "%":
        url = "'https://" + "a" * length + "%s' % host"
    else:
        url = "'https://" + "a" * length + "{}'.format(host)"
    source = _TOOL_HEAD.replace("p: str", "host: str") + f"    return requests.get({url}).text\n"
    assert [s.tainted for s in analyze_python(source)] == [tainted]


@pytest.mark.parametrize(("names", "tainted"), [(3, True), (4, False)])
@pytest.mark.parametrize("form", ["Template", "format"])
def test_a_template_is_read_through_four_names(form: str, names: int, tainted: bool) -> None:
    """AAK-SSRF-001's limitation states the bound: a value is read through four
    names, so the template the fourth name from the fetch holds is read, a
    `string.Template` as a `.format` string is, and one the fifth holds is
    text the code does not spell out, with the caller's host it fills."""
    if form == "Template":
        head, fill = "T = Template('https://$host/v1')\n", "T.substitute(arguments)"
    else:
        head, fill = "T = 'https://{host}/v1'\n", "T.format(host=arguments['host'])"
    chain = f"    u{names} = {fill}\n" + "".join(f"    u{i} = u{i + 1}\n" for i in range(names - 1, 0, -1))
    source = (
        _CYCLE_HEAD + "from string import Template\n" + head + "@mcp.tool()\ndef fetch(arguments: dict) -> str:\n"
        + chain + "    return requests.get(u1).text\n"
    )
    assert [site.tainted for site in analyze_python(source)] == [tainted]


def _wrapped(levels: int, inner: str) -> str:
    """`inner` inside `levels` of `"a" + (...).strip()`."""
    for _ in range(levels):
        inner = f"'a' + ({inner}).strip()"
    return inner


def test_a_verdict_the_nesting_bound_cut_is_not_reused_where_it_is_not_cut() -> None:
    """The host test remembers a verdict by expression or name and depth, not
    by how deeply it is nested, and stops reading 40 levels down. A verdict
    worked out near that bound, with a part cut off, was kept and handed to
    a shallow read of the same name, in one tool and, through the file's
    scope, in another: `u = p` read 40 levels deep cleared `requests.get(u)`,
    and a base spelled 37 levels deep in one tool cleared `BASE + host` in
    the next. A verdict worked out under a cut is now kept only for that
    depth of nesting."""
    for levels in range(20, 60):
        tool = (
            "@mcp.tool()\ndef t(p: str) -> str:\n    u = p\n"
            f"    requests.get({_wrapped(levels, 'u')})\n    return requests.get(u).text\n"
        )
        assert max(analyze_python(_CYCLE_HEAD + tool), key=lambda site: site.line).tainted, levels
    head = _CYCLE_HEAD + "SCHEME = 'https:'\nSEP = '//'\nBASE = SCHEME + SEP\n"
    second = "@mcp.tool()\ndef b(host: str) -> str:\n    return requests.get(BASE + host).text\n"
    for levels in range(20, 60):
        first = f"@mcp.tool()\ndef a(q: str) -> str:\n    return requests.get({_wrapped(levels, chr(39) + 'a' + chr(39) + ' + BASE')}).text\n"
        assert max(analyze_python(head + first + second), key=lambda site: site.line).tainted, levels


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
