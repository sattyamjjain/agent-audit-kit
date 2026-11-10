"""Group D of the feedback work list: wildcard-DNS names, mapped addresses in URL guards, default
redirects, agent tool classes and WebSocket servers.

The address tests run the guard's own comparison, so the rule's claim about `ipaddress` is checked
on every Python in the CI matrix, and the shape sources are fixture files under
`tests/fixtures/ssrf_gaps/`, so the self-scan does not read them here.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_config, ssrf_patterns, ssrf_toctou, websocket_server
from agent_audit_kit.scanners._helpers import wildcard_dns_ip

FIXTURES = Path(__file__).parent / "fixtures" / "ssrf_gaps"
MAPPED = "AAK-SSRF-MAPPED-001"
WEBSOCKET = "AAK-WEBSOCKET-SERVER-001"


def _dotted(*parts: int) -> str:
    return ".".join(str(p) for p in parts)


METADATA = _dotted(169, 254, 169, 254)


def test_rules_are_registered() -> None:
    assert RULES[MAPPED].severity is Severity.HIGH
    assert RULES[MAPPED].category is Category.TRANSPORT_SECURITY
    assert RULES[WEBSOCKET].severity is Severity.MEDIUM
    assert RULES[WEBSOCKET].category is Category.TRANSPORT_SECURITY
    assert RULES[MAPPED].limitations and RULES[WEBSOCKET].limitations


# -- wildcard DNS -----------------------------------------------------------------------------


@pytest.mark.parametrize("host, expected", [
    (f"{METADATA}.nip.io", METADATA),
    (f"app.{METADATA}.nip.io", METADATA),
    (f"{METADATA}.sslip.io", METADATA),
    (f"{METADATA}.xip.io", METADATA),
    ("169-254-169-254.nip.io", METADATA),
    ("www-169-254-169-254.sslip.io", METADATA),
    ("a9fea9fe.nip.io", METADATA),
    ("A9FEA9FE.NIP.IO", METADATA),
    ("app-a9fea9fe.nip.io", METADATA),
    (f"{METADATA}.nip.io.", METADATA),
    ("--1.sslip.io", "::1"),
    ("2a01-4f8-c17-b8f--2.nip.io", "2a01:4f8:c17:b8f::2"),
    ("--ffff-a9fe-a9fe.nip.io", METADATA),
    ("localtest.me", _dotted(127, 0, 0, 1)),
    ("any.name.localtest.me", _dotted(127, 0, 0, 1)),
    ("lvh.me", _dotted(127, 0, 0, 1)),
])
def test_a_wildcard_name_reads_as_its_address(host: str, expected: str) -> None:
    assert str(wildcard_dns_ip(host)) == expected


@pytest.mark.parametrize("host", [
    "nip.io", "example.nip.io", "www.sslip.io", "example.com", f"{METADATA}.nip.io.example.com", "evilnip.io",
    "notlocaltest.me", "999.1.1.1.nip.io", "1-2-3.nip.io", "abcdefg1.nip.io", "1-2-3-999.nip.io",
])
def test_other_names_read_as_nothing(host: str) -> None:
    assert wildcard_dns_ip(host) is None


def _tool_source(url: str) -> str:
    return (
        "import requests\nfrom mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('x')\n\n\n"
        f"@mcp.tool()\ndef fetch() -> str:\n    return requests.get({url!r}).text\n"
    )


@pytest.mark.parametrize("url, rule", [
    (f"http://{METADATA}.nip.io/latest/", "AAK-SSRF-003"),
    ("http://169-254-169-254.sslip.io/latest/", "AAK-SSRF-003"),
    ("http://a9fea9fe.nip.io/latest/", "AAK-SSRF-003"),
    (f"http://[::ffff:{METADATA}]/latest/", "AAK-SSRF-003"),
    ("http://2852039166/latest/", "AAK-SSRF-003"),
    ("http://10-0-0-5.nip.io/", "AAK-SSRF-002"),
    ("http://0a000005.nip.io/", "AAK-SSRF-002"),
    ("http://localtest.me/", "AAK-SSRF-002"),
    ("http://--1.sslip.io/", "AAK-SSRF-002"),
])
def test_ssrf_rules_read_the_embedded_address(tmp_path: Path, url: str, rule: str) -> None:
    (tmp_path / "tool.py").write_text(_tool_source(url))
    assert rule in {f.rule_id for f in ssrf_patterns.scan(tmp_path)[0]}


@pytest.mark.parametrize("url", ["http://example.nip.io/", "http://8-8-8-8.nip.io/", "http://example.com/"])
def test_a_public_address_fires_neither(tmp_path: Path, url: str) -> None:
    (tmp_path / "tool.py").write_text(_tool_source(url))
    assert not {"AAK-SSRF-002", "AAK-SSRF-003"} & {f.rule_id for f in ssrf_patterns.scan(tmp_path)[0]}


def _server_url(tmp_path: Path, url: str) -> set[str]:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": {"url": url}}}))
    return {f.rule_id for f in mcp_config.scan(tmp_path)[0]}


@pytest.mark.parametrize("url", [
    "http://10-0-0-5.nip.io/s", "http://0a000005.nip.io/s", "https://192-168-1-1.sslip.io/s", "http://10.0.0.5.nip.io/s",
])
def test_mcp_009_reads_an_embedded_private_address(tmp_path: Path, url: str) -> None:
    assert "AAK-MCP-009" in _server_url(tmp_path, url)


@pytest.mark.parametrize("url", ["https://8-8-8-8.nip.io/s", "https://example.nip.io/s", "http://localtest.me/s"])
def test_mcp_009_leaves_public_and_loopback_names(tmp_path: Path, url: str) -> None:
    assert "AAK-MCP-009" not in _server_url(tmp_path, url)


# -- AAK-SSRF-MAPPED-001 ----------------------------------------------------------------------


def _mapped(root: Path) -> list[Any]:
    return [f for f in ssrf_toctou.scan(root)[0] if f.rule_id == MAPPED]


def test_the_claim_about_ipaddress_holds_on_this_python() -> None:
    mapped = ipaddress.ip_address(f"::ffff:{METADATA}")
    assert mapped not in ipaddress.ip_network("169.254.0.0/16")
    assert mapped.is_private
    assert str(mapped.ipv4_mapped) == METADATA


@pytest.mark.parametrize("name", sorted(p.name for p in (FIXTURES / "mapped").glob("fires_*.py")))
def test_a_deny_list_that_never_unwraps_fires(tmp_path: Path, name: str) -> None:
    shutil.copy(FIXTURES / "mapped" / name, tmp_path / "guard.py")
    found = _mapped(tmp_path)
    assert len(found) == 1
    assert ".ipv4_mapped" in found[0].evidence and found[0].line_number


@pytest.mark.parametrize("name", sorted(p.name for p in (FIXTURES / "mapped").glob("quiet_*.py")))
def test_an_answer_stands_it_down(tmp_path: Path, name: str) -> None:
    shutil.copy(FIXTURES / "mapped" / name, tmp_path / "guard.py")
    assert _mapped(tmp_path) == []


def test_it_needs_a_url_word_in_the_file(tmp_path: Path) -> None:
    (tmp_path / "filter.py").write_text(
        "import ipaddress\n\nBLOCKED = [ipaddress.ip_network('10.0.0.0/8')]\n\n\n"
        "def filter_peer(peer: str) -> bool:\n    ip = ipaddress.ip_address(peer)\n    return ip in BLOCKED[0]\n"
    )
    assert _mapped(tmp_path) == []


def test_each_function_gets_its_own_finding(tmp_path: Path) -> None:
    text = (FIXTURES / "mapped" / "fires_any.py").read_text()
    (tmp_path / "guard.py").write_text(text + text.partition("def ")[2].replace("validate_url", "other_url", 1).join(["\n\ndef ", ""]))
    assert len(_mapped(tmp_path)) == 2


# -- AAK-SSRF-004 -----------------------------------------------------------------------------


def _ssrf(root: Path) -> list[Any]:
    return ssrf_patterns.scan(root)[0]


def _redirects(tmp_path: Path, body: str, name: str = "tool.py") -> list[Any]:
    (tmp_path / name).write_text(body)
    return [f for f in _ssrf(tmp_path) if f.rule_id == "AAK-SSRF-004"]


_TOOL_HEAD = "import requests, httpx, aiohttp, urllib.request\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\nsession = requests.Session()\nclient = httpx.Client()\n\n@mcp.tool()\ndef fetch(url: str):\n"


@pytest.mark.parametrize("call", [
    "requests.get(url)", "requests.post(url, data={})", "requests.request('GET', url)", "session.get(url)",
    "urllib.request.urlopen(url)", "aiohttp.request('GET', url)", "requests.get(url, **kw)",
])
def test_a_default_follower_with_a_caller_url_fires(tmp_path: Path, call: str) -> None:
    found = _redirects(tmp_path, f"{_TOOL_HEAD}    return {call}\n")
    assert len(found) == 1 and "by default" in found[0].evidence and found[0].line_number == 9


@pytest.mark.parametrize("call", [
    "requests.get(url, allow_redirects=False)", "requests.get(url, allow_redirects=follow)", "httpx.get(url)", "client.get(url)",
])
def test_a_client_that_does_not_follow_stays_quiet(tmp_path: Path, call: str) -> None:
    assert _redirects(tmp_path, f"{_TOOL_HEAD}    return {call}\n") == []


def test_a_fixed_url_stays_quiet(tmp_path: Path) -> None:
    assert _redirects(tmp_path, f"{_TOOL_HEAD}    return requests.get('https://api.example.com/v1')\n") == []


def test_the_explicit_flag_still_fires_on_its_own_line(tmp_path: Path) -> None:
    found = _redirects(tmp_path, f"{_TOOL_HEAD}    return httpx.get('https://api.example.com/', follow_redirects=True)\n")
    assert len(found) == 1 and "follow_redirects" in found[0].evidence


_JS_HEAD = "const server = new McpServer({});\nserver.tool('f', async (args) => {\n  const url = req.query.url;\n"


@pytest.mark.parametrize("call", ["fetch(url)", "axios.get(url)", "got(url)"])
def test_js_default_followers_fire(tmp_path: Path, call: str) -> None:
    assert len(_redirects(tmp_path, f"{_JS_HEAD}  return {call};\n}});\n", "tool.ts")) == 1


@pytest.mark.parametrize("call", [
    "fetch(url, { redirect: 'manual' })", "fetch(url, { redirect: \"error\" })", "axios.get(url, { maxRedirects: 0 })",
])
def test_js_options_that_turn_it_off_stay_quiet(tmp_path: Path, call: str) -> None:
    assert _redirects(tmp_path, f"{_JS_HEAD}  return {call};\n}});\n", "tool.ts") == []


# -- AAK-SSRF-001 on agent tool classes --------------------------------------------------------


_SMOL = """import requests
{import_line}


class Visit({base}):
    name = "visit"
    description = "Visit a page."
{attributes}
    def forward(self, url: str) -> str:
        return requests.get(url, timeout=20).text
"""
_ATTRIBUTES = '    inputs = {"url": {"type": "string", "description": "The page."}}\n    output_type = "string"\n'


@pytest.mark.parametrize("import_line, base, attributes", [
    ("from smolagents import Tool", "Tool", _ATTRIBUTES),
    ("from smolagents.tools import PipelineTool", "PipelineTool", _ATTRIBUTES),
    ("from .tools import Tool", "Tool", _ATTRIBUTES),
    ("import smolagents", "smolagents.Tool", _ATTRIBUTES),
])
def test_a_smolagents_forward_is_a_tool(tmp_path: Path, import_line: str, base: str, attributes: str) -> None:
    (tmp_path / "tools.py").write_text(_SMOL.format(import_line=import_line, base=base, attributes=attributes))
    assert {"AAK-SSRF-001", "AAK-SSRF-004", "AAK-SSRF-005"} <= {f.rule_id for f in _ssrf(tmp_path)}


def test_a_subclass_of_a_smolagents_tool_is_a_tool(tmp_path: Path) -> None:
    (tmp_path / "tools.py").write_text(
        "import requests\nfrom smolagents import Tool\n\n\nclass Base(Tool):\n    output_type = 'string'\n\n\n"
        "class Visit(Base):\n    def forward(self, url: str) -> str:\n        return requests.get(url).text\n"
    )
    assert "AAK-SSRF-001" in {f.rule_id for f in _ssrf(tmp_path)}


def test_a_model_file_with_a_download_helper_is_no_tool(tmp_path: Path) -> None:
    (tmp_path / "modeling.py").write_text(
        "import requests\nimport torch\n\n\nclass Net(torch.nn.Module):\n    output_type = 'logits'\n\n"
        "    def forward(self, url):\n        return url\n\n\n"
        "def download(url):\n    return requests.head(url, allow_redirects=True)\n"
    )
    assert _ssrf(tmp_path) == []


@pytest.mark.parametrize("base_line, base", [
    ("from langchain.tools import BaseTool", "BaseTool"),
    ("from langchain_core.tools import StructuredTool", "StructuredTool"),
])
def test_a_langchain_class_needs_no_mcp_marker(tmp_path: Path, base_line: str, base: str) -> None:
    (tmp_path / "tools.py").write_text(
        f"import requests\n{base_line}\n\n\nclass Visit({base}):\n    def _run(self, url: str) -> str:\n"
        "        return requests.get(url).text\n"
    )
    assert "AAK-SSRF-001" in {f.rule_id for f in _ssrf(tmp_path)}


# -- AAK-WEBSOCKET-SERVER-001 ------------------------------------------------------------------


def _websocket(root: Path) -> list[Any]:
    return [f for f in websocket_server.scan(root)[0] if f.rule_id == WEBSOCKET]


_EXPECTED = {
    "fires_no_origins.py": "no `origins`",
    "fires_module_alias.py": "no `origins`",
    "fires_function_alias.py": "no `origins`",
    "fires_origins_none.py": "no `origins`",
    "fires_max_size.py": "`max_size=None`",
    "fires_any_interface.py": "every interface",
    "fires_host_default.py": "every interface",
    "fires_traceback.py": "traceback",
    "fires_traceback_held.py": "traceback",
}


@pytest.mark.parametrize("name, expected", sorted(_EXPECTED.items()))
def test_an_open_websocket_server_fires(tmp_path: Path, name: str, expected: str) -> None:
    shutil.copy(FIXTURES / "websocket" / name, tmp_path / "mcp_server.py")
    found = _websocket(tmp_path)
    assert len(found) == 1 and expected in found[0].evidence and found[0].line_number


def test_every_firing_fixture_has_an_expectation() -> None:
    assert sorted(p.name for p in (FIXTURES / "websocket").glob("fires_*.py")) == sorted(_EXPECTED)


@pytest.mark.parametrize("name", sorted(p.name for p in (FIXTURES / "websocket").glob("quiet_*.py")))
def test_a_closed_websocket_server_does_not_fire(tmp_path: Path, name: str) -> None:
    shutil.copy(FIXTURES / "websocket" / name, tmp_path / "mcp_server.py")
    assert _websocket(tmp_path) == []


@pytest.mark.parametrize("rel, fires", [
    ("mcp_server.py", True), ("serving/websocket_policy_server.py", True), ("src/agents/bridge.py", True),
    ("src/model-server/app.py", True), ("src/llm/ws.py", True), ("inference.py", True),
    ("chat_server.py", False), ("src/remodel/app.py", False), ("tests/policy_server.py", False),
    ("examples/policy_server.py", False), ("test_mcp.py", False),
])
def test_scope_is_read_from_the_path(tmp_path: Path, rel: str, fires: bool) -> None:
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "websocket" / "fires_no_origins.py", target)
    assert bool(_websocket(tmp_path)) is fires


def test_an_mcp_import_puts_a_file_in_scope(tmp_path: Path) -> None:
    text = (FIXTURES / "websocket" / "fires_no_origins.py").read_text()
    (tmp_path / "bridge.py").write_text("import mcp\n\n_s = mcp\n" + text)
    assert len(_websocket(tmp_path)) == 1


def test_all_reasons_land_on_one_finding(tmp_path: Path) -> None:
    (tmp_path / "policy_server.py").write_text(
        "import websockets\n\n\nasync def h(c):\n    return c\n\n\n"
        "async def main():\n    return await websockets.serve(h, '0.0.0.0', 80, max_size=None)\n"
    )
    found = _websocket(tmp_path)
    assert len(found) == 1
    assert all(word in found[0].evidence for word in ("origins", "max_size", "every interface"))


def test_the_engine_runs_the_module(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "websocket" / "fires_no_origins.py", tmp_path / "mcp_server.py")
    result = run_scan(project_root=tmp_path, rules=[WEBSOCKET], strict_loading=True)
    assert [f.rule_id for f in result.findings] == [WEBSOCKET]
