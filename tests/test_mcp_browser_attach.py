"""AAK-MCP-BROWSER-ATTACH-001: a browser-automation MCP server with the user's own browser in reach."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category, Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_browser_attach

BROWSER = mcp_browser_attach.RULE


def test_rule_is_registered() -> None:
    assert RULES[BROWSER].severity is Severity.MEDIUM
    assert RULES[BROWSER].category is Category.MCP_CONFIG
    assert RULES[BROWSER].limitations


def test_the_engine_runs_it(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"b": {"command": "x", "args": ["--remote-debugging-port=9222"]}}}))
    result = run_scan(project_root=tmp_path, rules=[BROWSER], strict_loading=True)
    assert [f.rule_id for f in result.findings] == [BROWSER]


# -- AAK-MCP-BROWSER-ATTACH-001 ----------------------------------------------------------------


def _browser(tmp_path: Path, server: dict[str, Any], name: str = "browser") -> list[Any]:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {name: server}}, indent=2))
    return [f for f in mcp_browser_attach.scan(tmp_path)[0] if f.rule_id == BROWSER]


LOCAL = "http://" + ".".join(("127", "0", "0", "1")) + ":9222"
PLAYWRIGHT = "@playwright/mcp"
DEVTOOLS = "chrome-devtools-mcp"


@pytest.mark.parametrize("args, expected", [
    ([PLAYWRIGHT, "--cdp-endpoint", LOCAL], "--cdp-endpoint"),
    ([PLAYWRIGHT, f"--cdp-endpoint={LOCAL}"], "--cdp-endpoint"),
    ([PLAYWRIGHT, "--cdp-endpoint", "9222"], "--cdp-endpoint"),
    ([DEVTOOLS, "--browserUrl", LOCAL], "--browserUrl"),
    ([DEVTOOLS, f"--browser-url={LOCAL}"], "--browser-url"),
    ([DEVTOOLS, "--wsEndpoint", "ws://localhost:9222/devtools/browser/x"], "--wsEndpoint"),
    ([DEVTOOLS, "--autoConnect"], "--autoConnect"),
    ([PLAYWRIGHT, "--extension"], "--extension"),
    ([PLAYWRIGHT, "--remote-debugging-port=9222"], "--remote-debugging-port"),
    ([PLAYWRIGHT, "--no-sandbox"], "--no-sandbox"),
    ([DEVTOOLS, "--chrome-arg=--no-sandbox"], "--no-sandbox"),
    ([PLAYWRIGHT, "--user-data-dir", "/Users/me/Library/Application Support/Google/Chrome"], "--user-data-dir"),
    ([DEVTOOLS, "--userDataDir=/home/me/.config/google-chrome"], "--userDataDir"),
    ([PLAYWRIGHT, "--user-data-dir", "C:\\Users\\me\\AppData\\Local\\Google\\Chrome\\User Data"], "--user-data-dir"),
    ([PLAYWRIGHT, "--cookies-from-browser", "chrome"], "--cookies-from-browser"),
    ([PLAYWRIGHT, "--storage-state", "my-cookies.json"], "--storage-state"),
])
def test_reaching_the_users_browser_fires(tmp_path: Path, args: list[str], expected: str) -> None:
    found = _browser(tmp_path, {"command": "npx", "args": args})
    assert len(found) == 1 and expected in found[0].evidence and found[0].line_number == 3


@pytest.mark.parametrize("env, expected", [
    ({"PLAYWRIGHT_MCP_CDP_ENDPOINT": LOCAL}, "CDP_ENDPOINT"),
    ({"BROWSER_CDP_URL": LOCAL}, "CDP_URL"),
    ({"PLAYWRIGHT_MCP_NO_SANDBOX": "1"}, "NO_SANDBOX"),
    ({"PLAYWRIGHT_MCP_USER_DATA_DIR": "/home/me/.config/chromium"}, "USER_DATA_DIR"),
])
def test_the_env_is_read_too(tmp_path: Path, env: dict[str, str], expected: str) -> None:
    found = _browser(tmp_path, {"command": "npx", "args": [PLAYWRIGHT], "env": env})
    assert len(found) == 1 and expected in found[0].evidence


@pytest.mark.parametrize("server", [
    {"command": "npx", "args": [PLAYWRIGHT]},
    {"command": "npx", "args": [PLAYWRIGHT, "--isolated"]},
    {"command": "npx", "args": [PLAYWRIGHT, "--headless"]},
    {"command": "npx", "args": [PLAYWRIGHT, "--cdp-endpoint", "wss://connect.browserbase.com/x"]},
    {"command": "npx", "args": [PLAYWRIGHT, "--user-data-dir", "/tmp/agent-profile"]},
    {"command": "npx", "args": [PLAYWRIGHT, "--storage-state", "state.json"]},
    {"command": "docker", "args": ["run", "mcp/playwright", "--no-sandbox"]},
    {"command": "npx", "args": [PLAYWRIGHT], "env": {"PLAYWRIGHT_MCP_NO_SANDBOX": "false"}},
    {"url": "https://mcp.example.com/sse"},
])
def test_a_browser_of_its_own_stays_quiet(tmp_path: Path, server: dict[str, Any]) -> None:
    assert _browser(tmp_path, server) == []


@pytest.mark.parametrize("args", [["server.js", "--no-sandbox"], ["server.js", "--extension"], ["--cookies", "x"]])
def test_a_flag_on_another_kind_of_server_stays_quiet(tmp_path: Path, args: list[str]) -> None:
    assert _browser(tmp_path, {"command": "node", "args": args}, "notes") == []


def test_all_reasons_land_on_one_finding(tmp_path: Path) -> None:
    found = _browser(tmp_path, {"command": "npx", "args": [PLAYWRIGHT, "--no-sandbox", "--extension"]})
    assert len(found) == 1 and "--no-sandbox" in found[0].evidence and "--extension" in found[0].evidence
