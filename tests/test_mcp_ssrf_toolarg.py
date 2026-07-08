"""Tests for AAK-MCP-SSRF-001 (CVE-2026-14748, CWE-918).

An MCP tool handler that passes an attacker-controllable URL argument into an
outbound fetch without a host/scheme allow-list is a server-side request forgery:
the caller controls the destination, so the server fetches internal / loopback /
cloud-metadata endpoints on their behalf. AIAnytime Awesome-MCP-Server's
`mcp-wiki/wiki-summary` (CVE-2026-14748, CVSS 6.3) is the anchor.

The committed fixture pair pins the contract: `vulnerable_tool.py` (a `url`
parameter fetched with no guard) FLAGS; `safe_tool.py` (same tool, host + scheme
allow-list validated first) PASSES. Extra cases cover the TS/JS regex fallback
and the end-to-end engine wiring.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import ScanResult
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_ssrf_toolarg import scan

RULE_ID = "AAK-MCP-SSRF-001"
FIXTURES = Path(__file__).parent / "fixtures" / "mcp_ssrf"


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration / accuracy
# ---------------------------------------------------------------------------


def test_rule_is_registered_and_accurate() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    # NVD scores CVE-2026-14748 at CVSS 6.3 (MEDIUM); the rule matches that band
    # rather than inflating, consistent with the other CVE-pinned rules.
    assert rule.severity.value == "medium"
    assert "CVE-2026-14748" in rule.cve_references
    assert "CWE-918" in rule.description
    # NVD text is anchored verbatim.
    assert "manipulation of the argument url causes server-side request forgery" in rule.description
    # Cross-references the OWASP MCP Top-10 + Agentic Top-10 like the SSRF family.
    assert "MCP09:2025" in rule.owasp_mcp_references
    assert "ASI06" in rule.owasp_agentic_references


# ---------------------------------------------------------------------------
# Committed fixture pair — the core contract
# ---------------------------------------------------------------------------


def test_vulnerable_fixture_flags() -> None:
    findings, _ = scan(FIXTURES)
    hits = [f for f in _hits(findings) if f.file_path.endswith("vulnerable_tool.py")]
    assert hits, "vulnerable_tool.py (url -> requests.get, no allow-list) must fire"


def test_safe_fixture_passes() -> None:
    findings, _ = scan(FIXTURES)
    hits = [f for f in _hits(findings) if f.file_path.endswith("safe_tool.py")]
    assert not hits, "safe_tool.py (host + scheme allow-list) must NOT fire"


def test_fires_on_vulnerable_not_safe() -> None:
    findings, _ = scan(FIXTURES)
    flagged = {f.file_path for f in _hits(findings)}
    assert any(p.endswith("vulnerable_tool.py") for p in flagged)
    assert not any(p.endswith("safe_tool.py") for p in flagged)


# ---------------------------------------------------------------------------
# Python variants
# ---------------------------------------------------------------------------


def test_httpx_endpoint_param_flags(tmp_path: Path) -> None:
    _write(tmp_path, "srv.py", '''
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("proxy")

@mcp.tool()
async def relay(endpoint: str) -> str:
    async with httpx.AsyncClient() as client:
        r = await client.get(endpoint)
        return r.text
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "httpx client.get(endpoint) with no allow-list must fire"


def test_urlopen_target_param_flags(tmp_path: Path) -> None:
    _write(tmp_path, "srv.py", '''
from urllib.request import urlopen
from mcp.server import Server

server = Server("fetcher")

@server.tool()
def fetch(target: str) -> bytes:
    return urlopen(target).read()
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "urlopen(target) with no allow-list must fire"


def test_constant_url_passes(tmp_path: Path) -> None:
    _write(tmp_path, "srv.py", '''
import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("status")

@mcp.tool()
def health() -> str:
    return requests.get("https://status.internal/health").text
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "constant URL (no caller-controlled arg) must pass"


def test_non_mcp_file_passes(tmp_path: Path) -> None:
    _write(tmp_path, "util.py", '''
import requests

def fetch(url):
    return requests.get(url).text
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "no MCP tool context -> must not fire"


# ---------------------------------------------------------------------------
# TS / JS regex fallback
# ---------------------------------------------------------------------------


def test_typescript_tool_arg_fetch_flags(tmp_path: Path) -> None:
    _write(tmp_path, "tool.ts", '''
import { McpServer } from "@modelcontextprotocol/sdk";
const server = new McpServer({ name: "wiki" });
server.tool("wiki_summary", async ({ url }) => {
  const resp = await fetch(url);
  return await resp.text();
});
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "TS fetch(url) tool handler with no allow-list must fire"


def test_typescript_allowlisted_passes(tmp_path: Path) -> None:
    _write(tmp_path, "tool.ts", '''
import { McpServer } from "@modelcontextprotocol/sdk";
const ALLOWED_HOSTS = ["en.wikipedia.org"];
const server = new McpServer({ name: "wiki" });
server.tool("wiki_summary", async ({ url }) => {
  const u = new URL(url);
  if (!ALLOWED_HOSTS.includes(u.hostname)) throw new Error("host not allowed");
  const resp = await fetch(url);
  return await resp.text();
});
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "TS allow-listed fetch must pass"


# ---------------------------------------------------------------------------
# End-to-end (engine) + SARIF
# ---------------------------------------------------------------------------


def test_engine_run_scan_wires_the_rule() -> None:
    result = run_scan(FIXTURES)
    hits = [f for f in result.findings if f.rule_id == RULE_ID]
    assert any(f.file_path.endswith("vulnerable_tool.py") for f in hits), (
        "rule must fire through the real scanner registry"
    )


def test_sarif_carries_cve_and_severity() -> None:
    findings, _ = scan(FIXTURES)
    result = ScanResult()
    result.findings.extend(_hits(findings))
    assert result.findings
    sarif = json.loads(format_results(result))
    run = sarif["runs"][0]
    rule_obj = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == RULE_ID)
    assert float(rule_obj["properties"]["security-severity"]) >= 4.0
    assert "CVE-2026-14748" in rule_obj["properties"]["tags"]
