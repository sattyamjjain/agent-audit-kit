"""Tests for AAK-MCP-HTTP-NOAUTH-SERVER-001 (2026 no-auth-transport class).

A repo that publishes an MCP server over HTTP/SSE with no inbound auth, bound
to 0.0.0.0 or serving wildcard CORS, exposes a mutation-capable token-backed
endpoint to the network. GitLab MCP (CVE-2026-44895), Nocturne Memory
(CVE-2026-44830), and AgenticMail (CVE-2026-50287) all shipped this shape.

Fixtures pin the contract: no-auth + 0.0.0.0 / wildcard-CORS FAILS; an
authenticated server PASSES; a 127.0.0.1-bound server PASSES; a stdio (no HTTP)
server PASSES; Azure-MCP repos defer to AAK-AZURE-MCP-NOAUTH-001.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_http_noauth_server import scan

RULE_ID = "AAK-MCP-HTTP-NOAUTH-SERVER-001"


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


def test_rule_is_registered() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-44895" in rule.cve_references
    assert "MCP07:2025" in rule.owasp_mcp_references


# --------------------------------------------------------------------------
# Vulnerable — must fire.
# --------------------------------------------------------------------------


def test_ts_sse_server_no_auth_0000_is_flagged(tmp_path: Path) -> None:
    """GitLab-MCP shape: SSE transport, wildcard CORS, listen on 0.0.0.0, no
    auth."""
    _write(tmp_path, "transport.ts", '''
import express from "express";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
const app = express();
app.use((_, res, next) => { res.setHeader("Access-Control-Allow-Origin", "*"); next(); });
app.get("/mcp", async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  await server.connect(transport);
});
httpServer.listen(3000, "0.0.0.0");
''')
    findings, scanned = scan(tmp_path)
    assert "transport.ts" in scanned
    assert _hits(findings), f"no-auth SSE server on 0.0.0.0 must fire {RULE_ID}"


def test_python_streamable_http_no_auth_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "server.py", '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("memory", host="0.0.0.0")

@mcp.custom_route("/mcp", methods=["POST"])
async def handle(request):
    return await dispatch(request)

mcp.run(transport="streamable-http")
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "no-auth streamable-http MCP server on 0.0.0.0 must fire"


def test_auth_bypass_when_token_unset_is_flagged(tmp_path: Path) -> None:
    """Nocturne shape: middleware bypasses auth when API_TOKEN is empty."""
    _write(tmp_path, "app.py", '''
import os
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("nocturne", host="0.0.0.0")
API_TOKEN = os.environ.get("API_TOKEN", "")

async def bearer_token_auth_middleware(request, call_next):
    if not API_TOKEN:        # bypass auth entirely when unset
        return await call_next(request)
    verify_jwt(request.headers.get("authorization"))
    return await call_next(request)

mcp.run(transport="sse")
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "auth-bypass-when-token-unset must fire"


# --------------------------------------------------------------------------
# Safe — must pass.
# --------------------------------------------------------------------------


def test_authenticated_server_passes(tmp_path: Path) -> None:
    _write(tmp_path, "server.ts", '''
import express from "express";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
const app = express();
app.get("/mcp", requireAuth(), async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  await server.connect(transport);
});
httpServer.listen(3000, "0.0.0.0");
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "an authenticated server must pass"


def test_localhost_bound_passes(tmp_path: Path) -> None:
    """Bound to 127.0.0.1 and no wildcard CORS -> not network-exposed."""
    _write(tmp_path, "server.py", '''
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x", host="127.0.0.1")
@mcp.custom_route("/mcp", methods=["POST"])
async def handle(request):
    return await dispatch(request)
mcp.run(transport="streamable-http")
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "127.0.0.1-bound server must pass"


def test_stdio_server_passes(tmp_path: Path) -> None:
    """A stdio MCP server (no HTTP transport) is out of scope."""
    _write(tmp_path, "stdio.py", '''
from mcp.server import Server
import mcp.server.stdio
server = Server("x")

@server.list_tools()
async def list_tools():
    return []
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "stdio server must not fire"


def test_azure_repo_defers_to_azure_rule(tmp_path: Path) -> None:
    """Azure-MCP repos are owned by AAK-AZURE-MCP-NOAUTH-001 — this rule
    defers to avoid a double finding."""
    (tmp_path / "package.json").write_text(
        '{"name": "azure-mcp-server", "keywords": ["azure-mcp-server"]}',
        encoding="utf-8",
    )
    _write(tmp_path, "server.ts", '''
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
app.get("/mcp", async (req, res) => { await server.connect(new SSEServerTransport("/m", res)); });
httpServer.listen(3000, "0.0.0.0");
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "Azure repo must defer to AAK-AZURE-MCP-NOAUTH-001"
