"""Tests for AAK-MCP-TOOLGATE-ASYMMETRY-001 (CVE-2026-46519 class).

An MCP server that applies an allowlist / read-only / non-destructive gate in
the tools/list discovery handler but NOT in the tools/call execution handler
is broken-access-control: a direct call to a hidden tool bypasses the gate.
mcp-server-kubernetes < 3.6.0 enforced its three access-control env vars only
at the discovery layer (CWE-863, CVSS 8.8).

Fixtures pin the contract: gate-in-list-only FAILS (Python + TS); gate-in-both
PASSES; no MCP server / read-only-everywhere PASSES (false-positive guards).
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_toolgate_asymmetry import scan

RULE_ID = "AAK-MCP-TOOLGATE-ASYMMETRY-001"


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------


def test_rule_is_registered_with_cve_anchor() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-46519" in rule.cve_references
    assert "MCP06:2025" in rule.owasp_mcp_references


# ---------------------------------------------------------------------------
# Vulnerable — gate in list only — must FAIL the scan.
# ---------------------------------------------------------------------------


def test_python_gate_in_list_only_is_flagged(tmp_path: Path) -> None:
    """The CVE-2026-46519 shape: gate applied in list_tools, absent in
    call_tool."""
    _write(tmp_path, "server.py", '''
import os
from mcp.server import Server

server = Server("k8s")
ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS = os.environ.get("ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS")

@server.list_tools()
async def list_tools():
    tools = all_tools()
    if ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS:
        tools = [t for t in tools if not t.destructive]
    return tools

@server.call_tool()
async def call_tool(name, arguments):
    # BUG: no allowlist / non-destructive check here
    return dispatch(name, arguments)
''')
    findings, scanned = scan(tmp_path)
    assert "server.py" in scanned
    assert _hits(findings), f"gate-in-list-only must fire {RULE_ID}"


def test_typescript_gate_in_list_only_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "server.ts", '''
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "k8s", version: "1.0.0" });
const readOnly = process.env.READONLY === "true";

server.setRequestHandler(ListToolsRequestSchema, async () => {
  let tools = allTools();
  if (readOnly) tools = tools.filter((t) => !t.destructive);
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  // BUG: no readOnly check in the execution path
  return dispatch(req.params.name, req.params.arguments);
});
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "TS gate-in-list-only must fire"


# ---------------------------------------------------------------------------
# Correctly gated — check in both — must PASS.
# ---------------------------------------------------------------------------


def test_python_gate_in_both_passes(tmp_path: Path) -> None:
    _write(tmp_path, "server.py", '''
import os
from mcp.server import Server

server = Server("k8s")
ALLOWED_TOOLS = set(os.environ.get("ALLOWED_TOOLS", "").split(","))

@server.list_tools()
async def list_tools():
    return [t for t in all_tools() if t.name in ALLOWED_TOOLS]

@server.call_tool()
async def call_tool(name, arguments):
    if name not in ALLOWED_TOOLS:
        raise PermissionError(name)
    return dispatch(name, arguments)
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "gate enforced in BOTH handlers must pass"


def test_typescript_gate_in_both_passes(tmp_path: Path) -> None:
    _write(tmp_path, "server.ts", '''
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "k8s", version: "1.0.0" });
const readOnly = process.env.READONLY === "true";

server.setRequestHandler(ListToolsRequestSchema, async () => {
  let tools = allTools();
  if (readOnly) tools = tools.filter((t) => !t.destructive);
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (readOnly && isDestructive(req.params.name)) throw new Error("blocked");
  return dispatch(req.params.name, req.params.arguments);
});
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "TS gate enforced in BOTH must pass"


# ---------------------------------------------------------------------------
# False-positive guards.
# ---------------------------------------------------------------------------


def test_no_gate_anywhere_passes(tmp_path: Path) -> None:
    """A server with no access-control gate at all is out of scope for this
    rule (other rules cover missing-auth)."""
    _write(tmp_path, "server.py", '''
from mcp.server import Server
server = Server("x")

@server.list_tools()
async def list_tools():
    return all_tools()

@server.call_tool()
async def call_tool(name, arguments):
    return dispatch(name, arguments)
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "no gate present -> not this rule"


def test_no_call_handler_passes(tmp_path: Path) -> None:
    """Discovery-only file (no execution handler) cannot exhibit the
    asymmetry."""
    _write(tmp_path, "discovery.py", '''
import os
from mcp.server import Server
server = Server("x")
ALLOWED_TOOLS = os.environ.get("ALLOWED_TOOLS")

@server.list_tools()
async def list_tools():
    return [t for t in all_tools() if t.name in (ALLOWED_TOOLS or "")]
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "no call handler -> no asymmetry"


def test_non_mcp_file_passes(tmp_path: Path) -> None:
    """A plain module that happens to mention readonly is not an MCP server."""
    _write(tmp_path, "util.py", '''
READONLY = True
def list_tools():
    return []
def call_tool(n):
    return n
''')
    findings, _ = scan(tmp_path)
    # READONLY is module-level, not referenced inside the list_tools body,
    # so there is no discovery-side gate -> no asymmetry.
    assert not _hits(findings)
