"""CVE-2026-32211 — Azure MCP server consumed without authentication."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.supply_chain import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-32211"


def test_vulnerable_no_auth_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-no-auth")
    assert any(f.rule_id == "AAK-AZURE-MCP-001" for f in findings)


def test_patched_with_auth_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-with-auth")
    assert not any(f.rule_id == "AAK-AZURE-MCP-001" for f in findings)


def test_non_azure_endpoint_passes(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"local": {"command": "node", "args": ["server.js"]}}}',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-AZURE-MCP-001" for f in findings)


def test_azure_mtls_passes(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"az": {"url": "https://x.azurewebsites.net/mcp", '
        '"client_cert": "/etc/ssl/client.pem"}}}',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-AZURE-MCP-001" for f in findings)
