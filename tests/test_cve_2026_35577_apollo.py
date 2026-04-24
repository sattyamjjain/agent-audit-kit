"""CVE-2026-35577 — Apollo MCP Server DNS rebinding.

`@apollo/mcp-server` < 1.7.0 shipped a StreamableHTTP transport without
Host-header validation.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.dns_rebind import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "dns-rebind-sdk-class"


def test_apollo_vulnerable_pin_fires() -> None:
    findings, _ = scan(FIXTURES / "apollo-vulnerable")
    assert any(f.rule_id == "AAK-DNS-REBIND-002" for f in findings)


def test_apollo_patched_pin_passes() -> None:
    findings, _ = scan(FIXTURES / "apollo-patched")
    assert not any(f.rule_id == "AAK-DNS-REBIND-002" for f in findings)


def test_apollo_ts_sdk_vulnerable_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/sdk": "1.20.0"}}',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-DNS-REBIND-002" for f in findings)


def test_unrelated_package_passes(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "4.19.2"}}',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id.startswith("AAK-DNS-REBIND") for f in findings)
