"""Tests for AAK-MCP-KONG-CVE-2026-13341-001 (Kong Konnect MCP < 1.0.0).

CVE-2026-13341 (HIGH, CVSS 7.4, published 2026-07-03): the Kong Konnect MCP
server before 1.0.0 is vulnerable to indirect prompt injection — untrusted
content it relays can carry instructions the agent then acts on, issuing
unintended Konnect/Admin API requests. Fixed in 1.0.0.

Fixtures pin the contract: a config referencing the Konnect MCP server below
1.0.0 (or unpinned) FLAGS; a pinned >= 1.0.0 reference PASSES.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.supply_chain import _check_kong_konnect_mcp_pin

RULE_ID = "AAK-MCP-KONG-CVE-2026-13341-001"
_FIXTURES = Path(__file__).parent / "fixtures" / "kong_konnect"


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


def test_rule_registered_and_accurate() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-13341" in rule.cve_references
    # accurate threat class, not a generic "prompt injection" blurb
    assert "indirect prompt injection" in rule.description.lower()
    assert "api request" in rule.description.lower() or "api requests" in rule.description.lower()
    assert "MCP05:2025" in rule.owasp_mcp_references


def test_vulnerable_mcp_config_fixture_flags(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text((_FIXTURES / ".mcp.json").read_text(), encoding="utf-8")
    findings = _check_kong_konnect_mcp_pin(tmp_path, set())
    assert _hits(findings), "Konnect MCP @0.9.3 in .mcp.json must fire"


def test_unpinned_reference_flags(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({
        "mcpServers": {"kong": {"command": "npx", "args": ["@kong/konnect-mcp"]}}
    }), encoding="utf-8")
    findings = _check_kong_konnect_mcp_pin(tmp_path, set())
    assert _hits(findings), "unpinned Konnect MCP reference cannot be proven >= 1.0.0"


def test_requirements_old_version_flags(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("konnect-mcp-server==0.9.2\n", encoding="utf-8")
    findings = _check_kong_konnect_mcp_pin(tmp_path, set())
    assert _hits(findings)


def test_patched_version_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("konnect-mcp-server==1.0.1\n", encoding="utf-8")
    findings = _check_kong_konnect_mcp_pin(tmp_path, set())
    assert not _hits(findings), "Konnect MCP >= 1.0.0 is patched"


def test_unrelated_dependency_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nhttpx==0.27\n", encoding="utf-8")
    findings = _check_kong_konnect_mcp_pin(tmp_path, set())
    assert not _hits(findings)
