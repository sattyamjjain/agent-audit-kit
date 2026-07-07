"""Tests for AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001.

CVE-2026-14471 (HIGH, CVSS 8.1, published 2026-07-06): Amazon
`mcp-gateway-registry` before 1.0.13 interpolates a caller-supplied `table_name`
into an SQL identifier position in the metrics-service retention policy, allowing
an authenticated remote user to run arbitrary SQL. Fixed in 1.0.13.

The pin detector must flag a dependency below 1.0.13 (or unpinned) and stay quiet
at >= 1.0.13.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.supply_chain import _check_mcp_gateway_registry_pin

RULE_ID = "AAK-MCP-GATEWAY-REGISTRY-CVE-2026-14471-001"


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


def test_rule_registered_and_accurate() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-14471" in rule.cve_references
    assert "table_name" in rule.description
    assert "1.0.13" in rule.description
    assert "arbitrary SQL" in rule.description
    assert "MCP04:2025" in rule.owasp_mcp_references


def test_vulnerable_version_flags(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-gateway-registry==1.0.10\n", encoding="utf-8")
    assert _hits(_check_mcp_gateway_registry_pin(tmp_path, set()))


def test_unpinned_reference_flags(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["mcp-gateway-registry"]\n', encoding="utf-8"
    )
    assert _hits(_check_mcp_gateway_registry_pin(tmp_path, set()))


def test_patched_version_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-gateway-registry==1.0.13\n", encoding="utf-8")
    assert not _hits(_check_mcp_gateway_registry_pin(tmp_path, set()))


def test_later_version_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-gateway-registry>=1.1.0\n", encoding="utf-8")
    assert not _hits(_check_mcp_gateway_registry_pin(tmp_path, set()))


def test_unrelated_dependency_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nhttpx==0.27\n", encoding="utf-8")
    assert not _hits(_check_mcp_gateway_registry_pin(tmp_path, set()))
