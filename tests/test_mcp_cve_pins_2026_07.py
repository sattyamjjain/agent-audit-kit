"""Tests for the 2026-07 MCP/agent CVE dependency-pin wave.

Eight version-pin rules for CVEs disclosed 2026-07-08..12 with a vendor fix and a
pinnable PyPI/npm artifact. Each pin fires below its fix floor (or unpinned) and
stays quiet at/above it. Package names + floors were verified against PyPI/npm.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import scan

PINS = {
    "AAK-MCP-LITELLM-CVE-2026-59822-001": "high",
    "AAK-MCP-CLINE-CVE-2026-59723-001": "high",
    "AAK-MCP-TEXTEDITOR-CVE-2026-15138-001": "medium",
    "AAK-MCP-N8N-CVE-2026-59207-001": "medium",
    "AAK-MCP-RUFLO-CVE-2026-59726-001": "critical",
    "AAK-MCP-DEEPSEEK-CVE-2026-55604-001": "high",
    "AAK-MCP-K8S-CVE-2026-61459-001": "critical",
    "AAK-MCP-ASTRBOT-CVE-2026-15501-001": "medium",
    # 2026-07-13..15 wave
    "AAK-MCP-HEALTHLAKE-CVE-2026-15643-001": "high",
    "AAK-MCP-PRAISONAI-CVE-2026-61427-001": "high",
    "AAK-MCP-APPIUM-CVE-2026-58500-001": "high",
    "AAK-MCP-PENPOT-CVE-2026-45805-001": "critical",
    "AAK-MCP-OPENCLAW-CVE-2026-62195-001": "high",
    "AAK-MCP-REPOMIX-CVE-2026-49988-001": "medium",
    "AAK-MCP-BETTERAUTH-CVE-2026-53512-001": "high",
}


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return {f.rule_id for f in scan(tmp_path)[0]}


def test_all_pin_rules_registered_and_accurate() -> None:
    for rid, sev in PINS.items():
        assert rid in RULES, rid
        rule = RULES[rid]
        assert rule.severity.value == sev, rid
        assert rule.category.value == "supply-chain", rid
        assert rule.cve_references, rid
        assert all(c.startswith("CVE-2026-") for c in rule.cve_references), rid


def test_litellm_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-LITELLM-CVE-2026-59822-001" in _ids(tmp_path, "requirements.txt", "litellm==1.83.0\n")


def test_litellm_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-LITELLM-CVE-2026-59822-001" not in _ids(tmp_path, "requirements.txt", "litellm==1.84.0\n")


def test_litellm_unpinned_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-LITELLM-CVE-2026-59822-001" in _ids(tmp_path, "requirements.txt", "litellm\n")


def test_cline_npm_caret_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"cline": "^3.0.20"}}'
    assert "AAK-MCP-CLINE-CVE-2026-59723-001" in _ids(tmp_path, "package.json", content)


def test_cline_npm_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"cline": "3.0.30"}}'
    assert "AAK-MCP-CLINE-CVE-2026-59723-001" not in _ids(tmp_path, "package.json", content)


def test_deepseek_in_affected_range_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"@arikusi/deepseek-mcp-server": "1.7.5"}}'
    assert "AAK-MCP-DEEPSEEK-CVE-2026-55604-001" in _ids(tmp_path, "package.json", content)


def test_deepseek_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"@arikusi/deepseek-mcp-server": "1.8.0"}}'
    assert "AAK-MCP-DEEPSEEK-CVE-2026-55604-001" not in _ids(tmp_path, "package.json", content)


def test_deepseek_before_introduced_passes(tmp_path: Path) -> None:
    # The flaw was introduced in 1.4.2; 1.3.0 predates it and must not fire.
    content = '{"dependencies": {"@arikusi/deepseek-mcp-server": "1.3.0"}}'
    assert "AAK-MCP-DEEPSEEK-CVE-2026-55604-001" not in _ids(tmp_path, "package.json", content)


def test_k8s_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"mcp-server-kubernetes": "3.8.0"}}'
    assert "AAK-MCP-K8S-CVE-2026-61459-001" in _ids(tmp_path, "package.json", content)


def test_ruflo_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"ruflo": "3.16.0"}}'
    assert "AAK-MCP-RUFLO-CVE-2026-59726-001" in _ids(tmp_path, "package.json", content)


def test_n8n_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"n8n": "2.29.0"}}'
    assert "AAK-MCP-N8N-CVE-2026-59207-001" not in _ids(tmp_path, "package.json", content)


def test_astrbot_affected_fires_and_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-ASTRBOT-CVE-2026-15501-001" in _ids(tmp_path, "requirements.txt", "astrbot==4.25.2\n")


def test_astrbot_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-ASTRBOT-CVE-2026-15501-001" not in _ids(tmp_path, "requirements.txt", "astrbot==4.26.0\n")


def test_texteditor_affected_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-TEXTEDITOR-CVE-2026-15138-001" in _ids(tmp_path, "requirements.txt", "mcp-text-editor==1.0.2\n")


def test_texteditor_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-TEXTEDITOR-CVE-2026-15138-001" not in _ids(tmp_path, "requirements.txt", "mcp-text-editor==1.2.0\n")


def test_unrelated_dependencies_pass(tmp_path: Path) -> None:
    assert not _ids(tmp_path, "requirements.txt", "requests==2.31.0\nflask==3.0\n")


# --- 2026-07-13..15 wave -----------------------------------------------------


def test_healthlake_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-HEALTHLAKE-CVE-2026-15643-001" in _ids(
        tmp_path, "requirements.txt", "awslabs.healthlake-mcp-server==0.0.13\n"
    )


def test_healthlake_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-HEALTHLAKE-CVE-2026-15643-001" not in _ids(
        tmp_path, "requirements.txt", "awslabs.healthlake-mcp-server==0.0.14\n"
    )


def test_praisonai_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-PRAISONAI-CVE-2026-61427-001" in _ids(
        tmp_path, "requirements.txt", "praisonai==4.6.77\n"
    )


def test_appium_mcp_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"appium-mcp": "1.85.9"}}'
    assert "AAK-MCP-APPIUM-CVE-2026-58500-001" in _ids(tmp_path, "package.json", content)


def test_penpot_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"@penpot/mcp": "2.14.9"}}'
    assert "AAK-MCP-PENPOT-CVE-2026-45805-001" in _ids(tmp_path, "package.json", content)


def test_penpot_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"@penpot/mcp": "2.15.0"}}'
    assert "AAK-MCP-PENPOT-CVE-2026-45805-001" not in _ids(tmp_path, "package.json", content)


def test_openclaw_calver_in_range_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"openclaw": "2026.5.25"}}'
    assert "AAK-MCP-OPENCLAW-CVE-2026-62195-001" in _ids(tmp_path, "package.json", content)


def test_openclaw_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"openclaw": "2026.6.6"}}'
    assert "AAK-MCP-OPENCLAW-CVE-2026-62195-001" not in _ids(tmp_path, "package.json", content)


def test_openclaw_before_introduced_passes(tmp_path: Path) -> None:
    # The flaw range starts at 2026.5.20; an earlier calendar release must not fire.
    content = '{"dependencies": {"openclaw": "2026.5.10"}}'
    assert "AAK-MCP-OPENCLAW-CVE-2026-62195-001" not in _ids(tmp_path, "package.json", content)


def test_repomix_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"repomix": "1.14.0"}}'
    assert "AAK-MCP-REPOMIX-CVE-2026-49988-001" in _ids(tmp_path, "package.json", content)


def test_betterauth_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"better-auth": "1.6.10"}}'
    assert "AAK-MCP-BETTERAUTH-CVE-2026-53512-001" in _ids(tmp_path, "package.json", content)


def test_betterauth_scoped_provider_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"@better-auth/oauth-provider": "1.6.0"}}'
    assert "AAK-MCP-BETTERAUTH-CVE-2026-53512-001" in _ids(tmp_path, "package.json", content)


def test_betterauth_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"better-auth": "1.6.11"}}'
    assert "AAK-MCP-BETTERAUTH-CVE-2026-53512-001" not in _ids(tmp_path, "package.json", content)


def test_betterauth_rule_cites_both_cves() -> None:
    rule = RULES["AAK-MCP-BETTERAUTH-CVE-2026-53512-001"]
    assert set(rule.cve_references) == {"CVE-2026-53512", "CVE-2026-53518"}
