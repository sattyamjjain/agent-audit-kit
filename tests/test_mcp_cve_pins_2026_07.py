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
    # 2026-07-15..17 wave
    "AAK-MCP-SDK-CVE-2026-52869-001": "high",
    "AAK-MCP-9ROUTER-CVE-2026-46339-001": "critical",
    "AAK-MCP-N8NMCP-CVE-2026-54052-001": "critical",
    "AAK-MCP-DBTMCP-CVE-2026-44968-001": "medium",
    "AAK-MCP-APIFY-CVE-2026-46341-001": "medium",
    "AAK-MCP-AGENTICFLOW-CVE-2026-58195-001": "high",
    "AAK-MCP-HEALTHOMICS-CVE-2026-15415-001": "medium",
    # 2026-07-19..20 wave
    "AAK-MCP-WHATSAPP-CVE-2026-46555-001": "high",
    "AAK-MCP-AGENTICMAIL-CVE-2026-57495-001": "high",
    # 2026-07-21 wave
    "AAK-MCP-STATA-CVE-2026-47708-001": "high",
    # 2026-07-22 wave
    "AAK-MCP-N8N-CVE-2026-65594-001": "high",
    # 2026-07-23..24 wave
    "AAK-MCP-AWSAPIMCP-CVE-2026-16584-001": "high",
    # 2026-07-29..30 wave
    "AAK-MCP-FLYTO-CVE-2026-67425-001": "high",
    # 2026-07-30..31 wave
    "AAK-MCP-LANGFLOW-CVE-2026-12940-001": "critical",
    # 2026-08-01 wave
    "AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001": "medium",
    # 2026-08-04 wave
    "AAK-MCP-AMAZONMQ-CVE-2026-18655-001": "medium",
    # 2026-08-05 wave
    "AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001": "medium",
    # 2026-08-06 wave
    "AAK-MCP-DOCUMENTDB-CVE-2026-18954-001": "medium",
    # 2026-08-12 wave
    "AAK-MCP-ATLASSIAN-CVE-2026-73498-001": "high",
    # 2026-08-13 wave
    "AAK-MCP-JSHOOK-CVE-2026-49856-001": "medium",
    "AAK-MCP-AUTHFETCH-CVE-2026-49857-001": "high",
    # 2026-08-14..15 wave
    "AAK-MCP-MEMSERVICE-CVE-2026-50027-001": "critical",
    "AAK-MCP-CORTEX-CVE-2026-49986-001": "high",
    "AAK-MCP-CKAN-CVE-2026-73846-001": "medium",
    "AAK-MCP-FRONTMCP-CVE-2026-67531-001": "high",
    # 2026-08-08 wave
    "AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001": "medium",
    "AAK-METAADS-CVE-2026-48039-001": "critical",
    # 2026-08-09 wave
    "AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001": "medium",
    # 2026-08-11 wave
    "AAK-MCP-GRAFANA-CVE-2026-19516-001": "critical",
    # 2026-08-11..12 wave
    "AAK-MCP-N8N-CVE-2026-72768-001": "medium",
    "AAK-MCP-CCTEMPLATES-CVE-2026-73222-001": "high",
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


def test_aws_api_mcp_in_affected_range_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"aws": {"command": "uvx", "args": ["awslabs.aws-api-mcp-server@1.3.46"]}}}'
    assert "AAK-MCP-AWSAPIMCP-CVE-2026-16584-001" in _ids(tmp_path, ".mcp.json", content)


def test_aws_api_mcp_patched_passes(tmp_path: Path) -> None:
    content = '{"mcpServers": {"aws": {"command": "uvx", "args": ["awslabs.aws-api-mcp-server@1.3.47"]}}}'
    assert "AAK-MCP-AWSAPIMCP-CVE-2026-16584-001" not in _ids(tmp_path, ".mcp.json", content)


def test_aws_api_mcp_before_introduced_passes(tmp_path: Path) -> None:
    # Affected range starts at 0.2.13; 0.2.12 predates it and must not fire.
    content = '{"mcpServers": {"aws": {"command": "uvx", "args": ["awslabs.aws-api-mcp-server@0.2.12"]}}}'
    assert "AAK-MCP-AWSAPIMCP-CVE-2026-16584-001" not in _ids(tmp_path, ".mcp.json", content)


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
    # Floor raised to 1.6.13 for CVE-2026-67333; 1.6.13 is the first clear release.
    content = '{"dependencies": {"better-auth": "1.6.13"}}'
    assert "AAK-MCP-BETTERAUTH-CVE-2026-53512-001" not in _ids(tmp_path, "package.json", content)


def test_betterauth_1612_fires_for_67333(tmp_path: Path) -> None:
    # 1.6.11/1.6.12 fixed the earlier flaws but are still exposed to CVE-2026-67333
    # (redirect_uri scheme not validated; fixed 1.6.13), so the raised floor fires.
    content = '{"dependencies": {"better-auth": "1.6.12"}}'
    assert "AAK-MCP-BETTERAUTH-CVE-2026-53512-001" in _ids(tmp_path, "package.json", content)


def test_betterauth_rule_cites_all_cves() -> None:
    rule = RULES["AAK-MCP-BETTERAUTH-CVE-2026-53512-001"]
    assert set(rule.cve_references) == {
        "CVE-2026-53512", "CVE-2026-53518", "CVE-2026-67333", "CVE-2026-67336",
    }


# --- 2026-07-15..17 wave -----------------------------------------------------


def test_mcp_sdk_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-SDK-CVE-2026-52869-001" in _ids(tmp_path, "requirements.txt", "mcp==1.25.0\n")


def test_mcp_sdk_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-SDK-CVE-2026-52869-001" not in _ids(tmp_path, "requirements.txt", "mcp==1.28.1\n")


def test_mcp_sdk_with_extras_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-SDK-CVE-2026-52869-001" in _ids(tmp_path, "requirements.txt", "mcp[cli]==1.26.0\n")


def test_mcp_sdk_does_not_false_positive_on_similar_names(tmp_path: Path) -> None:
    # fastmcp / mcp-text-editor / n8n-mcp / awslabs.*-mcp-server must NOT trip the bare `mcp` pin.
    content = (
        "fastmcp==2.1.0\n"
        "mcp-text-editor==1.2.0\n"
        "awslabs.healthlake-mcp-server==0.0.16\n"
    )
    assert "AAK-MCP-SDK-CVE-2026-52869-001" not in _ids(tmp_path, "requirements.txt", content)


def test_9router_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"9router": "0.4.30"}}'
    assert "AAK-MCP-9ROUTER-CVE-2026-46339-001" in _ids(tmp_path, "package.json", content)


def test_n8n_mcp_fires_but_n8n_pin_does_not(tmp_path: Path) -> None:
    # The distinct n8n-mcp package must fire its own pin, and must NOT trip the
    # unrelated n8n (workflow-engine) pin via substring matching.
    ids = _ids(tmp_path, "package.json", '{"dependencies": {"n8n-mcp": "2.57.0"}}')
    assert "AAK-MCP-N8NMCP-CVE-2026-54052-001" in ids
    assert "AAK-MCP-N8N-CVE-2026-59207-001" not in ids


def test_n8n_mcp_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"n8n-mcp": "2.57.4"}}'
    assert "AAK-MCP-N8NMCP-CVE-2026-54052-001" not in _ids(tmp_path, "package.json", content)


def test_n8n_workflow_engine_still_fires(tmp_path: Path) -> None:
    # The n8n boundary fix must not break the original n8n pin.
    content = '{"dependencies": {"n8n": "2.20.0"}}'
    assert "AAK-MCP-N8N-CVE-2026-59207-001" in _ids(tmp_path, "package.json", content)


def test_dbt_mcp_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-DBTMCP-CVE-2026-44968-001" in _ids(tmp_path, "requirements.txt", "dbt-mcp==1.16.0\n")


def test_apify_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"@apify/actors-mcp-server": "0.9.20"}}'
    assert "AAK-MCP-APIFY-CVE-2026-46341-001" in _ids(tmp_path, "package.json", content)


def test_agentic_flow_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"agentic-flow": "2.0.13"}}'
    assert "AAK-MCP-AGENTICFLOW-CVE-2026-58195-001" in _ids(tmp_path, "package.json", content)


def test_healthomics_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-HEALTHOMICS-CVE-2026-15415-001" in _ids(
        tmp_path, "requirements.txt", "awslabs.aws-healthomics-mcp-server==0.0.35\n"
    )


def test_openclaw_rule_cites_both_cves() -> None:
    rule = RULES["AAK-MCP-OPENCLAW-CVE-2026-62195-001"]
    assert set(rule.cve_references) == {"CVE-2026-62195", "CVE-2026-62208"}


def test_mcp_sdk_rule_cites_three_cves() -> None:
    rule = RULES["AAK-MCP-SDK-CVE-2026-52869-001"]
    assert set(rule.cve_references) == {"CVE-2026-52869", "CVE-2026-52870", "CVE-2026-59950"}


# --- Lockfiles resolve the actual version (no false-positive after a fix) ------


def test_uv_lock_patched_version_clears(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "litellm"\nversion = "1.93.0"\n', encoding="utf-8"
    )
    assert "AAK-MCP-LITELLM-CVE-2026-59822-001" not in {f.rule_id for f in scan(tmp_path)[0]}


def test_uv_lock_vulnerable_version_fires(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "litellm"\nversion = "1.83.0"\n', encoding="utf-8"
    )
    assert "AAK-MCP-LITELLM-CVE-2026-59822-001" in {f.rule_id for f in scan(tmp_path)[0]}


def test_package_lock_patched_clears(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"node_modules/better-auth": {"version": "1.7.0"}}}', encoding="utf-8"
    )
    assert "AAK-MCP-BETTERAUTH-CVE-2026-53512-001" not in {f.rule_id for f in scan(tmp_path)[0]}


def test_lockfile_absent_package_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n', encoding="utf-8"
    )
    assert not {f.rule_id for f in scan(tmp_path)[0]}


# ---------------------------------------------------------------------------
# 2026-07-19..20 wave
# ---------------------------------------------------------------------------


def test_whatsapp_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"whatsapp-mcp": "0.1.0"}}'
    assert "AAK-MCP-WHATSAPP-CVE-2026-46555-001" in _ids(tmp_path, "package.json", content)


def test_whatsapp_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"whatsapp-mcp": "0.2.1"}}'
    assert "AAK-MCP-WHATSAPP-CVE-2026-46555-001" not in _ids(tmp_path, "package.json", content)


def test_whatsapp_uv_lock_resolved_below_floor_fires(tmp_path: Path) -> None:
    lock = '[[package]]\nname = "whatsapp-mcp"\nversion = "0.1.5"\n'
    assert "AAK-MCP-WHATSAPP-CVE-2026-46555-001" in _ids(tmp_path, "uv.lock", lock)


def test_whatsapp_uv_lock_patched_clears(tmp_path: Path) -> None:
    lock = '[[package]]\nname = "whatsapp-mcp"\nversion = "0.2.1"\n'
    assert "AAK-MCP-WHATSAPP-CVE-2026-46555-001" not in _ids(tmp_path, "uv.lock", lock)


def test_agenticmail_core_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"@agenticmail/core": "0.9.0"}}'
    assert "AAK-MCP-AGENTICMAIL-CVE-2026-57495-001" in _ids(tmp_path, "package.json", content)


def test_agenticmail_claudecode_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"@agenticmail/claudecode": "0.2.38"}}'
    assert "AAK-MCP-AGENTICMAIL-CVE-2026-57495-001" in _ids(tmp_path, "package.json", content)


def test_agenticmail_each_package_patched_passes(tmp_path: Path) -> None:
    content = (
        '{"dependencies": {'
        '"@agenticmail/claudecode": "0.2.39",'
        '"@agenticmail/codex": "0.1.33",'
        '"@agenticmail/core": "0.9.43",'
        '"@agenticmail/openclaw": "0.5.71"}}'
    )
    assert "AAK-MCP-AGENTICMAIL-CVE-2026-57495-001" not in _ids(tmp_path, "package.json", content)


def test_agenticmail_pin_does_not_match_bare_openclaw(tmp_path: Path) -> None:
    # The bare `openclaw` package has its own pin; the AgenticMail pin must not
    # fire on it (distinct scoped @agenticmail/openclaw only).
    content = '{"dependencies": {"openclaw": "0.5.0"}}'
    assert "AAK-MCP-AGENTICMAIL-CVE-2026-57495-001" not in _ids(tmp_path, "package.json", content)


# ---------------------------------------------------------------------------
# 2026-07-21 wave
# ---------------------------------------------------------------------------


def test_stata_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-STATA-CVE-2026-47708-001" in _ids(
        tmp_path, "requirements.txt", "mcp-for-stata==1.17.0\n"
    )


def test_stata_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-STATA-CVE-2026-47708-001" not in _ids(
        tmp_path, "requirements.txt", "mcp-for-stata==1.17.3\n"
    )


def test_praisonai_pin_covers_incomplete_fix_cve(tmp_path: Path) -> None:
    """The PraisonAI pin (floor 4.6.78) also covers CVE-2026-47394 (path
    traversal fixed 4.6.40) — any affected version is < 4.6.78 and fires."""
    assert "CVE-2026-47394" in RULES["AAK-MCP-PRAISONAI-CVE-2026-61427-001"].cve_references
    assert "AAK-MCP-PRAISONAI-CVE-2026-61427-001" in _ids(
        tmp_path, "requirements.txt", "praisonai==4.6.30\n"
    )


# ---------------------------------------------------------------------------
# 2026-07-22 wave — n8n CVE-2026-65594 (two-branch fix, distinct from 59207)
# ---------------------------------------------------------------------------


def _n8n(tmp_path: Path, ver: str) -> set[str]:
    return _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "%s"}}' % ver)


def test_n8n_65594_mainline_range_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-N8N-CVE-2026-65594-001" in _n8n(tmp_path, "2.28.5")


def test_n8n_65594_before_introduced_passes(tmp_path: Path) -> None:
    # Affected only from 2.27.0; an earlier release predates the OAuth flow.
    assert "AAK-MCP-N8N-CVE-2026-65594-001" not in _n8n(tmp_path, "2.26.0")


def test_n8n_65594_mainline_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-N8N-CVE-2026-65594-001" not in _n8n(tmp_path, "2.29.8")


def test_n8n_65594_230_branch_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-N8N-CVE-2026-65594-001" in _n8n(tmp_path, "2.30.0")


def test_n8n_65594_230_branch_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-N8N-CVE-2026-65594-001" not in _n8n(tmp_path, "2.30.1")


# ---------------------------------------------------------------------------
# 2026-07-29..30 wave — flyto-core CVE-2026-67425 (provider-key exfil, <2.26.6)
# ---------------------------------------------------------------------------


def test_flyto_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-FLYTO-CVE-2026-67425-001" in _ids(
        tmp_path, "requirements.txt", "flyto-core==2.26.5\n"
    )


def test_flyto_patched_passes(tmp_path: Path) -> None:
    # All versions below 2.26.6 are affected; the fix floor clears.
    assert "AAK-MCP-FLYTO-CVE-2026-67425-001" not in _ids(
        tmp_path, "requirements.txt", "flyto-core==2.26.6\n"
    )


def test_flyto_unpinned_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-FLYTO-CVE-2026-67425-001" in _ids(
        tmp_path, "requirements.txt", "flyto-core\n"
    )


def test_flyto_uv_lock_resolved_below_floor_fires(tmp_path: Path) -> None:
    lock = '[[package]]\nname = "flyto-core"\nversion = "2.20.0"\n'
    assert "AAK-MCP-FLYTO-CVE-2026-67425-001" in _ids(tmp_path, "uv.lock", lock)


# ---------------------------------------------------------------------------
# 2026-07-30..31 wave — langflow CVE-2026-12940 (MCP stdio env-injection RCE)
# ---------------------------------------------------------------------------


def test_langflow_in_affected_range_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-LANGFLOW-CVE-2026-12940-001" in _ids(
        tmp_path, "requirements.txt", "langflow==1.10.1\n"
    )


def test_langflow_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-LANGFLOW-CVE-2026-12940-001" not in _ids(
        tmp_path, "requirements.txt", "langflow==1.11.0\n"
    )


def test_langflow_before_introduced_passes(tmp_path: Path) -> None:
    # Affected range starts at 1.0.0; a pre-MCP 0.x release predates the launcher.
    assert "AAK-MCP-LANGFLOW-CVE-2026-12940-001" not in _ids(
        tmp_path, "requirements.txt", "langflow==0.6.19\n"
    )


def test_langflow_unpinned_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-LANGFLOW-CVE-2026-12940-001" in _ids(
        tmp_path, "requirements.txt", "langflow\n"
    )


# ---------------------------------------------------------------------------
# 2026-08-01 wave — gemini-bridge CVE-2026-54785 (tool-arg path traversal)
# ---------------------------------------------------------------------------


def test_gemini_bridge_in_affected_range_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001" in _ids(
        tmp_path, "requirements.txt", "gemini-bridge==1.3.0\n"
    )


def test_gemini_bridge_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001" not in _ids(
        tmp_path, "requirements.txt", "gemini-bridge==1.3.1\n"
    )


def test_gemini_bridge_before_introduced_passes(tmp_path: Path) -> None:
    # Affected range starts at 1.0.0; the unrelated 0.1.x line must not fire.
    assert "AAK-MCP-GEMINIBRIDGE-CVE-2026-54785-001" not in _ids(
        tmp_path, "requirements.txt", "gemini-bridge==0.1.1\n"
    )


# --- 2026-08-04 wave — awslabs.amazon-mq-mcp-server CVE-2026-18655 -------------


def test_amazon_mq_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-AMAZONMQ-CVE-2026-18655-001" in _ids(
        tmp_path, "requirements.txt", "awslabs.amazon-mq-mcp-server==2.0.23\n"
    )


def test_amazon_mq_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-AMAZONMQ-CVE-2026-18655-001" not in _ids(
        tmp_path, "requirements.txt", "awslabs.amazon-mq-mcp-server==2.0.24\n"
    )


def test_amazon_mq_uvx_mcp_config_below_floor_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"mq": {"command": "uvx", "args": ["awslabs.amazon-mq-mcp-server@2.0.20"]}}}'
    assert "AAK-MCP-AMAZONMQ-CVE-2026-18655-001" in _ids(tmp_path, ".mcp.json", content)


# --- 2026-08-05 wave — @langchain/langgraph-checkpoint-mongodb CVE-2026-48121 --


def test_langgraph_mongo_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"@langchain/langgraph-checkpoint-mongodb": "1.3.0"}}'
    assert "AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001" in _ids(tmp_path, "package.json", content)


def test_langgraph_mongo_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"@langchain/langgraph-checkpoint-mongodb": "1.3.1"}}'
    assert "AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001" not in _ids(tmp_path, "package.json", content)


# --- 2026-08-06 wave — awslabs.documentdb-mcp-server / frontmcp -------------


def test_documentdb_below_floor_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"docdb": {"command": "uvx", "args": ["awslabs.documentdb-mcp-server@1.0.11"]}}}'
    assert "AAK-MCP-DOCUMENTDB-CVE-2026-18954-001" in _ids(tmp_path, ".mcp.json", content)


def test_documentdb_patched_passes(tmp_path: Path) -> None:
    content = '{"mcpServers": {"docdb": {"command": "uvx", "args": ["awslabs.documentdb-mcp-server@1.0.12"]}}}'
    assert "AAK-MCP-DOCUMENTDB-CVE-2026-18954-001" not in _ids(tmp_path, ".mcp.json", content)


def test_frontmcp_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"frontmcp": "1.5.6"}}'
    assert "AAK-MCP-FRONTMCP-CVE-2026-67531-001" in _ids(tmp_path, "package.json", content)


def test_frontmcp_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"frontmcp": "1.5.7"}}'
    assert "AAK-MCP-FRONTMCP-CVE-2026-67531-001" not in _ids(tmp_path, "package.json", content)


# --- 2026-08-08 wave — langgraph-checkpoint-postgres/sqlite / meta-ads-mcp ----


def test_langgraph_checkpoint_postgres_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001" in _ids(
        tmp_path, "requirements.txt", "langgraph-checkpoint-postgres==3.1.0\n"
    )


def test_langgraph_checkpoint_sqlite_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001" in _ids(
        tmp_path, "requirements.txt", "langgraph-checkpoint-sqlite==3.1.0\n"
    )


def test_langgraph_checkpoint_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-LANGGRAPH-CHECKPOINT-CVE-2026-71433-001" not in _ids(
        tmp_path, "requirements.txt", "langgraph-checkpoint-postgres==3.1.1\n"
    )


def test_metaads_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-METAADS-CVE-2026-48039-001" in _ids(
        tmp_path, "requirements.txt", "meta-ads-mcp==1.0.108\n"
    )


def test_metaads_patched_passes(tmp_path: Path) -> None:
    assert "AAK-METAADS-CVE-2026-48039-001" not in _ids(
        tmp_path, "requirements.txt", "meta-ads-mcp==1.0.109\n"
    )


# --- CVE-2026-19337: @adenot/mcp-google-search SSRF (presence-only, no fix yet) ---

_GS_RULE = "AAK-MCP-GOOGLESEARCH-CVE-2026-19337-001"


def test_googlesearch_scoped_latest_fires(tmp_path: Path) -> None:
    # No fixed release exists, so even the latest published version (0.3.1) fires.
    content = '{"dependencies": {"@adenot/mcp-google-search": "0.3.1"}}'
    assert _GS_RULE in _ids(tmp_path, "package.json", content)


def test_googlesearch_scoped_unpinned_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"gs": {"command": "npx", "args": ["@adenot/mcp-google-search"]}}}'
    assert _GS_RULE in _ids(tmp_path, ".mcp.json", content)


def test_googlesearch_unscoped_package_does_not_fire(tmp_path: Path) -> None:
    # The unscoped `mcp-google-search` (latest 1.0.0) is an unrelated package by a
    # different author and must not be flagged as the CVE artifact.
    content = '{"dependencies": {"mcp-google-search": "1.0.0"}}'
    assert _GS_RULE not in _ids(tmp_path, "package.json", content)


def test_googlesearch_fixtures_positive_and_negative() -> None:
    # WI2 fixtures: a vulnerable manifest fires, the negative (unscoped-only)
    # manifest does not. `aak scan` over tests/fixtures/ exercises these too.
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-19337-mcp-google-search"
    vuln = {f.rule_id for f in scan(base / "vulnerable")[0]}
    negative = {f.rule_id for f in scan(base / "negative")[0]}
    assert _GS_RULE in vuln
    assert _GS_RULE not in negative


# --- CVE-2026-19516: mcp-grafana SSRF via X-Grafana-URL destination ---

_GRAFANA_RULE = "AAK-MCP-GRAFANA-CVE-2026-19516-001"


def test_grafana_below_floor_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"grafana": {"command": "uvx", "args": ["mcp-grafana@1.0.0"]}}}'
    assert _GRAFANA_RULE in _ids(tmp_path, ".mcp.json", content)


def test_grafana_patched_passes(tmp_path: Path) -> None:
    content = '{"mcpServers": {"grafana": {"command": "uvx", "args": ["mcp-grafana@1.1.0"]}}}'
    assert _GRAFANA_RULE not in _ids(tmp_path, ".mcp.json", content)


def test_grafana_unpinned_fires(tmp_path: Path) -> None:
    assert _GRAFANA_RULE in _ids(tmp_path, "requirements.txt", "mcp-grafana\n")


def test_grafana_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-19516-mcp-grafana"
    vuln = {f.rule_id for f in scan(base / "vulnerable")[0]}
    patched = {f.rule_id for f in scan(base / "patched")[0]}
    assert _GRAFANA_RULE in vuln
    assert _GRAFANA_RULE not in patched


# --- 2026-08-11..12 wave — n8n MCP Client node SSRF bypass (CVE-2026-72768) ---

_N8N_72768 = "AAK-MCP-N8N-CVE-2026-72768-001"


def test_n8n_72768_below_floor_fires(tmp_path: Path) -> None:
    assert _N8N_72768 in _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "2.32.0"}}')


def test_n8n_72768_patched_passes(tmp_path: Path) -> None:
    assert _N8N_72768 not in _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "2.32.1"}}')


def test_n8n_72768_unpinned_fires(tmp_path: Path) -> None:
    assert _N8N_72768 in _ids(tmp_path, "requirements.txt", "n8n\n")


def test_n8n_72768_is_the_only_n8n_arm_at_2_32_0(tmp_path: Path) -> None:
    # 2.32.0 is above the 59207 (2.27.4) and 65594 (2.29.8 / 2.30.1) floors, so this
    # new arm is the sole n8n finding — proving it is a distinct pin, not a duplicate.
    ids = _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "2.32.0"}}')
    assert _N8N_72768 in ids
    assert "AAK-MCP-N8N-CVE-2026-59207-001" not in ids
    assert "AAK-MCP-N8N-CVE-2026-65594-001" not in ids


def test_n8n_72768_does_not_trip_on_n8n_mcp(tmp_path: Path) -> None:
    # The distinct `n8n-mcp` package must not fire the n8n workflow-engine pin.
    ids = _ids(tmp_path, "package.json", '{"dependencies": {"n8n-mcp": "2.57.4"}}')
    assert _N8N_72768 not in ids


def test_n8n_72768_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-72768-n8n"
    vuln = {f.rule_id for f in scan(base / "vulnerable")[0]}
    negative = {f.rule_id for f in scan(base / "negative")[0]}
    assert _N8N_72768 in vuln
    assert _N8N_72768 not in negative


# --- 2026-08-11..12 wave — claude-code-templates --studio RCE (CVE-2026-73222) ---

_CCTEMPLATES = "AAK-MCP-CCTEMPLATES-CVE-2026-73222-001"


def test_cctemplates_below_floor_fires(tmp_path: Path) -> None:
    # 1.29.2 is the last release before the 1.29.4 fix (no 1.29.3 was published).
    content = '{"dependencies": {"claude-code-templates": "1.29.2"}}'
    assert _CCTEMPLATES in _ids(tmp_path, "package.json", content)


def test_cctemplates_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"claude-code-templates": "1.29.4"}}'
    assert _CCTEMPLATES not in _ids(tmp_path, "package.json", content)


def test_cctemplates_unpinned_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"cct": {"command": "npx", "args": ["claude-code-templates"]}}}'
    assert _CCTEMPLATES in _ids(tmp_path, ".mcp.json", content)


def test_cctemplates_package_lock_patched_clears(tmp_path: Path) -> None:
    lock = '{"packages": {"node_modules/claude-code-templates": {"version": "1.29.4"}}}'
    assert _CCTEMPLATES not in _ids(tmp_path, "package-lock.json", lock)


def test_cctemplates_package_lock_vulnerable_fires(tmp_path: Path) -> None:
    lock = '{"packages": {"node_modules/claude-code-templates": {"version": "1.29.2"}}}'
    assert _CCTEMPLATES in _ids(tmp_path, "package-lock.json", lock)


def test_cctemplates_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-73222-claude-code-templates"
    vuln = {f.rule_id for f in scan(base / "vulnerable")[0]}
    negative = {f.rule_id for f in scan(base / "negative")[0]}
    assert _CCTEMPLATES in vuln
    assert _CCTEMPLATES not in negative


# --- 2026-08-12 wave — mcp-atlassian attachment path traversal (CVE-2026-73498) ---

_ATLASSIAN_73498 = "AAK-MCP-ATLASSIAN-CVE-2026-73498-001"


def test_atlassian_73498_below_floor_fires(tmp_path: Path) -> None:
    # 0.21.1 is the last release before the 0.22.0 fix.
    assert _ATLASSIAN_73498 in _ids(tmp_path, "requirements.txt", "mcp-atlassian==0.21.1\n")


def test_atlassian_73498_patched_passes(tmp_path: Path) -> None:
    assert _ATLASSIAN_73498 not in _ids(tmp_path, "requirements.txt", "mcp-atlassian==0.22.0\n")


def test_atlassian_73498_unpinned_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"atlassian": {"command": "uvx", "args": ["mcp-atlassian"]}}}'
    assert _ATLASSIAN_73498 in _ids(tmp_path, ".mcp.json", content)


def test_atlassian_73498_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-73498-mcp-atlassian"
    vuln = {f.rule_id for f in scan(base / "vulnerable")[0]}
    negative = {f.rule_id for f in scan(base / "negative")[0]}
    assert _ATLASSIAN_73498 in vuln
    assert _ATLASSIAN_73498 not in negative


# --- 2026-08-13 wave — jshook ICMP SSRF-policy bypass (CVE-2026-49856) ---

_JSHOOK = "AAK-MCP-JSHOOK-CVE-2026-49856-001"


def test_jshook_below_floor_fires(tmp_path: Path) -> None:
    # 0.3.1 is the only affected release per GHSA-c5r6-m4mr-8q5j.
    content = '{"dependencies": {"@jshookmcp/jshook": "0.3.1"}}'
    assert _JSHOOK in _ids(tmp_path, "package.json", content)


def test_jshook_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"@jshookmcp/jshook": "0.3.2"}}'
    assert _JSHOOK not in _ids(tmp_path, "package.json", content)


def test_jshook_later_release_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"@jshookmcp/jshook": "0.3.5"}}'
    assert _JSHOOK not in _ids(tmp_path, "package.json", content)


def test_jshook_unpinned_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"jshook": {"command": "npx", "args": ["@jshookmcp/jshook"]}}}'
    assert _JSHOOK in _ids(tmp_path, ".mcp.json", content)


def test_jshook_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-49856-jshook"
    vuln = {f.rule_id for f in scan(base / "vulnerable")[0]}
    negative = {f.rule_id for f in scan(base / "negative")[0]}
    assert _JSHOOK in vuln
    assert _JSHOOK not in negative


# --- 2026-08-13 wave — auth-fetch-mcp mapped-IPv6 loopback (CVE-2026-49857) ---

_AUTHFETCH = "AAK-MCP-AUTHFETCH-CVE-2026-49857-001"


def test_authfetch_3_0_1_fires_despite_nvd_prose(tmp_path: Path) -> None:
    """NVD prose calls 3.0.1 the fix; GHSA-pvrj-8cg3-j5f8 records it as affected.

    The floor is 3.0.2. Pinning to 3.0.1 on the strength of the prose would have
    left the mapped-IPv6 loopback bypass reachable, so this is the case that
    matters most.
    """
    content = '{"dependencies": {"auth-fetch-mcp": "3.0.1"}}'
    assert _AUTHFETCH in _ids(tmp_path, "package.json", content)


def test_authfetch_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"auth-fetch-mcp": "3.0.2"}}'
    assert _AUTHFETCH not in _ids(tmp_path, "package.json", content)


def test_authfetch_later_release_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"auth-fetch-mcp": "3.0.3"}}'
    assert _AUTHFETCH not in _ids(tmp_path, "package.json", content)


def test_authfetch_unpinned_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"fetch": {"command": "npx", "args": ["auth-fetch-mcp"]}}}'
    assert _AUTHFETCH in _ids(tmp_path, ".mcp.json", content)


def test_authfetch_package_lock_vulnerable_fires(tmp_path: Path) -> None:
    lock = '{"packages": {"node_modules/auth-fetch-mcp": {"version": "3.0.1"}}}'
    assert _AUTHFETCH in _ids(tmp_path, "package-lock.json", lock)


def test_authfetch_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-49857-auth-fetch-mcp"
    vuln = {f.rule_id for f in scan(base / "vulnerable")[0]}
    negative = {f.rule_id for f in scan(base / "negative")[0]}
    assert _AUTHFETCH in vuln
    assert _AUTHFETCH not in negative


# --- 2026-08-13 wave — Flowise stdio RCE (CVE-2026-73601), already covered ---


def test_flowise_73601_is_carried_by_the_existing_rule() -> None:
    """CVE-2026-73601 shares Flowise's 3.1.3 fix floor, which AAK-FLOWISE-001
    already enforces, so it is a reference addition rather than a new pin."""
    from agent_audit_kit.rules.builtin import RULES
    from agent_audit_kit.scanners.stdio_injection import _FLOWISE_PATCHED_VERSION

    assert _FLOWISE_PATCHED_VERSION == (3, 1, 3)
    assert "CVE-2026-73601" in RULES["AAK-FLOWISE-001"].cve_references


# --- 2026-08-14..15 wave ---------------------------------------------------

_MEMSERVICE = "AAK-MCP-MEMSERVICE-CVE-2026-50027-001"
_CORTEX = "AAK-MCP-CORTEX-CVE-2026-49986-001"
_CKAN = "AAK-MCP-CKAN-CVE-2026-73846-001"


def test_memservice_below_floor_fires(tmp_path: Path) -> None:
    assert _MEMSERVICE in _ids(tmp_path, "requirements.txt", "mcp-memory-service==10.67.0\n")


def test_memservice_patched_passes(tmp_path: Path) -> None:
    assert _MEMSERVICE not in _ids(tmp_path, "requirements.txt", "mcp-memory-service==10.67.1\n")


def test_memservice_later_line_passes(tmp_path: Path) -> None:
    assert _MEMSERVICE not in _ids(tmp_path, "requirements.txt", "mcp-memory-service==11.8.0\n")


def test_memservice_unpinned_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"mem": {"command": "uvx", "args": ["mcp-memory-service"]}}}'
    assert _MEMSERVICE in _ids(tmp_path, ".mcp.json", content)


def test_memservice_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-50027-mcp-memory-service"
    assert _MEMSERVICE in {f.rule_id for f in scan(base / "vulnerable")[0]}
    assert _MEMSERVICE not in {f.rule_id for f in scan(base / "negative")[0]}


def test_cortex_last_affected_release_fires(tmp_path: Path) -> None:
    """3.17.0 is the last affected release per GHSA-gvpp-v77h-5w8g."""
    assert _CORTEX in _ids(tmp_path, "requirements.txt", "neuro-cortex-memory==3.17.0\n")


def test_cortex_floor_is_3_18_not_the_3_17_1_in_nvd_prose(tmp_path: Path) -> None:
    """The NVD text says 3.17.1 fixes it. GHSA says <= 3.17.0 affected, 3.18.0 first
    patched — and 3.17.1 was never published to PyPI. Pinning on the prose would
    have set a floor at a version that does not exist."""
    assert _CORTEX not in _ids(tmp_path, "requirements.txt", "neuro-cortex-memory==3.18.0\n")
    assert _CORTEX in _ids(tmp_path, "requirements.txt", "neuro-cortex-memory==3.17.0\n")


def test_cortex_successor_distribution_is_above_the_floor(tmp_path: Path) -> None:
    """`hypermnesia-mcp` is the rename; its earliest release is 3.24.0, so it is
    always above the floor and needs no pin of its own."""
    assert _CORTEX not in _ids(tmp_path, "requirements.txt", "hypermnesia-mcp==3.24.0\n")


def test_cortex_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-49986-neuro-cortex"
    assert _CORTEX in {f.rule_id for f in scan(base / "vulnerable")[0]}
    assert _CORTEX not in {f.rule_id for f in scan(base / "negative")[0]}


def test_ckan_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"@aborruso/ckan-mcp-server": "0.4.111"}}'
    assert _CKAN in _ids(tmp_path, "package.json", content)


def test_ckan_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"@aborruso/ckan-mcp-server": "0.4.112"}}'
    assert _CKAN not in _ids(tmp_path, "package.json", content)


def test_ckan_later_release_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"@aborruso/ckan-mcp-server": "0.4.118"}}'
    assert _CKAN not in _ids(tmp_path, "package.json", content)


def test_ckan_one_pin_carries_all_three_cves() -> None:
    from agent_audit_kit.rules.builtin import RULES
    refs = set(RULES[_CKAN].cve_references)
    assert refs == {"CVE-2026-73846", "CVE-2026-73845", "CVE-2026-73844"}


def test_ckan_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-73846-ckan-mcp"
    assert _CKAN in {f.rule_id for f in scan(base / "vulnerable")[0]}
    assert _CKAN not in {f.rule_id for f in scan(base / "negative")[0]}
