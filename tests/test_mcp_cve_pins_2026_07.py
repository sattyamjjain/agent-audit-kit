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
