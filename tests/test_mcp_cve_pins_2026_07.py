"""Tests for the 2026-07 MCP/agent CVE dependency-pin wave.

Eight version-pin rules for CVEs disclosed 2026-07-08..12 with a vendor fix and a
pinnable PyPI/npm artifact. Each pin fires below its fix floor (or unpinned) and
stays quiet at/above it. Package names + floors were verified against PyPI/npm.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import mcp_cve_pins_2026_07
from agent_audit_kit.scanners._versions import parse_range
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import (
    _PINS,
    _Pin,
    _fires,
    _spans_admit_affected,
    scan,
)

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
    "AAK-MCP-APIFY-CVE-2026-46341-001": "high",
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
    "AAK-MCP-LETTA-CVE-2025-51482-001": "high",
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
    "AAK-MCP-N8N-CVE-2026-72768-001": "high",
    "AAK-MCP-CCTEMPLATES-CVE-2026-73222-001": "high",
    # 2026-08-17 wave
    "AAK-MCP-FLORENCE2-CVE-2026-19984-001": "medium",
    "AAK-MCP-CODEWHALE-CVE-2026-75858-001": "high",
    "AAK-MCP-MARIMO-CVE-2026-75149-001": "high",
    "AAK-MCP-NEOMJS-CVE-2026-18482-001": "high",
    "AAK-MCP-LANGBOT-CVE-2026-54449-001": "high",
    # 2026-09-26 wave
    "AAK-MCP-REMOTE-CVE-2026-51994-001": "critical",
    "AAK-MCP-KIMICODE-CVE-2026-95660-001": "medium",
    # 2026-10-02 wave
    "AAK-MCP-PILLMWIKI-CVE-2026-102911-001": "critical",
    # 2026-10-03 wave
    "AAK-MCP-FASTMCPTELEGRAM-CVE-2026-55096-001": "high",
    # 2026-10-03 wave, second batch
    "AAK-MCP-OFFICEPPT-CVE-2025-71427-001": "medium",
    "AAK-MCP-PENPOT-CVE-2026-100868-001": "medium",
    "AAK-MCP-VOICEMODE-CVE-2026-79535-001": "medium",
    "AAK-MCP-SHARIQ-GITHUB-CVE-2026-102906-001": "medium",
    "AAK-MCP-OPENCLAW-CVE-2026-102807-001": "medium",
    # 2026-10-05 wave (#887-#896)
    "AAK-MCP-ZSCALER-CVE-2026-59563-001": "medium",
    "AAK-MCP-UTCP-CVE-2026-101057-001": "low",
    "AAK-MCP-TOOLBOX-CVE-2026-102242-001": "high",
    "AAK-MCP-NEXTJS-CVE-2026-94486-001": "low",
    "AAK-MCP-CLAUDECODE-CVE-2026-103012-001": "low",
    "AAK-MCP-LANGGRAPHSDK-CVE-2026-104873-001": "high",
    # 2026-10-07 batch (#911-#915)
    "AAK-MCP-TSSDK-CVE-2026-104850-001": "high",
    # 2026-10-08 batch (#916-#921)
    "AAK-MCP-PAYLOAD-CVE-2026-105806-001": "high",
    "AAK-MCP-LANGCHAIN-REDIS-CVE-2026-105799-001": "low",
    "AAK-MCP-LANGCHAIN-MONGO-CVE-2026-106119-001": "medium",
    # 2026-10-11 batch (#953-#959)
    "AAK-MCP-ARGOCD-CVE-2026-108585-001": "medium",
    "AAK-MCP-1MCP-CVE-2026-108586-001": "medium",
    # 2026-10-13 batch (#963, #973-#977)
    "AAK-MCP-ELVIX-CVE-2026-108542-001": "medium",
    # 2026-10-15 batch (#982-#986)
    "AAK-MCP-OBSIDIANTC-CVE-2026-77366-001": "critical",
    # 2026-10-15 second batch (#995-#999)
    "AAK-MCP-JUNIE-CVE-2026-111091-001": "high",
    # 2026-10-16 batch (#1001-#1005)
    "AAK-MCP-NETLICENSING-CVE-2026-54446-001": "critical",
    "AAK-MCP-SDK-CVE-2026-59951-001": "medium",
    "AAK-MCP-NETWORKAI-CVE-2026-109331-001": "high",
    "AAK-MCP-REMOTE-CVE-2026-108716-001": "medium",
    # 2026-10-16 second batch (records the watcher had not filed)
    "AAK-MCP-OPENCOMPUTERUSE-CVE-2026-108721-001": "medium",
    "AAK-MCP-ODOOMCP-CVE-2026-108861-001": "medium",
    "AAK-MCP-NETWORKAI-CVE-2026-109332-001": "low",
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
        # The table began as a 2026-07 wave and every CVE in it was CVE-2026-*.
        # It has since grown past that: the Letta chain includes CVE-2025-51482
        # and CVE-2025-6101, disclosed in 2025 but never covered here. Assert a
        # well-formed CVE id rather than a year, which was only ever incidental.
        assert all(re.fullmatch(r"CVE-\d{4}-\d{4,7}", c) for c in rule.cve_references), rid


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
    # 2.41.4 since CVE-2026-110852 raised the floor from 2.27.4 (2026-10-16).
    content = '{"dependencies": {"n8n": "2.41.4"}}'
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
    content = '{"dependencies": {"openclaw": "2026.7.1"}}'
    assert "AAK-MCP-OPENCLAW-CVE-2026-62195-001" not in _ids(tmp_path, "package.json", content)


def test_openclaw_between_the_two_fixes_fires(tmp_path: Path) -> None:
    """2026.6.6 fixed CVE-2026-62195, but CVE-2026-100585 (owner-only Claude
    permission replies over the MCP channel bridge) is fixed only in 2026.7.1.
    npm carries 2026.6.x patch releases up to 2026.6.35, all still exposed."""
    for version in ("2026.6.6", "2026.6.35"):
        content = '{"dependencies": {"openclaw": "%s"}}' % version
        assert "AAK-MCP-OPENCLAW-CVE-2026-62195-001" in _ids(tmp_path, "package.json", content), version


def test_openclaw_has_no_lower_bound(tmp_path: Path) -> None:
    # CVE-2026-62195 started at 2026.5.20, but GHSA-p5g8-m35v-7m82 (CVE-2026-100585)
    # is `< 2026.7.1` with no lower bound, so an earlier calendar release is exposed.
    content = '{"dependencies": {"openclaw": "2026.5.10"}}'
    assert "AAK-MCP-OPENCLAW-CVE-2026-62195-001" in _ids(tmp_path, "package.json", content)


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
    """1.28.1 fixed the session CVEs; CVE-2026-109527 moved the floor to 1.29.1."""
    assert "AAK-MCP-SDK-CVE-2026-52869-001" not in _ids(tmp_path, "requirements.txt", "mcp==1.29.1\n")
    assert "AAK-MCP-SDK-CVE-2026-52869-001" in _ids(tmp_path, "requirements.txt", "mcp==1.28.1\n")


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


def test_apify_between_old_and_new_floor_fires(tmp_path: Path) -> None:
    """CVE-2026-50143 moved this floor 0.9.21 -> 0.10.11.

    0.10.4 cleared the old floor and is still exposed, so this is the exact version
    band the floor move exists to catch. Without it the move is untested.
    """
    content = '{"dependencies": {"@apify/actors-mcp-server": "0.10.4"}}'
    assert "AAK-MCP-APIFY-CVE-2026-46341-001" in _ids(tmp_path, "package.json", content)


def test_apify_at_new_floor_is_quiet(tmp_path: Path) -> None:
    content = '{"dependencies": {"@apify/actors-mcp-server": "0.10.11"}}'
    assert "AAK-MCP-APIFY-CVE-2026-46341-001" not in _ids(tmp_path, "package.json", content)


def test_codewhale_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"codewhale": "0.8.50"}}'
    assert "AAK-MCP-CODEWHALE-CVE-2026-75858-001" in _ids(tmp_path, "package.json", content)


def test_codewhale_at_floor_is_quiet(tmp_path: Path) -> None:
    content = '{"dependencies": {"codewhale": "0.8.64"}}'
    assert "AAK-MCP-CODEWHALE-CVE-2026-75858-001" not in _ids(tmp_path, "package.json", content)


def test_codewhale_does_not_fire_on_the_cargo_only_twin(tmp_path: Path) -> None:
    """`codewhale-tui` is a crates.io package the pin detector does not read.

    It has the same defect, but no Cargo manifest is in _CANDIDATE_NAMES, so a finding
    here would be a claim the scanner cannot support from what it actually read.
    """
    content = '{"dependencies": {"codewhale-tui": "0.8.50"}}'
    assert "AAK-MCP-CODEWHALE-CVE-2026-75858-001" not in _ids(tmp_path, "package.json", content)


def test_deepseek_tui_pre_rename_name_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"deepseek-tui": "0.8.39"}}'
    assert "AAK-MCP-CODEWHALE-CVE-2026-75858-001" in _ids(tmp_path, "package.json", content)


def test_agentic_flow_below_floor_fires(tmp_path: Path) -> None:
    content = '{"dependencies": {"agentic-flow": "2.0.13"}}'
    assert "AAK-MCP-AGENTICFLOW-CVE-2026-58195-001" in _ids(tmp_path, "package.json", content)


def test_healthomics_below_floor_fires(tmp_path: Path) -> None:
    assert "AAK-MCP-HEALTHOMICS-CVE-2026-15415-001" in _ids(
        tmp_path, "requirements.txt", "awslabs.aws-healthomics-mcp-server==0.0.35\n"
    )


def test_openclaw_rule_cites_all_five_cves() -> None:
    # CVE-2026-100585 (#809) joined the pin that already carried the first two
    # and raised its floor to 2026.7.1. CVE-2026-100587 (#839) and CVE-2026-100596
    # (#840) are both `< 2026.7.1` per their GHSAs, so they join at that floor.
    rule = RULES["AAK-MCP-OPENCLAW-CVE-2026-62195-001"]
    assert set(rule.cve_references) == {
        "CVE-2026-62195", "CVE-2026-62208", "CVE-2026-100585",
        "CVE-2026-100587", "CVE-2026-100596",
    }


def test_openclaw_below_the_floor_lists_the_two_new_cves(tmp_path: Path) -> None:
    """2026.6.30 is exposed to the Codex computer-use install command (#839) and
    to `/mcp set` persisting a stdio command (#840); 2026.7.1 fixes both."""
    content = '{"dependencies": {"openclaw": "%s"}}'
    (tmp_path / "package.json").write_text(content % "2026.6.30", encoding="utf-8")
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == "AAK-MCP-OPENCLAW-CVE-2026-62195-001"]
    assert len(hits) == 1
    assert {"CVE-2026-100587", "CVE-2026-100596"} <= set(hits[0].cve_references)
    assert "CVE-2026-100587" in hits[0].evidence and "CVE-2026-100596" in hits[0].evidence
    assert "AAK-MCP-OPENCLAW-CVE-2026-62195-001" not in _ids(
        tmp_path, "package.json", content % "2026.7.1"
    )


def test_mcp_sdk_rule_cites_four_cves() -> None:
    rule = RULES["AAK-MCP-SDK-CVE-2026-52869-001"]
    assert set(rule.cve_references) == {
        "CVE-2026-52869", "CVE-2026-52870", "CVE-2026-59950", "CVE-2026-109527",
    }


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
        tmp_path, "requirements.txt", "stata-mcp==1.17.0\n"
    )


def test_stata_pin_uses_the_real_pypi_name(tmp_path: Path) -> None:
    """The pin shipped against `mcp-for-stata`, which is a 404 on PyPI.

    The GHSA titles say "MCP-for-Stata" because that is the project name; the
    distribution is `stata-mcp`. A pin on the project name never matched a
    manifest, so this rule had not fired on a real repo since it landed.
    """
    assert "AAK-MCP-STATA-CVE-2026-47708-001" not in _ids(
        tmp_path, "requirements.txt", "mcp-for-stata==1.17.0\n"
    )


def test_stata_floor_covers_the_second_cve(tmp_path: Path) -> None:
    """CVE-2026-55071 (`ado_package_install`) is fixed in 1.19.0, not 1.17.3.

    1.18.x clears the old floor and is still vulnerable to the newer one.
    """
    assert "AAK-MCP-STATA-CVE-2026-47708-001" in _ids(
        tmp_path, "requirements.txt", "stata-mcp==1.18.2\n"
    )


def test_stata_patched_passes(tmp_path: Path) -> None:
    assert "AAK-MCP-STATA-CVE-2026-47708-001" not in _ids(
        tmp_path, "requirements.txt", "stata-mcp==1.19.0\n"
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


# One row since 2026-10-16: the mainline range, and 2.30.0 as an `also` range. The
# two rows it replaced, one per fix line, reported an unversioned n8n twice. These
# tests hold the one row to exactly what the pair reported: version by version,
# range by range, and on every n8n fixture.
_N8N_OAUTH = "AAK-MCP-N8N-CVE-2026-65594-001"
_LEGACY_N8N_OAUTH = (
    _Pin(_N8N_OAUTH, "n8n", ("n8n",), (2, 29, 8), introduced=(2, 27, 0), fix_label="2.29.8"),
    _Pin(_N8N_OAUTH, "n8n", ("n8n",), (2, 30, 1), introduced=(2, 30, 0), fix_label="2.30.1"),
)


def _n8n_oauth_row() -> _Pin:
    [row] = [p for p in _PINS if p.rule_id == _N8N_OAUTH]
    return row


def _legacy_table() -> tuple[_Pin, ...]:
    """The pin table with the one row swapped back for the two it replaced."""
    rows: list[_Pin] = []
    for pin in _PINS:
        rows.extend(_LEGACY_N8N_OAUTH if pin.rule_id == _N8N_OAUTH else (pin,))
    return tuple(rows)


def test_n8n_65594_is_one_row() -> None:
    row = _n8n_oauth_row()
    assert (row.introduced, row.floor, row.also) == (
        (2, 27, 0), (2, 29, 8), (((2, 30, 0), (2, 30, 1)),)
    )


@pytest.mark.parametrize(("name", "content"), [
    ("requirements.txt", "n8n\n"),
    ("package.json", '{"dependencies": {"n8n": "latest"}}'),
    (".mcp.json", '{"mcpServers": {"n8n": {"command": "npx", "args": ["-y", "n8n"]}}}'),
])
def test_an_unversioned_n8n_reports_65594_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, content: str
) -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")

    def reported() -> int:
        return [f.rule_id for f in scan(tmp_path)[0]].count(_N8N_OAUTH)

    assert reported() == 1
    monkeypatch.setattr(mcp_cve_pins_2026_07, "_PINS", _legacy_table())
    assert reported() == 2, "the two rows this replaced each reported it"


def test_the_one_row_fires_on_every_version_the_two_rows_did() -> None:
    """Patches 0 to 15 of every minor from 2.0 to 2.44, a spread of 1.x, and no version."""
    row = _n8n_oauth_row()
    versions = [(1, minor, patch) for minor in (0, 88, 122, 123) for patch in range(0, 90, 7)]
    versions += [(2, minor, patch) for minor in range(0, 45) for patch in range(0, 16)]
    fired = 0
    for version in [*versions, None]:
        before = any(_fires(pin, version) for pin in _LEGACY_N8N_OAUTH)
        assert _fires(row, version) is before, version
        fired += before
    assert fired == 16 + 16 + 8 + 1 + 1  # 2.27.x, 2.28.x, 2.29.0-2.29.7, 2.30.0, no version


@pytest.mark.parametrize(("dialect", "spec"), [
    ("npm", "^2.29.8"), ("npm", "~2.29.8"), ("npm", "^2.30.1"), ("npm", "~2.30.0"),
    ("npm", "^2.27.0"), ("npm", "~2.26.0"), ("npm", ">=2.29.8 <2.30.0"), ("npm", ">=2.29.8"),
    ("npm", "2.30.x"), ("npm", "2.30.0"), ("npm", "<2.27.0"), ("npm", ">=2.30.1"),
    ("npm", "2.29.x || 2.31.x"), ("npm", "^1.123.0"), ("npm", "*"), ("npm", "latest"),
    ("pep440", "==2.30.0"), ("pep440", ">=2.29.8,<2.30"), ("pep440", "~=2.29.0"),
    ("pep440", ">=2.30.1"), ("pep440", "<2.27"), ("poetry", "^2.29"),
])
def test_the_one_row_admits_every_range_the_two_rows_did(dialect: str, spec: str) -> None:
    spans = parse_range(spec, dialect)
    before = any(_spans_admit_affected(pin, spans) for pin in _LEGACY_N8N_OAUTH)
    assert _spans_admit_affected(_n8n_oauth_row(), spans) is before


def test_every_n8n_fixture_reports_65594_where_the_two_rows_did(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run over every n8n fixture project with the one row and with the two rows. The
    same files report the rule, and no file reports it twice any more. The
    cve-2026-65594-n8n fixtures are negative only for this rule: the other n8n pins
    still report those versions."""
    fixtures = Path(__file__).resolve().parent / "fixtures"
    projects = sorted(
        project
        for base in (fixtures / "cves", fixtures / "limitations")
        for case in base.iterdir() if case.is_dir() and "n8n" in case.name.lower()
        for project in case.iterdir() if project.is_dir()
    )

    def reporting(root: Path) -> list[str]:
        return sorted(f.file_path for f in scan(root)[0] if f.rule_id == _N8N_OAUTH)

    after = {project: reporting(project) for project in projects}
    monkeypatch.setattr(mcp_cve_pins_2026_07, "_PINS", _legacy_table())
    before = {project: reporting(project) for project in projects}
    for project in projects:
        assert sorted(set(after[project])) == sorted(set(before[project])), project
        assert len(after[project]) == len(set(after[project])), project
    reported = {p.relative_to(fixtures).as_posix() for p in projects if after[p]}
    assert reported == {
        "cves/cve-2026-65594-n8n/branch-lockfile",
        "cves/cve-2026-65594-n8n/branch-range",
        "cves/cve-2026-65594-n8n/mainline",
        "cves/cve-2026-65594-n8n/unversioned",
        "limitations/AAK-MCP-N8N-CVE-2026-59207-001/positive",   # n8n 2.27.3
        "limitations/AAK-MCP-N8N-CVE-2026-65594-001/positive",   # n8n 2.28.0
    }
    assert before[fixtures / "cves" / "cve-2026-65594-n8n" / "unversioned"] == [
        "requirements.txt", "requirements.txt",
    ]


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
    # Floor moved 1.11.0 -> 1.11.3 on 2026-09-08 for CVE-2026-9186 (affects
    # 1.0.0-1.11.2), then 1.11.3 -> 1.11.6 on 2026-09-12 for CVE-2026-85025,
    # CVE-2026-78575 and CVE-2026-81941 (all scoped 1.0.0-1.11.5), then 1.11.6 ->
    # 1.12.0 on 2026-10-05 for CVE-2026-101861 (eval() on Tool-Mode input options,
    # 1.0.16-1.11.6). The version in this assertion moves each time rather than the
    # test being deleted, because "the patched release does not fire" is still the
    # property worth holding. The versions the old floors called patched are
    # asserted to fire in tests/test_cve_deferral_queue_2026_09_08.py.
    assert "AAK-MCP-LANGFLOW-CVE-2026-12940-001" not in _ids(
        tmp_path, "requirements.txt", "langflow==1.12.0\n"
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
    # Floor moved 1.0.109 -> 1.0.115 on 2026-09-19 for CVE-2026-54549
    # (upload_ad_image SSRF). 1.0.109 is no longer patched.
    assert "AAK-METAADS-CVE-2026-48039-001" not in _ids(
        tmp_path, "requirements.txt", "meta-ads-mcp==1.0.115\n"
    )


def test_metaads_gap_between_the_old_and_new_floor_now_fires(tmp_path: Path) -> None:
    """1.0.109 satisfied the old floor and was still vulnerable to
    CVE-2026-54549. This is the interval a cve_references line cannot cover."""
    for version in ("1.0.109", "1.0.114"):
        assert "AAK-METAADS-CVE-2026-48039-001" in _ids(
            tmp_path, "requirements.txt", f"meta-ads-mcp=={version}\n"
        ), version


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
    """2.41.4, not 2.35.4, not 2.34.1, and not 2.32.1.

    This floor has moved three times. CVE-2026-77068 / CVE-2026-77073 took it to
    2.34.1; CVE-2026-85166 took it to 2.35.4; CVE-2026-110842 took it to 2.41.4.
    Every earlier "fixed" version is now a positive case, which is the point of
    keeping them below rather than deleting them: a project that upgraded once and
    stopped is the population this pin is for.
    """
    assert _N8N_72768 not in _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "2.41.4"}}')
    assert _N8N_72768 in _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "2.35.4"}}')


def test_n8n_72768_prior_floor_is_now_exposed(tmp_path: Path) -> None:
    """2.34.1 cleared this pin until 2026-09-04 and no longer does."""
    assert _N8N_72768 in _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "2.34.1"}}')


def test_n8n_72768_old_fix_version_is_still_exposed(tmp_path: Path) -> None:
    """The regression the floor move exists to catch.

    A project that upgraded to 2.32.1 for CVE-2026-72768 and stopped there is still
    exposed to CVE-2026-77068. If this stops firing, the floor moved back down.
    """
    assert _N8N_72768 in _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "2.32.1"}}')


def test_n8n_72768_unpinned_fires(tmp_path: Path) -> None:
    assert _N8N_72768 in _ids(tmp_path, "requirements.txt", "n8n\n")


def test_n8n_72768_and_59207_are_distinct_pins_at_2_32_0(tmp_path: Path) -> None:
    # 2.32.0 is above the 65594 (2.29.8 / 2.30.1) floors. Until 2026-10-16 it was
    # above the 59207 floor (2.27.4) too, and this pin was the sole n8n finding; since
    # CVE-2026-110852 raised that floor to 2.41.4 both report it, each for its own
    # CVEs and at its own severity.
    ids = _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "2.32.0"}}')
    assert _N8N_72768 in ids
    assert "AAK-MCP-N8N-CVE-2026-59207-001" in ids
    assert "AAK-MCP-N8N-CVE-2026-65594-001" not in ids
    assert RULES[_N8N_72768].severity.value == "high"
    assert RULES["AAK-MCP-N8N-CVE-2026-59207-001"].severity.value == "medium"


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


def test_atlassian_73498_records_the_later_022_advisories() -> None:
    """#822, #823, #825, #830: four more advisories "fixed in version 0.22.0", this
    pin's floor, so they are recorded here rather than pinned again."""
    from agent_audit_kit.rules.builtin import get_rule

    refs = set(get_rule(_ATLASSIAN_73498).cve_references)
    assert {"CVE-2026-77250", "CVE-2026-77265", "CVE-2026-77268", "CVE-2026-77272"} <= refs


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


def test_ckan_below_the_dns_resolution_fix_fires(tmp_path: Path) -> None:
    """CVE-2026-61612 (#824), the third `validateServerUrl` bypass, was fixed in
    0.4.108, below this pin's 0.4.112 floor, so the pin already reports it."""
    from agent_audit_kit.rules.builtin import get_rule

    content = '{"dependencies": {"@aborruso/ckan-mcp-server": "0.4.107"}}'
    assert _CKAN in _ids(tmp_path, "package.json", content)
    assert "CVE-2026-61612" in get_rule(_CKAN).cve_references


def test_ckan_patched_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"@aborruso/ckan-mcp-server": "0.4.112"}}'
    assert _CKAN not in _ids(tmp_path, "package.json", content)


def test_ckan_later_release_passes(tmp_path: Path) -> None:
    content = '{"dependencies": {"@aborruso/ckan-mcp-server": "0.4.118"}}'
    assert _CKAN not in _ids(tmp_path, "package.json", content)


def test_ckan_one_pin_carries_every_cve_its_floor_covers() -> None:
    """One pin, five CVEs, and the last two arrived free.

    Three came from the 2026-08-15 batch, which shared a package and a fix
    version. CVE-2026-53509 (2026-08-22) is fixed in 0.4.106 and CVE-2026-61612
    (2026-09-21) in 0.4.108, both below this pin's 0.4.112 floor, so each was
    already being reported before it was published -- recorded here rather than
    given a second pin that would report one dependency twice.
    """
    from agent_audit_kit.rules.builtin import RULES
    refs = set(RULES[_CKAN].cve_references)
    assert refs == {
        "CVE-2026-73846", "CVE-2026-73845", "CVE-2026-73844", "CVE-2026-53509",
        "CVE-2026-61612",
    }


def test_ckan_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-73846-ckan-mcp"
    assert _CKAN in {f.rule_id for f in scan(base / "vulnerable")[0]}
    assert _CKAN not in {f.rule_id for f in scan(base / "negative")[0]}


# --- Letta (MemGPT) CVE chain — closes the pin arm of #161 ------------------

_LETTA = "AAK-MCP-LETTA-CVE-2025-51482-001"


def test_letta_highest_affected_version_fires(tmp_path: Path) -> None:
    """0.16.4 is the newest version NVD names as affected."""
    assert _LETTA in _ids(tmp_path, "requirements.txt", "letta==0.16.4\n")


def test_letta_older_affected_versions_fire(tmp_path: Path) -> None:
    for v in ("0.4.1", "0.7.12", "0.16.0"):
        assert _LETTA in _ids(tmp_path, "requirements.txt", f"letta=={v}\n"), v


def test_letta_floor_clears(tmp_path: Path) -> None:
    """0.16.5 is the first release past every affected version."""
    assert _LETTA not in _ids(tmp_path, "requirements.txt", "letta==0.16.5\n")


def test_letta_latest_clears(tmp_path: Path) -> None:
    assert _LETTA not in _ids(tmp_path, "requirements.txt", "letta==0.16.8\n")


def test_letta_unpinned_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"letta": {"command": "uvx", "args": ["letta"]}}}'
    assert _LETTA in _ids(tmp_path, ".mcp.json", content)


def test_letta_client_sdk_is_not_the_server(tmp_path: Path) -> None:
    """`letta-client` is a separate client SDK on its own version line.

    The vulnerable code lives in the server's `letta/...` module paths. Pinning
    the client would fire on consumers of a package that does not contain it.
    """
    assert _LETTA not in _ids(tmp_path, "requirements.txt", "letta-client==1.0.0\n")


def test_letta_carries_all_four_cves() -> None:
    from agent_audit_kit.rules.builtin import RULES
    assert set(RULES[_LETTA].cve_references) == {
        "CVE-2025-51482", "CVE-2026-4964", "CVE-2026-4965", "CVE-2025-6101",
    }


def test_letta_remediation_does_not_claim_a_vendor_fix() -> None:
    """No vendor fix exists for any of the four; the rule must not imply one."""
    from agent_audit_kit.rules.builtin import RULES
    text = RULES[_LETTA].description
    assert "not a vendor fix statement" in text or "inference from release ordering" in text


def test_letta_fixtures_positive_and_negative() -> None:
    base = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2025-51482-letta"
    assert _LETTA in {f.rule_id for f in scan(base / "vulnerable")[0]}
    assert _LETTA not in {f.rule_id for f in scan(base / "negative")[0]}


# --- CVE-2026-19984: mcp-florence2 get_images SSRF (presence-only, no fix planned) ---

_FLORENCE2_RULE = "AAK-MCP-FLORENCE2-CVE-2026-19984-001"
_FLORENCE2_FIXTURES = (
    Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-19984-mcp-florence2"
)


def test_florence2_latest_published_version_fires(tmp_path: Path) -> None:
    """0.3.13 is the newest release, not a safe one — upstream ships no code fix."""
    assert _FLORENCE2_RULE in _ids(tmp_path, "requirements.txt", "mcp-florence2==0.3.13\n")


def test_florence2_unpinned_uvx_config_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"f2": {"command": "uvx", "args": ["mcp-florence2"]}}}'
    assert _FLORENCE2_RULE in _ids(tmp_path, ".mcp.json", content)


def test_florence2_hypothetical_newer_version_still_fires(tmp_path: Path) -> None:
    """The pin must not be silently satisfied by an upgrade.

    The vendor's stated mitigation is an SSRF-safe egress proxy, explicitly "without
    requiring changes to the mcp-florence2 source code". A version floor would tell
    users an upgrade clears this, which it does not — so presence-only is the
    permanent shape here, and a future release must still fire.
    """
    assert _FLORENCE2_RULE in _ids(tmp_path, "requirements.txt", "mcp-florence2==9.9.9\n")


def test_florence2_bare_florence2_does_not_fire(tmp_path: Path) -> None:
    """`florence2` is an unrelated model package; the pin escapes the full name."""
    assert _FLORENCE2_RULE not in _ids(tmp_path, "requirements.txt", "florence2==1.0.0\n")


def test_florence2_positive_fixture_fires() -> None:
    ids = {f.rule_id for f in scan(_FLORENCE2_FIXTURES / "vulnerable")[0]}
    assert _FLORENCE2_RULE in ids


def test_florence2_negative_fixture_is_quiet() -> None:
    ids = {f.rule_id for f in scan(_FLORENCE2_FIXTURES / "negative")[0]}
    assert _FLORENCE2_RULE not in ids


def test_florence2_remediation_does_not_promise_an_upgrade() -> None:
    """Guard the honest-remediation property this release is about.

    There is no fixed version. Advice to "upgrade to X" would be advice that does
    nothing — the same defect class as the v0.3.78 transport-flip keys.
    """
    text = RULES[_FLORENCE2_RULE].remediation
    assert "egress" in text.lower(), "remediation must name the mitigation that works"
    assert "will not ship in the package" in text, (
        "remediation must state plainly that an upgrade does not resolve this"
    )


# --- CVE-2026-59723 (cline): the pin must not match "cline" inside English words ---
#
# `_mk_re` anchors on neither side, so the unbounded pattern matched the substring in
# "declined", "inclined" and "recline". Any prose file containing one of those reported
# a CVE pin for a package the project does not depend on. Found while writing the
# mcp-florence2 fixtures, whose comment used the word "declined". Fixed with `_CLINE_RE`,
# the same bounded shape as `_LETTA_RE` / `_N8N_RE`.

_CLINE_RULE = "AAK-MCP-CLINE-CVE-2026-59723-001"


@pytest.mark.parametrize("word", ["declined", "declines", "inclined", "recline", "disinclined"])
def test_cline_does_not_match_english_words(tmp_path: Path, word: str) -> None:
    assert _CLINE_RULE not in _ids(
        tmp_path, "requirements.txt", f"# the vendor {word} to patch this\nrequests==2.0\n"
    )


def test_cline_does_not_match_a_different_package(tmp_path: Path) -> None:
    """`cline-utils` is not `cline`; the right boundary excludes the hyphen."""
    content = '{"dependencies": {"cline-utils": "1.0.0"}}'
    assert _CLINE_RULE not in _ids(tmp_path, "package.json", content)


def test_cline_pip_pin_below_floor_still_fires(tmp_path: Path) -> None:
    """The bound must not cost a true positive."""
    assert _CLINE_RULE in _ids(tmp_path, "requirements.txt", "cline==3.0.20\n")


def test_cline_unpinned_mcp_config_still_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"c": {"command": "npx", "args": ["cline"]}}}'
    assert _CLINE_RULE in _ids(tmp_path, ".mcp.json", content)


def _affected_version(pin: object) -> str:
    """A version inside the pin's affected range, so a match is a finding."""
    lowest = getattr(pin, "introduced", None) or (0, 0, 1)
    return ".".join(str(n) for n in lowest)


@pytest.mark.parametrize("pin", _PINS, ids=lambda p: f"{p.rule_id}:{p.display}")
def test_every_pin_matches_whole_names_only(tmp_path: Path, pin: object) -> None:
    """Assert the mechanism, not just the behaviour, for every row of the table.

    Each pin used to need its own bounded regex, because the default pattern had
    no left boundary and stopped at the first textual match: `cline` fired on
    "declined", `n8n` on a server *named* n8n, `openclaw` on
    `@agenticmail/openclaw`, and a comment naming the package with a number hid
    the real declaration. Pins now read parsed declarations by whole name, so a
    longer name, a scoped lookalike, prose and a server label cannot stand in for
    the package. The positive control proves each fixture would have fired.
    """
    name = pin.names[0]  # type: ignore[attr-defined]
    version = _affected_version(pin)
    rule_id = pin.rule_id  # type: ignore[attr-defined]
    ecosystem = pin.ecosystem  # type: ignore[attr-defined]
    base = name.rsplit("/", 1)[-1]
    lookalikes = {f"{name}-extras", f"@lookalike/{base}"}
    if not name.startswith("@"):
        lookalikes.add(f"sub{name}")
    mates = {n for p in _PINS if p.rule_id == rule_id for n in p.names}
    lookalikes -= mates

    if ecosystem in (None, "js"):
        quiet = {
            "description": f"works with {name} {version} and later",
            "keywords": [name],
            "dependencies": {other: version for other in sorted(lookalikes)},
        }
        assert rule_id not in _ids(tmp_path, "package.json", json.dumps(quiet))
        config = {"mcpServers": {name: {"command": "node", "args": [f"/opt/{name}/index.js"]},
                                 f"{name}-remote": {"url": f"https://example.test/{name}"}}}
        assert rule_id not in _ids(tmp_path, ".mcp.json", json.dumps(config))
        (tmp_path / ".mcp.json").unlink()
        requires_arg = pin.requires_arg  # type: ignore[attr-defined]
        if requires_arg is None:
            real = {"dependencies": {name: version}}
            assert rule_id in _ids(tmp_path, "package.json", json.dumps(real))
            (tmp_path / "package.json").unlink()
        else:
            # Only a launch that passes the option can show the flaw.
            launch = {"mcpServers": {"x": {"command": "npx",
                                           "args": ["-y", f"{name}@{version}", requires_arg]}}}
            assert rule_id in _ids(tmp_path, ".mcp.json", json.dumps(launch))
            (tmp_path / ".mcp.json").unlink()
    if ecosystem in (None, "py") and not name.startswith("@"):
        quiet_lines = [f"# see {name} {version} for details"]
        quiet_lines += [f"{other}=={version}" for other in sorted(lookalikes) if not other.startswith("@")]
        assert rule_id not in _ids(tmp_path, "requirements.txt", "\n".join(quiet_lines) + "\n")
        assert rule_id in _ids(tmp_path, "requirements.txt", f"{name}=={version}\n")


# --- 2026-09-26 wave -------------------------------------------------------

_REMOTE = "AAK-MCP-REMOTE-CVE-2026-51994-001"


def _remote_config(spec: str) -> str:
    return '{"mcpServers": {"x": {"command": "npx", "args": ["-y", "%s", "https://mcp.example.com/sse"]}}}' % spec


def test_mcp_remote_in_the_advisory_range_fires(tmp_path: Path) -> None:
    """CVE-2026-51994 and CVE-2026-51995: OAuth discovery SSRF, 0.1.32 through 0.1.38."""
    for spec in ("mcp-remote@0.1.32", "mcp-remote@0.1.35", "mcp-remote@0.1.38"):
        assert _REMOTE in _ids(tmp_path, ".mcp.json", _remote_config(spec)), spec


def test_mcp_remote_browser_launch_range_fires(tmp_path: Path) -> None:
    """CVE-2026-51997 starts at 0.1.16, where the URL check it bypasses was added
    for CVE-2025-6514, so the pin's lower bound moved down from 0.1.32."""
    for spec in ("mcp-remote@0.1.16", "mcp-remote@0.1.24", "mcp-remote@0.1.31"):
        assert _REMOTE in _ids(tmp_path, ".mcp.json", _remote_config(spec)), spec


def test_mcp_remote_outside_the_advisory_range_passes(tmp_path: Path) -> None:
    # 0.1.15 predates the range; 0.1.39+ is not confirmed vulnerable by the advisory
    # and upstream published no fix, so the rule makes no claim about it either way.
    for spec in ("mcp-remote@0.1.15", "mcp-remote@0.1.39", "mcp-remote@0.14.3"):
        assert _REMOTE not in _ids(tmp_path, ".mcp.json", _remote_config(spec)), spec


def test_mcp_remote_rule_cites_the_three_advisories() -> None:
    from agent_audit_kit.rules.builtin import get_rule

    refs = set(get_rule(_REMOTE).cve_references)
    assert {"CVE-2026-51994", "CVE-2026-51995", "CVE-2026-51997"} <= refs


def test_mcp_remote_finding_lists_cve_2026_51996(tmp_path: Path) -> None:
    """CVE-2026-51996 (#834): NVD scopes it 0.1.16 through 0.1.38, the range the
    pin already reports, so it joins the rule and nothing moves. A stated 0.1.20
    is below the 0.1.32 start of the SSRF pair and still inside it."""
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"mcp-remote": "0.1.20"}}', encoding="utf-8"
    )
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == _REMOTE]
    assert len(hits) == 1
    assert "CVE-2026-51996" in hits[0].cve_references


def test_mcp_remote_rule_cites_cve_2026_51996_and_its_advisory_correction() -> None:
    """NVD calls it code execution; the advisory NVD cites (F-04, v1.0.1) was
    corrected to hardening with no token takeover shown. The rule says both."""
    from agent_audit_kit.rules.builtin import get_rule

    rule = get_rule(_REMOTE)
    assert set(rule.cve_references) == {
        "CVE-2026-51994", "CVE-2026-51995", "CVE-2026-51996", "CVE-2026-51997",
        "CVE-2026-52001",
    }
    assert "getServerUrlHash" in rule.description
    assert "no token takeover" in rule.description


def test_mcp_remote_finding_lists_cve_2026_52001(tmp_path: Path) -> None:
    """CVE-2026-52001 (#921): NVD scopes it 0.1.18 through 0.1.38, inside the range
    the pin already reports, so it joins the rule and nothing moves. Like 51996, its
    advisory (F-11, v1.0.1) was corrected to defense in depth; the rule says both."""
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"mcp-remote": "0.1.18"}}', encoding="utf-8"
    )
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == _REMOTE]
    assert len(hits) == 1
    assert "CVE-2026-52001" in hits[0].cve_references
    pin = next(p for p in _PINS if p.rule_id == _REMOTE)
    assert (pin.introduced, pin.floor) == ((0, 1, 16), (0, 1, 39))
    from agent_audit_kit.rules.builtin import get_rule

    assert "eventSourceInit" in get_rule(_REMOTE).description


def test_mcp_remote_unpinned_passes(tmp_path: Path) -> None:
    """Unpinned `npx mcp-remote` resolves to the newest release (0.14.x), outside
    the range, and it is in a very large share of MCP configs. Treating it as
    exposed, the house default for a floor pin, would put a CRITICAL on all of
    them for a version the advisory never tested."""
    assert _REMOTE not in _ids(tmp_path, ".mcp.json", _remote_config("mcp-remote"))


def test_mcp_remote_in_package_json_fires(tmp_path: Path) -> None:
    assert _REMOTE in _ids(tmp_path, "package.json", '{"dependencies": {"mcp-remote": "0.1.36"}}')


_KIMI = "AAK-MCP-KIMICODE-CVE-2026-95660-001"


def test_kimi_code_below_floor_fires(tmp_path: Path) -> None:
    """CVE-2026-95660: Kimi Code up to 0.31.0 spawns an untrusted workspace's
    `.mcp.json` servers without a trust prompt. Fixed in 0.31.1."""
    content = '{"devDependencies": {"@moonshot-ai/kimi-code": "0.31.0"}}'
    assert _KIMI in _ids(tmp_path, "package.json", content)


def test_kimi_code_patched_passes(tmp_path: Path) -> None:
    content = '{"devDependencies": {"@moonshot-ai/kimi-code": "0.31.1"}}'
    assert _KIMI not in _ids(tmp_path, "package.json", content)


# --- 2026-10-02 wave -------------------------------------------------------

_PILLMWIKI = "AAK-MCP-PILLMWIKI-CVE-2026-102911-001"
_PILLMWIKI_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-102911-pi-llm-wiki"


def test_pi_llm_wiki_fixtures_positive_and_negative() -> None:
    """CVE-2026-102911 (#833): the wiki_capture_source MCP tool passes its `url`
    argument into `sh -c "uvx ... markitdown \"${source}\""`. Fixed in 0.11.8."""
    assert _PILLMWIKI in {f.rule_id for f in scan(_PILLMWIKI_FIXTURES / "vulnerable")[0]}
    assert _PILLMWIKI not in {f.rule_id for f in scan(_PILLMWIKI_FIXTURES / "negative")[0]}


def test_pi_llm_wiki_has_no_lower_bound(tmp_path: Path) -> None:
    """NVD says "up to 0.11.7", and the shell call is in the upstream source from
    May 2026, months before 0.11.0, so an early release is reported too."""
    content = '{"dependencies": {"@zosmaai/pi-llm-wiki": "0.6.3"}}'
    assert _PILLMWIKI in _ids(tmp_path, "package.json", content)


def test_pi_llm_wiki_locked_version_decides(tmp_path: Path) -> None:
    lock = (
        '{"name": "x", "lockfileVersion": 3, "packages": {'
        '"node_modules/@zosmaai/pi-llm-wiki": {"version": "%s"}}}'
    )
    assert _PILLMWIKI in _ids(tmp_path, "package-lock.json", lock % "0.11.7")
    assert _PILLMWIKI not in _ids(tmp_path, "package-lock.json", lock % "0.11.8")


def test_pi_llm_wiki_needs_a_stated_version(tmp_path: Path) -> None:
    """Upstream registers the MCP server by its path inside node_modules, which
    states no version, and `pi install npm:<pkg>` writes pi's own settings, which
    this scanner does not read. An unpinned reference is not reported, as for
    mcp-remote."""
    config = (
        '{"mcpServers": {"llm-wiki": {"command": "node", "args": '
        '["/abs/node_modules/@zosmaai/pi-llm-wiki/dist/mcp/index.js"]}}}'
    )
    assert _PILLMWIKI not in _ids(tmp_path, ".mcp.json", config)


def test_the_unscoped_pi_llm_wiki_is_another_project(tmp_path: Path) -> None:
    """npm's unscoped `pi-llm-wiki` (0.1.0) is a different author's package."""
    content = '{"dependencies": {"pi-llm-wiki": "0.1.0"}}'
    assert _PILLMWIKI not in _ids(tmp_path, "package.json", content)


# --- 2026-10-03 wave -------------------------------------------------------

_FMTG = "AAK-MCP-FASTMCPTELEGRAM-CVE-2026-55096-001"
_FMTG_FIXTURES = (
    Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-55096-fast-mcp-telegram"
)


def test_fast_mcp_telegram_fixtures_positive_and_negative() -> None:
    """CVE-2026-55096 (#853): the attachment guard checks the literal hostname and
    never resolves it. Fixed in 0.30.1, which NVD and the advisory print as "30.1"."""
    assert _FMTG in {f.rule_id for f in scan(_FMTG_FIXTURES / "vulnerable")[0]}
    assert _FMTG not in {f.rule_id for f in scan(_FMTG_FIXTURES / "negative")[0]}


def test_fast_mcp_telegram_later_release_passes(tmp_path: Path) -> None:
    assert _FMTG not in _ids(tmp_path, "requirements.txt", "fast-mcp-telegram==0.45.0\n")


def test_fast_mcp_telegram_unpinned_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"telegram": {"command": "uvx", "args": ["fast-mcp-telegram"]}}}'
    assert _FMTG in _ids(tmp_path, ".mcp.json", content)


def test_fast_mcp_telegram_locked_version_decides(tmp_path: Path) -> None:
    lock = '[[package]]\nname = "fast-mcp-telegram"\nversion = "%s"\n'
    assert _FMTG in _ids(tmp_path, "uv.lock", lock % "0.30.0")
    assert _FMTG not in _ids(tmp_path, "uv.lock", lock % "0.30.1")


def test_fast_mcp_telegram_is_a_pypi_pin(tmp_path: Path) -> None:
    """npm has no package of that name, so a package.json entry is not this project."""
    content = '{"dependencies": {"fast-mcp-telegram": "0.29.0"}}'
    assert _FMTG not in _ids(tmp_path, "package.json", content)


def test_fast_mcp_telegram_longer_name_is_another_package(tmp_path: Path) -> None:
    assert _FMTG not in _ids(tmp_path, "requirements.txt", "fast-mcp-telegram-bot==0.1.0\n")


# --- 2026-10-03 wave, second batch (#863-#867) ------------------------------
_OFFICEPPT = "AAK-MCP-OFFICEPPT-CVE-2025-71427-001"
_OFFICEPPT_FIXTURES = (
    Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2025-71427-office-powerpoint-mcp"
)
_PENPOT_BRIDGE = "AAK-MCP-PENPOT-CVE-2026-100868-001"
_PENPOT_REPL = "AAK-MCP-PENPOT-CVE-2026-45805-001"
_PENPOT_FIXTURES = (
    Path(__file__).resolve().parent / "fixtures" / "cves" / "cve-2026-100868-penpot-mcp"
)


def test_office_powerpoint_fixtures_positive_and_negative() -> None:
    """CVE-2025-71427 (#864): save_presentation, open_presentation and manage_image
    take any path through 2.0.7, and there is no fixed release (upstream PR #33 is
    unmerged). The negative is the same author's Word server, a different package."""
    assert _OFFICEPPT in {f.rule_id for f in scan(_OFFICEPPT_FIXTURES / "vulnerable")[0]}
    assert _OFFICEPPT not in {f.rule_id for f in scan(_OFFICEPPT_FIXTURES / "negative")[0]}


@pytest.mark.parametrize("version", ["2.0.1", "2.0.7", "2.1.0"])
def test_office_powerpoint_every_version_fires_until_a_fix_ships(tmp_path: Path, version: str) -> None:
    """Presence-only: no release is known to be fixed, so no version clears the pin.
    2.1.0 does not exist; it stands for whatever ships next, which is reported until
    the pin gets a floor."""
    assert _OFFICEPPT in _ids(tmp_path, "requirements.txt", f"office-powerpoint-mcp-server=={version}\n")


def test_office_powerpoint_uvx_config_fires(tmp_path: Path) -> None:
    content = (
        '{"mcpServers": {"ppt": {"command": "uvx", '
        '"args": ["--from", "office-powerpoint-mcp-server", "ppt_mcp_server"]}}}'
    )
    assert _OFFICEPPT in _ids(tmp_path, ".mcp.json", content)


def test_office_powerpoint_underscore_spelling_fires(tmp_path: Path) -> None:
    """PyPI treats `-` and `_` as one name, and requirements files use both."""
    assert _OFFICEPPT in _ids(tmp_path, "requirements.txt", "office_powerpoint_mcp_server==2.0.7\n")


def test_office_powerpoint_is_a_pypi_pin(tmp_path: Path) -> None:
    """npm has no package of that name, so a package.json entry is not this project."""
    content = '{"dependencies": {"office-powerpoint-mcp-server": "2.0.7"}}'
    assert _OFFICEPPT not in _ids(tmp_path, "package.json", content)


def test_office_powerpoint_longer_name_is_another_package(tmp_path: Path) -> None:
    assert _OFFICEPPT not in _ids(tmp_path, "requirements.txt", "office-powerpoint-mcp-server-lite==0.1.0\n")


def test_penpot_bridge_fixtures_positive_and_negative() -> None:
    """CVE-2026-100868 (#867): the plugin WebSocket bridge listens on every interface
    before Penpot 2.18.0, and npm has no @penpot/mcp 2.18.x yet. 2.17.0 is past the
    REPL RCE's 2.15.0 fix, so only the bridge rule fires on it."""
    vulnerable = {f.rule_id for f in scan(_PENPOT_FIXTURES / "vulnerable")[0]}
    assert _PENPOT_BRIDGE in vulnerable
    assert _PENPOT_REPL not in vulnerable
    negative = {f.rule_id for f in scan(_PENPOT_FIXTURES / "negative")[0]}
    assert not {_PENPOT_BRIDGE, _PENPOT_REPL} & negative


def test_penpot_below_the_rce_fix_reports_both_cves(tmp_path: Path) -> None:
    content = '{"dependencies": {"@penpot/mcp": "2.14.9"}}'
    assert {_PENPOT_BRIDGE, _PENPOT_REPL} <= _ids(tmp_path, "package.json", content)


def test_penpot_latest_dist_tag_fires_the_bridge_rule_only(tmp_path: Path) -> None:
    """npm's `latest` was 2.15.4 on 2026-10-03: clear of the RCE, not of the bridge."""
    ids = _ids(tmp_path, "package.json", '{"dependencies": {"@penpot/mcp": "2.15.4"}}')
    assert _PENPOT_BRIDGE in ids
    assert _PENPOT_REPL not in ids


def test_penpot_unpinned_npx_fires_the_bridge_rule(tmp_path: Path) -> None:
    content = '{"mcpServers": {"penpot": {"command": "npx", "args": ["-y", "@penpot/mcp"]}}}'
    assert _PENPOT_BRIDGE in _ids(tmp_path, ".mcp.json", content)


def test_penpot_bridge_stays_a_separate_lower_severity_rule() -> None:
    """Raising the 45805 floor instead would have called 2.15.0-2.17.x a critical RCE."""
    assert RULES[_PENPOT_BRIDGE].severity.value == "medium"
    assert RULES[_PENPOT_REPL].severity.value == "critical"
    assert RULES[_PENPOT_REPL].cve_references == ["CVE-2026-45805"]


def test_penpot_bridge_label_says_the_fix_is_not_on_npm_yet() -> None:
    """Re-checked 2026-10-04 (#872). The fix, b5274a44 (2026-09-22), is in Penpot's
    2.18.0 tag, but that tag's mcp/package.json reads 2.17.0 (penpot/penpot#12007)
    and npm has no build from it: `latest` is 2.15.4, and `next` is 2.17.0, which
    was published on 2026-07-08 and still binds every interface.

    The wording is pinned on purpose. When npm publishes a fixed build, this label
    and the 2.18.0 floor are both out of date (a fixed build numbered 2.17.x would
    be reported), so changing either one should mean revisiting both."""
    pin = next(p for p in _PINS if p.rule_id == _PENPOT_BRIDGE)
    assert pin.floor == (2, 18, 0)
    assert pin.fix_label == (
        "Penpot 2.18.0, but no npm build has been published from that tag yet "
        "(its mcp/package.json reads 2.17.0, penpot/penpot#12007, and npm's 2.17.0 "
        "predates the fix); meanwhile firewall the plugin WebSocket port, 4402 by default"
    )
    description = RULES[_PENPOT_BRIDGE].description
    assert "no `@penpot/mcp` has been published to npm from that tag yet" in description
    assert "still reads 2.17.0 (penpot/penpot#12007)" in description


# --- 2026-10-03 wave, third batch (#879-#883) -------------------------------
_CVE_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cves"
_VOICEMODE = "AAK-MCP-VOICEMODE-CVE-2026-79535-001"
_SHARIQ = "AAK-MCP-SHARIQ-GITHUB-CVE-2026-102906-001"
_OPENCLAW_APP = "AAK-MCP-OPENCLAW-CVE-2026-102807-001"
_OPENCLAW_OLD = "AAK-MCP-OPENCLAW-CVE-2026-62195-001"


def test_voicemode_fixtures_positive_and_negative() -> None:
    """CVE-2026-79535 (#879): update_config writes the caller's value into a sourced
    env file. Checked in the wheels: 8.10.1 double-quotes at best, which does not
    stop `$(...)`; 8.10.2 single-quotes anything that is not shell-inert."""
    root = _CVE_FIXTURES / "cve-2026-79535-voicemode"
    assert _VOICEMODE in {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert _VOICEMODE not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("line", "fires"), [
    ("voice-mode==8.10.1\n", True),
    ("voice_mode==8.9.0\n", True),       # PyPI folds - and _
    ("voice-mode>=8.10.2\n", False),
    ("voice-mode==8.12.0\n", False),
    ("voice-mode-extras==1.0.0\n", False),  # a longer name is another package
])
def test_voicemode_versions(tmp_path: Path, line: str, fires: bool) -> None:
    assert (_VOICEMODE in _ids(tmp_path, "requirements.txt", line)) is fires


def test_voicemode_unpinned_uvx_config_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"voice": {"command": "uvx", "args": ["voice-mode"]}}}'
    assert _VOICEMODE in _ids(tmp_path, ".mcp.json", content)


def test_shariq_github_fixtures_positive_and_negative() -> None:
    """CVE-2026-102906 (#880): `gitRemove(file)` runs `git reset HEAD "${file}"`
    through child_process.exec. Checked in the npm tarballs of 2.0.0 and 2.5.0 (the
    newest): both have it, and there is no fixed release. The negative holds the
    official GitHub server and an unscoped package of a similar name."""
    root = _CVE_FIXTURES / "cve-2026-102906-shariq-github-mcp"
    assert _SHARIQ in {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert _SHARIQ not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize("version", ["2.0.0", "2.5.0", "2.6.0"])
def test_shariq_github_every_version_fires_until_a_fix_ships(tmp_path: Path, version: str) -> None:
    """Presence-only. 2.6.0 does not exist; it stands for whatever ships next."""
    content = '{"dependencies": {"@0xshariq/github-mcp-server": "%s"}}' % version
    assert _SHARIQ in _ids(tmp_path, "package.json", content)


def test_shariq_github_npx_config_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"git": {"command": "npx", "args": ["-y", "@0xshariq/github-mcp-server"]}}}'
    assert _SHARIQ in _ids(tmp_path, ".mcp.json", content)


def test_openclaw_app_fixtures_positive_and_negative() -> None:
    """CVE-2026-102807 (#883): fixed in 2026.9.4 (3bd8ec2b). 2026.9.3 is affected and
    past the older pin's 2026.7.1 floor, so only the new rule fires on it."""
    root = _CVE_FIXTURES / "cve-2026-102807-openclaw"
    vulnerable = {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert _OPENCLAW_APP in vulnerable
    assert _OPENCLAW_OLD not in vulnerable
    assert _OPENCLAW_APP not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("version", "fires"), [
    ("2026.7.1", False),   # the standalone MCP App host is absent here
    ("2026.6.34", False),  # extended-stable 2026.6 line, no host either
    ("2026.7.2", True),
    ("2026.8.1", True),    # first stable release with tools through the host
    ("2026.8.35", True),   # extended-stable 2026.8 line: no backport on 2026-10-02
    ("2026.9.3", True),
    ("2026.9.4", False),
    ("2026.9.8", False),
])
def test_openclaw_app_version_range(tmp_path: Path, version: str, fires: bool) -> None:
    content = '{"dependencies": {"openclaw": "%s"}}' % version
    assert (_OPENCLAW_APP in _ids(tmp_path, "package.json", content)) is fires


def test_openclaw_app_is_its_own_medium_rule_beside_the_high_pin() -> None:
    """Raising the 2026.7.1 floor would have called 2026.7.1-2026.9.3 the HIGH bugs."""
    assert RULES[_OPENCLAW_APP].severity.value == "medium"
    assert RULES[_OPENCLAW_OLD].severity.value == "high"
    assert "CVE-2026-102807" not in RULES[_OPENCLAW_OLD].cve_references


# --- 2026-10-05 wave (#887-#896) --------------------------------------------
_ZSCALER = "AAK-MCP-ZSCALER-CVE-2026-59563-001"
_UTCP = "AAK-MCP-UTCP-CVE-2026-101057-001"
_TOOLBOX = "AAK-MCP-TOOLBOX-CVE-2026-102242-001"
_NEXTJS = "AAK-MCP-NEXTJS-CVE-2026-94486-001"
_CLAUDECODE = "AAK-MCP-CLAUDECODE-CVE-2026-103012-001"
_CLAUDECODE_TRUST = "AAK-CLAUDECODE-CVE-2026-40068-PIN-001"
_LANGFLOW = "AAK-MCP-LANGFLOW-CVE-2026-12940-001"


@pytest.mark.parametrize(("fixture", "rule_id"), [
    ("cve-2026-59563-zscaler-mcp", _ZSCALER),
    ("cve-2026-101057-utcp-mcp", _UTCP),
    ("cve-2026-102242-mcp-toolbox", _TOOLBOX),
    ("cve-2026-94486-nextjs-dev-mcp", _NEXTJS),
    ("cve-2026-103012-claude-code", _CLAUDECODE),
    ("cve-2026-101861-langflow", _LANGFLOW),
])
def test_2026_10_05_fixtures_positive_and_negative(fixture: str, rule_id: str) -> None:
    """Each pin or floor change of the batch, on a firing fixture and a negative
    one. The Next.js negative also carries a pnpm lockfile whose ESLint plugins lag
    behind an upgraded `next`, and the Claude Code negative an unpinned npx entry."""
    root = _CVE_FIXTURES / fixture
    assert rule_id in {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert rule_id not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("line", "fires"), [
    ("zscaler-mcp==0.6.2\n", False),   # binds the arguments on every call
    ("zscaler-mcp==0.7.0\n", True),    # the 31 empty-parameter calls arrive
    ("zscaler_mcp==0.7.1\n", True),    # PyPI folds - and _
    ("zscaler-mcp==0.7.2\n", False),   # zscaler/zscaler-mcp-server#41
    ("zscaler-mcp==0.15.4\n", False),
])
def test_zscaler_version_range(tmp_path: Path, line: str, fires: bool) -> None:
    assert (_ZSCALER in _ids(tmp_path, "requirements.txt", line)) is fires


def test_zscaler_readme_uvx_name_is_not_the_package(tmp_path: Path) -> None:
    """The README's uvx example names `zscaler-mcp-server`, which is not on PyPI;
    the package and its console script are `zscaler-mcp`."""
    content = ('{"mcpServers": {"zscaler-mcp-server": {"command": "uvx", '
               '"args": ["--env-file", "/path/to/.env", "zscaler-mcp-server"]}}}')
    assert _ZSCALER not in _ids(tmp_path, ".mcp.json", content)
    unpinned = '{"mcpServers": {"zscaler": {"command": "uvx", "args": ["zscaler-mcp"]}}}'
    assert _ZSCALER in _ids(tmp_path, ".mcp.json", unpinned)


@pytest.mark.parametrize(("line", "fires"), [
    ("utcp-mcp==1.0.0\n", True),
    ("utcp_mcp==1.1.2\n", True),
    ("utcp-mcp==1.1.3\n", False),   # `_ensure_secure_mcp_url` on every server URL
    ("utcp-mcp==1.2.0\n", False),
])
def test_utcp_version_range(tmp_path: Path, line: str, fires: bool) -> None:
    assert (_UTCP in _ids(tmp_path, "requirements.txt", line)) is fires


def test_utcp_call_template_is_not_seen_by_the_cleartext_class_rule(tmp_path: Path) -> None:
    """Why #889 is a pin: AAK-TRANSPORT-001 reads a top-level `mcpServers`, and a
    utcp call template nests it under `config`. If the class rule learns the
    template shape, this fails and the pin's reason should be looked at again."""
    from agent_audit_kit.scanners import transport_security

    template = ('{"name": "remote_mcp", "call_template_type": "mcp", "config": '
                '{"mcpServers": {"api": {"transport": "http", '
                '"url": "http://mcp.internal.example.com:8080/mcp"}}}}')
    (tmp_path / "remote_mcp.json").write_text(template, encoding="utf-8")
    fired = {f.rule_id for f in transport_security.scan(tmp_path)[0]}
    assert "AAK-TRANSPORT-001" not in fired


@pytest.mark.parametrize(("version", "fires"), [
    ("1.1.0", False),   # no local-path tools yet
    ("1.2.0", True),    # ValidateLocalPath, lexical only
    ("1.5.0", True),    # allowedLocalRoots arrives, still lexical
    ("1.9.0", True),
    ("1.10.0", False),  # ResolveSymlinks (googleapis/mcp-toolbox#3810)
    ("1.13.1", False),
])
def test_toolbox_version_range(tmp_path: Path, version: str, fires: bool) -> None:
    content = '{"dependencies": {"@toolbox-sdk/server": "%s"}}' % version
    assert (_TOOLBOX in _ids(tmp_path, "package.json", content)) is fires


def test_toolbox_platform_binaries_are_not_the_launcher(tmp_path: Path) -> None:
    content = '{"optionalDependencies": {"@toolbox-sdk/server-linux-x64": "1.9.0"}}'
    assert _TOOLBOX not in _ids(tmp_path, "package.json", content)


@pytest.mark.parametrize(("spec", "fires"), [
    ("15.5.7", False),            # no MCP middleware before 16.0.0
    ("16.0.0", True),
    ("^16.2.0", True),            # a range reads as its lowest version
    ("16.3.7", True),
    ("16.3.8", False),            # 2d9f50a
    ("16.4.0-canary.12", False),
    ("latest", False),            # states no version
    ("canary", False),
])
def test_nextjs_version_range(tmp_path: Path, spec: str, fires: bool) -> None:
    content = '{"dependencies": {"next": "%s"}}' % spec
    assert (_NEXTJS in _ids(tmp_path, "package.json", content)) is fires


def test_nextjs_reads_only_the_next_dependency_entry(tmp_path: Path) -> None:
    """`next` is a word and part of many package names; none of these is it."""
    content = ('{"scripts": {"dev": "next dev", "build": "next build"}, '
               '"dependencies": {"next-auth": "4.24.11", "@next/env": "16.2.0", '
               '"eslint-config-next": "16.2.0", "@sentry/nextjs": "10.0.0"}}')
    assert _NEXTJS not in _ids(tmp_path, "package.json", content)


def test_pnpm_lockfile_reads_next_and_not_names_ending_in_it(tmp_path: Path) -> None:
    """The lowest locked version wins, so an unbounded `next@` read an ESLint plugin
    left on 16.2.0 as `next` itself, and `@vercel/next` hid a vulnerable `next`."""
    lagging_plugins = ("packages:\n"
                       "  eslint-config-next@16.2.0:\n    resolution: {integrity: a}\n"
                       "  '@next/eslint-plugin-next@16.2.0':\n    resolution: {integrity: b}\n"
                       "  next@16.3.8:\n    resolution: {integrity: c}\n")
    assert _NEXTJS not in _ids(tmp_path, "pnpm-lock.yaml", lagging_plugins)
    vercel_builder = ("packages:\n"
                      "  '@vercel/next@4.4.0':\n    resolution: {integrity: a}\n"
                      "  /next@16.2.0:\n    resolution: {integrity: b}\n")
    assert _NEXTJS in _ids(tmp_path, "pnpm-lock.yaml", vercel_builder)


def test_nextjs_rule_says_dev_server_only_and_names_the_fix() -> None:
    rule = RULES[_NEXTJS]
    assert rule.severity.value == "low"
    assert "dev server only" in rule.title
    assert "Dev server only" in rule.description
    assert "16.3.8" in rule.remediation
    assert rule.cve_references == ["CVE-2026-94486"]


@pytest.mark.parametrize(("version", "fires"), [
    ("2.0.67", False),
    ("2.0.68", True),    # Claude for Enterprise affected from here
    ("2.1.38", True),    # Team from here
    ("2.1.259", True),
    ("2.1.260", False),
    ("2.1.289", False),
])
def test_claudecode_version_range(tmp_path: Path, version: str, fires: bool) -> None:
    content = '{"devDependencies": {"@anthropic-ai/claude-code": "%s"}}' % version
    assert (_CLAUDECODE in _ids(tmp_path, "package.json", content)) is fires


def test_claudecode_needs_a_stated_version(tmp_path: Path) -> None:
    """As for the folder-trust pin on the same package: an unpinned npx reference
    resolves to the newest release, and the CLI updates itself."""
    unpinned = ('{"mcpServers": {"claude": {"command": "npx", '
                '"args": ["-y", "@anthropic-ai/claude-code", "mcp", "serve"]}}}')
    assert _CLAUDECODE not in _ids(tmp_path, ".mcp.json", unpinned)
    versioned = unpinned.replace("claude-code\"", "claude-code@2.1.100\"")
    assert _CLAUDECODE in _ids(tmp_path, ".mcp.json", versioned)


def test_claudecode_is_its_own_low_rule_beside_the_high_pin() -> None:
    """Raising the folder-trust pin's floor to 2.1.260 would call everything from its
    own floor (2.1.83 then, 2.1.129 since CVE-2026-103435) to 2.1.259 the HIGH bug."""
    assert RULES[_CLAUDECODE].severity.value == "low"
    assert RULES[_CLAUDECODE_TRUST].severity.value == "high"
    assert "CVE-2026-103012" not in RULES[_CLAUDECODE_TRUST].cve_references


def test_langflow_floor_moves_to_1_12_0_for_cve_2026_101861(tmp_path: Path) -> None:
    pin = next(p for p in _PINS if p.rule_id == _LANGFLOW)
    assert pin.floor == (1, 12, 0)
    assert "CVE-2026-101861" in RULES[_LANGFLOW].cve_references
    assert _LANGFLOW in _ids(tmp_path, "requirements.txt", "langflow==1.11.6\n")


# --- 2026-10-05 wave, second batch (#900-#901) ------------------------------
_LANGGRAPH_SDK = "AAK-MCP-LANGGRAPHSDK-CVE-2026-104873-001"


def test_langgraph_sdk_fixtures_positive_and_negative() -> None:
    """CVE-2026-104873 (#901): in 0.4.3 `_ResourceOn` registers the handler under
    "*" whatever `actions` says; 0.4.4 registers each named action."""
    root = _CVE_FIXTURES / "cve-2026-104873-langgraph-sdk"
    assert _LANGGRAPH_SDK in {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert _LANGGRAPH_SDK not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("line", "fires"), [
    ("langgraph-sdk==0.1.44\n", False),  # no `langgraph_sdk.auth` yet
    ("langgraph-sdk==0.1.45\n", True),   # the auth decorators arrive
    ("langgraph_sdk==0.4.3\n", True),    # PyPI folds - and _
    ("langgraph-sdk==0.4.4\n", False),
    ("langgraph-sdk==0.4.5\n", False),
])
def test_langgraph_sdk_version_range(tmp_path: Path, line: str, fires: bool) -> None:
    assert (_LANGGRAPH_SDK in _ids(tmp_path, "requirements.txt", line)) is fires


def test_langgraph_sdk_ignores_the_javascript_sdk(tmp_path: Path) -> None:
    content = '{"mcpServers": {"x": {"command": "npx", "args": ["@langchain/langgraph-sdk@0.1.0"]}}}'
    assert _LANGGRAPH_SDK not in _ids(tmp_path, ".mcp.json", content)


# --- 2026-10-06 wave (#903-#907): the Langflow rule reads its whole train ----
_LANGFLOW_CVES_2026_10_06 = (
    "CVE-2026-105697", "CVE-2026-105740", "CVE-2026-105741", "CVE-2026-105699",
)


def test_langflow_rule_carries_the_october_cves_at_the_same_floor() -> None:
    """#903-#905 and #908: fixed in 1.10.3, 1.9.0, 1.10.3 and 1.9.1, all under the
    1.12.0 floor, so they join the rule and no floor moves. One rule, three pins."""
    for cve in _LANGFLOW_CVES_2026_10_06:
        assert cve in RULES[_LANGFLOW].cve_references
    pins = [p for p in _PINS if p.rule_id == _LANGFLOW]
    assert sorted(p.display for p in pins) == ["langflow", "langflow-base", "lfx"]
    assert {p.floor for p in pins} == {(1, 12, 0)}
    assert {p.ecosystem for p in pins} == {"py"}


@pytest.mark.parametrize("package", ["langflow-base", "lfx"])
def test_langflow_train_fixtures_positive_and_negative(package: str) -> None:
    root = _CVE_FIXTURES / f"cve-2026-105697-{package}"
    assert _LANGFLOW in {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert _LANGFLOW not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("line", "fires"), [
    ("langflow-base==0.10.2\n", True),   # before CVE-2026-105697's 0.10.3
    ("langflow_base==0.11.6\n", True),   # past 0.10.3, still under CVE-2026-101861
    ("langflow-base==1.12.0\n", False),  # the 0.x line jumped to 1.12.0 here
    ("lfx==1.10.2\n", True),
    ("lfx==1.11.6\n", True),
    ("lfx==1.12.0\n", False),
])
def test_langflow_base_and_lfx_versions(tmp_path: Path, line: str, fires: bool) -> None:
    assert (_LANGFLOW in _ids(tmp_path, "requirements.txt", line)) is fires


def test_langflow_base_is_no_longer_read_as_an_unpinned_langflow(tmp_path: Path) -> None:
    """The unbounded `_mk_re("langflow")` read `langflow-base==1.12.0` as `langflow`
    with no version and reported it, whatever the version."""
    findings = scan(_write_and_root(tmp_path, "requirements.txt", "langflow-base==1.12.0\n"))[0]
    assert not [f for f in findings if f.rule_id == _LANGFLOW]


@pytest.mark.parametrize(("name", "content"), [
    # npm's `langflow` is a React frontend for another product, and npm's `lfx` an
    # empty placeholder: neither is the PyPI release train.
    ("package.json", '{"dependencies": {"langflow": "1.5.1", "lfx": "0.0.0"}}'),
    # A repository URL names the project, not an installed version.
    ("requirements.txt", "git+https://github.com/langflow-ai/langflow.git\n"),
])
def test_langflow_lookalikes_are_quiet(tmp_path: Path, name: str, content: str) -> None:
    assert _LANGFLOW not in _ids(tmp_path, name, content)


def _write_and_root(tmp_path: Path, name: str, content: str) -> Path:
    (tmp_path / name).write_text(content, encoding="utf-8")
    return tmp_path


# --- 2026-10-07 batch (#911-#915): the MCP TypeScript SDK -----------------------
_TSSDK = "AAK-MCP-TSSDK-CVE-2026-104850-001"


@pytest.mark.parametrize("fixture", ["cve-2026-104850-mcp-ts-sdk", "cve-2026-104850-mcp-ts-client"])
def test_ts_sdk_fixtures_positive_and_negative(fixture: str) -> None:
    root = _CVE_FIXTURES / fixture
    assert _TSSDK in {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert _TSSDK not in {f.rule_id for f in scan(root / "negative")[0]}


def test_ts_sdk_is_one_rule_with_two_pins() -> None:
    """CVE-2026-104850 (#914): 1.x ships as `@modelcontextprotocol/sdk`, which npm has
    never published at 2.x, and 2.x as `@modelcontextprotocol/client`."""
    pins = [p for p in _PINS if p.rule_id == _TSSDK]
    assert sorted(p.display for p in pins) == [
        "@modelcontextprotocol/client", "@modelcontextprotocol/sdk",
    ]
    assert {p.ecosystem for p in pins} == {"js"}


@pytest.mark.parametrize(("dep", "fires"), [
    ('"@modelcontextprotocol/sdk": "1.11.5"', False),  # no resource-metadata discovery yet
    ('"@modelcontextprotocol/sdk": "1.12.0"', True),
    ('"@modelcontextprotocol/sdk": "^1.30.1"', True),
    ('"@modelcontextprotocol/sdk": "1.31.0"', False),
    ('"@modelcontextprotocol/sdk": "latest"', False),   # resolves to a fixed release
    ('"@modelcontextprotocol/client": "2.0.0-beta.5"', True),
    ('"@modelcontextprotocol/client": "~2.1.0"', True),
    ('"@modelcontextprotocol/client": "2.2.0"', False),
    ('"@modelcontextprotocol/server": "2.1.0"', False),  # servers are not affected
    ('"@modelcontextprotocol/core": "2.1.0"', False),    # NVD names client and sdk only
])
def test_ts_sdk_versions(tmp_path: Path, dep: str, fires: bool) -> None:
    content = '{"dependencies": {%s}}' % dep
    assert (_TSSDK in _ids(tmp_path, "package.json", content)) is fires


@pytest.mark.parametrize(("version", "fires"), [("1.30.1", True), ("1.31.0", False)])
def test_ts_sdk_lockfile_reads_the_resolved_version(
    tmp_path: Path, version: str, fires: bool
) -> None:
    lock = (
        '{"lockfileVersion": 3, "packages": {"": {"name": "client"}, '
        '"node_modules/@modelcontextprotocol/sdk": {"version": "%s"}}}' % version
    )
    assert (_TSSDK in _ids(tmp_path, "package-lock.json", lock)) is fires


@pytest.mark.parametrize("content", [
    # An import path in a script names a module, not an installed version.
    '{"scripts": {"probe": "node -e \\"import(\'@modelcontextprotocol/sdk/client/auth.js\')\\""}}',
    # Other packages under the scope are not the SDK.
    '{"dependencies": {"@modelcontextprotocol/server-filesystem": "0.6.2", '
    '"@modelcontextprotocol/inspector": "0.16.0"}}',
])
def test_ts_sdk_lookalikes_are_quiet(tmp_path: Path, content: str) -> None:
    assert _TSSDK not in _ids(tmp_path, "package.json", content)


# --- 2026-10-08 batch (#916-#921): three npm pins --------------------------------
_PAYLOAD = "AAK-MCP-PAYLOAD-CVE-2026-105806-001"
_LC_REDIS = "AAK-MCP-LANGCHAIN-REDIS-CVE-2026-105799-001"
_LC_MONGO = "AAK-MCP-LANGCHAIN-MONGO-CVE-2026-106119-001"


@pytest.mark.parametrize(("fixture", "rule_id"), [
    ("cve-2026-105806-payload-mcp", _PAYLOAD),
    ("cve-2026-105799-langchain-redis", _LC_REDIS),
    ("cve-2026-106119-langchain-mongodb", _LC_MONGO),
])
def test_october_8_fixtures_positive_and_negative(fixture: str, rule_id: str) -> None:
    root = _CVE_FIXTURES / fixture
    assert rule_id in {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert rule_id not in {f.rule_id for f in scan(root / "negative")[0]}


def test_payload_mcp_fixture_below_the_range_is_quiet() -> None:
    """3.60.0 sits below 3.61.0, the plugin's first release and the GHSA's lower bound."""
    root = _CVE_FIXTURES / "cve-2026-105806-payload-mcp" / "negative-before-range"
    assert _PAYLOAD not in {f.rule_id for f in scan(root)[0]}


@pytest.mark.parametrize(("version", "fires"), [
    ("0.0.1-alpha.0", False),  # the placeholder published before the first release
    ("3.60.0", False),
    ("3.61.0", True),
    ("3.87.0", True),
    ("3.88.0", False),
    ("4.0.0-canary.38", False),
])
def test_payload_mcp_versions(tmp_path: Path, version: str, fires: bool) -> None:
    """CVE-2026-105806 (#917): the API-keys collection had no access rules from the
    plugin's first release, 3.61.0, until 3.88.0."""
    content = '{"dependencies": {"@payloadcms/plugin-mcp": "%s"}}' % version
    assert (_PAYLOAD in _ids(tmp_path, "package.json", content)) is fires


@pytest.mark.parametrize(("dep", "rule_id", "fires"), [
    ('"@langchain/redis": "0.0.5"', _LC_REDIS, True),   # the string-array path, every release
    ('"@langchain/redis": "^1.1.0"', _LC_REDIS, True),
    ('"@langchain/redis": "1.1.1"', _LC_REDIS, False),
    ('"@langchain/mongodb": "0.0.1"', _LC_MONGO, True),
    ('"@langchain/mongodb": "1.3.0"', _LC_MONGO, True),
    ('"@langchain/mongodb": "1.3.1"', _LC_MONGO, False),
    # The LangGraph checkpointer is a different package with its own pin.
    ('"@langchain/langgraph-checkpoint-mongodb": "1.3.0"', _LC_MONGO, False),
])
def test_langchain_js_integration_versions(
    tmp_path: Path, dep: str, rule_id: str, fires: bool
) -> None:
    content = '{"dependencies": {%s}}' % dep
    assert (rule_id in _ids(tmp_path, "package.json", content)) is fires


def test_langchain_js_pins_skip_the_python_packages(tmp_path: Path) -> None:
    """`langchain-redis` and `langchain-mongodb` on PyPI are separate packages on
    their own version lines, and neither advisory names them."""
    found = _ids(tmp_path, "requirements.txt", "langchain-redis==0.2.0\nlangchain-mongodb==0.6.0\n")
    assert not {_LC_REDIS, _LC_MONGO} & found


# --- 2026-10-11 batch (#953-#959): two npm pins, neither with a fixed release ---
_ARGOCD = "AAK-MCP-ARGOCD-CVE-2026-108585-001"
_ONEMCP = "AAK-MCP-1MCP-CVE-2026-108586-001"


@pytest.mark.parametrize(("fixture", "rule_id"), [
    ("cve-2026-108585-argocd-mcp", _ARGOCD),
    ("cve-2026-108586-1mcp-agent", _ONEMCP),
])
def test_october_11_fixtures_positive_and_negative(fixture: str, rule_id: str) -> None:
    root = _CVE_FIXTURES / fixture
    assert rule_id in {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert rule_id not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize("version", ["0.0.1", "0.4.0", "0.9.0", "0.9.1"])
def test_argocd_mcp_every_version_fires_until_a_fix_ships(tmp_path: Path, version: str) -> None:
    """CVE-2026-108585 (#955): presence-only. Checked in the npm tarballs: 0.0.1 and
    0.9.0 (the newest) both build the delete path from the raw application name.
    0.9.1 does not exist; it stands for whatever ships next."""
    content = '{"dependencies": {"argocd-mcp": "%s"}}' % version
    assert _ARGOCD in _ids(tmp_path, "package.json", content)


@pytest.mark.parametrize("dep", [
    '"argocd-mcp-server": "0.1.0"',  # another project on npm
    '"mcp-argocd": "1.0.0"',         # another project on npm
    '"@acme/argocd-mcp": "1.0.0"',   # a scoped name is not the package
])
def test_argocd_mcp_lookalikes_are_quiet(tmp_path: Path, dep: str) -> None:
    content = '{"dependencies": {%s}}' % dep
    assert _ARGOCD not in _ids(tmp_path, "package.json", content)


def test_argocd_mcp_readme_npx_config_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"argocd": {"command": "npx", "args": ["argocd-mcp@latest", "stdio"]}}}'
    assert _ARGOCD in _ids(tmp_path, ".mcp.json", content)


def test_onemcp_agent_fixture_below_the_range_is_quiet() -> None:
    """0.19.0 has no `tag-filter` parameter, so there is no expression to bypass with."""
    root = _CVE_FIXTURES / "cve-2026-108586-1mcp-agent" / "negative-before-range"
    assert _ONEMCP not in {f.rule_id for f in scan(root)[0]}


@pytest.mark.parametrize(("version", "fires"), [
    ("0.19.0", False),        # no `tag-filter` yet
    ("0.20.0", True),         # the advanced filter and its scope check arrive
    ("^0.38.3", True),
    ("0.39.0-beta.5", True),
    ("0.39.0", True),         # the newest release
    ("0.40.0", True),         # does not exist; presence-only until a fix ships
])
def test_onemcp_agent_versions(tmp_path: Path, version: str, fires: bool) -> None:
    """CVE-2026-108586 (#956): the scope check validates only the tags an advanced
    `tag-filter` expression names, from 0.20.0 to 0.39.0, the newest."""
    content = '{"dependencies": {"@1mcp/agent": "%s"}}' % version
    assert (_ONEMCP in _ids(tmp_path, "package.json", content)) is fires


def test_onemcp_agent_unpinned_npx_config_fires(tmp_path: Path) -> None:
    content = '{"mcpServers": {"1mcp": {"command": "npx", "args": ["-y", "@1mcp/agent", "--transport", "stdio"]}}}'
    assert _ONEMCP in _ids(tmp_path, ".mcp.json", content)


def test_onemcp_agent_pin_skips_the_unscoped_package(tmp_path: Path) -> None:
    """npm `1mcp` is buremba/1mcp, a different aggregator on its own 0.1.x line."""
    assert _ONEMCP not in _ids(tmp_path, "package.json", '{"dependencies": {"1mcp": "0.1.3"}}')


# --- 2026-10-13 batch (#963): @elvix.is/sdk, fixed in 0.10.2 ---
_ELVIX = "AAK-MCP-ELVIX-CVE-2026-108542-001"


def test_elvix_fixtures_positive_and_negative() -> None:
    """A package.json on ^0.10.1 and an MCP config on 0.9.6 fire; ^0.10.2 does not,
    and neither does the 0.0.0 placeholder, which has no MCP server."""
    root = _CVE_FIXTURES / "cve-2026-108542-elvix-sdk"
    assert {f.file_path for f in scan(root / "vulnerable")[0] if f.rule_id == _ELVIX} == {
        "package.json", ".mcp.json",
    }
    assert _ELVIX not in {f.rule_id for f in scan(root / "negative")[0]}
    assert _ELVIX not in {f.rule_id for f in scan(root / "negative-before-range")[0]}


@pytest.mark.parametrize(("version", "fires"), [
    ("0.0.0", False),     # an empty placeholder, no dist/mcp
    ("0.1.0", True),      # the MCP server's first release, already building URLs this way
    ("0.9.6", True),
    ("^0.10.1", True),    # the last affected release
    ("0.10.2", False),    # ed0c622 binds each tool to its manifest path
    ("^0.14.4", False),   # the newest release on 2026-10-13
])
def test_elvix_versions(tmp_path: Path, version: str, fires: bool) -> None:
    content = '{"dependencies": {"@elvix.is/sdk": "%s"}}' % version
    assert (_ELVIX in _ids(tmp_path, "package.json", content)) is fires


@pytest.mark.parametrize("dep", [
    '"elvix": "0.10.1"',              # not an npm package
    '"elvix-sdk": "0.10.1"',          # not an npm package
    '"@021is/elvix-sdk": "0.10.1"',   # the GitHub org, not the npm scope
    '"@elvix.is/sdk-react": "0.10.1"',
])
def test_elvix_lookalikes_are_quiet(tmp_path: Path, dep: str) -> None:
    content = '{"dependencies": {%s}}' % dep
    assert _ELVIX not in _ids(tmp_path, "package.json", content)


def test_elvix_lockfile_reads_the_locked_version(tmp_path: Path) -> None:
    lock = (
        '{"name": "a", "lockfileVersion": 3, "packages": {'
        '"node_modules/@elvix.is/sdk": {"version": "0.10.1"}}}'
    )
    assert _ELVIX in _ids(tmp_path, "package-lock.json", lock)
# --- Declarations, not text (found while proving the table's limitations) -------
#
# The scan used to search each file for a package name and judge the first match.
# Each case below was wrong on that code: a prose mention hid the real pin, a
# patched pin read as unpinned, a longer name or a scoped lookalike read as the
# package, and an upper bound read as the version.

_LITELLM = "AAK-MCP-LITELLM-CVE-2026-59822-001"
_CLINE = "AAK-MCP-CLINE-CVE-2026-59723-001"
_REPOMIX = "AAK-MCP-REPOMIX-CVE-2026-49988-001"
_OPENCLAW = "AAK-MCP-OPENCLAW-CVE-2026-62195-001"
_AGENTICMAIL = "AAK-MCP-AGENTICMAIL-CVE-2026-57495-001"
_DEEPSEEK = "AAK-MCP-DEEPSEEK-CVE-2026-55604-001"
_N8N_65594 = "AAK-MCP-N8N-CVE-2026-65594-001"
_RUFLO = "AAK-MCP-RUFLO-CVE-2026-59726-001"


@pytest.mark.parametrize(("name", "content"), [
    ("requirements.txt", "# gateway needs litellm 1.90 or newer\nlitellm==1.0.0\n"),
    ("pyproject.toml", '[project]\nname = "gw"\ndescription = "a litellm 1.90 gateway"\n'
                       'dependencies = ["litellm==1.0.0"]\n'),
    ("package.json", '{"description": "works with litellm 1.90", "dependencies": {"litellm": "1.0.0"}}'),
])
def test_prose_naming_the_package_does_not_hide_the_real_pin(
    tmp_path: Path, name: str, content: str
) -> None:
    assert _LITELLM in _ids(tmp_path, name, content)


@pytest.mark.parametrize(("name", "content"), [
    ("requirements.txt", "# we moved off litellm 1.0.0 last year\nrequests==2.31.0\n"),
    ("pyproject.toml", '[project]\nname = "gw"\ndescription = "replaces litellm 1.0"\n'
                       'dependencies = ["requests==2.31.0"]\n'),
    (".mcp.json", '{"mcpServers": {"n8n": {"url": "https://n8n.example.test/mcp"},'
                  ' "better-auth": {"url": "https://auth.example.test/mcp"}}}'),
    (".mcp.json", '{"mcpServers": {"w": {"command": "uv", "args": ["--directory",'
                  ' "/opt/whatsapp-mcp", "run", "main.py"]}}}'),
])
def test_prose_labels_and_paths_are_not_declarations(
    tmp_path: Path, name: str, content: str
) -> None:
    assert not _ids(tmp_path, name, content)


@pytest.mark.parametrize(("name", "content"), [
    ("requirements.txt", "litellm[proxy]==1.90.0\n"),
    ("requirements.txt", "litellm [proxy] >= 1.90.0, < 2\n"),
    ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.9"\nlitellm = "^1.90.0"\n'),
    ("pyproject.toml", '[tool.poetry.dependencies]\n'
                       'litellm = {version = "^1.90.0", extras = ["proxy"]}\n'),
    ("Pipfile", '[packages]\nlitellm = "==1.90.0"\n'),
    ("Pipfile", '[packages]\nlitellm = {version = "==1.90.0", extras = ["proxy"]}\n'),
])
def test_a_patched_pin_clears_in_every_manifest_format(
    tmp_path: Path, name: str, content: str
) -> None:
    assert _LITELLM not in _ids(tmp_path, name, content)


@pytest.mark.parametrize(("name", "content"), [
    ("requirements.txt", "litellm[proxy]==1.80.0\n"),
    ("pyproject.toml", '[tool.poetry.dependencies]\nlitellm = "^1.80.0"\n'),
    ("Pipfile", '[packages]\nlitellm = "==1.80.0"\n'),
    ("Pipfile", '[packages]\nlitellm = "*"\n'),
])
def test_an_affected_pin_fires_in_every_manifest_format(
    tmp_path: Path, name: str, content: str
) -> None:
    assert _LITELLM in _ids(tmp_path, name, content)


@pytest.mark.parametrize(("content", "rule_id"), [
    ("repomix-plugin-extras==0.0.1\n", _REPOMIX),
    ("ruflo-extras==0.0.1\n", _RUFLO),
    ("mcp-text-editor-extras==0.0.1\n", "AAK-MCP-TEXTEDITOR-CVE-2026-15138-001"),
    ("litellm-proxy-extras==0.4.3\n", _LITELLM),
])
def test_a_longer_name_is_another_package(tmp_path: Path, content: str, rule_id: str) -> None:
    assert rule_id not in _ids(tmp_path, "requirements.txt", content)


def test_a_scoped_package_is_not_the_bare_one(tmp_path: Path) -> None:
    """`@agenticmail/openclaw` is AgenticMail's package, on its own version line."""
    ids = _ids(tmp_path, "package.json", '{"dependencies": {"@agenticmail/openclaw": "0.9.9"}}')
    assert _OPENCLAW not in ids
    assert _AGENTICMAIL not in ids          # 0.9.9 is past its 0.5.71 floor
    ids = _ids(tmp_path, "package.json", '{"dependencies": {"@agenticmail/openclaw": "0.5.0"}}')
    assert _AGENTICMAIL in ids and _OPENCLAW not in ids


@pytest.mark.parametrize(("name", "content", "fires"), [
    ("requirements.txt", "litellm<1.84.0\n", True),               # every allowed version is affected
    ("requirements.txt", "litellm<2.0.0,>=1.0.0\n", True),        # read as 2.0.0 before
    ("requirements.txt", "litellm>=1.0.0,<2.0.0\n", True),
    ("requirements.txt", "litellm>=1.84.0,<2.0.0\n", False),
    ("requirements.txt", "litellm~=1.90\n", False),
    ("requirements.txt", "litellm>=2.0,<1.0\n", False),           # admits nothing
    ("package.json", '{"dependencies": {"cline": "<3.0.30"}}', True),
    ("package.json", '{"dependencies": {"cline": ">=3.0.0 <4.0.0"}}', True),
    ("package.json", '{"dependencies": {"cline": "^3.0.30"}}', False),
    ("package.json", '{"dependencies": {"cline": ">=3.0.30"}}', False),
])
def test_a_range_is_judged_by_what_it_admits(
    tmp_path: Path, name: str, content: str, fires: bool
) -> None:
    rule_id = _LITELLM if name == "requirements.txt" else _CLINE
    assert (rule_id in _ids(tmp_path, name, content)) is fires


@pytest.mark.parametrize(("spec", "fires"), [
    ("^1.3.0", True),    # admits 1.4.2 to 1.7.x, though its lowest version predates the flaw
    ("~1.3.0", False),   # 1.3.x only, all before 1.4.2
    ("1.3.0", False),
])
def test_a_range_reaching_past_introduced_fires(tmp_path: Path, spec: str, fires: bool) -> None:
    content = '{"dependencies": {"@arikusi/deepseek-mcp-server": "%s"}}' % spec
    assert (_DEEPSEEK in _ids(tmp_path, "package.json", content)) is fires


def test_a_caret_reaching_a_vulnerable_branch_fires(tmp_path: Path) -> None:
    """`^2.29.8` clears the mainline fix but admits 2.30.0, which needs 2.30.1."""
    assert _N8N_65594 in _n8n(tmp_path, "^2.29.8")
    assert _N8N_65594 not in _n8n(tmp_path, "~2.29.8")
    assert _N8N_65594 not in _n8n(tmp_path, "^2.30.1")


@pytest.mark.parametrize(("dep", "rule_id"), [
    ('"next": ">=15.0.0"', "AAK-MCP-NEXTJS-CVE-2026-94486-001"),
    ('"@modelcontextprotocol/sdk": ">=1.0.0"', "AAK-MCP-TSSDK-CVE-2026-104850-001"),
    ('"@payloadcms/plugin-mcp": "^3.0.0"', "AAK-MCP-PAYLOAD-CVE-2026-105806-001"),
])
def test_a_stated_range_reaching_a_versioned_pin_fires(
    tmp_path: Path, dep: str, rule_id: str
) -> None:
    assert rule_id in _ids(tmp_path, "package.json", '{"dependencies": {%s}}' % dep)


def test_an_exact_override_decides_the_installed_version(tmp_path: Path) -> None:
    patched = '{"dependencies": {"cline": "^3.0.20"}, "overrides": {"cline": "3.0.31"}}'
    assert _CLINE not in _ids(tmp_path, "package.json", patched)
    affected = '{"dependencies": {"cline": "^3.0.30"}, "overrides": {"cline": "3.0.20"}}'
    assert _CLINE in _ids(tmp_path, "package.json", affected)
    assert _LITELLM not in _ids(tmp_path, "requirements.txt", "litellm>=1.0\nlitellm==1.90.0\n")


def test_each_mcp_server_launch_is_judged_on_its_own(tmp_path: Path) -> None:
    config = ('{"mcpServers": {"old": {"command": "npx", "args": ["cline@3.0.20"]},'
              ' "new": {"command": "npx", "args": ["cline@3.0.31"]}}}')
    assert _CLINE in _ids(tmp_path, ".mcp.json", config)


def test_the_launcher_names_the_registry(tmp_path: Path) -> None:
    """`npx` installs from npm and `uvx` from PyPI, so a same-named package on the
    other registry is not the pinned one."""
    npm_praisonai = '{"mcpServers": {"p": {"command": "npx", "args": ["-y", "praisonai@1.7.0"]}}}'
    ids = _ids(tmp_path, ".mcp.json", npm_praisonai)
    assert "AAK-MCP-PRAISONAI-TS-CVE-2026-57139-001" in ids
    assert "AAK-MCP-PRAISONAI-CVE-2026-61427-001" not in ids
    pypi_flowise = '{"mcpServers": {"f": {"command": "uvx", "args": ["flowise==3.0.0"]}}}'
    assert "AAK-MCP-FLOWISE-CVE-2026-91931-001" not in _ids(tmp_path, ".mcp.json", pypi_flowise)


@pytest.mark.parametrize("config", [
    '{"mcpServers": {"r": {"command": "ruflo", "args": ["mcp", "start"]}}}',
    '{"mcpServers": {"w": {"command": "cmd", "args": ["/c", "npx", "-y", "ruflo@3.0.0"]}}}',
    '{"mcpServers": {"b": {"command": "bash", "args": ["-c", "cd /x && npx -y ruflo@3.0.0"]}}}',
    '{"mcpServers": {"s": {"command": "npx", "args": ["-y", "supergateway", "--stdio",'
    ' "npx -y ruflo@3.0.0"]}}}',
])
def test_a_launch_behind_a_shell_or_a_program_run_by_name_is_read(
    tmp_path: Path, config: str
) -> None:
    assert _RUFLO in _ids(tmp_path, ".mcp.json", config)


def test_a_from_option_names_the_package_and_not_the_command(tmp_path: Path) -> None:
    config = ('{"mcpServers": {"a": {"command": "uvx", "args": ["--from",'
              ' "mcp-atlassian==0.22.0", "mcp-atlassian"]}}}')
    assert "AAK-MCP-ATLASSIAN-CVE-2026-73498-001" not in _ids(tmp_path, ".mcp.json", config)


def test_a_launch_in_a_package_json_script_is_read(tmp_path: Path) -> None:
    content = '{"scripts": {"mcp": "npx -y repomix@1.0.0 --mcp"}}'
    assert _REPOMIX in _ids(tmp_path, "package.json", content)


def test_a_lockfile_reports_any_affected_resolution(tmp_path: Path) -> None:
    """The lowest locked `next` predates the MCP middleware; another is affected."""
    lock = ("packages:\n"
            "  next@15.0.0:\n    resolution: {integrity: a}\n"
            "  next@16.1.0:\n    resolution: {integrity: b}\n")
    assert "AAK-MCP-NEXTJS-CVE-2026-94486-001" in _ids(tmp_path, "pnpm-lock.yaml", lock)


def test_the_evidence_quotes_the_declaration(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("# litellm 1.90\nlitellm[proxy]<1.84\n", encoding="utf-8")
    hits = [f for f in scan(tmp_path)[0] if f.rule_id == _LITELLM]
    assert len(hits) == 1
    assert "'litellm[proxy]<1.84'" in hits[0].evidence


# --- PyPI names compare as PEP 503 normalises them --------------------------------
#
# The table matched `awslabs.<x>-mcp-server` as spelled on PyPI's project page, and
# every other spelling of the same package was silent: the hyphenated name uv.lock
# records, the underscore form, a mixed-case requirement, `uvx awslabs-...@0.0.5`.

_AWSLABS_PINS = [p for p in _PINS if any(n.startswith("awslabs.") for n in p.names)]


def _awslabs_spellings(name: str) -> list[str]:
    hyphens = name.replace(".", "-")
    return [hyphens, hyphens.replace("-", "_"), name.upper(), name.replace("-", "_")]


@pytest.mark.parametrize("pin", _AWSLABS_PINS, ids=lambda p: p.display)
def test_every_pep503_spelling_of_an_awslabs_pin_is_read(tmp_path: Path, pin: object) -> None:
    name = pin.names[0]  # type: ignore[attr-defined]
    version = _affected_version(pin)
    rule_id = pin.rule_id  # type: ignore[attr-defined]
    for spelling in _awslabs_spellings(name):
        assert rule_id in _ids(tmp_path, "requirements.txt", f"{spelling}=={version}\n"), spelling
    (tmp_path / "requirements.txt").unlink()
    normalised = name.replace(".", "-")
    uv_lock = f'version = 1\n\n[[package]]\nname = "{normalised}"\nversion = "{version}"\n'
    assert rule_id in _ids(tmp_path, "uv.lock", uv_lock)
    (tmp_path / "uv.lock").unlink()
    poetry_lock = f'[[package]]\nname = "{normalised}"\nversion = "{version}"\n'
    assert rule_id in _ids(tmp_path, "poetry.lock", poetry_lock)
    (tmp_path / "poetry.lock").unlink()
    pipfile_lock = '{"default": {"%s": {"version": "==%s"}}}' % (normalised, version)
    assert rule_id in _ids(tmp_path, "Pipfile.lock", pipfile_lock)
    (tmp_path / "Pipfile.lock").unlink()
    config = '{"mcpServers": {"a": {"command": "uvx", "args": ["%s@%s"]}}}' % (normalised, version)
    assert rule_id in _ids(tmp_path, ".mcp.json", config)


def test_a_normalised_lockfile_name_clears_at_the_floor(tmp_path: Path) -> None:
    lock = 'version = 1\n\n[[package]]\nname = "awslabs-healthlake-mcp-server"\nversion = "0.0.14"\n'
    assert "AAK-MCP-HEALTHLAKE-CVE-2026-15643-001" not in _ids(tmp_path, "uv.lock", lock)


def test_npm_names_are_not_normalised(tmp_path: Path) -> None:
    """npm has no PEP 503: `neo-mjs` and `neo.mjs` are two packages there."""
    content = '{"dependencies": {"neo-mjs": "13.1.0"}}'
    assert "AAK-MCP-NEOMJS-CVE-2026-18482-001" not in _ids(tmp_path, "package.json", content)
    assert "AAK-MCP-NEOMJS-CVE-2026-18482-001" in _ids(
        tmp_path, "package.json", '{"dependencies": {"neo.mjs": "13.1.0"}}'
    )


def test_a_longer_normalised_name_is_still_another_package(tmp_path: Path) -> None:
    content = "awslabs-healthlake-mcp-server-extras==0.0.1\n"
    assert "AAK-MCP-HEALTHLAKE-CVE-2026-15643-001" not in _ids(tmp_path, "requirements.txt", content)


# --- An exact pin clears only the declarations it constrains -----------------------
#
# A dev, optional or extra group does not constrain a production install, so its
# patched pin must not silence an affected range in the runtime section. What does
# constrain every install is the same section (pip merges a package's lines in one
# requirements file or one PEP 621 list), a global constraint (uv
# `constraint-dependencies`) and an override, which replaces the regular entries.


@pytest.mark.parametrize(("name", "content"), [
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["litellm>=1.0"]\n'
                       '[dependency-groups]\ndev = ["litellm==1.90.0"]\n'),
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["litellm>=1.0"]\n'
                       '[project.optional-dependencies]\nproxy = ["litellm==1.90.0"]\n'),
    ("pyproject.toml", '[tool.poetry.dependencies]\nlitellm = "^1.0"\n'
                       '[tool.poetry.group.dev.dependencies]\nlitellm = "1.90.0"\n'),
    ("Pipfile", '[packages]\nlitellm = ">=1.0"\n[dev-packages]\nlitellm = "==1.90.0"\n'),
])
def test_a_patched_pin_in_another_group_does_not_clear_the_runtime_range(
    tmp_path: Path, name: str, content: str
) -> None:
    assert _LITELLM in _ids(tmp_path, name, content)


def test_a_patched_dev_dependency_does_not_clear_the_runtime_dependency(tmp_path: Path) -> None:
    content = '{"dependencies": {"repomix": "^1.0.0"}, "devDependencies": {"repomix": "1.14.1"}}'
    assert _REPOMIX in _ids(tmp_path, "package.json", content)


@pytest.mark.parametrize(("name", "content"), [
    # A global constraint narrows every install of the package.
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["litellm>=1.0"]\n'
                       '[tool.uv]\nconstraint-dependencies = ["litellm==1.90.0"]\n'),
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["litellm>=1.0"]\n'
                       '[tool.uv]\nconstraint-dependencies = ["litellm>=1.84"]\n'),
    # An override replaces the regular entries.
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["litellm>=1.0"]\n'
                       '[tool.uv]\noverride-dependencies = ["litellm==1.90.0"]\n'),
    # The same section: pip merges both lines into one requirement.
    ("requirements.txt", "litellm>=1.0\nlitellm==1.90.0\n"),
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["litellm>=1.0", "litellm==1.90.0"]\n'),
])
def test_a_constraint_override_or_same_section_pin_clears(
    tmp_path: Path, name: str, content: str
) -> None:
    assert _LITELLM not in _ids(tmp_path, name, content)


def test_declarations_under_different_markers_do_not_constrain_each_other(tmp_path: Path) -> None:
    """Under python_version < 3.9 only the first line applies, and it admits 1.0."""
    content = ('litellm>=1.0 ; python_version < "3.9"\n'
               'litellm==1.90.0 ; python_version >= "3.9"\n')
    assert _LITELLM in _ids(tmp_path, "requirements.txt", content)


def test_poetry_multiple_constraints_are_alternatives(tmp_path: Path) -> None:
    content = ('[tool.poetry.dependencies]\nlitellm = [\n'
               '  {version = "^1.0", python = "<3.9"},\n'
               '  {version = "1.90.0", python = ">=3.9"},\n]\n')
    assert _LITELLM in _ids(tmp_path, "pyproject.toml", content)


# --- Large lockfiles -----------------------------------------------------------------
#
# Every candidate over 2,000,000 bytes was skipped, lockfiles included, so a large
# project's package-lock.json reported nothing for any pin in the table. A lockfile is
# now read up to MAX_LOCKFILE_BYTES; manifests and MCP configs keep MAX_MANIFEST_BYTES.


def test_a_package_lock_over_2mb_is_read(tmp_path: Path) -> None:
    entry = {
        "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/filler/-/filler-1.0.0.tgz",
        "integrity": "sha512-" + "A" * 86 + "==",
    }
    count = 2_100_000 // len(json.dumps(entry)) + 1
    packages = {f"node_modules/filler-{i}": entry for i in range(count)}
    packages["node_modules/repomix"] = {"version": "1.0.0"}
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")
    assert lock.stat().st_size > 2_000_000
    hits = [f.evidence for f in scan(tmp_path)[0] if f.rule_id == _REPOMIX]
    assert len(hits) == 1 and "resolves to 1.0.0 in package-lock.json" in hits[0], hits


def test_each_kind_of_file_keeps_its_own_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A manifest and a lockfile of the same size: only the lockfile is within its limit."""
    from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins

    padding = " " * 400
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"repomix": "^1.0.0"}}' + padding, encoding="utf-8"
    )
    lock = {"lockfileVersion": 3, "packages": {"node_modules/repomix": {"version": "1.0.0"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock) + padding, encoding="utf-8")
    monkeypatch.setattr(pins, "MAX_MANIFEST_BYTES", 300)
    monkeypatch.setattr(pins, "MAX_LOCKFILE_BYTES", 1_000)
    findings, scanned = scan(tmp_path)
    assert [f.file_path for f in findings if f.rule_id == _REPOMIX] == ["package-lock.json"]
    assert scanned == {"package-lock.json"}, "a skipped file is not reported as scanned"


def test_a_lockfile_is_parsed_once_for_the_whole_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hundred pins used to re-parse a lockfile a hundred times."""
    from agent_audit_kit.scanners import mcp_cve_pins_2026_07 as pins

    calls: list[str] = []
    real = pins._lockfile_index

    def counting(text: str, filename: str) -> dict:
        calls.append(filename)
        return real(text, filename)

    monkeypatch.setattr(pins, "_lockfile_index", counting)
    lock = "packages:\n  /repomix@1.0.0:\n    resolution: {integrity: a}\n"
    assert _REPOMIX in _ids(tmp_path, "pnpm-lock.yaml", lock)
    assert calls == ["pnpm-lock.yaml"]


def test_every_lockfile_rule_states_the_size_limits() -> None:
    """The limitations quote the limits the readers apply, so changing one without
    the other fails here."""
    from agent_audit_kit.scanners._manifest_deps import MAX_LOCKFILE_BYTES, MAX_MANIFEST_BYTES

    assert MAX_LOCKFILE_BYTES % 2**20 == 0 and MAX_MANIFEST_BYTES % 10**6 == 0
    lockfile_limit = f"lockfile over {MAX_LOCKFILE_BYTES // 2**20} MiB"
    file_limit = f"over {MAX_MANIFEST_BYTES // 10**6} MB"
    pin_rules = sorted({p.rule_id for p in _PINS})
    for rule_id in [*pin_rules, "AAK-SUPPLY-002", "AAK-SUPPLY-005"]:
        assert lockfile_limit in RULES[rule_id].limitations, rule_id
    for rule_id in pin_rules:
        assert file_limit in RULES[rule_id].limitations, rule_id


# --- The PyPI `openclaw` is not OpenClaw ---------------------------------------------
#
# OpenClaw ships on npm only: each openclaw/openclaw advisory names the npm package
# `openclaw`, and NVD's CPE for CVE-2026-62195 is node.js. PyPI's `openclaw` (2.0.1
# and 2.0.2) is an installer for the cmdop CLI, and the unscoped pin read
# `openclaw==2.0.2` as an OpenClaw below 2026.7.1.


@pytest.mark.parametrize(("name", "content"), [
    ("requirements.txt", "openclaw==2.0.2\n"),
    ("pyproject.toml", '[project]\nname = "x"\ndependencies = ["openclaw==2.0.2"]\n'),
    ("Pipfile", '[packages]\nopenclaw = "==2.0.2"\n'),
    ("uv.lock", 'version = 1\n\n[[package]]\nname = "openclaw"\nversion = "2.0.2"\n'),
    ("poetry.lock", '[[package]]\nname = "openclaw"\nversion = "2.0.2"\n'),
    ("Pipfile.lock", '{"default": {"openclaw": {"version": "==2.0.2"}}}'),
    (".mcp.json", '{"mcpServers": {"a": {"command": "uvx", "args": ["openclaw@2.0.2"]}}}'),
    (".mcp.json", '{"mcpServers": {"a": {"command": "uvx", "args": ["openclaw==2.0.2"]}}}'),
])
def test_the_pypi_openclaw_is_another_package(tmp_path: Path, name: str, content: str) -> None:
    assert not _ids(tmp_path, name, content) & {_OPENCLAW_OLD, _OPENCLAW_APP}


def test_an_npm_launch_of_openclaw_is_still_read(tmp_path: Path) -> None:
    content = '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "openclaw@2026.6.0"]}}}'
    assert _OPENCLAW_OLD in _ids(tmp_path, ".mcp.json", content)


# --- 2026-10-15 batch (#982, #984): obsidian-tc, fixed in 1.3.1 ---------------------
#
# One rule for the five CVEs 1.3.1 closes. Checked in the npm tarballs: 1.0.1, 1.0.2
# and 1.2.1 resolve each tool's `vault` argument against every vault and carry no Host
# or Origin check; 1.3.1 has both guards. 0.0.1 is a placeholder with no server, there
# is no 1.3.0, and `latest` is 1.33.1, so an unstated version is not reported.
_OBSIDIANTC = "AAK-MCP-OBSIDIANTC-CVE-2026-77366-001"


def test_obsidian_tc_rule_carries_all_five_cves() -> None:
    assert RULES[_OBSIDIANTC].cve_references == [
        "CVE-2026-77366", "CVE-2026-77363", "CVE-2026-77364", "CVE-2026-77361",
        "CVE-2026-77362",
    ]


def test_obsidian_tc_fixtures_positive_and_negative() -> None:
    """The README's client block on 1.2.1 and a package.json on 1.0.2 fire; the block
    on 1.3.1 does not, and neither do the two 0.0.1 placeholders."""
    root = _CVE_FIXTURES / "cve-2026-77366-obsidian-tc"
    assert {f.file_path for f in scan(root / "vulnerable")[0] if f.rule_id == _OBSIDIANTC} == {
        ".mcp.json", "package.json",
    }
    assert _OBSIDIANTC not in {f.rule_id for f in scan(root / "negative")[0]}
    assert _OBSIDIANTC not in {f.rule_id for f in scan(root / "negative-placeholder")[0]}


@pytest.mark.parametrize(("version", "fires"), [
    ("0.0.1", False),     # "Reserved namespace placeholder", no dist/
    ("1.0.1", True),      # the first release with a server
    ("1.0.2", True),
    ("1.2.1", True),      # the last release before the fix
    ("^1.2.1", True),     # admits 1.2.1
    ("1.3.1", False),     # 38b4992 (vault binding) and 6428bfe (Host and Origin)
    ("^1.3.1", False),
    ("1.33.1", False),    # the newest release on 2026-10-15
])
def test_obsidian_tc_versions(tmp_path: Path, version: str, fires: bool) -> None:
    content = '{"dependencies": {"obsidian-tc": "%s"}}' % version
    assert (_OBSIDIANTC in _ids(tmp_path, "package.json", content)) is fires


def test_obsidian_tc_readme_config_states_no_version(tmp_path: Path) -> None:
    """The README's own client block launches `npx -y obsidian-tc`, which installs
    `latest` (1.33.1, fixed), so the pin needs a stated version."""
    content = (
        '{"mcpServers": {"obsidian-tc": {"command": "npx", "args": ["-y", "obsidian-tc"], '
        '"env": {"OBSIDIAN_TC_CONFIG": "/ABSOLUTE/PATH/TO/obsidian-tc.config.json"}}}}'
    )
    assert _OBSIDIANTC not in _ids(tmp_path, ".mcp.json", content)


@pytest.mark.parametrize("dep", [
    '"@the-40-thieves/obsidian-tc": "0.0.1"',          # the scoped placeholder
    '"@the-40-thieves/obsidian-tc-shared": "1.2.1"',   # a monorepo part, not the server
    '"@the-40-thieves/obsidian-tc-native": "1.2.1"',
])
def test_obsidian_tc_lookalikes_are_quiet(tmp_path: Path, dep: str) -> None:
    content = '{"dependencies": {%s}}' % dep
    assert _OBSIDIANTC not in _ids(tmp_path, "package.json", content)


def test_obsidian_tc_lockfile_reads_the_locked_version(tmp_path: Path) -> None:
    lock = (
        '{"name": "a", "lockfileVersion": 3, "packages": {'
        '"node_modules/obsidian-tc": {"version": "1.2.1"}}}'
    )
    assert _OBSIDIANTC in _ids(tmp_path, "package-lock.json", lock)


# --- 2026-10-15 second batch (#998): Junie CLI, fixed in 26.8.3 -----------------------
#
# The npm package is a launcher whose version is the Junie build it installs
# (`junieVersion`), and 26.8.3 is build 2548.5 (npm 2548.5.0, 2026-08-03). Checked in
# the builds: 888.112 and 2470.4 read `<project>/.junie/mcp/mcp.json`, and 2548.5 adds
# the trust prompt that previews it. `@jetbrains/junie-cli` is the earlier name; below
# 888 it installed the EAP builds of August 2025 to February 2026, and its 1.0.0 is an
# empty package.json.
_JUNIE = "AAK-MCP-JUNIE-CVE-2026-111091-001"


def test_junie_rule_carries_its_cve() -> None:
    assert RULES[_JUNIE].cve_references == ["CVE-2026-111091"]


def test_junie_fixtures_positive_and_negative() -> None:
    """A devDependency on 2470.4.0, the last npm release before the fix, fires; on
    2548.5.0 it does not, and neither does the old name's empty 1.0.0."""
    root = _CVE_FIXTURES / "cve-2026-111091-junie"
    assert [f.file_path for f in scan(root / "vulnerable")[0] if f.rule_id == _JUNIE] == [
        "package.json",
    ]
    assert _JUNIE not in {f.rule_id for f in scan(root / "negative")[0]}
    assert _JUNIE not in {f.rule_id for f in scan(root / "negative-placeholder")[0]}


@pytest.mark.parametrize(("name", "version", "fires"), [
    ("@jetbrains/junie", "888.112.0", True),       # the first @jetbrains/junie release
    ("@jetbrains/junie", "2144.7.0", True),
    ("@jetbrains/junie", "2470.4.0", True),        # Junie 26.7.27, the last before the fix
    ("@jetbrains/junie", "^2470.4.0", True),       # admits 2470.4.0
    ("@jetbrains/junie", "2548.5.0", False),       # Junie 26.8.3
    ("@jetbrains/junie", "^2548.5.0", False),
    ("@jetbrains/junie", "3110.7.0", False),       # latest on 2026-10-15
    ("@jetbrains/junie-cli", "888.77.0", True),    # the old name, on release builds
    ("@jetbrains/junie-cli", "1468.30.0", True),   # its last version
    ("@jetbrains/junie-cli", "849.19.0", False),   # an EAP build, below the pin's start
    ("@jetbrains/junie-cli", "0.1.5", False),      # a 2025 cloud EAP launcher
    ("@jetbrains/junie-cli", "1.0.0", False),      # the empty package.json
])
def test_junie_versions(tmp_path: Path, name: str, version: str, fires: bool) -> None:
    content = '{"devDependencies": {"%s": "%s"}}' % (name, version)
    assert (_JUNIE in _ids(tmp_path, "package.json", content)) is fires


def test_junie_unpinned_reference_is_not_reported(tmp_path: Path) -> None:
    """`latest` is 3110.7.0, fixed, so the pin needs a stated version."""
    content = '{"devDependencies": {"@jetbrains/junie": "latest"}}'
    assert _JUNIE not in _ids(tmp_path, "package.json", content)


def test_junie_evidence_names_the_build_and_the_release(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"devDependencies": {"@jetbrains/junie": "2470.4.0"}}', encoding="utf-8")
    [finding] = [f for f in scan(tmp_path)[0] if f.rule_id == _JUNIE]
    assert "fixed in 2548.5.0, which is Junie 26.8.3" in finding.evidence


# --- 2026-10-16 batch (#1001-#1005) ------------------------------------------------
#
# #1001: CVE-2026-57496 joins the NetLicensing pin, whose floor rises from 0.1.6 to
# 0.1.8 and whose severity rises to CRITICAL: every release before 0.1.8 builds the
# product path unchecked, so the old range is inside the new one.
_NETLICENSING = "AAK-MCP-NETLICENSING-CVE-2026-54446-001"


def test_netlicensing_rule_is_critical_and_cites_both_cves() -> None:
    rule = RULES[_NETLICENSING]
    assert rule.severity.value == "critical"
    assert rule.cve_references == ["CVE-2026-54446", "CVE-2026-57496"]


def test_netlicensing_fixtures_positive_and_negative() -> None:
    root = _CVE_FIXTURES / "cve-2026-57496-netlicensing"
    assert [f.file_path for f in scan(root / "vulnerable")[0] if f.rule_id == _NETLICENSING] == [
        ".mcp.json",
    ]
    assert _NETLICENSING not in {f.rule_id for f in scan(root / "negative")[0]}
    # The README's unpinned `uvx netlicensing-mcp` installs 0.1.10, which is fixed.
    assert _NETLICENSING not in {f.rule_id for f in scan(root / "negative-unpinned")[0]}


@pytest.mark.parametrize(("version", "fires"), [
    ("0.0.6", True),     # the first release; the product path is already unchecked
    ("0.1.5", True),     # also below the old 0.1.6 floor (CVE-2026-54446)
    ("0.1.6", True),     # newly reported: above the old floor, below the new one
    ("0.1.7", True),     # adds token redaction, which the traversal skips
    ("0.1.8", False),    # b8fd0ea validates each path segment
    ("0.1.10", False),   # the newest release on 2026-10-16
])
def test_netlicensing_versions(tmp_path: Path, version: str, fires: bool) -> None:
    assert (_NETLICENSING in _ids(tmp_path, "requirements.txt", f"netlicensing-mcp=={version}\n")) is fires


# #1002: CVE-2026-109527 raises the HIGH `mcp` pin from 1.28.1 to 1.29.1 and adds the
# 2.0 line, which 2.0.1 (released after 2.1.0) still carries. CVE-2026-59951, not yet
# filed, is MEDIUM, so it is its own rule: 1.8.0 to 1.29.x, and 2.0.x and 2.1.x.
_SDK = "AAK-MCP-SDK-CVE-2026-52869-001"
_SDK_SESSIONS = "AAK-MCP-SDK-CVE-2026-59951-001"


def test_mcp_sdk_fixtures() -> None:
    root = _CVE_FIXTURES / "cve-2026-109527-mcp-python-sdk"
    assert {f.rule_id for f in scan(root / "vulnerable")[0]} >= {_SDK, _SDK_SESSIONS}
    assert {f.rule_id for f in scan(root / "vulnerable-2x")[0]} >= {_SDK, _SDK_SESSIONS}
    assert not {_SDK, _SDK_SESSIONS} & {f.rule_id for f in scan(root / "negative")[0]}
    # npm's `mcp` (1.4.2 on 2026-10-16) is another package, not the Python SDK.
    assert not {_SDK, _SDK_SESSIONS} & {f.rule_id for f in scan(root / "negative-npm")[0]}
    sessions = _CVE_FIXTURES / "cve-2026-59951-mcp-python-sdk-sessions"
    assert {f.rule_id for f in scan(sessions / "vulnerable")[0]} & {_SDK, _SDK_SESSIONS} == {_SDK_SESSIONS}
    assert not {_SDK, _SDK_SESSIONS} & {f.rule_id for f in scan(sessions / "negative")[0]}


@pytest.mark.parametrize(("version", "body_limit", "sessions"), [
    ("0.9.1", True, False),      # SSE reads the body whole; no session manager yet
    ("1.7.1", True, False),
    ("1.8.0", True, True),       # StreamableHTTPSessionManager arrives
    ("1.28.1", True, True),      # the session CVEs' fix; the body limit is not there yet
    ("1.29.0", True, True),
    ("1.29.1", False, True),     # body limit (5f0b6af9, 4dc224fa); sessions still unbounded
    ("1.30.0", False, False),    # default idle timeout and session cap
    ("2.0.0a1", True, True),     # the 2.0 line, pre-releases included
    ("2.0.0", True, True),
    ("2.0.1", True, True),       # released after 2.1.0, still without the limit
    ("2.1.0", False, True),
    ("2.1.1", False, True),
    ("2.2.0", False, False),
    ("2.3.0", False, False),     # the newest release on 2026-10-16
])
def test_mcp_sdk_version_lines(tmp_path: Path, version: str, body_limit: bool, sessions: bool) -> None:
    ids = _ids(tmp_path, "requirements.txt", f"mcp=={version}\n")
    assert (_SDK in ids, _SDK_SESSIONS in ids) == (body_limit, sessions)


def test_mcp_sdk_open_range_reaching_the_2_0_line_is_reported(tmp_path: Path) -> None:
    """`>=1.29.1` admits 2.0.1, so the second range reports it."""
    assert _SDK in _ids(tmp_path, "requirements.txt", "mcp>=1.29.1,<2.1\n")
    assert _SDK not in _ids(tmp_path, "requirements.txt", "mcp>=1.29.1,<2.0\n")


def test_mcp_sdk_rules_read_the_uv_lock(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "mcp"\nversion = "2.0.1"\n', encoding="utf-8")
    assert {_SDK, _SDK_SESSIONS} <= {f.rule_id for f in scan(tmp_path)[0]}


# #1003: Network-AI's ClaudeHookBridge, 5.14.0 to 5.15.1, carrying CVE-2026-109331 and
# CVE-2026-73614, which the 2026-08-14 ledger had called unpinnable.
_NETWORKAI = "AAK-MCP-NETWORKAI-CVE-2026-109331-001"


def test_network_ai_rule_carries_both_cves() -> None:
    assert RULES[_NETWORKAI].cve_references == ["CVE-2026-109331", "CVE-2026-73614"]


def test_network_ai_fixtures_positive_and_negative() -> None:
    root = _CVE_FIXTURES / "cve-2026-109331-network-ai"
    assert sorted(f.file_path for f in scan(root / "vulnerable")[0] if f.rule_id == _NETWORKAI) == [
        ".mcp.json", "package.json",
    ]
    assert _NETWORKAI not in {f.rule_id for f in scan(root / "negative")[0]}
    assert _NETWORKAI not in {f.rule_id for f in scan(root / "negative-unpinned")[0]}


@pytest.mark.parametrize(("version", "fires"), [
    ("5.13.4", False),   # no ClaudeHookBridge yet
    ("5.14.0", True),    # the bridge arrives: first field only, cut at 500 characters
    ("5.15.0", True),
    ("5.15.1", True),    # truncation gone (CVE-2026-73614); still the first field only
    ("5.15.2", False),   # every field is checked
    ("5.15.4", False),   # latest on 2026-10-16
])
def test_network_ai_versions(tmp_path: Path, version: str, fires: bool) -> None:
    content = '{"dependencies": {"network-ai": "%s"}}' % version
    assert (_NETWORKAI in _ids(tmp_path, "package.json", content)) is fires


# #1005: mcp-remote's device-code grant, from 0.8.0, with no fixed release. It runs
# only with `--device-code`, so only a launch that passes the flag is judged.
_REMOTE_DEVICE = "AAK-MCP-REMOTE-CVE-2026-108716-001"


def _device_config(args: list[str], command: str = "npx") -> str:
    return json.dumps({"mcpServers": {"x": {"command": command, "args": args}}})


def test_mcp_remote_device_code_fixtures() -> None:
    root = _CVE_FIXTURES / "cve-2026-108716-mcp-remote"
    assert [f.file_path for f in scan(root / "vulnerable")[0] if f.rule_id == _REMOTE_DEVICE] == [".mcp.json"]
    assert _REMOTE_DEVICE not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("args", "fires"), [
    (["mcp-remote", "https://x.test/mcp", "--device-code"], True),             # the README's form
    (["-y", "mcp-remote@0.15.1", "https://x.test/mcp", "--device-code"], True),  # the newest release
    (["-y", "mcp-remote@0.8.0", "https://x.test/mcp", "--device-code"], True),
    (["-y", "mcp-remote@0.7.0", "https://x.test/mcp", "--device-code"], False),  # no device grant yet
    (["-y", "mcp-remote@0.1.38", "https://x.test/mcp", "--device-code"], False),
    (["mcp-remote", "https://x.test/mcp"], False),                              # browser sign-in
    (["mcp-remote", "https://x.test/mcp", "--device-code-timeout", "60"], False),
])
def test_mcp_remote_device_code_launches(tmp_path: Path, args: list[str], fires: bool) -> None:
    assert (_REMOTE_DEVICE in _ids(tmp_path, ".mcp.json", _device_config(args))) is fires


def test_mcp_remote_device_code_run_by_name_and_behind_a_shell(tmp_path: Path) -> None:
    """A global install run by name states no version, and every release is affected;
    a launch inside a quoted shell line passes the flag too."""
    by_name = _device_config(["https://x.test/mcp", "--device-code"], command="mcp-remote")
    assert _REMOTE_DEVICE in _ids(tmp_path, ".mcp.json", by_name)
    shell = _device_config(["--stdio", "npx -y mcp-remote https://x.test/mcp --device-code"],
                           command="supergateway")
    assert _REMOTE_DEVICE in _ids(tmp_path, ".mcp.json", shell)


def test_mcp_remote_device_code_needs_a_launch(tmp_path: Path) -> None:
    """A dependency entry or a lockfile records no arguments, so neither is judged."""
    assert _REMOTE_DEVICE not in _ids(tmp_path, "package.json", '{"dependencies": {"mcp-remote": "0.14.3"}}')
    (tmp_path / "package.json").unlink()
    lock = '{"lockfileVersion": 3, "packages": {"node_modules/mcp-remote": {"version": "0.14.3"}}}'
    assert _REMOTE_DEVICE not in _ids(tmp_path, "package-lock.json", lock)


def test_mcp_remote_device_code_in_a_package_json_script(tmp_path: Path) -> None:
    content = '{"scripts": {"sign-in": "npx -y mcp-remote@0.14.3 https://x.test/mcp --device-code"}}'
    assert _REMOTE_DEVICE in _ids(tmp_path, "package.json", content)


# --- 2026-10-16 second batch (records the watcher had not filed) --------------------
#
# CVE-2026-110842 (HIGH) and CVE-2026-110852 (MEDIUM) raise both n8n floors to 2.41.4,
# with the 2.42.0 release, which sorts above it, as a further range on the same row.
_N8N_59207 = "AAK-MCP-N8N-CVE-2026-59207-001"


def test_n8n_2_42_fixtures_positive_and_negative() -> None:
    root = _CVE_FIXTURES / "cve-2026-110842-n8n"
    assert {_N8N_59207, _N8N_72768} <= {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert not {_N8N_59207, _N8N_72768} & {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("version", "fires"), [
    ("1.123.83", True),   # fixes the webhook bypass, but not CVE-2026-59207 (2.27.4)
    ("2.0.0", True),      # the static lookup returns a dynamic row on 2.x from the start
    ("2.27.4", True),     # the old 59207 floor
    ("2.35.4", True),     # the old 72768 floor
    ("2.36.2", True),     # the old 2.36.x branch fix
    ("2.41.3", True),
    ("2.41.4", False),
    ("2.42.0", True),     # above 2.41.4 and still affected
    ("2.42.1", False),
    ("2.43.7", False),    # latest on 2026-10-16
])
def test_n8n_floors_are_2_41_4_and_2_42_1(tmp_path: Path, version: str, fires: bool) -> None:
    ids = _ids(tmp_path, "package.json", '{"dependencies": {"n8n": "%s"}}' % version)
    assert (_N8N_59207 in ids, _N8N_72768 in ids) == (fires, fires)


def test_n8n_rules_cite_the_new_cves_and_report_unversioned_n8n_once(tmp_path: Path) -> None:
    """One row each, with the 2.42.0 range on it: two rows, as the 72768 pin had for
    the 2.36.x line, reported an unversioned `n8n` twice."""
    assert "CVE-2026-110852" in RULES[_N8N_59207].cve_references
    assert "CVE-2026-110842" in RULES[_N8N_72768].cve_references
    for rule_id in (_N8N_59207, _N8N_72768):
        [row] = [p for p in _PINS if p.rule_id == rule_id]
        assert (row.floor, row.also) == ((2, 41, 4), (((2, 42, 0), (2, 42, 1)),))
    (tmp_path / "requirements.txt").write_text("n8n\n", encoding="utf-8")
    hits = [f.rule_id for f in scan(tmp_path)[0] if f.rule_id in (_N8N_59207, _N8N_72768)]
    assert sorted(hits) == [_N8N_59207, _N8N_72768]


# CVE-2026-108721: Open Computer Use's macOS denylist is case-sensitive. No fixed
# release; the same build ships under three npm names.
_OCU = "AAK-MCP-OPENCOMPUTERUSE-CVE-2026-108721-001"


def test_open_computer_use_fixtures_positive_and_negative() -> None:
    root = _CVE_FIXTURES / "cve-2026-108721-open-computer-use"
    assert sorted(f.file_path for f in scan(root / "vulnerable")[0] if f.rule_id == _OCU) == [
        ".mcp.json", "package.json",
    ]
    assert _OCU not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("name", "content", "fires"), [
    ("package.json", '{"dependencies": {"open-computer-use": "0.1.2"}}', True),   # first release
    ("package.json", '{"dependencies": {"open-computer-use": "1.1.1"}}', True),   # the newest
    ("package.json", '{"dependencies": {"open-codex-computer-use-mcp": "^1.0.0"}}', True),
    (".mcp.json", '{"mcpServers": {"c": {"command": "npx", "args": ["-y", "open-computer-use-mcp"]}}}', True),
    (".mcp.json", '{"mcpServers": {"c": {"command": "open-computer-use", "args": ["mcp"]}}}', True),
    (".mcp.json", '{"mcpServers": {"c": {"command": "ocu", "args": ["mcp"]}}}', False),  # the alias
])
def test_open_computer_use_declarations(tmp_path: Path, name: str, content: str, fires: bool) -> None:
    assert (_OCU in _ids(tmp_path, name, content)) is fires


# CVE-2026-108861: odoo-mcp's execute_method skips the field policy, which arrives in
# 1.0.0. No fixed release; npm's `odoo-mcp` is another project.
_ODOO = "AAK-MCP-ODOOMCP-CVE-2026-108861-001"


def test_odoo_mcp_fixtures_positive_and_negative() -> None:
    root = _CVE_FIXTURES / "cve-2026-108861-odoo-mcp"
    assert sorted(f.file_path for f in scan(root / "vulnerable")[0] if f.rule_id == _ODOO) == [
        ".mcp.json", "requirements.txt",
    ]
    assert _ODOO not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("line", "fires"), [
    ("odoo-mcp==0.0.3\n", False),
    ("odoo-mcp==0.9.0\n", False),   # no field policy yet
    ("odoo-mcp==1.0.0\n", True),    # the policy arrives; execute_method skips it
    ("odoo-mcp==1.3.0\n", True),    # the newest on PyPI
    ("odoo-mcp\n", True),           # unversioned: the newest is affected
    ("odoo_mcp>=1.2\n", True),
])
def test_odoo_mcp_versions(tmp_path: Path, line: str, fires: bool) -> None:
    assert (_ODOO in _ids(tmp_path, "requirements.txt", line)) is fires


# CVE-2026-109332 (LOW): Network-AI's SSE transport answers other origins, from 4.0.0
# below 5.15.2. Its own rule beside the HIGH pin on the same package.
_NETWORKAI_CORS = "AAK-MCP-NETWORKAI-CVE-2026-109332-001"


def test_network_ai_cors_fixtures_positive_and_negative() -> None:
    root = _CVE_FIXTURES / "cve-2026-109332-network-ai"
    fired = {f.rule_id for f in scan(root / "vulnerable")[0]}
    assert _NETWORKAI_CORS in fired and _NETWORKAI not in fired
    assert _NETWORKAI_CORS not in {f.rule_id for f in scan(root / "negative")[0]}


@pytest.mark.parametrize(("version", "cors", "hook"), [
    ("3.9.0", False, False),    # no SSE transport yet
    ("4.0.0", True, False),     # the transport arrives with Access-Control-Allow-Origin: *
    ("5.1.0", True, False),
    ("5.13.4", True, False),    # reflects a localhost Origin whatever the bind address
    ("5.14.0", True, True),
    ("5.15.1", True, True),
    ("5.15.2", False, False),   # reflects only on a loopback bind
    ("latest", False, False),   # 5.15.4 on 2026-10-16
])
def test_network_ai_cors_versions(tmp_path: Path, version: str, cors: bool, hook: bool) -> None:
    ids = _ids(tmp_path, "package.json", '{"dependencies": {"network-ai": "%s"}}' % version)
    assert (_NETWORKAI_CORS in ids, _NETWORKAI in ids) == (cors, hook)
    assert RULES[_NETWORKAI_CORS].severity.value == "low"
