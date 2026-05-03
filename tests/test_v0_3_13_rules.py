"""v0.3.13 tests — chatgpt-mcp-server CVE-2026-7061 pin-check (closes #80)."""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.supply_chain import scan as supply_chain_scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves"
CHATGPT_RULE = "AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001"


def test_chatgpt_mcp_git_url_pin_fires(tmp_path: Path) -> None:
    """package.json with `"chatgpt-mcp-server": "git+https://..."` must fire."""
    src = FIXTURES / "cve-2026-7061-chatgpt-mcp" / "vulnerable-git" / "package.json"
    shutil.copy(src, tmp_path / "package.json")
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == CHATGPT_RULE]
    assert len(fires) == 1
    assert "git+https" in fires[0].evidence or "Toowiredd" in fires[0].evidence


def test_chatgpt_mcp_github_shorthand_pin_fires(tmp_path: Path) -> None:
    """package.json with `"chatgpt-mcp-server": "github:Toowiredd/..."` must fire."""
    src = FIXTURES / "cve-2026-7061-chatgpt-mcp" / "vulnerable-shorthand" / "package.json"
    shutil.copy(src, tmp_path / "package.json")
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == CHATGPT_RULE]
    assert len(fires) == 1


def test_chatgpt_mcp_safe_passes(tmp_path: Path) -> None:
    """package.json without chatgpt-mcp-server must not fire."""
    src = FIXTURES / "cve-2026-7061-chatgpt-mcp" / "safe" / "package.json"
    shutil.copy(src, tmp_path / "package.json")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == CHATGPT_RULE for f in findings)


def test_chatgpt_mcp_no_package_json_passes(tmp_path: Path) -> None:
    """No package.json at root → rule must not fire."""
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == CHATGPT_RULE for f in findings)
