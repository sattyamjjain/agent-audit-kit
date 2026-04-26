"""AAK-SPLUNK-MCP-TOKEN-LEAK-001 — config-side variant."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.splunk_mcp_config import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-20205-config"


def test_vulnerable_yaml_fires(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "vulnerable-yaml", tmp_path / "splunk-mcp", dirs_exist_ok=True)
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-SPLUNK-MCP-TOKEN-LEAK-001" for f in findings)


def test_patched_yaml_passes(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "patched-yaml", tmp_path / "splunk-mcp", dirs_exist_ok=True)
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-SPLUNK-MCP-TOKEN-LEAK-001" for f in findings)


def test_vulnerable_inputs_conf_fires(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "vulnerable-inputs", tmp_path / "splunk-mcp", dirs_exist_ok=True)
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-SPLUNK-MCP-TOKEN-LEAK-001" for f in findings)
