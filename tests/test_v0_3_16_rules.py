"""v0.3.16 — AAK-CLAUDECODE-CVE-2026-40068-PIN-001 (Claude Code <2.1.83
folder-trust bypass via git worktree commondir).

Closes the v0.3.15 triage deferral of issue #181.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.supply_chain import scan as supply_chain_scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-40068-claudecode"
RULE = "AAK-CLAUDECODE-CVE-2026-40068-PIN-001"


def test_claudecode_vulnerable_pin_fires(tmp_path: Path) -> None:
    """`@anthropic-ai/claude-code` < 2.1.83 must fire."""
    shutil.copy(FIXTURES / "pin-vulnerable" / "package.json", tmp_path / "package.json")
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == RULE]
    assert len(fires) == 1
    assert "2.1.81" in fires[0].evidence


def test_claudecode_safe_pin_passes(tmp_path: Path) -> None:
    """`@anthropic-ai/claude-code` >= 2.1.83 must not fire."""
    shutil.copy(FIXTURES / "pin-safe" / "package.json", tmp_path / "package.json")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


def test_claudecode_no_dep_passes(tmp_path: Path) -> None:
    """package.json without @anthropic-ai/claude-code must not fire."""
    (tmp_path / "package.json").write_text(
        '{"name":"x","version":"0.0.1","dependencies":{"react":"^18.0.0"}}',
        encoding="utf-8",
    )
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)
