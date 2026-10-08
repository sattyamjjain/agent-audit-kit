"""v0.3.16 — AAK-CLAUDECODE-CVE-2026-40068-PIN-001 (Claude Code <2.1.83
folder-trust bypass via git worktree commondir).

Closes the v0.3.15 triage deferral of issue #181. Since 2026-10-08 the floor is
2.1.129, for CVE-2026-103435 (#920).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
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
    """`@anthropic-ai/claude-code` >= 2.1.129 must not fire (the floor rose from
    2.1.83 for CVE-2026-103435)."""
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


# --- 2026-10-08 (#920): CVE-2026-103435 raises the floor to 2.1.129 ---------------
FIXTURES_103435 = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-103435-claude-code"


def test_cve_2026_103435_fixtures_positive_and_negative(tmp_path: Path) -> None:
    for kind, fires in (("vulnerable", True), ("negative", False)):
        work = tmp_path / kind
        work.mkdir()
        shutil.copy(FIXTURES_103435 / kind / "package.json", work / "package.json")
        findings, _ = supply_chain_scan(work)
        assert any(f.rule_id == RULE for f in findings) is fires, kind


@pytest.mark.parametrize(("version", "fires", "names_folder_trust"), [
    ("2.1.81", True, True),     # below both fixes
    ("2.1.83", True, False),    # folder trust fixed, the write-time symlink is not
    ("2.1.128", True, False),
    ("2.1.129", False, False),
])
def test_claudecode_floor_is_2_1_129(
    tmp_path: Path, version: str, fires: bool, names_folder_trust: bool
) -> None:
    """The fix is above the old 2.1.83 floor and the CVE is HIGH like the rule, so
    the floor moves. The evidence names the folder-trust bug only where it applies."""
    (tmp_path / "package.json").write_text(
        '{"devDependencies": {"@anthropic-ai/claude-code": "%s"}}' % version,
        encoding="utf-8",
    )
    findings = [f for f in supply_chain_scan(tmp_path)[0] if f.rule_id == RULE]
    assert bool(findings) is fires
    if findings:
        assert "CVE-2026-103435" in findings[0].evidence
        assert ("CVE-2026-40068" in findings[0].evidence) is names_folder_trust
    assert "CVE-2026-103435" in RULES[RULE].cve_references
