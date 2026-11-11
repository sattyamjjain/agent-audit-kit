"""v0.3.16 — AAK-CLAUDECODE-CVE-2026-40068-PIN-001 (Claude Code <2.1.84
folder-trust bypass via git worktree commondir).

Closes the v0.3.15 triage deferral of issue #181. Since 2026-10-08 the floor is
2.1.129, for CVE-2026-103435 (#920), since 2026-10-16 2.1.179, for CVE-2026-86063,
and since 2026-11-11 2.1.251, for CVE-2026-88968 (#1185). The folder-trust fix is
2.1.84 (GHSA-q5hj-mxqh-vv77); the pin said 2.1.83 until 2026-10-16.
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
    """`@anthropic-ai/claude-code` >= 2.1.251 must not fire (the floor rose from
    2.1.83 for CVE-2026-103435, from 2.1.129 for CVE-2026-86063, then from 2.1.179
    for CVE-2026-88968)."""
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


# --- 2026-10-16: CVE-2026-86063 raises the floor to 2.1.179 -------------------------
FIXTURES_86063 = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-86063-claude-code"


def test_cve_2026_86063_fixtures_positive_and_negative(tmp_path: Path) -> None:
    for kind, fires in (("vulnerable", True), ("negative", False)):
        work = tmp_path / kind
        work.mkdir()
        shutil.copy(FIXTURES_86063 / kind / "package.json", work / "package.json")
        findings, _ = supply_chain_scan(work)
        assert any(f.rule_id == RULE for f in findings) is fires, kind


_E = "CVE-2026-88968"  # every release below 2.1.251; the advisory gives no lower bound


@pytest.mark.parametrize(("version", "fires", "named"), [
    ("2.0.0", True, {"CVE-2026-103435", _E}),
    ("2.1.13", True, {"CVE-2026-103435", _E}),                       # before plugin commit pins
    ("2.1.14", True, {"CVE-2026-103435", "CVE-2026-86063", _E}),     # commit pins arrive
    ("2.1.62", True, {"CVE-2026-103435", "CVE-2026-86063", _E}),
    ("2.1.63", True, {"CVE-2026-40068", "CVE-2026-103435", "CVE-2026-86063", _E}),
    ("2.1.81", True, {"CVE-2026-40068", "CVE-2026-103435", "CVE-2026-86063", _E}),
    ("2.1.83", True, {"CVE-2026-40068", "CVE-2026-103435", "CVE-2026-86063", _E}),
    ("2.1.84", True, {"CVE-2026-103435", "CVE-2026-86063", _E}),     # folder trust fixed
    ("2.1.128", True, {"CVE-2026-103435", "CVE-2026-86063", _E}),
    ("2.1.129", True, {"CVE-2026-86063", _E}),                       # an old floor
    ("2.1.178", True, {"CVE-2026-86063", _E}),
    ("2.1.179", True, {_E}),                                         # the floor before 2026-11-11
    ("2.1.250", True, {_E}),
    ("2.1.251", False, set()),
])
def test_claudecode_floor_is_2_1_251(
    tmp_path: Path, version: str, fires: bool, named: set[str]
) -> None:
    """Each fix sat above the floor before it, and each CVE is HIGH like the rule,
    so the floor moved each time. The evidence names each bug only where it applies:
    CVE-2026-40068 from 2.1.63 below 2.1.84, CVE-2026-103435 below 2.1.129,
    CVE-2026-86063 from 2.1.14, which added commit pins for plugins, below 2.1.179,
    and CVE-2026-88968 below 2.1.251."""
    (tmp_path / "package.json").write_text(
        '{"devDependencies": {"@anthropic-ai/claude-code": "%s"}}' % version,
        encoding="utf-8",
    )
    findings = [f for f in supply_chain_scan(tmp_path)[0] if f.rule_id == RULE]
    assert bool(findings) is fires
    cves = {"CVE-2026-40068", "CVE-2026-103435", "CVE-2026-86063", _E}
    if findings:
        assert {c for c in cves if c in findings[0].evidence} == named
    assert set(RULES[RULE].cve_references) == cves
