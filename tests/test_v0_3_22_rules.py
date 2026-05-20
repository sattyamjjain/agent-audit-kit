"""v0.3.22 — SkillsVote lifecycle attribution + Code-as-Harness shared-state rules.

Anchors:
- arXiv:2605.18401 — SkillsVote (Liu et al., 2026-05-18)
- arXiv:2605.18747 — Code as Agent Harness (Ning et al., 2026-05-18)

Both rules MEDIUM (research-grade) — papers don't prescribe specific
code shapes; rules catch the most concrete extrapolations.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.agent_harness_shared_state import scan as harness_scan
from agent_audit_kit.scanners.skill_lifecycle_attribution import scan as skill_scan

FIXTURES = Path(__file__).parent / "fixtures"

SKILL_RULE = "AAK-SKILL-LIFECYCLE-ATTRIBUTION-001"
HARNESS_RULE = "AAK-AGENT-HARNESS-SHARED-STATE-001"


# -------------------- Suggestion 1: SkillsVote attribution --------------------


def test_skill_mutates_without_attribution_fires(tmp_path: Path) -> None:
    """@skill execute writes a file but emits no record_outcome — must fire MEDIUM."""
    (tmp_path / "skills").mkdir()  # path hint
    shutil.copy(
        FIXTURES / "skill_lifecycle" / "unsafe_skill.py",
        tmp_path / "skills" / "unsafe_skill.py",
    )
    findings, _ = skill_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == SKILL_RULE]
    assert len(fires) == 1
    assert fires[0].severity.name == "MEDIUM"


def test_skill_with_record_outcome_passes(tmp_path: Path) -> None:
    """@skill execute that calls record_outcome must NOT fire."""
    (tmp_path / "skills").mkdir()
    shutil.copy(
        FIXTURES / "skill_lifecycle" / "safe_skill.py",
        tmp_path / "skills" / "safe_skill.py",
    )
    findings, _ = skill_scan(tmp_path)
    assert not any(f.rule_id == SKILL_RULE for f in findings)


def test_skill_no_decorator_outside_skills_path_passes(tmp_path: Path) -> None:
    """File with eval-like shape but no @skill + not in skills path → pass."""
    (tmp_path / "normal.py").write_text(
        "from pathlib import Path\n\ndef execute(x):\n    Path('y').write_text(x)\n",
        encoding="utf-8",
    )
    findings, _ = skill_scan(tmp_path)
    assert not any(f.rule_id == SKILL_RULE for f in findings)


# -------------------- Suggestion 2: Code-as-Harness shared state --------------


def test_multi_agent_shared_dict_no_lock_fires(tmp_path: Path) -> None:
    """Two Agent classes mutating _SHARED without a Lock must fire MEDIUM."""
    shutil.copy(
        FIXTURES / "harness_shared_state" / "unsafe_multi_agent.py",
        tmp_path / "agents.py",
    )
    findings, _ = harness_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == HARNESS_RULE]
    assert len(fires) == 1
    assert "ReaderAgent" in fires[0].evidence
    assert "WriterAgent" in fires[0].evidence


def test_multi_agent_with_lock_passes(tmp_path: Path) -> None:
    """Same shape but with `with _LOCK:` guards must NOT fire."""
    shutil.copy(
        FIXTURES / "harness_shared_state" / "safe_multi_agent.py",
        tmp_path / "agents.py",
    )
    findings, _ = harness_scan(tmp_path)
    assert not any(f.rule_id == HARNESS_RULE for f in findings)


def test_single_agent_class_no_fire(tmp_path: Path) -> None:
    """Only ONE Agent class mutating shared state — does not satisfy ≥2-agents rule."""
    (tmp_path / "single.py").write_text(
        "_SHARED: dict = {}\n\nclass SoloAgent:\n    def add(self, k, v):\n        _SHARED[k] = v\n",
        encoding="utf-8",
    )
    findings, _ = harness_scan(tmp_path)
    assert not any(f.rule_id == HARNESS_RULE for f in findings)
