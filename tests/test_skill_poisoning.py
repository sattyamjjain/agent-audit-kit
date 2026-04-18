"""Tests for scanners/skill_poisoning.py (AAK-SKILL-001..005)."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners import skill_poisoning

FIX = Path(__file__).parent / "fixtures" / "cves" / "skills"


def _stage(tmp_path: Path, fixture: str) -> Path:
    skills = tmp_path / "skills" / "evil-skill"
    skills.mkdir(parents=True)
    shutil.copy(FIX / fixture, skills / "SKILL.md")
    return tmp_path


def test_vulnerable_skill_triggers_multiple_rules(tmp_path: Path) -> None:
    project = _stage(tmp_path, "vulnerable.md")
    findings, scanned = skill_poisoning.scan(project)
    ids = {f.rule_id for f in findings}
    # vulnerable fixture should trigger at least these three signatures:
    assert "AAK-SKILL-001" in ids  # post-install curl|sh
    assert "AAK-SKILL-003" in ids  # exfil shape
    assert "AAK-SKILL-005" in ids  # frontmatter injection trigger
    assert any("SKILL.md" in p for p in scanned)


def test_safe_skill_fires_nothing(tmp_path: Path) -> None:
    project = _stage(tmp_path, "safe.md")
    findings, _ = skill_poisoning.scan(project)
    assert findings == []


def test_frontmatter_parsing() -> None:
    meta, body = skill_poisoning._parse_frontmatter(
        "---\nname: test\ndescription: A skill.\n---\nbody text\n"
    )
    assert meta["name"] == "test"
    assert meta["description"] == "A skill."
    assert "body text" in body


def test_looks_like() -> None:
    assert skill_poisoning._looks_like("pdff", "pdf")
    assert skill_poisoning._looks_like("docxx", "docx")
    assert not skill_poisoning._looks_like("completely-different", "pdf")
    assert not skill_poisoning._looks_like("pdf", "pdf")  # exact match excluded
