"""Tests for the AAK-A2A-008..012 extension (2026 gaps)."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.a2a_protocol import scan

FIX = Path(__file__).parent / "fixtures" / "cves" / "a2a_2026"


def test_a2a_2026_gaps_fire(tmp_path: Path) -> None:
    shutil.copy(FIX / "vulnerable_card.json", tmp_path / "agent-card.json")
    findings, _ = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    for rid in ("AAK-A2A-008", "AAK-A2A-009", "AAK-A2A-010", "AAK-A2A-011", "AAK-A2A-012"):
        assert rid in ids, f"expected {rid} to fire; got {ids}"
