"""Tests for scanners/marketplace_manifest.py (AAK-MARKETPLACE-001..004)."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners import marketplace_manifest

FIX = Path(__file__).parent / "fixtures" / "cves" / "marketplace"


def _stage(tmp_path: Path, fixture: str) -> Path:
    plugin_dir = tmp_path / ".claude-plugin"
    plugin_dir.mkdir()
    shutil.copy(FIX / fixture, plugin_dir / "marketplace.json")
    return tmp_path


def test_vulnerable_manifest_fires_all_four_rules(tmp_path: Path) -> None:
    project = _stage(tmp_path, "vulnerable.json")
    findings, scanned = marketplace_manifest.scan(project)
    ids = {f.rule_id for f in findings}
    assert {
        "AAK-MARKETPLACE-001",
        "AAK-MARKETPLACE-002",
        "AAK-MARKETPLACE-003",
        "AAK-MARKETPLACE-004",
    }.issubset(ids)
    assert any(".claude-plugin/marketplace.json" in p for p in scanned)


def test_safe_manifest_fires_nothing(tmp_path: Path) -> None:
    project = _stage(tmp_path, "safe.json")
    findings, _ = marketplace_manifest.scan(project)
    assert findings == []


def test_typosquat_detection() -> None:
    assert marketplace_manifest._is_typosquat("anthropi")
    assert marketplace_manifest._is_typosquat("lagnchain")
    assert not marketplace_manifest._is_typosquat("company-specific-helpers")
    assert not marketplace_manifest._is_typosquat("anthropic")
