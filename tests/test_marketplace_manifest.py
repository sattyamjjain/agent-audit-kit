"""Tests for scanners/marketplace_manifest.py (AAK-MARKETPLACE-001..004)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

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


# --- AAK-MARKETPLACE-005: a manifest AAK cannot read is reported, not skipped ---


def _write_manifest(tmp_path: Path, payload: bytes) -> Path:
    plugin_dir = tmp_path / ".claude-plugin"
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "marketplace.json").write_bytes(payload)
    return tmp_path


def _rule_ids(project: Path) -> list[str]:
    findings, _ = marketplace_manifest.scan(project)
    return [f.rule_id for f in findings]


@pytest.mark.parametrize("payload", [
    b'{"name": "old", "plugins": [{"name": "acme-tool",}]}',   # trailing comma
    b'{"plugins": [ // a comment\n {"name": "acme-tool"}]}',
    b'{"name": "\xff\xfe"}',                                   # not UTF-8
    b'[{"name": "acme-tool"}]',                                # JSON, not an object
])
def test_an_unreadable_manifest_is_reported(tmp_path: Path, payload: bytes) -> None:
    findings, _ = marketplace_manifest.scan(_write_manifest(tmp_path, payload))
    assert [f.rule_id for f in findings] == ["AAK-MARKETPLACE-005"]
    assert findings[0].severity.value == "low"
    assert ".claude-plugin/marketplace.json" in findings[0].evidence


def test_the_parse_error_points_at_its_line(tmp_path: Path) -> None:
    payload = b'{\n  "name": "old",\n  "plugins": [{"name": "acme-tool",}]\n}\n'
    findings, _ = marketplace_manifest.scan(_write_manifest(tmp_path, payload))
    assert findings[0].line_number == 3
    assert "is not valid JSON" in findings[0].evidence


def test_a_byte_order_mark_does_not_make_a_manifest_unreadable(tmp_path: Path) -> None:
    payload = b'\xef\xbb\xbf{"name": "m", "plugins": [{"name": "acme-tool"}]}'
    assert _rule_ids(_write_manifest(tmp_path, payload)) == ["AAK-MARKETPLACE-001"]


def test_a_readable_manifest_is_not_reported_as_unreadable(tmp_path: Path) -> None:
    project = _stage(tmp_path, "safe.json")
    assert "AAK-MARKETPLACE-005" not in _rule_ids(project)


def test_aak_scan_shows_an_unreadable_manifest_at_default_settings(tmp_path: Path) -> None:
    """The finding must be visible at the default reporting floor, not only in a
    lowered `--severity info` run, or the file still reads as clean."""
    from click.testing import CliRunner

    from agent_audit_kit.cli import cli

    _write_manifest(tmp_path, b'{"name": "old", "plugins": [{"name": "acme-tool",}]}')
    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "AAK-MARKETPLACE-005" in result.output
