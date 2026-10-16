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


# --- AAK-MARKETPLACE-002: a grant at least as broad as a listed one ---


def _broad(tmp_path: Path, permissions: object) -> list[str]:
    import json

    manifest = {"name": "acme-market", "plugins": [
        {"name": "acme-tool", "signature": "sig", "permissions": permissions},
    ]}
    project = _write_manifest(tmp_path, json.dumps(manifest, indent=2).encode())
    findings, _ = marketplace_manifest.scan(project)
    return [f.evidence for f in findings if f.rule_id == "AAK-MARKETPLACE-002"]


@pytest.mark.parametrize("permissions,shown", [
    (["shell:exec"], "shell:exec"),
    (["shell:*"], "shell:*"),              # broader than shell:exec
    (["*"], "*"),                          # every scope and action
    (["*:exec"], "*:exec"),                # exec on every scope
    (["SHELL:EXEC"], "SHELL:EXEC"),        # case is not a different grant
    ([" fs : * "], " fs : * "),
    (["Network:*"], "Network:*"),
    ({"fs": "*"}, "fs:*"),                 # the object form
    ({"shell": ["read", "exec"]}, "shell:exec"),
    ({"shell": True}, "shell: true"),      # a boolean grants every action
    ("shell:exec", "shell:exec"),          # one grant written as a string
    ("*", "*"),
])
def test_a_grant_covering_a_broad_one_fires(tmp_path: Path, permissions: object, shown: str) -> None:
    """Six exact strings were compared, so `shell:*` and a bare `*`, both
    broader than `shell:exec`, passed while `shell:exec` was flagged."""
    (evidence,) = _broad(tmp_path, permissions)
    assert evidence.endswith(f"declares broad permissions: {shown}")


@pytest.mark.parametrize("permissions", [
    ["fs:read"], ["fs:write"], ["shell:read"], ["credentials:read"],
    ["*:read"],  # reads everything, but covers none of the six broad grants
    ["network"], ["files:*"], [], {"fs": "read"}, {"shell": False}, {"fs": None},
    "fs:read", "", [7, None], 7,
])
def test_a_narrower_grant_is_quiet(tmp_path: Path, permissions: object) -> None:
    assert _broad(tmp_path, permissions) == []
