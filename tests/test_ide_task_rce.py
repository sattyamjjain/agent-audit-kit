"""Tests for the VS Code IDE task/launch folder-open RCE scanner.

AAK-IDE-TASK-001..004 — the surface the keyv worm used (`runOn: folderOpen`)
that the scanner did not read before (`.vscode/mcp.json` was covered,
`.vscode/tasks.json` / `.vscode/launch.json` were not).
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners import ide_task_rce

_FIXTURES = Path(__file__).parent / "fixtures" / "ide_task_rce"


def _ids(root: Path) -> list[str]:
    findings, _ = ide_task_rce.scan(root)
    return [f.rule_id for f in findings]


def _by_id(root: Path, rule_id: str):
    findings, _ = ide_task_rce.scan(root)
    return [f for f in findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# Worm shape: a folderOpen task invoking a script in the repo.
# ---------------------------------------------------------------------------


def test_worm_folderopen_shell_is_critical() -> None:
    hits = _by_id(_FIXTURES / "worm", "AAK-IDE-TASK-001")
    assert hits, "folderOpen auto-run must fire AAK-IDE-TASK-001"
    assert hits[0].severity.value == "critical", (
        "a folderOpen task that runs a shell/interpreter must escalate to critical"
    )
    assert ".vscode/tasks.json" in hits[0].file_path


def test_worm_command_reaches_shell_002() -> None:
    # `bash ./scripts/postinstall.sh` is an interpreter on a repo-local script path.
    assert "AAK-IDE-TASK-002" in _ids(_FIXTURES / "worm")


def test_worm_launch_prelaunchtask_chain_003_names_both_files() -> None:
    hits = _by_id(_FIXTURES / "worm", "AAK-IDE-TASK-003")
    assert hits, "launch.json preLaunchTask -> flagged task must fire AAK-IDE-TASK-003"
    ev = hits[0].evidence
    assert ".vscode/launch.json" in hits[0].file_path
    assert "tasks.json" in ev and "postinstall" in ev


# ---------------------------------------------------------------------------
# Clean negative fixture: no folderOpen, no shell-reaching command.
# ---------------------------------------------------------------------------


def test_clean_fixture_has_no_findings() -> None:
    assert _ids(_FIXTURES / "clean") == []


# ---------------------------------------------------------------------------
# JSONC: comments + trailing comma + a `//` inside a URL string must survive.
# ---------------------------------------------------------------------------


def test_jsonc_parses_and_still_flags_folderopen() -> None:
    ids = _ids(_FIXTURES / "jsonc")
    # Parser survived the comments/trailing comma → the folderOpen task is flagged.
    assert "AAK-IDE-TASK-001" in ids
    # And it did NOT fall back to the unparseable finding.
    assert "AAK-IDE-TASK-004" not in ids


# ---------------------------------------------------------------------------
# Parse failure: report it (LOW) rather than skipping silently.
# ---------------------------------------------------------------------------


def test_unparseable_config_reports_004(tmp_path: Path) -> None:
    vsc = tmp_path / ".vscode"
    vsc.mkdir()
    # Genuinely broken JSON, not merely JSONC.
    (vsc / "tasks.json").write_text('{ "tasks": [ { "label": }  ')
    ids = _ids(tmp_path)
    assert ids == ["AAK-IDE-TASK-004"]


# ---------------------------------------------------------------------------
# Severity nuance: a folderOpen task whose command is not a shell/interpreter/
# fetch stays HIGH (not critical).
# ---------------------------------------------------------------------------


def test_folderopen_benign_command_is_high(tmp_path: Path) -> None:
    vsc = tmp_path / ".vscode"
    vsc.mkdir()
    (vsc / "tasks.json").write_text(
        '{"version":"2.0.0","tasks":[{"label":"greet","type":"process",'
        '"command":"echo","args":["hello"],"runOptions":{"runOn":"folderOpen"}}]}'
    )
    hits = _by_id(tmp_path, "AAK-IDE-TASK-001")
    assert hits and hits[0].severity.value == "high"


def test_no_vscode_dir_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "tasks.json").write_text('{"tasks":[]}')  # not under .vscode/
    assert _ids(tmp_path) == []
