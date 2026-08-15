"""`suggest --apply-trivial` must do what its help text says.

The flag shipped in v0.3.8 printing "scaffolded but not yet implemented (queued
for v0.3.9)" and was still printing it at v0.3.78 — seventy releases later —
while `agent-audit-kit fix` had been applying exactly these fixes the whole time.
A flag that documents behaviour it does not have is the same class of problem as
a rule whose remediation names a config key that does not exist.

It now delegates to the same `run_fixes` engine, so there is one fixer and two
entry points rather than two implementations.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.cli import cli

runner = CliRunner()


def _fixable_project(tmp_path: Path) -> Path:
    """A project with findings for two auto-fixable rules."""
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(
        json.dumps({
            "enableAllProjectMcpServers": True,
            "permissions": {"allow": ["Bash(ls:*)"]},
        }, indent=2),
        encoding="utf-8",
    )
    return tmp_path


def _sarif_for(project: Path) -> Path:
    out = project / "scan.sarif"
    result = runner.invoke(cli, ["scan", str(project), "--format", "sarif", "-o", str(out)])
    assert out.is_file(), result.output
    return out


def test_apply_trivial_actually_applies(tmp_path: Path) -> None:
    project = _fixable_project(tmp_path)
    sarif = _sarif_for(project)

    result = runner.invoke(
        cli, ["suggest", str(sarif), "--apply-trivial", "--project", str(project)]
    )
    assert result.exit_code == 0, result.output

    settings = json.loads((project / ".claude" / "settings.json").read_text())
    assert settings["enableAllProjectMcpServers"] is False
    assert settings["permissions"].get("deny"), "default deny rules should have been added"


def test_apply_trivial_writes_a_fix_log(tmp_path: Path) -> None:
    project = _fixable_project(tmp_path)
    sarif = _sarif_for(project)
    runner.invoke(cli, ["suggest", str(sarif), "--apply-trivial", "--project", str(project)])
    assert (project / ".agent-audit-kit" / "fix-log.json").is_file()


def test_dry_run_changes_nothing(tmp_path: Path) -> None:
    project = _fixable_project(tmp_path)
    sarif = _sarif_for(project)
    before = (project / ".claude" / "settings.json").read_text()

    result = runner.invoke(
        cli,
        ["suggest", str(sarif), "--apply-trivial", "--dry-run", "--project", str(project)],
    )
    assert result.exit_code == 0
    assert (project / ".claude" / "settings.json").read_text() == before
    assert not (project / ".agent-audit-kit" / "fix-log.json").exists()


def test_no_longer_claims_to_be_unimplemented(tmp_path: Path) -> None:
    """The specific regression: a flag advertising work it never did."""
    project = _fixable_project(tmp_path)
    sarif = _sarif_for(project)
    result = runner.invoke(
        cli, ["suggest", str(sarif), "--apply-trivial", "--project", str(project)]
    )
    combined = result.output
    assert "not yet implemented" not in combined
    assert "scaffolded" not in combined
    assert "queued for v0.3.9" not in combined


def test_help_text_does_not_promise_a_future_version() -> None:
    result = runner.invoke(cli, ["suggest", "--help"])
    assert "NOT YET IMPLEMENTED" not in result.output
    assert "scaffolded" not in result.output


def test_nothing_fixable_says_so_rather_than_failing(tmp_path: Path) -> None:
    """A project with findings but none auto-fixable must report, not error."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"d": {"command": "npx", "args": ["-y", "x"]}}}),
        encoding="utf-8",
    )
    sarif = _sarif_for(tmp_path)
    result = runner.invoke(
        cli, ["suggest", str(sarif), "--apply-trivial", "--project", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert "no mechanically-safe fix applies" in result.output


def test_without_the_flag_nothing_is_written(tmp_path: Path) -> None:
    project = _fixable_project(tmp_path)
    sarif = _sarif_for(project)
    before = (project / ".claude" / "settings.json").read_text()
    result = runner.invoke(cli, ["suggest", str(sarif), "--project", str(project)])
    assert result.exit_code == 0
    assert (project / ".claude" / "settings.json").read_text() == before


def test_markdown_body_is_still_produced(tmp_path: Path) -> None:
    """Applying fixes must not replace the report; both happen."""
    project = _fixable_project(tmp_path)
    sarif = _sarif_for(project)
    result = runner.invoke(
        cli, ["suggest", str(sarif), "--apply-trivial", "--project", str(project)]
    )
    assert "AgentAuditKit suggested remediations" in result.output
