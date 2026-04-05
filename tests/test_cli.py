"""Integration tests for the AgentAuditKit CLI.

Exercises the ``scan`` command through Click's ``CliRunner``, covering
exit-code behaviour, output formats, rule exclusion, config-file loading,
and the ``--ci`` shorthand.
"""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit import __version__
from agent_audit_kit.cli import cli

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_vulnerable_mcp(project: Path) -> None:
    """Write a .mcp.json that triggers CRITICAL (AAK-MCP-001) and MEDIUM
    (AAK-MCP-005 / AAK-MCP-007) findings."""
    mcp = {
        "mcpServers": {
            "remote-no-auth": {
                "url": "https://mcp.evil-corp.com/api",
                "transport": "sse",
            },
            "npx-no-pin": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem", "/home/user/data"],
            },
        }
    }
    (project / ".mcp.json").write_text(json.dumps(mcp), encoding="utf-8")


def _write_medium_only_mcp(project: Path) -> None:
    """Write a .mcp.json that triggers only MEDIUM-severity findings
    (AAK-MCP-005 npx without version pin)."""
    mcp = {
        "mcpServers": {
            "npx-no-pin": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem", "/home/user/data"],
            },
        }
    }
    (project / ".mcp.json").write_text(json.dumps(mcp), encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_scan_default_exit_zero_on_clean(tmp_path: Path) -> None:
    """Scanning a clean directory (no configs) should exit 0."""
    result = runner.invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output


def test_fail_on_critical_exits_zero_when_only_medium(tmp_path: Path) -> None:
    """--fail-on critical should not trip when the worst finding is MEDIUM."""
    _write_medium_only_mcp(tmp_path)
    result = runner.invoke(cli, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 0, result.stderr


def test_fail_on_medium_exits_one_when_medium_exists(tmp_path: Path) -> None:
    """--fail-on medium should exit 1 when a MEDIUM finding is present."""
    _write_medium_only_mcp(tmp_path)
    result = runner.invoke(cli, ["scan", str(tmp_path), "--fail-on", "medium"])
    assert result.exit_code == 1, result.stderr


def test_fail_on_none_always_exits_zero(tmp_path: Path) -> None:
    """--fail-on none should always exit 0 regardless of findings."""
    _write_vulnerable_mcp(tmp_path)
    result = runner.invoke(cli, ["scan", str(tmp_path), "--fail-on", "none"])
    assert result.exit_code == 0, result.output


def test_ci_flag_produces_sarif_file(tmp_path: Path) -> None:
    """--ci should write an agent-audit-results.sarif file in cwd."""
    # Use isolated filesystem so the sarif file is written inside a temp dir
    with runner.isolated_filesystem(temp_dir=tmp_path) as td:
        project = Path(td) / "project"
        project.mkdir()
        result = runner.invoke(cli, ["scan", str(project), "--ci"])
        sarif_path = Path(td) / "agent-audit-results.sarif"
        assert sarif_path.is_file(), (
            f"Expected SARIF file at {sarif_path}; "
            f"exit_code={result.exit_code}, stderr={result.stderr}"
        )
        content = json.loads(sarif_path.read_text(encoding="utf-8"))
        assert content["version"] == "2.1.0"


def test_ci_flag_sets_fail_on_high(tmp_path: Path) -> None:
    """--ci implies --fail-on high; a CRITICAL finding should cause exit 1."""
    _write_vulnerable_mcp(tmp_path)
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(cli, ["scan", str(tmp_path), "--ci"])
    assert result.exit_code == 1, (
        f"Expected exit 1 due to CRITICAL findings; stderr={result.stderr}"
    )


def test_format_json_valid(tmp_path: Path) -> None:
    """--format json should produce valid JSON output."""
    _write_vulnerable_mcp(tmp_path)
    result = runner.invoke(cli, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "findings" in data
    assert "summary" in data
    assert data["summary"]["total"] > 0


def test_exclude_rules_suppresses(tmp_path: Path) -> None:
    """--exclude-rules AAK-MCP-001 should remove that rule from output."""
    _write_vulnerable_mcp(tmp_path)
    result = runner.invoke(
        cli,
        ["scan", str(tmp_path), "--format", "json", "--exclude-rules", "AAK-MCP-001"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    rule_ids = {f["ruleId"] for f in data["findings"]}
    assert "AAK-MCP-001" not in rule_ids


def test_config_file_loaded(tmp_path: Path) -> None:
    """A .agent-audit-kit.yml with exclude-rules should suppress those rules."""
    _write_vulnerable_mcp(tmp_path)
    config_content = (
        "exclude-rules:\n"
        "  - AAK-MCP-001\n"
        "  - AAK-MCP-005\n"
    )
    (tmp_path / ".agent-audit-kit.yml").write_text(config_content, encoding="utf-8")
    result = runner.invoke(
        cli, ["scan", str(tmp_path), "--format", "json"]
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    rule_ids = {f["ruleId"] for f in data["findings"]}
    assert "AAK-MCP-001" not in rule_ids
    assert "AAK-MCP-005" not in rule_ids


def test_version_command() -> None:
    """--version should print the package version and exit 0."""
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_fail_on_prints_failing_findings(tmp_path: Path) -> None:
    """When --fail-on threshold is exceeded, stderr should contain 'FAILED' and
    the offending rule IDs."""
    _write_vulnerable_mcp(tmp_path)
    result = runner.invoke(cli, ["scan", str(tmp_path), "--fail-on", "high"])
    assert result.exit_code == 1
    assert "FAILED" in result.stderr
    assert "AAK-MCP-001" in result.stderr
