"""AAK-MCP-OX-PRESET-2026-04 — preset loader + CLI flag."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.presets import (
    PresetNotFoundError,
    available_presets,
    load_preset,
)
from agent_audit_kit.rules.builtin import RULES


def test_preset_lists_only_real_rule_ids() -> None:
    rule_ids = load_preset("mcp-ox-2026-04")
    assert rule_ids, "preset must list at least one rule"
    for rid in rule_ids:
        assert rid in RULES, f"preset references unknown rule id {rid!r}"


def test_preset_covers_ox_class() -> None:
    rule_ids = set(load_preset("mcp-ox-2026-04"))
    must_have = {
        "AAK-STDIO-001",
        "AAK-ANTHROPIC-SDK-001",
        "AAK-MCP-STDIO-CMD-INJ-001",
        "AAK-MCP-STDIO-CMD-INJ-002",
        "AAK-MCP-STDIO-CMD-INJ-003",
        "AAK-MCP-STDIO-CMD-INJ-004",
        "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001",
        "AAK-AZURE-MCP-NOAUTH-001",
        "AAK-LMDEPLOY-VL-SSRF-001",
        "AAK-SPLUNK-MCP-TOKEN-LEAK-001",
    }
    missing = must_have - rule_ids
    assert not missing, f"preset missing OX-class rules: {missing}"


def test_unknown_preset_raises() -> None:
    with pytest.raises(PresetNotFoundError):
        load_preset("does-not-exist")


def test_available_presets_lists_mcp_ox() -> None:
    assert "mcp-ox-2026-04" in available_presets()


def test_cli_preset_flag_runs_clean(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(tmp_path), "--preset", "mcp-ox-2026-04"],
    )
    # Empty project → clean exit. Bad preset name would have errored.
    assert result.exit_code in (0, 1), result.output


def test_cli_unknown_preset_errors(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(tmp_path), "--preset", "does-not-exist"],
    )
    assert result.exit_code != 0
