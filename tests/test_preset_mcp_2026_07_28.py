"""mcp-2026-07-28 auth-profile preset + --profile CLI alias."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.presets import available_presets, load_preset
from agent_audit_kit.rules.builtin import RULES

PROFILE = "mcp-2026-07-28"
EXPECTED = {"AAK-OAUTH-006", "AAK-OAUTH-007", "AAK-OAUTH-008"}


def test_profile_lists_exactly_the_auth_trio() -> None:
    rule_ids = set(load_preset(PROFILE))
    assert rule_ids == EXPECTED, rule_ids
    for rid in rule_ids:
        assert rid in RULES, f"profile references unknown rule id {rid!r}"


def test_profile_is_available() -> None:
    assert PROFILE in available_presets()


def test_cli_profile_flag_is_alias_for_preset(tmp_path: Path) -> None:
    # A remote MCP config with an embedded credential and no PRM discovery must
    # be flagged by AAK-OAUTH-008 when the profile is selected via --profile.
    (tmp_path / "server.mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "remote": {
                        "type": "http",
                        "url": "https://api.example.com/mcp",
                        "headers": {"Authorization": "Bearer ${TOKEN}"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", str(tmp_path), "--profile", PROFILE, "--format", "json"],
    )
    assert result.exit_code in (0, 1), result.output
    payload = json.loads(result.stdout)
    ids = {f["ruleId"] for f in payload["findings"]}
    assert "AAK-OAUTH-008" in ids
    # The profile narrows the run to the trio — no unrelated rules leak in.
    assert ids <= EXPECTED


def test_cli_profile_and_preset_are_equivalent(tmp_path: Path) -> None:
    (tmp_path / "c.mcp.json").write_text(
        json.dumps({"mcpServers": {"r": {"type": "sse", "url": "https://x/mcp",
                                          "auth": {"type": "oauth"}}}}),
        encoding="utf-8",
    )
    runner = CliRunner()
    a = runner.invoke(cli, ["scan", str(tmp_path), "--profile", PROFILE, "--format", "json"])
    b = runner.invoke(cli, ["scan", str(tmp_path), "--preset", PROFILE, "--format", "json"])
    ids_a = {f["ruleId"] for f in json.loads(a.stdout)["findings"]}
    ids_b = {f["ruleId"] for f in json.loads(b.stdout)["findings"]}
    assert ids_a == ids_b
