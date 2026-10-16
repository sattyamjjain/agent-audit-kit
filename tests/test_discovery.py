"""Tests for agent_audit_kit.discovery module."""
from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.discovery import (
    DiscoveredAgent,
    _count_hooks,
    discover_agents,
)


class TestDiscoverAgents:
    def test_finds_claude_code_when_mcp_json_exists(self, tmp_path: Path) -> None:
        mcp_cfg = {"mcpServers": {"fs": {"command": "mcp-fs"}}}
        (tmp_path / ".mcp.json").write_text(json.dumps(mcp_cfg))

        agents = discover_agents(project_root=tmp_path)
        project_agents = [a for a in agents if a.name == "Claude Code"]
        assert len(project_agents) == 1
        agent = project_agents[0]
        assert any(".mcp.json" in f for f in agent.config_files)

    def test_returns_correct_fields(self, tmp_path: Path) -> None:
        mcp_cfg = {"mcpServers": {"s1": {"command": "cmd1"}, "s2": {"command": "cmd2"}}}
        (tmp_path / ".mcp.json").write_text(json.dumps(mcp_cfg))

        agents = discover_agents(project_root=tmp_path)
        claude = [a for a in agents if a.name == "Claude Code"][0]
        assert isinstance(claude, DiscoveredAgent)
        assert claude.name == "Claude Code"
        assert claude.mcp_server_count == 2
        assert len(claude.config_files) >= 1

    def test_empty_project_returns_no_project_agents(self, tmp_path: Path) -> None:
        agents = discover_agents(project_root=tmp_path)
        # Filter out user-level agents -- only check project-level
        project_names = {
            "Claude Code", "Cursor", "VS Code Copilot", "Windsurf",
            "Amazon Q", "Goose", "Continue", "Roo Code", "Kiro", "ZCode",
        }
        project_agents = [a for a in agents if a.name in project_names]
        assert len(project_agents) == 0

    def test_mcp_server_counting(self, tmp_path: Path) -> None:
        mcp_cfg = {
            "mcpServers": {
                "server-a": {"command": "a"},
                "server-b": {"command": "b"},
                "server-c": {"command": "c"},
            }
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(mcp_cfg))
        agents = discover_agents(project_root=tmp_path)
        claude = [a for a in agents if a.name == "Claude Code"][0]
        assert claude.mcp_server_count == 3

    def test_cursor_detected_when_cursor_mcp_exists(self, tmp_path: Path) -> None:
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        mcp_cfg = {"mcpServers": {"tool": {"command": "tool"}}}
        (cursor_dir / "mcp.json").write_text(json.dumps(mcp_cfg))

        agents = discover_agents(project_root=tmp_path)
        cursor = [a for a in agents if a.name == "Cursor"]
        assert len(cursor) == 1
        assert cursor[0].mcp_server_count == 1

    def test_vscode_servers_are_counted(self, tmp_path: Path) -> None:
        """`.vscode/mcp.json` keeps its servers under `servers`; reading only
        `mcpServers` reported every VS Code workspace as having none."""
        vscode = tmp_path / ".vscode"
        vscode.mkdir()
        cfg = {"servers": {
            "a": {"type": "stdio", "command": "node", "args": ["a.js"]},
            "b": {"type": "http", "url": "https://mcp.example.com/mcp"},
        }}
        (vscode / "mcp.json").write_text(json.dumps(cfg))

        agents = discover_agents(project_root=tmp_path)
        vs_code = [a for a in agents if a.name == "VS Code Copilot"]
        assert len(vs_code) == 1
        assert vs_code[0].mcp_server_count == 2

    def test_hook_counting_from_claude_settings(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {
            "hooks": {
                "PostToolUse": [{"command": "echo 1"}, {"command": "echo 2"}],
                "PreToolUse": [{"command": "echo 3"}],
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(settings))
        # Also need at least one file for Claude Code to be discovered
        (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {}}))

        agents = discover_agents(project_root=tmp_path)
        claude = [a for a in agents if a.name == "Claude Code"][0]
        assert claude.hook_count == 3

    def test_hook_counting_counts_each_hook_in_a_matcher_group(self, tmp_path: Path) -> None:
        """Claude Code's documented shape nests the hooks in a matcher group; the
        count is of hooks, not of groups (it read 2 here before)."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "echo 1"},
                        {"type": "command", "command": "echo 2"},
                    ],
                }],
                "Stop": [{"hooks": [{"type": "command", "command": "echo 3"}]}],
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(settings))

        agents = discover_agents(project_root=tmp_path)
        claude = [a for a in agents if a.name == "Claude Code"][0]
        assert claude.hook_count == 3

    def test_malformed_json_skipped(self, tmp_path: Path) -> None:
        (tmp_path / ".mcp.json").write_text("{invalid json")
        agents = discover_agents(project_root=tmp_path)
        claude = [a for a in agents if a.name == "Claude Code"]
        # File exists so agent is discovered, but parsing fails gracefully
        assert len(claude) == 1
        assert claude[0].mcp_server_count == 0

    def test_none_project_root_returns_only_user_agents(self) -> None:
        agents = discover_agents(project_root=None)
        project_names = {
            "Claude Code", "Cursor", "VS Code Copilot", "Windsurf",
            "Amazon Q", "Goose", "Continue", "Roo Code", "Kiro", "ZCode",
        }
        project_agents = [a for a in agents if a.name in project_names]
        assert len(project_agents) == 0


class TestCountHooks:
    def test_empty_dict(self) -> None:
        assert _count_hooks({}) == 0

    def test_hooks_with_lists(self) -> None:
        data = {"hooks": {"event1": [{"cmd": "a"}, {"cmd": "b"}], "event2": [{"cmd": "c"}]}}
        assert _count_hooks(data) == 3

    def test_hooks_non_list_value(self) -> None:
        data = {"hooks": {"event1": {"command": "a"}}}
        assert _count_hooks(data) == 1

    def test_a_bare_string_under_an_event_is_not_a_hook(self) -> None:
        """Counted as one while the count was of entries; it defines no hook a
        client would run, so a count of hooks leaves it out."""
        data = {"hooks": {"event1": "single-value"}}
        assert _count_hooks(data) == 0

    def test_hooks_not_dict_returns_zero(self) -> None:
        data = {"hooks": "invalid"}
        assert _count_hooks(data) == 0
