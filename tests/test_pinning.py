"""Tests for agent_audit_kit.pinning module."""
from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.pinning import (
    _discover_tools,
    _hash_tool,
    create_pins,
    verify_pins,
)


def _write_mcp_config(project_root: Path, servers: dict) -> None:
    """Write an .mcp.json with the given server definitions."""
    (project_root / ".mcp.json").write_text(
        json.dumps({"mcpServers": servers})
    )


def _make_server_with_tools(tools: list[dict]) -> dict:
    return {"command": "test-cmd", "tools": tools}


class TestHashTool:
    def test_consistent_hash(self) -> None:
        h1 = _hash_tool("tool", "desc", '{"type":"object"}')
        h2 = _hash_tool("tool", "desc", '{"type":"object"}')
        assert h1 == h2

    def test_different_name_different_hash(self) -> None:
        h1 = _hash_tool("tool_a", "desc", "{}")
        h2 = _hash_tool("tool_b", "desc", "{}")
        assert h1 != h2

    def test_different_description_different_hash(self) -> None:
        h1 = _hash_tool("tool", "desc_a", "{}")
        h2 = _hash_tool("tool", "desc_b", "{}")
        assert h1 != h2


class TestDiscoverTools:
    def test_finds_tools_in_mcp_json(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path, {
            "server1": _make_server_with_tools([
                {"name": "read_file", "description": "Read a file", "inputSchema": {}},
            ]),
        })
        tools = _discover_tools(tmp_path)
        assert "server1/read_file" in tools
        assert tools["server1/read_file"]["name"] == "read_file"

    def test_empty_project_returns_empty(self, tmp_path: Path) -> None:
        tools = _discover_tools(tmp_path)
        assert tools == {}

    def test_multiple_servers_and_tools(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path, {
            "srv1": _make_server_with_tools([
                {"name": "t1", "description": "d1"},
                {"name": "t2", "description": "d2"},
            ]),
            "srv2": _make_server_with_tools([
                {"name": "t3", "description": "d3"},
            ]),
        })
        tools = _discover_tools(tmp_path)
        assert len(tools) == 3
        assert "srv1/t1" in tools
        assert "srv1/t2" in tools
        assert "srv2/t3" in tools


class TestCreatePins:
    def test_creates_tool_pins_json(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path, {
            "server": _make_server_with_tools([
                {"name": "my_tool", "description": "Does stuff", "inputSchema": {"type": "object"}},
            ]),
        })
        count = create_pins(tmp_path)
        assert count == 1

        pin_file = tmp_path / ".agent-audit-kit" / "tool-pins.json"
        assert pin_file.exists()

        pins = json.loads(pin_file.read_text())
        assert "server/my_tool" in pins
        assert "hash" in pins["server/my_tool"]
        assert "name" in pins["server/my_tool"]

    def test_pins_multiple_tools(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "t1", "description": "d1"},
                {"name": "t2", "description": "d2"},
            ]),
        })
        count = create_pins(tmp_path)
        assert count == 2

    def test_empty_project_pins_nothing(self, tmp_path: Path) -> None:
        count = create_pins(tmp_path)
        assert count == 0

    def test_creates_agent_audit_kit_directory(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([{"name": "t", "description": "d"}]),
        })
        create_pins(tmp_path)
        assert (tmp_path / ".agent-audit-kit").is_dir()


class TestVerifyPins:
    def test_no_pin_file_returns_empty(self, tmp_path: Path) -> None:
        findings = verify_pins(tmp_path)
        assert findings == []

    def test_detects_changed_tools(self, tmp_path: Path) -> None:
        # Create initial pins
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "tool1", "description": "original description"},
            ]),
        })
        create_pins(tmp_path)

        # Change the tool description
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "tool1", "description": "MODIFIED description"},
            ]),
        })

        findings = verify_pins(tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "AAK-RUGPULL-001"
        assert "changed" in findings[0].evidence.lower()

    def test_detects_new_tools(self, tmp_path: Path) -> None:
        # Create initial pins with one tool
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "tool1", "description": "original"},
            ]),
        })
        create_pins(tmp_path)

        # Add a new tool
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "tool1", "description": "original"},
                {"name": "tool2", "description": "new tool"},
            ]),
        })

        findings = verify_pins(tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "AAK-RUGPULL-002"
        assert "new" in findings[0].evidence.lower() or "added" in findings[0].evidence.lower()

    def test_detects_removed_tools(self, tmp_path: Path) -> None:
        # Create initial pins with two tools
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "tool1", "description": "desc1"},
                {"name": "tool2", "description": "desc2"},
            ]),
        })
        create_pins(tmp_path)

        # Remove one tool
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "tool1", "description": "desc1"},
            ]),
        })

        findings = verify_pins(tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "AAK-RUGPULL-003"
        assert "removed" in findings[0].evidence.lower()

    def test_no_changes_returns_empty(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "tool1", "description": "stable"},
            ]),
        })
        create_pins(tmp_path)

        # No changes to config
        findings = verify_pins(tmp_path)
        assert findings == []

    def test_malformed_pin_file_returns_empty(self, tmp_path: Path) -> None:
        pin_dir = tmp_path / ".agent-audit-kit"
        pin_dir.mkdir()
        (pin_dir / "tool-pins.json").write_text("{bad json")

        findings = verify_pins(tmp_path)
        assert findings == []

    def test_combined_changes_detected(self, tmp_path: Path) -> None:
        # Create pins with tools A and B
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "toolA", "description": "descA"},
                {"name": "toolB", "description": "descB"},
            ]),
        })
        create_pins(tmp_path)

        # Change A's description, remove B, add C
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([
                {"name": "toolA", "description": "CHANGED"},
                {"name": "toolC", "description": "descC"},
            ]),
        })

        findings = verify_pins(tmp_path)
        rule_ids = {f.rule_id for f in findings}
        assert "AAK-RUGPULL-001" in rule_ids  # toolA changed
        assert "AAK-RUGPULL-002" in rule_ids  # toolC added
        assert "AAK-RUGPULL-003" in rule_ids  # toolB removed
        assert len(findings) == 3
