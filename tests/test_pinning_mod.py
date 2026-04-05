"""Tests for agent_audit_kit.pinning module."""
from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.pinning import create_pins, verify_pins


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_mcp_config(project_root: Path, servers: dict) -> None:
    """Write a .mcp.json with the given mcpServers dict."""
    config = {"mcpServers": servers}
    (project_root / ".mcp.json").write_text(json.dumps(config))


def _make_tool(
    name: str = "read_file",
    description: str = "Read a file from disk",
    input_schema: dict | None = None,
) -> dict:
    """Create a tool definition dict."""
    tool: dict = {"name": name, "description": description}
    if input_schema is not None:
        tool["inputSchema"] = input_schema
    return tool


# ---------------------------------------------------------------------------
# create_pins
# ---------------------------------------------------------------------------


class TestCreatePins:
    def test_creates_tool_pins_json_with_mcp_config(self, tmp_path: Path) -> None:
        """create_pins() creates .agent-audit-kit/tool-pins.json when MCP configs exist."""
        _write_mcp_config(tmp_path, {
            "file-server": {
                "command": "node",
                "args": ["server.js"],
                "tools": [
                    _make_tool("read_file", "Reads a file"),
                    _make_tool("write_file", "Writes a file"),
                ],
            }
        })

        count = create_pins(tmp_path)
        assert count == 2

        pin_file = tmp_path / ".agent-audit-kit" / "tool-pins.json"
        assert pin_file.exists()

        pins = json.loads(pin_file.read_text())
        assert "file-server/read_file" in pins
        assert "file-server/write_file" in pins
        assert "hash" in pins["file-server/read_file"]
        assert "name" in pins["file-server/read_file"]

    def test_creates_empty_pins_with_no_mcp_configs(self, tmp_path: Path) -> None:
        """create_pins() with no MCP configs creates empty pins."""
        count = create_pins(tmp_path)
        assert count == 0

        pin_file = tmp_path / ".agent-audit-kit" / "tool-pins.json"
        assert pin_file.exists()

        pins = json.loads(pin_file.read_text())
        assert pins == {}

    def test_pins_contain_sha256_hashes(self, tmp_path: Path) -> None:
        """Each pin entry should contain a valid-looking SHA-256 hex hash."""
        _write_mcp_config(tmp_path, {
            "srv": {
                "tools": [_make_tool("tool_a", "desc A")],
            }
        })
        create_pins(tmp_path)

        pin_file = tmp_path / ".agent-audit-kit" / "tool-pins.json"
        pins = json.loads(pin_file.read_text())

        for key, pin in pins.items():
            assert len(pin["hash"]) == 64  # SHA-256 hex digest length
            int(pin["hash"], 16)  # Must be valid hex


# ---------------------------------------------------------------------------
# verify_pins -- no changes
# ---------------------------------------------------------------------------


class TestVerifyPinsNoChanges:
    def test_returns_empty_when_pins_match(self, tmp_path: Path) -> None:
        """verify_pins() returns empty when pins match current state."""
        _write_mcp_config(tmp_path, {
            "server-a": {
                "tools": [_make_tool("tool1", "desc1")],
            }
        })

        create_pins(tmp_path)
        findings = verify_pins(tmp_path)
        assert findings == []

    def test_returns_empty_when_no_pin_file(self, tmp_path: Path) -> None:
        """verify_pins() returns empty when no pin file exists."""
        findings = verify_pins(tmp_path)
        assert findings == []


# ---------------------------------------------------------------------------
# verify_pins -- changed tool (AAK-RUGPULL-001)
# ---------------------------------------------------------------------------


class TestVerifyPinsChangedTool:
    def test_detects_changed_tool(self, tmp_path: Path) -> None:
        """verify_pins() detects a changed tool definition (AAK-RUGPULL-001)."""
        _write_mcp_config(tmp_path, {
            "server-a": {
                "tools": [_make_tool("tool1", "Original description")],
            }
        })
        create_pins(tmp_path)

        # Modify the tool description
        _write_mcp_config(tmp_path, {
            "server-a": {
                "tools": [_make_tool("tool1", "Modified description with hidden payload")],
            }
        })

        findings = verify_pins(tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "AAK-RUGPULL-001"
        assert "changed" in findings[0].evidence.lower()

    def test_detects_changed_input_schema(self, tmp_path: Path) -> None:
        """A change in inputSchema alone should also trigger AAK-RUGPULL-001."""
        _write_mcp_config(tmp_path, {
            "srv": {
                "tools": [
                    _make_tool("t", "d", input_schema={"type": "object"}),
                ],
            }
        })
        create_pins(tmp_path)

        _write_mcp_config(tmp_path, {
            "srv": {
                "tools": [
                    _make_tool("t", "d", input_schema={"type": "object", "properties": {"x": {}}}),
                ],
            }
        })

        findings = verify_pins(tmp_path)
        rule_ids = {f.rule_id for f in findings}
        assert "AAK-RUGPULL-001" in rule_ids


# ---------------------------------------------------------------------------
# verify_pins -- new tool (AAK-RUGPULL-002)
# ---------------------------------------------------------------------------


class TestVerifyPinsNewTool:
    def test_detects_new_tool(self, tmp_path: Path) -> None:
        """verify_pins() detects a new tool added since last pin (AAK-RUGPULL-002)."""
        _write_mcp_config(tmp_path, {
            "server-a": {
                "tools": [_make_tool("tool1", "desc1")],
            }
        })
        create_pins(tmp_path)

        # Add a new tool
        _write_mcp_config(tmp_path, {
            "server-a": {
                "tools": [
                    _make_tool("tool1", "desc1"),
                    _make_tool("tool2", "desc2"),
                ],
            }
        })

        findings = verify_pins(tmp_path)
        new_tool_findings = [f for f in findings if f.rule_id == "AAK-RUGPULL-002"]
        assert len(new_tool_findings) == 1
        assert "tool2" in new_tool_findings[0].evidence.lower() or "new" in new_tool_findings[0].evidence.lower()


# ---------------------------------------------------------------------------
# verify_pins -- removed tool (AAK-RUGPULL-003)
# ---------------------------------------------------------------------------


class TestVerifyPinsRemovedTool:
    def test_detects_removed_tool(self, tmp_path: Path) -> None:
        """verify_pins() detects a removed tool (AAK-RUGPULL-003)."""
        _write_mcp_config(tmp_path, {
            "server-a": {
                "tools": [
                    _make_tool("tool1", "desc1"),
                    _make_tool("tool2", "desc2"),
                ],
            }
        })
        create_pins(tmp_path)

        # Remove tool2
        _write_mcp_config(tmp_path, {
            "server-a": {
                "tools": [_make_tool("tool1", "desc1")],
            }
        })

        findings = verify_pins(tmp_path)
        removed_findings = [f for f in findings if f.rule_id == "AAK-RUGPULL-003"]
        assert len(removed_findings) == 1
        assert "tool2" in removed_findings[0].evidence.lower() or "removed" in removed_findings[0].evidence.lower()


# ---------------------------------------------------------------------------
# verify_pins -- combined changes
# ---------------------------------------------------------------------------


class TestVerifyPinsCombined:
    def test_detects_multiple_change_types(self, tmp_path: Path) -> None:
        """A single verify_pins call can detect changed, new, and removed tools."""
        _write_mcp_config(tmp_path, {
            "srv": {
                "tools": [
                    _make_tool("keep_same", "unchanged"),
                    _make_tool("will_change", "original desc"),
                    _make_tool("will_remove", "going away"),
                ],
            }
        })
        create_pins(tmp_path)

        _write_mcp_config(tmp_path, {
            "srv": {
                "tools": [
                    _make_tool("keep_same", "unchanged"),
                    _make_tool("will_change", "MODIFIED desc"),
                    _make_tool("brand_new", "just appeared"),
                ],
            }
        })

        findings = verify_pins(tmp_path)
        rule_ids = {f.rule_id for f in findings}

        assert "AAK-RUGPULL-001" in rule_ids  # will_change modified
        assert "AAK-RUGPULL-002" in rule_ids  # brand_new added
        assert "AAK-RUGPULL-003" in rule_ids  # will_remove gone
