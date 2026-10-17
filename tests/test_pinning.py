"""Tests for agent_audit_kit.pinning module."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

import agent_audit_kit
from agent_audit_kit.cli import cli
from agent_audit_kit.pinning import (
    PIN_FILE,
    PinWriteError,
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


# `create_pins` runs in a child process, so a write that blocks on a FIFO fails the test
# on its timeout instead of hanging the suite.
_PIN_CHILD = (
    "import sys\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.pinning import PinWriteError, create_pins\n"
    "try:\n"
    "    print(create_pins(Path(sys.argv[1])))\n"
    "except PinWriteError as exc:\n"
    "    print(exc)\n"
)


class TestCreatePinsWritesOnlyInsideTheProject:
    """`aak pin` wrote its pin file with `Path.mkdir(exist_ok=True)` and `Path.write_text`
    under `.agent-audit-kit/`, which the scanned repository can ship as anything: a link
    to a directory outside the project took the pins there, a link at the pin file had
    them written over its target, and a FIFO blocked the command forever. The write goes
    through `fix._write_inside_project`, and a refusal raises `PinWriteError`."""

    def _projects(self, tmp_path: Path) -> tuple[Path, Path]:
        project, outside = tmp_path / "proj", tmp_path / "outside"
        project.mkdir()
        outside.mkdir()
        _write_mcp_config(project, {"srv": _make_server_with_tools([{"name": "t", "description": "d"}])})
        return project, outside

    def test_the_pin_file_is_written_as_before(self, tmp_path: Path) -> None:
        project, _ = self._projects(tmp_path)

        assert create_pins(project) == 1

        written = (project / PIN_FILE).read_bytes()
        pins = json.loads(written)
        assert written == json.dumps(pins, indent=2).encode()
        assert pins == {"srv/t": {"hash": _hash_tool("t", "d", "{}"), "name": "t"}}

    def test_a_linked_pin_file_is_refused_and_its_target_left_alone(self, tmp_path: Path) -> None:
        project, outside = self._projects(tmp_path)
        (outside / "rc").write_bytes(b"keep\n")
        (project / ".agent-audit-kit").mkdir()
        (project / PIN_FILE).symlink_to(outside / "rc")

        with pytest.raises(PinWriteError, match=r"^\.agent-audit-kit/tool-pins\.json is a symlink$"):
            create_pins(project)
        assert (outside / "rc").read_bytes() == b"keep\n"

    def test_a_dangling_linked_pin_file_creates_nothing(self, tmp_path: Path) -> None:
        project, outside = self._projects(tmp_path)
        (project / ".agent-audit-kit").mkdir()
        (project / PIN_FILE).symlink_to(outside / "created-by-pin")

        with pytest.raises(PinWriteError, match="is a symlink"):
            create_pins(project)
        assert not os.path.lexists(outside / "created-by-pin")

    def test_a_directory_named_like_the_pin_file_is_refused(self, tmp_path: Path) -> None:
        project, _ = self._projects(tmp_path)
        (project / PIN_FILE).mkdir(parents=True)

        with pytest.raises(PinWriteError, match=r"tool-pins\.json is not a regular file$"):
            create_pins(project)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
    def test_a_fifo_named_like_the_pin_file_is_refused_without_blocking(self, tmp_path: Path) -> None:
        project, _ = self._projects(tmp_path)
        (project / ".agent-audit-kit").mkdir()
        os.mkfifo(project / PIN_FILE)
        package_root = Path(agent_audit_kit.__file__).resolve().parent.parent

        done = subprocess.run(
            [sys.executable, "-c", _PIN_CHILD, str(project)], capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONPATH": str(package_root)},
        )

        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == ".agent-audit-kit/tool-pins.json is not a regular file"

    def test_a_directory_linked_out_of_the_project_is_refused(self, tmp_path: Path) -> None:
        project, outside = self._projects(tmp_path)
        (project / ".agent-audit-kit").symlink_to(outside, target_is_directory=True)

        with pytest.raises(PinWriteError, match=r"^\.agent-audit-kit resolves outside the project$"):
            create_pins(project)
        assert os.listdir(outside) == []

    def test_a_dangling_linked_directory_creates_nothing(self, tmp_path: Path) -> None:
        project, outside = self._projects(tmp_path)
        (project / ".agent-audit-kit").symlink_to(outside / "made-by-pin", target_is_directory=True)

        with pytest.raises(PinWriteError, match=r"^\.agent-audit-kit is not a directory$"):
            create_pins(project)
        assert not os.path.lexists(outside / "made-by-pin")

    def test_aak_pin_exits_2_and_says_why(self, tmp_path: Path) -> None:
        project, outside = self._projects(tmp_path)
        (project / ".agent-audit-kit").symlink_to(outside, target_is_directory=True)

        result = CliRunner().invoke(cli, ["pin", str(project)])

        assert result.exit_code == 2
        assert result.output.strip() == (
            "Cannot pin: .agent-audit-kit resolves outside the project. "
            ".agent-audit-kit/tool-pins.json was not written."
        )
        assert os.listdir(outside) == []

    @pytest.mark.usefixtures("full_disk")
    def test_aak_pin_says_a_pin_file_written_part_way_may_hold_part_of_it(self, tmp_path: Path) -> None:
        """A write that fails after the open has truncated the file leaves part of it,
        so the message no longer says the pin file was not written."""
        project, _ = self._projects(tmp_path)

        result = CliRunner().invoke(cli, ["pin", str(project)])

        assert result.exit_code == 2
        assert result.output.strip() == (
            "Cannot pin: tool-pins.json could not be written (No space left on device) and may be partly written."
        )


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

    def test_malformed_pin_file_raises(self, tmp_path: Path) -> None:
        """It used to return [], which every caller read as "matches its pins"."""
        from agent_audit_kit.pinning import PinFileError

        pin_dir = tmp_path / ".agent-audit-kit"
        pin_dir.mkdir()
        (pin_dir / "tool-pins.json").write_text("{bad json")

        with pytest.raises(PinFileError, match="not valid JSON") as excinfo:
            verify_pins(tmp_path)
        assert excinfo.value.line == 1

    def test_undecodable_pin_file_raises(self, tmp_path: Path) -> None:
        from agent_audit_kit.pinning import PinFileError

        pin_dir = tmp_path / ".agent-audit-kit"
        pin_dir.mkdir()
        (pin_dir / "tool-pins.json").write_bytes(b'{"a/b": {"hash": "\xff"}}')

        with pytest.raises(PinFileError, match="not UTF-8"):
            verify_pins(tmp_path)

    def test_pin_file_that_is_not_a_pin_map_raises(self, tmp_path: Path) -> None:
        from agent_audit_kit.pinning import PinFileError

        pin_dir = tmp_path / ".agent-audit-kit"
        pin_dir.mkdir()
        for text in ("[]", "null", '{"srv/tool": {"name": "tool"}}', '{"srv/tool": {"hash": 7}}'):
            (pin_dir / "tool-pins.json").write_text(text)
            with pytest.raises(PinFileError):
                verify_pins(tmp_path)

    def test_pin_file_written_by_pin_round_trips(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path, {
            "srv": _make_server_with_tools([{"name": "tool1", "description": "stable"}]),
        })
        create_pins(tmp_path)
        assert verify_pins(tmp_path) == []

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
