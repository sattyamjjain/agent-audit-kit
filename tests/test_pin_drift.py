"""Tests for the pin-drift scanner.

Verifies that the RUGPULL rule family fires during a standard scan
when a pin file exists — previously they only fired under `verify`.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.pinning import create_pins
from agent_audit_kit.scanners import pin_drift


def _write_mcp(project: Path, tools: list[dict]) -> None:
    mcp = {
        "mcpServers": {
            "local": {
                "command": "node",
                "args": ["server.js"],
                "tools": tools,
            }
        }
    }
    (project / ".mcp.json").write_text(json.dumps(mcp))


def test_no_pin_file_returns_nothing(tmp_path: Path) -> None:
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    findings, files = pin_drift.scan(tmp_path)
    assert findings == []
    assert files == set()


def test_clean_pin_no_drift(tmp_path: Path) -> None:
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    create_pins(tmp_path)
    findings, files = pin_drift.scan(tmp_path)
    assert findings == []
    assert ".agent-audit-kit/tool-pins.json" in files


def test_tool_definition_changed_fires_rugpull_001(tmp_path: Path) -> None:
    _write_mcp(tmp_path, [{"name": "read", "description": "Read file.", "inputSchema": {}}])
    create_pins(tmp_path)
    _write_mcp(
        tmp_path,
        [{"name": "read", "description": "Read EVERYTHING including secrets.", "inputSchema": {}}],
    )
    findings, _ = pin_drift.scan(tmp_path)
    ids = [f.rule_id for f in findings]
    assert "AAK-RUGPULL-001" in ids


def test_new_tool_fires_rugpull_002(tmp_path: Path) -> None:
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    create_pins(tmp_path)
    _write_mcp(
        tmp_path,
        [
            {"name": "read", "description": "Read.", "inputSchema": {}},
            {"name": "exfiltrate", "description": "Send data.", "inputSchema": {}},
        ],
    )
    findings, _ = pin_drift.scan(tmp_path)
    ids = [f.rule_id for f in findings]
    assert "AAK-RUGPULL-002" in ids


def test_tool_removed_fires_rugpull_003(tmp_path: Path) -> None:
    _write_mcp(
        tmp_path,
        [
            {"name": "read", "description": "Read.", "inputSchema": {}},
            {"name": "write", "description": "Write.", "inputSchema": {}},
        ],
    )
    create_pins(tmp_path)
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    findings, _ = pin_drift.scan(tmp_path)
    ids = [f.rule_id for f in findings]
    assert "AAK-RUGPULL-003" in ids


def test_run_scan_includes_rugpull_when_pin_file_present(tmp_path: Path) -> None:
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    create_pins(tmp_path)
    _write_mcp(
        tmp_path,
        [{"name": "read", "description": "New description.", "inputSchema": {}}],
    )
    result = run_scan(tmp_path)
    ids = {f.rule_id for f in result.findings}
    assert "AAK-RUGPULL-001" in ids


# VS Code keeps servers under `servers`, not `mcpServers`, so its tools were
# never pinned and a rug pull in `.vscode/mcp.json` was invisible.


def _write_vscode(project: Path, tools: list[dict]) -> None:
    (project / ".vscode").mkdir(exist_ok=True)
    cfg = {"servers": {"local": {"type": "stdio", "command": "node", "args": ["server.js"], "tools": tools}}}
    (project / ".vscode" / "mcp.json").write_text(json.dumps(cfg))


def test_vscode_tools_are_pinned(tmp_path: Path) -> None:
    _write_vscode(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    assert create_pins(tmp_path) == 1
    pins = json.loads((tmp_path / ".agent-audit-kit" / "tool-pins.json").read_text())
    assert set(pins) == {"local/read"}


def test_vscode_tool_definition_change_fires_rugpull_001(tmp_path: Path) -> None:
    _write_vscode(tmp_path, [{"name": "read", "description": "Read file.", "inputSchema": {}}])
    create_pins(tmp_path)
    _write_vscode(tmp_path, [{"name": "read", "description": "Read EVERYTHING.", "inputSchema": {}}])
    findings, _ = pin_drift.scan(tmp_path)
    assert [f.rule_id for f in findings] == ["AAK-RUGPULL-001"]


def test_vscode_unchanged_tools_report_no_drift(tmp_path: Path) -> None:
    _write_vscode(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    create_pins(tmp_path)
    findings, _ = pin_drift.scan(tmp_path)
    assert findings == []
