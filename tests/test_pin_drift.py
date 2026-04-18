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
