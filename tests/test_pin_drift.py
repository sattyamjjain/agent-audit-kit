"""Tests for the pin-drift scanner.

Verifies that the RUGPULL rule family fires during a standard scan
when a pin file exists — previously they only fired under `verify`.
"""

from __future__ import annotations

import json
import sys
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
    assert set(pins) == {"local/", "local/read"}
    assert pins["local/"]["kind"] == "server"


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


# A pin file that does not parse used to return no findings, so all three
# RUGPULL rules went quiet and the scan read as clean. A check that cannot read
# its baseline has checked nothing, and says so the way a crashed scanner does.

_PINS = ".agent-audit-kit/tool-pins.json"
_TRAILING_COMMA = '{\n  "local/read": {\n    "hash": "abc",\n    "name": "read"\n  },\n}\n'


def _break_pins(project: Path, text: str = _TRAILING_COMMA) -> None:
    (project / ".agent-audit-kit").mkdir(exist_ok=True)
    (project / _PINS).write_text(text)


def test_unparseable_pin_file_is_reported_not_passed(tmp_path: Path) -> None:
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    _break_pins(tmp_path)
    findings, files = pin_drift.scan(tmp_path)
    assert [f.rule_id for f in findings] == ["AAK-INTERNAL-SCANNER-FAIL"]
    (finding,) = findings
    assert finding.file_path == _PINS
    # The line json reports: from 3.13 the trailing comma's own, before that the
    # closing brace after it.
    assert finding.line_number == (5 if sys.version_info >= (3, 13) else 6)
    assert "not valid JSON" in finding.evidence
    assert "AAK-RUGPULL-001, AAK-RUGPULL-002 and AAK-RUGPULL-003 were not evaluated" in finding.evidence
    assert files == {_PINS}


def test_unparseable_pin_file_makes_the_scan_incomplete(tmp_path: Path) -> None:
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    _break_pins(tmp_path)
    result = run_scan(tmp_path)
    assert [f.file_path for f in result.scanner_failures] == [_PINS]


def test_unparseable_pin_file_survives_a_rules_filter(tmp_path: Path) -> None:
    """Gating on the RUGPULL rules alone must not filter the warning away."""
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    _break_pins(tmp_path)
    result = run_scan(tmp_path, rules=["AAK-RUGPULL-001", "AAK-RUGPULL-002", "AAK-RUGPULL-003"])
    assert [f.rule_id for f in result.findings] == ["AAK-INTERNAL-SCANNER-FAIL"]


def test_unparseable_pin_file_fails_the_cli_scan(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from agent_audit_kit.cli import cli

    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    _break_pins(tmp_path)
    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert "INCOMPLETE" in result.output
    assert "tool-pins.json is not valid JSON" in result.output


def test_wrongly_shaped_pin_file_is_reported_without_a_crash(tmp_path: Path) -> None:
    """A JSON array, or an entry without a hash, used to raise inside the scanner."""
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    for text, why in (
        ("[]", "array"),
        ('{"local/read": {"name": "read"}}', "hash"),
        ('{"local/read": "abc"}', "hash"),
    ):
        _break_pins(tmp_path, text)
        findings, _ = pin_drift.scan(tmp_path)
        assert [f.rule_id for f in findings] == ["AAK-INTERNAL-SCANNER-FAIL"], text
        assert why in findings[0].evidence, findings[0].evidence
        assert "PinFileError" in findings[0].evidence, findings[0].evidence


def test_an_empty_pin_map_is_a_readable_baseline(tmp_path: Path) -> None:
    """`{}` parses: every current server and tool is new, which is drift, not a failure."""
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    _break_pins(tmp_path, "{}")
    findings, _ = pin_drift.scan(tmp_path)
    assert [(f.rule_id, f.evidence) for f in findings] == [
        ("AAK-RUGPULL-002", "New server 'local' added since last pin"),
        ("AAK-RUGPULL-002", "New tool 'local/read' added since last pin"),
    ]


def test_a_valid_pin_file_reports_no_failure(tmp_path: Path) -> None:
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    create_pins(tmp_path)
    assert run_scan(tmp_path).scanner_failures == []


def test_rugpull_003_blind_spot_is_a_real_before_and_after(tmp_path: Path) -> None:
    """The AAK-RUGPULL-002 and -003 limitation fixtures are not hand-made pin files.

    Each pin file is what `pin` (v2) records for the other blind spot's config:
    002 is pinned without the `toolDescriptions` tool and then declares it, 003
    is pinned with it and then drops it. Neither is reported, because no pin
    records such a tool; the servers are the same on both sides, so neither
    fixture leans on the server entries v2 added.
    """
    fixtures = Path(__file__).parent / "fixtures" / "limitations"
    blind_002 = fixtures / "AAK-RUGPULL-002" / "blind_spot"
    blind_003 = fixtures / "AAK-RUGPULL-003" / "blind_spot"
    for pinned, other in ((blind_002, blind_003), (blind_003, blind_002)):
        project = tmp_path / pinned.parent.name
        project.mkdir()
        (project / ".mcp.json").write_text((other / ".mcp.json").read_text())
        create_pins(project)
        assert json.loads((project / _PINS).read_text()) == json.loads((pinned / _PINS).read_text())
        assert all(pin.get("v") == 2 for pin in json.loads((pinned / _PINS).read_text()).values())
    declares = json.loads((blind_002 / ".mcp.json").read_text())["mcpServers"]
    lacks = json.loads((blind_003 / ".mcp.json").read_text())["mcpServers"]
    assert set(declares) == set(lacks) == {"notes"}
    assert "toolDescriptions" in declares["notes"]
    assert "toolDescriptions" not in lacks["notes"]
    assert {k: v for k, v in declares["notes"].items() if k != "toolDescriptions"} == lacks["notes"]


def test_rugpull_001_fixtures_share_one_v2_baseline(tmp_path: Path) -> None:
    """positive/ and blind_spot/ start from the same pin, written by v2 `pin`:
    positive/ reverts its one change (the annotations) and re-pins to it."""
    fixtures = Path(__file__).parent / "fixtures" / "limitations" / "AAK-RUGPULL-001"
    pins = (fixtures / "positive" / _PINS).read_text()
    assert pins == (fixtures / "blind_spot" / _PINS).read_text()
    assert all(pin.get("v") == 2 for pin in json.loads(pins).values())
    config = json.loads((fixtures / "positive" / ".mcp.json").read_text())
    config["mcpServers"]["notes"]["tools"][0]["annotations"] = {"readOnlyHint": True, "destructiveHint": False}
    (tmp_path / ".mcp.json").write_text(json.dumps(config))
    create_pins(tmp_path)
    assert json.loads((tmp_path / _PINS).read_text()) == json.loads(pins)


def test_failure_evidence_names_the_registered_scanner(tmp_path: Path) -> None:
    """The JSON report reads the scanner name back out of `scanner='...'`."""
    from agent_audit_kit import engine
    from agent_audit_kit.output.json_report import _scanner_name

    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    _break_pins(tmp_path)
    (finding,) = pin_drift.scan(tmp_path)[0]
    names = {reg.scan_fn.__module__.rsplit(".", 1)[-1]: reg.name for reg in engine._get_registry()}
    assert _scanner_name(finding) == names["pin_drift"]


def test_a_pin_file_over_the_config_cap_or_nested_too_deep_is_reported_once(tmp_path: Path) -> None:
    """The pin file was read whole and parsed by `json.loads`, so a 200 MB file
    cost 200 MB, and one nested too deep for the parser raised RecursionError
    out of the scanner. It is read as the other config files are, up to 1 MB,
    and either refusal is one PinFileError against the file: the pin-drift
    check does not report the same file a second time as refused."""
    _write_mcp(tmp_path, [{"name": "read", "description": "Read.", "inputSchema": {}}])
    pins = tmp_path / _PINS
    pins.parent.mkdir(parents=True, exist_ok=True)
    for text, reason in (
        (" " * 1_000_001, "could not be read (larger than 1,000,000 bytes)"),
        ("[" * 100_000 + "]" * 100_000, "could not be read (JSON nested deeper than 500 levels)"),
    ):
        pins.write_text(text)
        result = run_scan(tmp_path)
        mine = [f for f in result.scanner_failures if f.evidence.startswith("scanner='Pin drift'")]
        assert [f.file_path for f in mine] == [_PINS]
        assert "error=PinFileError: " in mine[0].evidence and reason in mine[0].evidence, mine[0].evidence
