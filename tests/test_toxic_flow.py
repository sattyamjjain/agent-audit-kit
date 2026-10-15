"""AAK-TOXICFLOW-001 — Snyk-parity source/sink pair scoring."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.scanners.toxic_flow import scan


@pytest.fixture
def enable_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AAK_TOXIC_FLOW", "1")


def _write_mcp(root: Path, servers: dict) -> None:
    import json

    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": servers}), encoding="utf-8"
    )


def test_disabled_by_default(tmp_path: Path) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    # No AAK_TOXIC_FLOW env → no findings.
    findings, _ = scan(tmp_path)
    assert findings == []


def test_fs_read_paired_with_http_post_fires(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


def test_only_source_no_sink_passes(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
    })
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


def test_trust_allowlist_suppresses(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    (tmp_path / ".aak-toxic-flow-trust.yml").write_text(
        """
trust:
  - source: fs_read
    sink: http_post
    justification: "Documented data-export feature; sink is allow-listed in egress proxy."
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


def test_trust_without_justification_does_not_suppress(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    (tmp_path / ".aak-toxic-flow-trust.yml").write_text(
        """
trust:
  - source: fs_read
    sink: http_post
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


def test_secrets_paired_with_email_fires(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "vault": {"command": "node", "args": ["mcp__vault__read_secret"]},
        "smtp": {"command": "node", "args": ["mcp__email__send"]},
    })
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-TOXICFLOW-001" for f in findings)


# VS Code keeps servers under `servers`, not `mcpServers`, so a VS Code project
# exposed no MCP tools to this rule at all.


def _write_vscode(root: Path, servers: dict) -> None:
    import json

    (root / ".vscode").mkdir(exist_ok=True)
    (root / ".vscode" / "mcp.json").write_text(json.dumps({"servers": servers}), encoding="utf-8")


def test_vscode_servers_pair_fires(tmp_path: Path, enable_flag: None) -> None:
    _write_vscode(tmp_path, {
        "fs": {"type": "stdio", "command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"type": "stdio", "command": "node", "args": ["mcp__fetch__post"]},
    })
    findings, scanned = scan(tmp_path)
    flows = [f for f in findings if f.rule_id == "AAK-TOXICFLOW-001"]
    assert flows, "a source/sink pair declared under VS Code's `servers` must be reported"
    # Reported against the file the pair came from, not a `.mcp.json` the
    # project does not have.
    assert {f.file_path for f in flows} == {".vscode/mcp.json"}
    assert scanned == {".vscode/mcp.json"}


def test_vscode_source_without_sink_passes(tmp_path: Path, enable_flag: None) -> None:
    _write_vscode(tmp_path, {
        "fs": {"type": "stdio", "command": "node", "args": ["mcp__filesystem__read_text_file"]},
    })
    findings, _ = scan(tmp_path)
    assert findings == []


def test_mcp_json_pair_is_still_reported_against_mcp_json(tmp_path: Path, enable_flag: None) -> None:
    _write_mcp(tmp_path, {
        "fs": {"command": "node", "args": ["mcp__filesystem__read_text_file"]},
        "fetch": {"command": "node", "args": ["mcp__fetch__post"]},
    })
    findings, scanned = scan(tmp_path)
    assert {f.file_path for f in findings} == {".mcp.json"}
    assert scanned == {".mcp.json"}


@pytest.mark.parametrize(("line", "decorator"), [
    ("@tool", False),
    ("@tool()", True),
    ("@mcp.tool( )", True),
    ("@tool\n", True),
    ("@tool(name='x')", False),
    ("@tool )", True),
])
def test_tool_decorator_keeps_its_shape(line: str, decorator: bool) -> None:
    from agent_audit_kit.scanners.toxic_flow import _TOOL_DECORATOR_RE

    assert bool(_TOOL_DECORATOR_RE.search(line)) is decorator


def test_a_long_decorator_line_reads_in_linear_time() -> None:
    """`@tool` and 1 MB of blanks. The two `\\s*` around an optional `(`
    split the run every way: 40,000 blanks took 4 seconds and the time grew
    with the square. The bound is loose for slow CI runners."""
    import time

    from agent_audit_kit.scanners.toxic_flow import _TOOL_DECORATOR_RE

    started = time.perf_counter()
    _TOOL_DECORATOR_RE.search("@tool" + " " * 1_000_000 + "x")
    assert time.perf_counter() - started < 5.0
