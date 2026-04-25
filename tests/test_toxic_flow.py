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
