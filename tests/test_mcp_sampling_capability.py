"""AAK-MCP-SAMPLING-001 — sampling-without-consent detection tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners import mcp_sampling_capability

FIXTURES = Path(__file__).parent / "fixtures" / "mcp_sampling"
RULE_ID = "AAK-MCP-SAMPLING-001"


def _copy(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        target = dst / entry.name
        if entry.is_dir():
            _copy(entry, target)
        else:
            shutil.copy2(entry, target)


def test_python_sampling_without_consent_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_python", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_ID]
    assert matches, "expected AAK-MCP-SAMPLING-001 to fire on unguarded Python sampling"
    assert any(m.file_path.endswith("server.py") for m in matches)


def test_python_sampling_with_elicit_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "clean_python", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        "elicit_input consent marker must suppress AAK-MCP-SAMPLING-001"


def test_typescript_sampling_without_consent_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_typescript", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_ID]
    assert matches, "expected AAK-MCP-SAMPLING-001 to fire on unguarded TS sampling"
    assert any(m.file_path.endswith("server.ts") for m in matches)


def test_documented_risk_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "documented_risk", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        ".agent-audit-kit.yml accepts_sampling_risk must suppress the finding"


def test_config_sampling_without_consent_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "config_vulnerable", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_ID]
    assert matches, "expected AAK-MCP-SAMPLING-001 to fire on .mcp.json sampling declaration"
    assert all(m.file_path.endswith(".mcp.json") for m in matches)


def test_config_sampling_with_consent_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "config_clean", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        "requires_consent flag on .mcp.json server entry must suppress the finding"


def test_no_sdk_no_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("click>=8.1\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "# Code mentions CreateMessageRequestSchema but no SDK is declared\n"
        "CreateMessageRequestSchema = None\n",
        encoding="utf-8",
    )
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


def test_sdk_without_sampling_marker_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "server = Server('non-sampling')\n",
        encoding="utf-8",
    )
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


def test_prose_mention_does_not_fire(tmp_path: Path) -> None:
    """Bare prose mentioning the word `sampling` must not trip the rule —
    we only fire on tight protocol/SDK markers."""
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "server.py").write_text(
        "from mcp.server import Server\n"
        "# This server does NOT use sampling — sampling is mentioned only\n"
        "# for documentation purposes.\n"
        "server = Server('docs-only')\n",
        encoding="utf-8",
    )
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


def test_finding_carries_owasp_mapping(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_python", tmp_path)
    findings, _ = mcp_sampling_capability.scan(tmp_path)
    match = next((f for f in findings if f.rule_id == RULE_ID), None)
    assert match is not None
    assert "MCP07:2025" in match.owasp_mcp_references
    assert "ASI03" in match.owasp_agentic_references
