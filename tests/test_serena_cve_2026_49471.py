"""Tests for AAK-MCP-SERENA-CVE-2026-49471-001.

CVE-2026-49471 (HIGH, CVSS 8.3, published 2026-07-07): the Serena MCP coding
toolkit (`serena-agent`) before 1.5.2 ships an unauthenticated Flask dashboard on
a fixed port with no auth, no CSRF, and no Host-header validation. A DNS
rebinding attack writes arbitrary content into the agent's persistent memory
store, which the agent acts on — and combined with `execute_shell_command`
(`shell=True`) that is a remote-code-execution chain. CWE-306 + CWE-352. Fixed
in serena-agent 1.5.2.

The pin detector must flag a dependency below 1.5.2 (or unpinned, or an unpinned
`oraios/serena` / `serena-mcp-server` reference) and stay quiet at >= 1.5.2.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.supply_chain import _check_serena_pin

RULE_ID = "AAK-MCP-SERENA-CVE-2026-49471-001"


def _hits(findings: list) -> list:
    return [f for f in findings if f.rule_id == RULE_ID]


def test_rule_registered_and_accurate() -> None:
    assert RULE_ID in RULES
    rule = RULES[RULE_ID]
    assert rule.severity.value == "high"
    assert "CVE-2026-49471" in rule.cve_references
    assert "1.5.2" in rule.description
    assert "CWE-306" in rule.description
    assert "MCP02:2025" in rule.owasp_mcp_references
    assert "ASI04" in rule.owasp_agentic_references


def test_vulnerable_version_flags(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("serena-agent==1.5.0\n", encoding="utf-8")
    assert _hits(_check_serena_pin(tmp_path, set()))


def test_unpinned_reference_flags(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["serena-agent"]\n', encoding="utf-8"
    )
    assert _hits(_check_serena_pin(tmp_path, set()))


def test_git_launch_reference_flags(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers":{"serena":{"command":"uvx","args":'
        '["--from","git+https://github.com/oraios/serena","serena-mcp-server"]}}}',
        encoding="utf-8",
    )
    assert _hits(_check_serena_pin(tmp_path, set()))


def test_patched_version_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("serena-agent==1.5.2\n", encoding="utf-8")
    assert not _hits(_check_serena_pin(tmp_path, set()))


def test_later_version_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("serena-agent>=1.6.0\n", encoding="utf-8")
    assert not _hits(_check_serena_pin(tmp_path, set()))


def test_unrelated_dependency_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nhttpx==0.27\n", encoding="utf-8")
    assert not _hits(_check_serena_pin(tmp_path, set()))
