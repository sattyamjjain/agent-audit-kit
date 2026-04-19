"""Tests for the v0.3.1 CVE rule family.

Covers:
- AAK-STDIO-001     CVE-2026-30615 + Ox architectural class (see also test_stdio_injection.py)
- AAK-WINDSURF-001  CVE-2026-30615 Windsurf auto-registration
- AAK-NEO4J-001     CVE-2026-35402
- AAK-CLAUDE-WIN-001 CVE-2026-35603
- AAK-LOGINJ-001    CVE-2026-6494
- AAK-SEC-MD-001    SECURITY.md requirement
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from agent_audit_kit.scanners import (
    agent_config,
    log_injection,
    mcp_config,
    marketplace_manifest,
    neo4j_cve,
)


# ---------------------------------------------------------------------------
# AAK-WINDSURF-001
# ---------------------------------------------------------------------------


def test_windsurf_auto_approve_fires(tmp_path: Path) -> None:
    windsurf_dir = tmp_path / ".windsurf"
    windsurf_dir.mkdir()
    (windsurf_dir / "mcp.json").write_text(
        json.dumps({
            "auto_approve": True,
            "mcpServers": {
                "bad": {"command": "node", "args": ["server.js"]},
            },
        })
    )
    findings, _ = mcp_config.scan(tmp_path)
    ids = [f.rule_id for f in findings]
    windsurf_hits = [f for f in findings if f.rule_id == "AAK-WINDSURF-001"]
    assert windsurf_hits, f"expected AAK-WINDSURF-001; got {ids}"
    assert any("auto_approve" in f.evidence for f in windsurf_hits)


def test_windsurf_unpinned_command_fires(tmp_path: Path) -> None:
    windsurf_dir = tmp_path / ".windsurf"
    windsurf_dir.mkdir()
    (windsurf_dir / "mcp.json").write_text(
        json.dumps({
            "auto_approve": False,
            "mcpServers": {
                "srv": {"command": "npx", "args": ["some-mcp-server"]},
            },
        })
    )
    findings, _ = mcp_config.scan(tmp_path)
    assert any(
        f.rule_id == "AAK-WINDSURF-001" and "no SHA-256 pin" in f.evidence
        for f in findings
    )


def test_windsurf_pinned_command_is_quiet(tmp_path: Path) -> None:
    windsurf_dir = tmp_path / ".windsurf"
    windsurf_dir.mkdir()
    (windsurf_dir / "mcp.json").write_text(
        json.dumps({
            "auto_approve": False,
            "auto_execute": False,
            "mcpServers": {
                "srv": {
                    "command": "npx",
                    "args": ["some-mcp-server@1.2.3"],
                    "sha256": "f" * 64,
                },
            },
        })
    )
    findings, _ = mcp_config.scan(tmp_path)
    assert not any(f.rule_id == "AAK-WINDSURF-001" for f in findings)


def test_windsurf_rule_maps_cve_2026_30615() -> None:
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES["AAK-WINDSURF-001"]
    assert "CVE-2026-30615" in rule.cve_references


# ---------------------------------------------------------------------------
# AAK-NEO4J-001 (CVE-2026-35402)
# ---------------------------------------------------------------------------


def test_neo4j_vulnerable_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-neo4j-cypher==0.5.0\n")
    findings, _ = neo4j_cve.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-NEO4J-001" in ids


def test_neo4j_patched_pin_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-neo4j-cypher>=0.6.0\n")
    findings, _ = neo4j_cve.scan(tmp_path)
    assert not any(f.rule_id == "AAK-NEO4J-001" for f in findings)


def test_neo4j_apoc_pattern_fires(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        'q = "CALL apoc.load.json(\'https://attacker/\')"\n'
        "session.run(q, read_only=True)\n"
    )
    findings, _ = neo4j_cve.scan(tmp_path)
    assert any(f.rule_id == "AAK-NEO4J-001" for f in findings)


# ---------------------------------------------------------------------------
# AAK-CLAUDE-WIN-001 (CVE-2026-35603)
# ---------------------------------------------------------------------------


def test_claude_win_programdata_without_setup_ps1_fires(tmp_path: Path) -> None:
    target_dir = tmp_path / "ProgramData" / "ClaudeCode"
    target_dir.mkdir(parents=True)
    (target_dir / "managed-settings.json").write_text("{}")
    findings, _ = agent_config.scan(tmp_path)
    ids = [f.rule_id for f in findings]
    assert "AAK-CLAUDE-WIN-001" in ids, ids


def test_claude_win_programdata_with_hardened_setup_ps1_is_quiet(tmp_path: Path) -> None:
    target_dir = tmp_path / "ProgramData" / "ClaudeCode"
    target_dir.mkdir(parents=True)
    (target_dir / "managed-settings.json").write_text("{}")
    (target_dir / "setup.ps1").write_text(
        "Write-Host 'setup'\n"
        "icacls $PSScriptRoot /inheritance:d /grant:r 'TrustedInstaller:F'\n"
    )
    findings, _ = agent_config.scan(tmp_path)
    assert not any(f.rule_id == "AAK-CLAUDE-WIN-001" for f in findings)


def test_claude_win_non_programdata_is_quiet(tmp_path: Path) -> None:
    target_dir = tmp_path / "home" / "user" / ".claude"
    target_dir.mkdir(parents=True)
    (target_dir / "managed-settings.json").write_text("{}")
    findings, _ = agent_config.scan(tmp_path)
    assert not any(f.rule_id == "AAK-CLAUDE-WIN-001" for f in findings)


# ---------------------------------------------------------------------------
# AAK-LOGINJ-001 (CVE-2026-6494)
# ---------------------------------------------------------------------------


def test_loginj_tool_logs_unsanitized_param_fires(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(
        "import logging\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "log = logging.getLogger(__name__)\n"
        "\n"
        "@mcp.tool()\n"
        "def run(toolsetroute: str) -> str:\n"
        "    log.info('received route %s', toolsetroute)\n"
        "    return toolsetroute\n"
    )
    findings, _ = log_injection.scan(tmp_path)
    assert any(f.rule_id == "AAK-LOGINJ-001" for f in findings)


def test_loginj_sanitized_tool_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(
        "import logging\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "log = logging.getLogger(__name__)\n"
        "\n"
        "@mcp.tool()\n"
        "def run(toolsetroute: str) -> str:\n"
        "    safe = toolsetroute.replace('\\r', '').replace('\\n', '')\n"
        "    log.info('received route %s', safe)\n"
        "    return safe\n"
    )
    findings, _ = log_injection.scan(tmp_path)
    assert not any(f.rule_id == "AAK-LOGINJ-001" for f in findings)


def test_loginj_non_tool_function_ignored(tmp_path: Path) -> None:
    (tmp_path / "util.py").write_text(
        "import logging\n"
        "log = logging.getLogger(__name__)\n"
        "\n"
        "def run(route: str) -> str:\n"
        "    log.info('route %s', route)\n"
        "    return route\n"
    )
    findings, _ = log_injection.scan(tmp_path)
    assert not any(f.rule_id == "AAK-LOGINJ-001" for f in findings)


# ---------------------------------------------------------------------------
# AAK-SEC-MD-001
# ---------------------------------------------------------------------------


def test_security_md_required_for_mcp_named_repo(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my-mcp-server"\nkeywords = ["mcp"]\n'
    )
    # No SECURITY.md, no security_contact.
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


def test_security_md_present_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my-mcp-server"\nkeywords = ["mcp"]\n'
    )
    (tmp_path / "SECURITY.md").write_text("# Security\n\nReport at security@example.com\n")
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert not any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


def test_security_contact_in_pyproject_satisfies(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\n'
        'name = "my-mcp-server"\n'
        'keywords = ["mcp"]\n'
        'urls = { Security = "https://example.com/security" }\n'
    )
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert not any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


def test_non_mcp_repo_not_required(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "totally-normal-lib"\n')
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert not any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


def _ignore() -> None:  # keep os import used (pyright noise-control)
    _ = os
