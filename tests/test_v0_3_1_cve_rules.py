"""Tests for the v0.3.1 CVE rule family.

Covers:
- AAK-STDIO-001     CVE-2026-30615 + Ox architectural class (see also test_stdio_injection.py)
- AAK-NEO4J-001     CVE-2026-35402
- AAK-CLAUDE-WIN-001 CVE-2026-35603
- AAK-LOGINJ-001    CVE-2026-6494
- AAK-SEC-MD-001    SECURITY.md requirement
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_audit_kit.scanners import (
    agent_config,
    log_injection,
    marketplace_manifest,
    neo4j_cve,
)


# ---------------------------------------------------------------------------
# AAK-NEO4J-001 (CVE-2026-35402)
# ---------------------------------------------------------------------------


def test_neo4j_vulnerable_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-neo4j-cypher==0.5.0\n")
    findings, _ = neo4j_cve.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-NEO4J-001" in ids


def test_neo4j_pin_after_blank_lines_names_its_line(tmp_path: Path) -> None:
    """The match opened at the first blank line above the pin, so its text held a
    newline and `find_line_number` found no line for the finding."""
    (tmp_path / "requirements.txt").write_text("flask\n\n\nmcp-neo4j-cypher==0.5.0\n")
    findings, _ = neo4j_cve.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == "AAK-NEO4J-001"] == [4]


@pytest.mark.parametrize("requirements", ["\n" * 1_999_000 + "x", "mcp-neo4j-cypher" + " " * 1_999_000 + "x"])
def test_neo4j_pin_reads_a_crafted_requirements_file_in_linear_time(tmp_path: Path, requirements: str) -> None:
    """From every line start in a run of blank lines `^\\s*` read to the end of the
    run, and two `\\s*` around the optional operator split a blank run every way,
    so both shapes grew with the square. The bound is loose for slow CI runners."""
    import time

    (tmp_path / "requirements.txt").write_text(requirements, encoding="utf-8")
    started = time.perf_counter()
    neo4j_cve.scan(tmp_path)
    assert time.perf_counter() - started < 5.0


def test_neo4j_patched_pin_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp-neo4j-cypher>=0.6.0\n")
    findings, _ = neo4j_cve.scan(tmp_path)
    assert not any(f.rule_id == "AAK-NEO4J-001" for f in findings)


@pytest.mark.parametrize(("name", "text", "line"), [
    # The pin took the first number after the name, had no place for extras, and
    # never opened the pyproject.toml its docstring promised.
    ("requirements.txt", "mcp-neo4j-cypher<0.6.0\n", 1),
    ("requirements.txt", "mcp-neo4j-cypher[all]==0.5.0\n", 1),
    ("requirements-dev.txt", "pytest\nmcp-neo4j-cypher>=0.4,<0.7  # upper bound only\n", 2),
    ("dev-requirements.txt", "mcp-neo4j-cypher~=0.5.0\n", 1),
    ("pyproject.toml", '[project]\nname = "d"\nversion = "0.1.0"\ndependencies = ["mcp-neo4j-cypher==0.5.0"]\n', 4),
    ("pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.11"\nmcp-neo4j-cypher = "^0.5.0"\n', 3),
])
def test_neo4j_pin_reads_ranges_extras_and_pyproject(tmp_path: Path, name: str, text: str, line: int) -> None:
    (tmp_path / name).write_text(text, encoding="utf-8")
    findings, _ = neo4j_cve.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == "AAK-NEO4J-001"] == [line]


@pytest.mark.parametrize(("name", "text"), [
    ("requirements.txt", "mcp-neo4j-cypher\n"),                     # no version stated
    ("requirements.txt", "mcp-neo4j-cypher[all]>=0.6.0\n"),
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["mcp-neo4j-cypher>=0.6.0,<1"]\n'),
    ("package.json", '{"dependencies": {"mcp-neo4j-cypher": "0.5.0"}}'),  # a PyPI package; npm has none
])
def test_neo4j_pin_stays_quiet(tmp_path: Path, name: str, text: str) -> None:
    (tmp_path / name).write_text(text, encoding="utf-8")
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


@pytest.mark.parametrize("where", ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"])
def test_security_md_in_any_folder_github_reads_is_quiet(tmp_path: Path, where: str) -> None:
    """GitHub reads a community health file such as SECURITY.md from the
    repository root, `.github/` or `docs/`, in that order of precedence after
    `.github/` (docs.github.com, "Creating a default community health file").
    A repo that kept its policy in `docs/` was told it shipped none."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my-mcp-server"\nkeywords = ["mcp"]\n'
    )
    policy = tmp_path / where
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("# Security\n\nReport at security@example.com\n")
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert not any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


@pytest.mark.parametrize("where", ["security/SECURITY.md", "packages/server/SECURITY.md"])
def test_security_md_outside_those_folders_still_fires(tmp_path: Path, where: str) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my-mcp-server"\nkeywords = ["mcp"]\n'
    )
    policy = tmp_path / where
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("# Security\n\nReport at security@example.com\n")
    findings, _ = marketplace_manifest.scan(tmp_path)
    assert any(f.rule_id == "AAK-SEC-MD-001" for f in findings)


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
