"""Tests for AAK-STDIO-001 / CVE-2026-30615 + Ox-disclosure family."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners import stdio_injection

FIX = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-30615"


def _stage(tmp_path: Path, source: Path) -> Path:
    shutil.copy(source, tmp_path / source.name)
    return tmp_path


def test_py_subprocess_shell_fires(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "vulnerable" / "py_subprocess_shell.py")
    findings, _ = stdio_injection.scan(project)
    assert any(f.rule_id == "AAK-STDIO-001" for f in findings)
    msg = next(f for f in findings if f.rule_id == "AAK-STDIO-001")
    assert "shell=True" in msg.evidence or "subprocess" in msg.evidence


def test_py_os_system_stdin_fires(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "vulnerable" / "py_os_system_stdin.py")
    findings, _ = stdio_injection.scan(project)
    assert any(f.rule_id == "AAK-STDIO-001" for f in findings)


def test_ts_execa_shell_fires(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "vulnerable" / "ts_execa_shell.ts")
    findings, _ = stdio_injection.scan(project)
    assert any(f.rule_id == "AAK-STDIO-001" for f in findings)


def test_patched_argv_allowlist_is_quiet(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "patched" / "py_argv_allowlist.py")
    findings, _ = stdio_injection.scan(project)
    assert not any(f.rule_id == "AAK-STDIO-001" for f in findings)


def test_non_mcp_python_ignored(tmp_path: Path) -> None:
    # No MCP hint → skip entirely.
    (tmp_path / "util.py").write_text(
        "import subprocess\n"
        "def run(cmd):\n"
        "    return subprocess.run(cmd, shell=True).stdout\n"
    )
    findings, _ = stdio_injection.scan(tmp_path)
    assert findings == []


def test_rule_metadata_has_cve_and_owasp() -> None:
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES["AAK-STDIO-001"]
    assert "CVE-2026-30615" in rule.cve_references
    assert "MCP01:2025" in rule.owasp_mcp_references
    assert "ASI02" in rule.owasp_agentic_references
    assert rule.severity.value == "critical"
