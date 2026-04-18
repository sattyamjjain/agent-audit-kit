"""Phase 2 rule-family tests: 2026 CVE wave.

Each test stages a fixture project under `tmp_path`, runs the relevant
scanner, and asserts the expected rule IDs fire (vulnerable) or none fire
(safe). See `tests/fixtures/cves/` for the source material.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners import (
    hook_rce,
    langchain_vuln,
    mcp_auth_patterns,
    mcp_tasks,
    oauth_misconfig,
    routines,
    ssrf_patterns,
)

FIX = Path(__file__).parent / "fixtures" / "cves"


# ---------------------------------------------------------------------------
# AAK-MCP-011..020 (MCP auth bypass wave, CVE-2026-33032 template)
# ---------------------------------------------------------------------------


def test_mcp_auth_vulnerable_fires_core_rules(tmp_path: Path) -> None:
    shutil.copy(FIX / "mcp_auth" / "vulnerable_server.py", tmp_path / "server.py")
    findings, _ = mcp_auth_patterns.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    for rid in ("AAK-MCP-011", "AAK-MCP-012", "AAK-MCP-013", "AAK-MCP-014",
                "AAK-MCP-015", "AAK-MCP-017"):
        assert rid in ids, f"expected {rid} to fire on vulnerable fixture; got {ids}"


def test_mcp_auth_safe_fires_nothing(tmp_path: Path) -> None:
    shutil.copy(FIX / "mcp_auth" / "safe_server.py", tmp_path / "server.py")
    findings, _ = mcp_auth_patterns.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    bad = {"AAK-MCP-011", "AAK-MCP-012", "AAK-MCP-013", "AAK-MCP-014", "AAK-MCP-017"}
    assert ids.isdisjoint(bad), f"safe fixture should not fire {ids & bad}"


# ---------------------------------------------------------------------------
# AAK-SSRF-001..005
# ---------------------------------------------------------------------------


def test_ssrf_vulnerable_fires(tmp_path: Path) -> None:
    shutil.copy(FIX / "ssrf" / "vulnerable.py", tmp_path / "tool.py")
    findings, _ = ssrf_patterns.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-SSRF-001" in ids
    assert "AAK-SSRF-003" in ids or "AAK-SSRF-002" in ids
    assert "AAK-SSRF-004" in ids
    assert "AAK-SSRF-005" in ids


def test_ssrf_safe_is_quiet(tmp_path: Path) -> None:
    shutil.copy(FIX / "ssrf" / "safe.py", tmp_path / "tool.py")
    findings, _ = ssrf_patterns.scan(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# AAK-OAUTH-001..005
# ---------------------------------------------------------------------------


def test_oauth_vulnerable_fires(tmp_path: Path) -> None:
    shutil.copy(FIX / "oauth" / "vulnerable.py", tmp_path / "oauth.py")
    findings, _ = oauth_misconfig.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-OAUTH-001" in ids
    assert "AAK-OAUTH-002" in ids
    assert "AAK-OAUTH-003" in ids
    assert "AAK-OAUTH-004" in ids


def test_oauth_safe_is_quiet_for_pkce_rules(tmp_path: Path) -> None:
    shutil.copy(FIX / "oauth" / "safe.py", tmp_path / "oauth.py")
    findings, _ = oauth_misconfig.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    # Safe fixture must not fire PKCE/plain/passthrough/wildcard rules.
    for rid in ("AAK-OAUTH-001", "AAK-OAUTH-002", "AAK-OAUTH-003", "AAK-OAUTH-004"):
        assert rid not in ids


# ---------------------------------------------------------------------------
# AAK-HOOK-RCE-001..003
# ---------------------------------------------------------------------------


def test_hook_rce_vulnerable_fires(tmp_path: Path) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    shutil.copy(FIX / "hook_rce" / "vulnerable_settings.json", claude_dir / "settings.local.json")
    findings, _ = hook_rce.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-HOOK-RCE-001" in ids
    assert "AAK-HOOK-RCE-003" in ids


def test_hook_rce_safe_is_quiet(tmp_path: Path) -> None:
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    shutil.copy(FIX / "hook_rce" / "safe_settings.json", claude_dir / "settings.json")
    findings, _ = hook_rce.scan(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# AAK-LANGCHAIN-001..003
# ---------------------------------------------------------------------------


def test_langchain_vulnerable_requirements_fires(tmp_path: Path) -> None:
    shutil.copy(
        FIX / "langchain" / "vulnerable_requirements.txt",
        tmp_path / "requirements.txt",
    )
    shutil.copy(FIX / "langchain" / "vulnerable_prompt.py", tmp_path / "app.py")
    findings, _ = langchain_vuln.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-LANGCHAIN-001" in ids
    assert "AAK-LANGCHAIN-002" in ids
    assert "AAK-LANGCHAIN-003" in ids


def test_langchain_safe_requirements_is_quiet(tmp_path: Path) -> None:
    shutil.copy(FIX / "langchain" / "safe_requirements.txt", tmp_path / "requirements.txt")
    findings, _ = langchain_vuln.scan(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# AAK-ROUTINE-001..003
# ---------------------------------------------------------------------------


def test_routine_vulnerable_fires(tmp_path: Path) -> None:
    routines_dir = tmp_path / ".claude" / "routines"
    routines_dir.mkdir(parents=True)
    shutil.copy(FIX / "routines" / "vulnerable.json", routines_dir / "r.json")
    findings, _ = routines.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-ROUTINE-001" in ids
    assert "AAK-ROUTINE-002" in ids
    assert "AAK-ROUTINE-003" in ids


def test_routine_safe_is_quiet(tmp_path: Path) -> None:
    routines_dir = tmp_path / ".claude" / "routines"
    routines_dir.mkdir(parents=True)
    shutil.copy(FIX / "routines" / "safe.json", routines_dir / "r.json")
    findings, _ = routines.scan(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# AAK-TASKS-001..003
# ---------------------------------------------------------------------------


def test_tasks_vulnerable_fires(tmp_path: Path) -> None:
    shutil.copy(FIX / "tasks" / "vulnerable.py", tmp_path / "tasks.py")
    findings, _ = mcp_tasks.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-TASKS-001" in ids
    assert "AAK-TASKS-002" in ids
    assert "AAK-TASKS-003" in ids


def test_tasks_safe_is_quieter(tmp_path: Path) -> None:
    shutil.copy(FIX / "tasks" / "safe.py", tmp_path / "tasks.py")
    findings, _ = mcp_tasks.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    # Safe fixture must not fire owner-miss (001) or zeroize-miss (002).
    assert "AAK-TASKS-001" not in ids
    assert "AAK-TASKS-002" not in ids
