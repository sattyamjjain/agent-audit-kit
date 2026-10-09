"""Phase 2 rule-family tests: 2026 CVE wave.

Each test stages a fixture project under `tmp_path`, runs the relevant
scanner, and asserts the expected rule IDs fire (vulnerable) or none fire
(safe). See `tests/fixtures/cves/` for the source material.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
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


# AAK-LANGCHAIN-001 and -003 read Python manifests only, and only the
# `langchain-core` distribution both advisories name. They used to compare any npm
# dependency containing "langchain" against these Python floors, so
# `@langchain/redis` 1.1.1, a fixed release, got a HIGH no upgrade cleared (#924).
_LANGCHAIN_CORE_PINS = {"AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003"}
_REDIS = FIX / "cve-2026-105799-langchain-redis"


@pytest.mark.parametrize("kind", ["vulnerable", "negative"])
def test_langchain_core_pins_ignore_npm_langchain_redis(kind: str) -> None:
    """`@langchain/redis` at 1.1.0 and at the fixed 1.1.1: the core pins stay quiet."""
    ids = {f.rule_id for f in run_scan(_REDIS / kind).findings}
    assert not _LANGCHAIN_CORE_PINS & ids


def test_langchain_redis_pin_still_fires_on_1_1_0() -> None:
    ids = {f.rule_id for f in run_scan(_REDIS / "vulnerable").findings}
    assert "AAK-MCP-LANGCHAIN-REDIS-CVE-2026-105799-001" in ids


def test_langchain_python_fixture_reports_only_the_core_line(tmp_path: Path) -> None:
    """The positive fixture pins langchain, langchain-core and langchain-community;
    only langchain-core is the distribution the floors are for."""
    shutil.copy(FIX / "langchain" / "vulnerable_requirements.txt", tmp_path / "requirements.txt")
    findings = [f for f in langchain_vuln.scan(tmp_path)[0] if f.rule_id in _LANGCHAIN_CORE_PINS]
    assert sorted(f.rule_id for f in findings) == ["AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003"]
    assert all(f.evidence.startswith("langchain-core pinned at 0.3.10") for f in findings)


@pytest.mark.parametrize(("line", "expected"), [
    ("langchain-core==0.3.10\n", {"AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003"}),
    ("langchain_core==1.2.21\n", {"AAK-LANGCHAIN-001"}),    # a PEP 503 spelling
    ("LangChain-Core>=1.0.0\n", {"AAK-LANGCHAIN-001"}),     # the lowest a range allows
    ("langchain-core[all]==0.3.13\n", {"AAK-LANGCHAIN-001", "AAK-LANGCHAIN-003"}),
    ("langchain-core==1.2.22\n", set()),
    ("langchain==1.1.5\n", set()),              # the umbrella, on its own version line
    ("langchain-community==0.1.0\n", set()),
    ("langchain-core-extras==0.1.0\n", set()),  # a longer name is not langchain-core
])
def test_langchain_core_pins_read_the_exact_distribution(
    tmp_path: Path, line: str, expected: set[str]
) -> None:
    (tmp_path / "requirements.txt").write_text(line, encoding="utf-8")
    ids = {f.rule_id for f in langchain_vuln.scan(tmp_path)[0]}
    assert ids & _LANGCHAIN_CORE_PINS == expected


@pytest.mark.parametrize("deps", [
    '{"langchain": "0.2.0"}',
    '{"@langchain/core": "0.3.10"}',
    '{"langchainjs": "0.2.0"}',
])
def test_langchain_core_pins_never_read_package_json(tmp_path: Path, deps: str) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": %s}' % deps, encoding="utf-8")
    assert langchain_vuln.scan(tmp_path)[0] == []


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


# ---------------------------------------------------------------------------
# FP guards (P2 rule-scoping precision)
# ---------------------------------------------------------------------------


def test_react_hook_not_flagged_as_claude_hook(tmp_path: Path) -> None:
    """FP guard: a React hook under `src/hooks/` with a `` `${event}` ``
    template literal is not a Claude Code hook — Claude hooks live under
    `.claude/`, and a pure UI helper has no shell-exec sink."""
    hooks_dir = tmp_path / "src" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "use-audit.ts").write_text(
        "import { useState } from 'react';\n"
        "export function useAudit(event: string) {\n"
        "  const [log] = useState(`audit:${event}`);\n"
        "  return log;\n"
        "}\n",
        encoding="utf-8",
    )
    findings, _ = hook_rce.scan(tmp_path)
    assert not any(f.rule_id.startswith("AAK-HOOK-RCE") for f in findings)


def test_claude_hook_script_with_exec_sink_still_fires(tmp_path: Path) -> None:
    """A real Claude hook script under `.claude/hooks/` that interpolates
    input into an exec sink must still fire."""
    hooks_dir = tmp_path / ".claude" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "deploy.ts").write_text(
        "import { execSync } from 'child_process';\n"
        "export function run(event: any) { execSync(`deploy ${event.input}`); }\n",
        encoding="utf-8",
    )
    findings, _ = hook_rce.scan(tmp_path)
    assert any(f.rule_id == "AAK-HOOK-RCE-001" for f in findings)


def test_generic_task_id_module_not_flagged(tmp_path: Path) -> None:
    """FP guard: a job-queue/Celery worker that merely mentions `task_id`
    (no task class, store, or SEP-1686 primitive) must not fire TASKS-002/003."""
    (tmp_path / "worker.py").write_text(
        "def process(task_id: str) -> str:\n"
        "    log(f'task {task_id} failed')\n"
        "    return task_id\n",
        encoding="utf-8",
    )
    findings, _ = mcp_tasks.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-TASKS-002" not in ids
    assert "AAK-TASKS-003" not in ids
