"""AAK-MCP-STATELESS-001..004 — 2026-07-28 stateless-MCP migration tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners import mcp_stateless_migration

FIXTURES = Path(__file__).parent / "fixtures" / "mcp_stateless"
RULE_001 = "AAK-MCP-STATELESS-001"
RULE_002 = "AAK-MCP-STATELESS-002"
RULE_003 = "AAK-MCP-STATELESS-003"
RULE_004 = "AAK-MCP-STATELESS-004"


def _copy(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        target = dst / entry.name
        if entry.is_dir():
            _copy(entry, target)
        else:
            shutil.copy2(entry, target)


# --------------------------------------------------------------------------
# 001 — Mcp-Session-Id reliance
# --------------------------------------------------------------------------

def test_001_python_session_id_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_001_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_001]
    assert matches, "expected AAK-MCP-STATELESS-001 to fire on Mcp-Session-Id header read"
    assert any(m.file_path.endswith("server.py") for m in matches)


def test_001_typescript_session_id_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_001_ts", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_001]
    assert matches, "expected AAK-MCP-STATELESS-001 to fire on TS Mcp-Session-Id reference"
    assert any(m.file_path.endswith("server.ts") for m in matches)


def test_001_no_sdk_no_finding(tmp_path: Path) -> None:
    """No SDK declared — even if the literal appears, the rule must stay
    silent (matches the sampling-rule SDK gate)."""
    (tmp_path / "requirements.txt").write_text("click>=8.1\n", encoding="utf-8")
    (tmp_path / "notes.py").write_text(
        '# Reference: Mcp-Session-Id is removed in the 2026-07-28 RC\n',
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_001 for f in findings)


# --------------------------------------------------------------------------
# 002 — tasks/list usage
# --------------------------------------------------------------------------

def test_002_tasks_list_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_002_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_002]
    assert matches, "expected AAK-MCP-STATELESS-002 to fire on tasks/list dispatch"
    assert any(m.file_path.endswith("client.py") for m in matches)


def test_002_no_sdk_no_finding(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("click>=8.1\n", encoding="utf-8")
    (tmp_path / "client.py").write_text(
        'method = "tasks/list"\n',
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_002 for f in findings)


# --------------------------------------------------------------------------
# 003 — sticky-session / shared-store dependency
# --------------------------------------------------------------------------

def test_003_nginx_sticky_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_003_nginx", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_003]
    assert matches, "expected AAK-MCP-STATELESS-003 to fire on nginx ip_hash"
    assert any(m.file_path.endswith("nginx.conf") for m in matches)


def test_003_k8s_session_affinity_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_003_k8s", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_003]
    assert matches, "expected AAK-MCP-STATELESS-003 to fire on K8s sessionAffinity: ClientIP"


def test_003_session_store_code_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_003_store_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_003]
    assert matches, "expected AAK-MCP-STATELESS-003 to fire on session_store[session_id]"
    assert any(m.file_path.endswith("handlers.py") for m in matches)


def test_003_unrelated_k8s_manifest_quiet(tmp_path: Path) -> None:
    """A K8s manifest with sessionAffinity but no MCP mention and no MCP
    SDK in the project must not fire."""
    (tmp_path / "service.yaml").write_text(
        "apiVersion: v1\nkind: Service\nspec:\n  sessionAffinity: ClientIP\n",
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_003 for f in findings)


# --------------------------------------------------------------------------
# 004 — client no-cache + per-session state
# --------------------------------------------------------------------------

def test_004_client_no_cache_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_004_client", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_004]
    assert matches, "expected AAK-MCP-STATELESS-004 to fire on un-cached tools/list + session_id"
    assert any(m.file_path.endswith("client.py") for m in matches)


def test_004_cache_marker_suppresses(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "client.py").write_text(
        "from functools import lru_cache\n"
        "@lru_cache\n"
        "def fetch(session_id):\n"
        "    a = client.list_tools()\n"
        "    b = client.list_tools()\n"
        "    return a, b\n",
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_004 for f in findings)


def test_004_single_call_quiet(tmp_path: Path) -> None:
    """One call alone is not the hot-path pattern; rule requires ≥2 calls."""
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n", encoding="utf-8")
    (tmp_path / "client.py").write_text(
        "def init(session_id):\n    return client.list_tools()\n",
        encoding="utf-8",
    )
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    assert not any(f.rule_id == RULE_004 for f in findings)


# --------------------------------------------------------------------------
# Cross-cutting: documented-risk opt-out + OWASP mapping
# --------------------------------------------------------------------------

def test_documented_risk_suppresses_all(tmp_path: Path) -> None:
    _copy(FIXTURES / "documented_risk", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    stateless = [f for f in findings if f.rule_id.startswith("AAK-MCP-STATELESS-")]
    assert not stateless, (
        ".agent-audit-kit.yml accepts_stateless_migration_risk must suppress every "
        "STATELESS finding"
    )


def test_clean_python_no_findings(tmp_path: Path) -> None:
    _copy(FIXTURES / "clean_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    stateless = [f for f in findings if f.rule_id.startswith("AAK-MCP-STATELESS-")]
    assert not stateless


def test_findings_carry_owasp_mapping(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable_001_py", tmp_path)
    findings, _ = mcp_stateless_migration.scan(tmp_path)
    match = next((f for f in findings if f.rule_id == RULE_001), None)
    assert match is not None
    assert "MCP07:2025" in match.owasp_mcp_references


def test_scanner_registered_in_engine() -> None:
    """Defensive: ensure the scanner is wired into the engine registry so
    `agent-audit-kit scan` actually runs it."""
    from agent_audit_kit.engine import _OPTIONAL_SCANNERS
    names = {name for name, _, _ in _OPTIONAL_SCANNERS}
    assert "mcp_stateless_migration" in names
