"""Tests for AAK-MCPWN-001 (CVE-2026-33032 twin-route asymmetry)."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners import mcp_middleware

FIX = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-33032"


def _stage(tmp_path: Path, src: Path, filename: str | None = None) -> Path:
    dst = tmp_path / (filename or src.name)
    shutil.copy(src, dst)
    return tmp_path


# ---------------------------------------------------------------------------
# Vulnerable (MCPwn) shape must fire.
# ---------------------------------------------------------------------------


def test_gin_twin_asymmetry_fires(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "vulnerable" / "router.go")
    findings, scanned = mcp_middleware.scan(project)
    assert any(f.rule_id == "AAK-MCPWN-001" for f in findings), findings
    hit = next(f for f in findings if f.rule_id == "AAK-MCPWN-001")
    assert "/mcp_message" in hit.evidence
    assert "CVE-2026-33032" in hit.description
    assert "router.go" in next(iter(scanned))


def test_fastapi_twin_asymmetry_fires(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "vulnerable" / "server.py")
    findings, _ = mcp_middleware.scan(project)
    assert any(f.rule_id == "AAK-MCPWN-001" for f in findings)
    hit = next(f for f in findings if f.rule_id == "AAK-MCPWN-001")
    assert "/mcp_message" in hit.evidence


def test_express_twin_asymmetry_fires(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "vulnerable" / "server.ts")
    findings, _ = mcp_middleware.scan(project)
    assert any(f.rule_id == "AAK-MCPWN-001" for f in findings)


# ---------------------------------------------------------------------------
# Patched shape must NOT fire (router-group with shared middleware).
# ---------------------------------------------------------------------------


def test_patched_group_is_quiet(tmp_path: Path) -> None:
    project = _stage(tmp_path, FIX / "patched" / "router.go")
    findings, _ = mcp_middleware.scan(project)
    assert not any(f.rule_id == "AAK-MCPWN-001" for f in findings)


# ---------------------------------------------------------------------------
# No MCP routes at all → no finding. No false positives on arbitrary code.
# ---------------------------------------------------------------------------


def test_no_mcp_routes_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "api.go").write_text(
        "package api\n"
        "import \"github.com/gin-gonic/gin\"\n"
        "func Register(r *gin.Engine) {\n"
        "    r.POST(\"/users\", userHandler)\n"
        "}\n"
    )
    findings, _ = mcp_middleware.scan(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# Single-route files never fire — MCPwn is inherently a twin bug.
# ---------------------------------------------------------------------------


def test_single_unauthenticated_mcp_route_is_quiet(tmp_path: Path) -> None:
    # This SHOULD fire AAK-MCP-011 separately but NOT AAK-MCPWN-001.
    (tmp_path / "solo.go").write_text(
        "package mcp\n"
        "import \"github.com/gin-gonic/gin\"\n"
        "func Register(r *gin.Engine) {\n"
        "    r.POST(\"/mcp\", handler)\n"
        "}\n"
    )
    findings, _ = mcp_middleware.scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCPWN-001" for f in findings)


# ---------------------------------------------------------------------------
# Rule metadata sanity — the rule advertises the right things.
# ---------------------------------------------------------------------------


def test_rule_metadata_cve_and_incident() -> None:
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES["AAK-MCPWN-001"]
    assert rule.severity.value == "critical"
    assert "CVE-2026-33032" in rule.cve_references
    assert "ASI01" in rule.owasp_agentic_references
    assert "ASI02" in rule.owasp_agentic_references
    assert "MCP02:2025" in rule.owasp_mcp_references
    assert "MCPWN-2026-04-16" in rule.incident_references
