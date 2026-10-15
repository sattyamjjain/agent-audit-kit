"""Tests for AAK-MCPWN-001 (CVE-2026-33032 twin-route asymmetry)."""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

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
    # A route that skips the auth middleware its twin has is OWASP MCP07
    # (Insufficient Authentication & Authorization) and ASI03. The ASI01/ASI02 and
    # MCP02 pins here did not describe an authentication bypass.
    assert rule.owasp_agentic_references == ["ASI03"]
    assert rule.owasp_mcp_references == ["MCP07:2025"]
    assert "MCPWN-2026-04-16" in rule.incident_references


# ---------------------------------------------------------------------------
# Route extraction keeps its shape, and reads a crafted file in linear time.
# ---------------------------------------------------------------------------


def _hits(hits: list) -> list[tuple[str, int, str, bool]]:
    return [(h.route, h.line, h.line_text, h.has_auth) for h in hits]


@pytest.mark.parametrize(("source", "hits"), [
    ('@app.post("/mcp")\n@limit(1)\nasync def a(x): ...\n', [("/mcp", 1, '@app.post("/mcp")', False)]),
    ('@app.post("/mcp", dependencies=[Depends(auth)])\ndef a(x): ...\n\n@app.post("/mcp_message")\ndef b(y): ...\n',
     [("/mcp", 1, '@app.post("/mcp", dependencies=[Depends(auth)])', True), ("/mcp_message", 4, '@app.post("/mcp_message")', False)]),
    ('@app.post("/mcp")\nprint(x)\ndef a(x): ...\n', [("/mcp", 1, '@app.post("/mcp")', False)]),
    ('@app.post("/mcp")\nx = 1\n', []),
])
def test_fastapi_routes_keep_their_shape(source: str, hits: list) -> None:
    assert _hits(mcp_middleware._extract_fastapi(source)) == hits


@pytest.mark.parametrize(("source", "hits"), [
    ('app.post("/mcp", authMw, h);\napp.post("/mcp_message", h);\n', [("/mcp", 1, "authMw, h", True), ("/mcp_message", 2, "h", False)]),
    ('app.post("/mcp", )', [("/mcp", 1, " ", False)]),
    ('app.post("/mcp",)', []),
    ('app.post("/mcp", a; b)', []),
    ('app.post("/mcp", app.post("/mcp_message", h))', [("/mcp", 1, 'app.post("/mcp_message", h', False)]),
])
def test_express_routes_keep_their_shape(source: str, hits: list) -> None:
    assert _hits(mcp_middleware._extract_express(source)) == hits


_CRAFTED = {
    "word.go": "/mcp " + "a" * 500_000 + ")",
    "calls.go": 'r.POST("/mcp", ' * 30_000,
    "groups.go": '/mcp g := r.Group("x", ' * 20_000,
    "calls.ts": 'app.post("/mcp", ' * 28_000,
    "statements.ts": 'app.post("/mcp", h;' * 25_000 + ")",
    "decorators.py": '@app.post("/mcp")\n' * 27_000,
}


@pytest.mark.parametrize("name", sorted(_CRAFTED))
def test_a_crafted_route_file_scans_in_linear_time(tmp_path: Path, name: str) -> None:
    """About 500 KB each, under the scanner's 512 KB cap. Before, a long word
    was read once per character, a call with no `)` after it once per call
    (120 KB of Gin calls took 3.8 seconds), and the FastAPI pattern tried
    every split of the decorator lines, doubling with each one: 22 took half
    a second. The bound is loose for slow CI runners; each takes milliseconds."""
    (tmp_path / name).write_text(_CRAFTED[name], encoding="utf-8")
    started = time.perf_counter()
    mcp_middleware.scan(tmp_path)
    assert time.perf_counter() - started < 5.0
