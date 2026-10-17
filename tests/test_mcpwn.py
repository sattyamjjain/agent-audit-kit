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
# The router the CVE was found in: two middlewares, inline handlers.
# ---------------------------------------------------------------------------


def test_the_real_router_shape_fires(tmp_path: Path) -> None:
    """A minimal reproduction of nginx-ui's router at e8ee931e16af. The Gin
    pattern this rule used read each route to the first `)`, the one closing
    `middleware.IPWhiteList()`, so `/mcp` never looked authenticated and the
    rule was silent on the code its CVE was found in. AAK-MCP-020 recognises
    the route too; it is reported once, here."""
    project = _stage(tmp_path, FIX / "vulnerable" / "mcp_router.go")
    findings, _ = mcp_middleware.scan(project)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-MCPWN-001", 21)]
    assert "/mcp_message" in findings[0].evidence


def test_the_real_fix_is_quiet(tmp_path: Path) -> None:
    """nginx-ui's fix, 413dc631eea8, adds `AuthRequired()` to the second route."""
    project = _stage(tmp_path, FIX / "patched" / "mcp_router.go")
    findings, _ = mcp_middleware.scan(project)
    assert findings == []


def test_routes_after_a_regex_literal_holding_a_backtick_are_read(tmp_path: Path) -> None:
    """The bracket reader took a regex literal's backtick for a template and
    read everything to the next backtick as one string; the regex reader this
    replaced fired here."""
    (tmp_path / "server.ts").write_text(
        "import express from 'express';\n"
        "const app = express();\n"
        "const fence = (s) => s.split(/`/).length;\n"
        "app.post('/mcp', requireAuth, handler);\n"
        "app.post('/mcp_message', handler);\n"
        "const banner = `listening on ${port}`;\n"
    )
    findings, _ = mcp_middleware.scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-MCPWN-001", 5)]


def test_a_group_made_with_several_middlewares_covers_its_routes(tmp_path: Path) -> None:
    (tmp_path / "router.go").write_text(
        "package mcp\n"
        "func Register(r *gin.Engine) {\n"
        '    g := r.Group("/", middleware.IPWhiteList(), middleware.AuthRequired())\n'
        '    r.POST("/mcp", AuthRequired(), handler)\n'
        '    g.POST("/mcp_message", handler)\n'
        "}\n"
    )
    findings, _ = mcp_middleware.scan(tmp_path)
    assert findings == []


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
    # Every middleware is read, not only the text before the first `)`.
    ('app.post("/mcp", cors(), requireAuth, h);\n', [("/mcp", 1, "cors(), requireAuth, h", True)]),
    # The handler is read to its first `)`: an auth wrapper counts, a body does not.
    ("app.post('/mcp', requireAuth(h));\n", [("/mcp", 1, "requireAuth(h)", True)]),
    ('app.post("/mcp", (req, res) => requireAuth(req));\n', [("/mcp", 1, "(req, res) => requireAuth(req)", False)]),
    # A route needs a handler; a call in a comment or a string is no route.
    ('app.post("/mcp", )', []),
    ('app.post("/mcp",)', []),
    ('// app.post("/mcp", authMw, h)\nconst s = \'app.post("/mcp", authMw, h)\';\n', []),
    ('app.post("/mcp", app.post("/mcp_message", h))', [("/mcp", 1, 'app.post("/mcp_message", h)', False), ("/mcp_message", 1, "h", False)]),
])
def test_express_routes_keep_their_shape(source: str, hits: list) -> None:
    assert _hits(mcp_middleware._extract_express(source)) == hits


@pytest.mark.parametrize(("source", "hits"), [
    ('r.Any("/mcp", middleware.IPWhiteList(), middleware.AuthRequired(),\n\tfunc(c *gin.Context) {\n\t\tmcp.ServeHTTP(c)\n\t})\n',
     [("/mcp", 1, "middleware.IPWhiteList(), middleware.AuthRequired(),\n\tfunc(c *gin.Context) {\n\t\tmcp.ServeHTTP(c)\n\t}", True)]),
    ('r.Handle("POST", "/mcp_message", AuthRequired(), h)\n', [("/mcp_message", 1, "AuthRequired(), h", True)]),
    ('r.POST("/mcp", h,\n)\n', [("/mcp", 1, "h", False)]),
    # Paths are double-quoted literals, as before.
    ("r.POST(`/mcp`, AuthRequired(), h)\n", []),
])
def test_gin_routes_keep_their_shape(source: str, hits: list) -> None:
    assert _hits(mcp_middleware._extract_gin(source)) == hits


_CRAFTED = {
    "word.go": "/mcp " + "a" * 500_000 + ")",
    "calls.go": 'r.POST("/mcp", ' * 30_000,
    "groups.go": '/mcp g := r.Group("x", ' * 20_000,
    "calls.ts": 'app.post("/mcp", ' * 28_000,
    "middlewares.go": 'r.POST("/mcp", ' + "mw(), " * 80_000 + "h)\n",
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


@pytest.mark.parametrize(("pad", "fires"), [(182, True), (183, False)])
def test_a_middleware_argument_is_read_for_auth_markers_in_its_first_200_characters(
    tmp_path: Path, pad: int, fires: bool,
) -> None:
    """`AuthRequired` ends at character 200 of the argument, or one past it."""
    middleware = "chain(" + "x" * pad + "AuthRequired())"
    (tmp_path / "router.go").write_text(
        f'package mcp\nfunc Register(r *gin.Engine) {{\n    r.POST("/mcp", {middleware}, handler)\n'
        '    r.POST("/mcp_message", handler)\n}\n'
    )
    findings, _ = mcp_middleware.scan(tmp_path)
    mcpwn = [(f.rule_id, f.line_number) for f in findings if f.rule_id == "AAK-MCPWN-001"]
    assert mcpwn == ([("AAK-MCPWN-001", 4)] if fires else [])


def test_the_rule_states_its_windows() -> None:
    from agent_audit_kit.rules.builtin import RULES

    limitations = RULES["AAK-MCPWN-001"].limitations
    assert "first 200 characters" in limitations and "512 characters of its `/`" in limitations
