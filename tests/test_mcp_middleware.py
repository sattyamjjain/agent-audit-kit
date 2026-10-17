"""AAK-MCP-020: one MCP handler on two routes, authentication on only one.

AAK-MCPWN-001, the other rule in `mcp_middleware`, has its tests in
`test_mcpwn.py`.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_audit_kit.scanners import mcp_middleware
from agent_audit_kit.scanners._http_routes import CodeIndex

RULE = "AAK-MCP-020"
FIX = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-33032"

# A minimal reproduction of nginx-ui's mcp/router.go before the CVE-2026-33032
# fix, and of the fix: both routes run one handler behind an IP allowlist, and
# only `/mcp` (line 17) adds `middleware.AuthRequired()` until the fix adds it
# to `/mcp_message` (line 21) too.
NGINX_UI = (FIX / "vulnerable" / "mcp_router.go").read_text(encoding="utf-8")
NGINX_UI_FIXED = (FIX / "patched" / "mcp_router.go").read_text(encoding="utf-8")


def _hits(root: Path) -> list[tuple[str, int | None]]:
    findings, _ = mcp_middleware.scan(root)
    return [(f.file_path, f.line_number) for f in findings if f.rule_id == RULE]


def _one(tmp_path: Path, name: str, text: str) -> list[tuple[str, int | None]]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return _hits(tmp_path)


# ---------------------------------------------------------------------------
# Detecting
# ---------------------------------------------------------------------------


def test_the_nginx_ui_router_is_recognised_and_reported_once(tmp_path: Path) -> None:
    """Both rules recognise CVE-2026-33032's own router. The route is reported
    once, by AAK-MCPWN-001, the rule named for the CVE: two findings on one line
    would be one defect twice."""
    (tmp_path / "mcp").mkdir()
    (tmp_path / "mcp" / "router.go").write_text(NGINX_UI, encoding="utf-8")
    findings, _ = mcp_middleware.scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-MCPWN-001", 21)]
    own = mcp_middleware._shared_handler_findings(CodeIndex(NGINX_UI, go=True), "mcp/router.go", set())
    assert [(f.rule_id, f.line_number) for f in own] == [(RULE, 21)]
    assert "line 17" in own[0].evidence and "middleware.AuthRequired()" in own[0].evidence


def test_the_fixed_nginx_ui_router_is_quiet(tmp_path: Path) -> None:
    assert _one(tmp_path, "mcp/router.go", NGINX_UI_FIXED) == []
    assert mcp_middleware._shared_handler_findings(CodeIndex(NGINX_UI_FIXED, go=True), "mcp/router.go", set()) == []


EXPRESS = '''import express from "express";
const app = express();
app.post("/mcp", requireBearerAuth({ verifier }), handleMcp);
app.get("/mcp", handleMcp);
app.delete("/mcp", handleMcp);
'''


def test_an_express_handler_open_on_other_methods_is_reported(tmp_path: Path) -> None:
    assert _one(tmp_path, "server.ts", EXPRESS) == [("server.ts", 4), ("server.ts", 5)]


def test_the_finding_names_both_routes_and_the_auth(tmp_path: Path) -> None:
    _one(tmp_path, "server.ts", EXPRESS)
    findings, _ = mcp_middleware.scan(tmp_path)
    evidence = next(f.evidence for f in findings if f.rule_id == RULE)
    assert "GET '/mcp'" in evidence and "POST '/mcp'" in evidence and "requireBearerAuth" in evidence


@pytest.mark.parametrize(("name", "text", "line"), [
    ("router.go", 'package x\nfunc R(mux *http.ServeMux) {\n\tmux.Handle("/mcp", authMiddleware(handler))\n'
     '\tmux.Handle("/mcp/", handler)\n}\n', 4),
    ("echo.go", 'package x\nimport "github.com/labstack/echo/v4"\nfunc R(e *echo.Echo) {\n'
     '\te.POST("/mcp", h.serve, middleware.KeyAuth(validate))\n\te.GET("/mcp", h.serve)\n}\n', 5),
    ("hono.ts", 'const app = new Hono();\napp.post("/mcp", bearerAuth({ token }), (c) => transport.handleRequest(c));\n'
     'app.get("/mcp", (c) => transport.handleRequest(c));\n', 3),
])
def test_other_frameworks_are_read(tmp_path: Path, name: str, text: str, line: int) -> None:
    assert _one(tmp_path, name, text) == [(name, line)]


# ---------------------------------------------------------------------------
# Not detecting
# ---------------------------------------------------------------------------


def test_registrations_in_an_if_and_its_else_never_coexist(tmp_path: Path) -> None:
    """The TypeScript SDK's example server, copied widely."""
    text = '''if (useOAuth && authMiddleware) {
  app.post("/mcp", authMiddleware, mcpPostHandler);
  app.post("/", authMiddleware, mcpPostHandler);
} else {
  app.post("/mcp", mcpPostHandler);
  app.post("/", mcpPostHandler);
}
'''
    assert _one(tmp_path, "server.ts", text) == []


@pytest.mark.parametrize("scope", [
    'app.use(authMiddleware);\n',
    'app.use("/mcp", authMiddleware);\n',
    'app.use("/mcp/*", bearerAuth({ token }));\n',
])
def test_scope_auth_covers_the_open_route(tmp_path: Path, scope: str) -> None:
    assert _one(tmp_path, "server.ts", scope + EXPRESS) == []


def test_a_gin_group_made_with_auth_covers_its_routes(tmp_path: Path) -> None:
    text = '''package x
func R(r *gin.Engine) {
	g := r.Group("/", middleware.AuthRequired())
	g.POST("/mcp", middleware.AuthRequired(), h)
	g.GET("/mcp", h)
}
'''
    assert _one(tmp_path, "router.go", text) == []


def test_a_mux_handed_to_an_auth_wrapper_is_covered(tmp_path: Path) -> None:
    text = '''package x
func main() {
	mux.Handle("/mcp", requireAuth(handler))
	mux.Handle("/mcp/", handler)
	http.ListenAndServe(":8080", withAuth(mux))
}
'''
    assert _one(tmp_path, "main.go", text) == []


def test_an_unknown_middleware_on_the_open_route_may_be_its_auth(tmp_path: Path) -> None:
    assert _one(tmp_path, "server.ts", EXPRESS.replace('app.get("/mcp", handleMcp)', 'app.get("/mcp", checkKey, handleMcp)')) == [
        ("server.ts", 5)
    ]


def test_different_handlers_are_not_paired(tmp_path: Path) -> None:
    """A 405 stub on GET is its own handler: dataforseo-mcp-server, lark-mcp."""
    text = '''app.post("/mcp", authMiddleware, handleStreamableRequest);
app.get("/mcp", handleNotAllowed("GET MCP"));
app.delete("/mcp", (req, res) => res.status(405).end());
'''
    assert _one(tmp_path, "server.ts", text) == []


def test_two_health_checks_answering_with_res_json_are_not_one_handler(tmp_path: Path) -> None:
    text = '''app.post("/mcp/initialize", validateApiKey, (req, res) => res.json({ ok: true }));
app.get("/health", (req, res) => res.json({ ok: true }));
'''
    assert _one(tmp_path, "server.js", text) == []


def test_routes_that_are_not_mcp_are_not_read(tmp_path: Path) -> None:
    text = 'app.post("/admin/users", requireAuth, users);\napp.get("/users", users);\n// mcp\n'
    assert _one(tmp_path, "server.ts", text) == []


def test_an_ip_allowlist_is_not_authentication(tmp_path: Path) -> None:
    text = NGINX_UI.replace("middleware.AuthRequired(),", "")
    assert _one(tmp_path, "mcp/router.go", text) == []


@pytest.mark.parametrize("name", ["router_test.go", "test/server.ts", "mocks/server.ts"])
def test_test_files_are_not_read(tmp_path: Path, name: str) -> None:
    text = NGINX_UI if name.endswith(".go") else EXPRESS
    assert _one(tmp_path, name, text) == []


def test_a_route_mcpwn_reports_is_not_reported_twice(tmp_path: Path) -> None:
    _one(tmp_path, "router.go", (FIX / "vulnerable" / "router.go").read_text(encoding="utf-8"))
    findings, _ = mcp_middleware.scan(tmp_path)
    assert {f.rule_id for f in findings} == {"AAK-MCPWN-001"}


# ---------------------------------------------------------------------------
# Linear time on crafted files
# ---------------------------------------------------------------------------

_CRAFTED = {
    # Nested route calls, every paren closed: each level used to rebuild the text below it.
    "nested.ts": 'app.post("/mcp", ' * 20_000 + "h" + ")" * 20_000 + ";\nmcp\n",
    "nested.go": 'r.POST("/mcp", ' * 20_000 + "h" + ")" * 20_000 + "\n",
    # Middleware arguments holding nested calls.
    "middleware.ts": 'app.post("/mcp", auth(' * 15_000 + "x" + ")" * 15_000 + ", h);\napp.get('/mcp', h);\n",
    # Unclosed strings and comments.
    "strings.ts": '"\\' * 100_000 + "\n/* mcp " * 20_000,
    "groups.go": 'g := r.Group("/x", ' * 20_000 + "\nmcp\n",
}


@pytest.mark.parametrize("name", sorted(_CRAFTED))
def test_a_crafted_route_file_scans_in_linear_time(tmp_path: Path, name: str) -> None:
    """About 400 KB each, under the scanner's 512 KB cap; each takes well under a second."""
    (tmp_path / name).write_text(_CRAFTED[name], encoding="utf-8")
    started = time.perf_counter()
    mcp_middleware.scan(tmp_path)
    assert time.perf_counter() - started < 5.0


def test_the_rule_states_what_it_reads() -> None:
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES[RULE]
    assert "Go or TypeScript/JavaScript" in rule.description
    assert "Python servers are not read" in rule.limitations
    assert "AAK-MCPWN-001 reports is left to that rule" in rule.limitations
