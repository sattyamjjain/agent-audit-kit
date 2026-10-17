"""AAK-MCP-020 (one MCP handler on two routes, authentication on only one) and
AAK-MCP-019 (a lookup keyed on the caller's input, answered before the auth check).

AAK-MCPWN-001, the other rule in `mcp_middleware`, has its tests in
`test_mcpwn.py`.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

import pytest

import agent_audit_kit
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


def _seconds(run: Callable[[], object]) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


def _grows_linearly(tmp_path: Path, name: str, build: Callable[[int], str], count: int) -> None:
    """``build(count)`` and ``build(10 * count)``: the second reports ten times
    the routes and must not take a hundred times as long."""
    roots = []
    for label, n in (("small", count), ("large", 10 * count)):
        root = tmp_path / label
        root.mkdir()
        text = build(n)
        assert len(text) < 512_000, "under the scanner's 512 KB cap"
        (root / name).write_text(text, encoding="utf-8")
        roots.append(root)
    assert len(_hits(roots[0])) == count and len(_hits(roots[1])) == 10 * count
    t_small, t_large = _seconds(lambda: mcp_middleware.scan(roots[0])), _seconds(lambda: mcp_middleware.scan(roots[1]))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


_GIN_HEAD = 'package main\nimport "github.com/gin-gonic/gin"\nfunc h(c *gin.Context) {}\nfunc main() {\n\tr := gin.New()\n'


def _twins_on_one_path(n: int) -> str:
    """n open and n authenticated routes of one handler on one method and path,
    then one authenticated on another: each open route searched the whole
    authenticated list for a twin. 8,300 routes took 6.6 seconds."""
    return (
        _GIN_HEAD + '\tr.GET("/mcp/rpc", h)\n' * n + '\tr.GET("/mcp/rpc", authRequired(), h)\n' * n
        + '\tr.POST("/mcp", authRequired(), h)\n}\n'
    )


def _many_scopes(n: int) -> str:
    """n open routes and n auth calls on other receivers: each route was
    checked against every scope."""
    routes = "".join(f'\tr.GET("/mcp/v{i}", h)\n' for i in range(n))
    scopes = "".join(f"\tauthRequired(router{i})\n" for i in range(n))
    return _GIN_HEAD + routes + '\tr.POST("/mcp", authRequired(), h)\n' + scopes + "}\n"


def _many_prefixes(n: int) -> str:
    """n auth prefixes on one app and n open routes outside all of them."""
    scopes = "".join(f"app.use('/p{i}', requireAuth);\n" for i in range(n))
    routes = "".join(f"app.get('/mcp/v{i}', handleMcp);\n" for i in range(n))
    return "const app = express();\n" + scopes + "app.post('/mcp', requireAuth, handleMcp);\n" + routes


@pytest.mark.parametrize(("name", "build", "count"), [
    ("twins.go", _twins_on_one_path, 800),
    ("scopes.go", _many_scopes, 900),
    ("prefixes.ts", _many_prefixes, 700),
])
def test_a_large_route_table_pairs_in_linear_time(
    tmp_path: Path, name: str, build: Callable[[int], str], count: int,
) -> None:
    _grows_linearly(tmp_path, name, build, count)


# A regex literal holding a backtick: the reader took everything to the next
# backtick as a template, and the routes after it with it.
_REGEX_PRELUDE = "const fence = (s) => s.split(/`/).length;\n"


def test_routes_after_a_regex_literal_are_still_read(tmp_path: Path) -> None:
    text = EXPRESS.replace("const app = express();\n", "const app = express();\n" + _REGEX_PRELUDE) + (
        "const banner = `listening on ${port}`;\n"
    )
    assert _one(tmp_path, "server.ts", text) == [("server.ts", 5), ("server.ts", 6)]


def test_the_rule_states_what_it_reads() -> None:
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES[RULE]
    assert "Go or TypeScript/JavaScript" in rule.description
    assert "Python servers are not read" in rule.limitations
    assert "AAK-MCPWN-001 reports is left to that rule" in rule.limitations


# ---------------------------------------------------------------------------
# AAK-MCP-019: a lookup keyed on the caller's input, answered before auth
# ---------------------------------------------------------------------------

LOOKUP = "AAK-MCP-019"
GATEWAY = (Path(__file__).parent / "fixtures" / "limitations" / LOOKUP / "positive" / "gateway.go").read_text(
    encoding="utf-8"
)


def _lookups(tmp_path: Path, name: str, text: str) -> list[tuple[str, int | None]]:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    findings, _ = mcp_middleware.scan(tmp_path)
    return [(f.file_path, f.line_number) for f in findings if f.rule_id == LOOKUP]


def test_a_lookup_answered_404_before_the_token_check_is_reported(tmp_path: Path) -> None:
    """The shape of SUSE/suse-ai-up's uniproxy REST MCP endpoints at fdd1812e."""
    assert _lookups(tmp_path, "gateway.go", GATEWAY) == [("gateway.go", 21)]
    findings, _ = mcp_middleware.scan(tmp_path)
    evidence = next(f.evidence for f in findings if f.rule_id == LOOKUP)
    assert "store.Get" in evidence and "`name`" in evidence and "line 22" in evidence and "line 27" in evidence


NET_HTTP = """package mcp

import "net/http"

func Routes(mux *http.ServeMux, sessions SessionStore) {
	mux.HandleFunc("/mcp/{session}", func(w http.ResponseWriter, r *http.Request) {
		handleMCP(w, r, sessions)
	})
}

func handleMCP(w http.ResponseWriter, r *http.Request, sessions SessionStore) {
	session, ok := sessions.Lookup(r.PathValue("session"))
	if !ok || session == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	if !validateBearerToken(r, session.Owner) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	session.Serve(w, r)
}
"""

IF_HEADER = """package mcp

func Register(r *gin.Engine, store Store) {
	r.POST("/mcp/:tenant", func(c *gin.Context) { serveMCP(c, store) })
}

func serveMCP(c *gin.Context, store Store) {
	if _, err := store.FindTenant(c.Param("tenant")); err != nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if err := authenticate(c); err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}
"""


@pytest.mark.parametrize(("name", "text", "line"), [("server.go", NET_HTTP, 12), ("tenant.go", IF_HEADER, 8)])
def test_other_spellings_are_read(tmp_path: Path, name: str, text: str, line: int) -> None:
    assert _lookups(tmp_path, name, text) == [(name, line)]


@pytest.mark.parametrize("change", [
    # The credential is checked first.
    lambda t: t.replace(
        '\tname := c.Param("name")\n',
        '\tif err := checkClientToken(c, ""); err != nil {\n'
        '\t\tc.JSON(http.StatusUnauthorized, gin.H{})\n\t\treturn\n\t}\n\tname := c.Param("name")\n',
    ),
    # The key is not the caller's: the server's own setting.
    lambda t: t.replace("store.Get(c.Request.Context(), name)", "store.Get(c.Request.Context(), defaultAdapter)"),
    # The miss is not answered "not found".
    lambda t: t.replace("http.StatusNotFound", "http.StatusBadGateway"),
    # The later 401 relays an upstream answer; no credential of the caller's is checked.
    lambda t: t.replace("checkClientToken(c, adapter.Token)", "upstreamStatus(adapter)"),
    # Behind auth middleware on the route, or on its group, the lookup runs after auth.
    lambda t: t.replace('adapters.GET("/:name/tools", func', 'adapters.GET("/:name/tools", requireAuth(), func'),
    lambda t: t.replace('r.Group("/api/v1/adapters")', 'r.Group("/api/v1/adapters", middleware.AuthRequired())'),
    # Not registered in this file: what runs before it is unknown.
    lambda t: t.replace('adapters.GET("/:name/tools", func(c *gin.Context) {\n\t\tlistMCPTools(c, store)\n\t})\n', ""),
    # Nothing in the handler or its name says MCP.
    lambda t: t.replace("listMCPTools", "listTools").replace("forwardMCP", "forward").replace('"tools/list"', '"list"'),
])
def test_quiet_variants(tmp_path: Path, change) -> None:
    text = change(GATEWAY)
    assert text != GATEWAY
    assert _lookups(tmp_path, "gateway.go", text) == []


@pytest.mark.parametrize("name", ["gateway_test.go", "testdata/gateway.go", "mocks/gateway.go"])
def test_test_files_are_not_read_for_the_lookup_order(tmp_path: Path, name: str) -> None:
    assert _lookups(tmp_path, name, GATEWAY) == []


def test_the_lookup_rule_states_what_it_reads() -> None:
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES[LOOKUP]
    assert rule.title == "MCP auth check runs after a resource lookup"
    assert "Go MCP HTTP handler" in rule.description
    assert "TypeScript, JavaScript and Python handlers are not read" in rule.limitations


_LOOKUP_LEVEL = (
    'r.GET("/mcp", func(c *gin.Context) {\n'
    '\tx, err := s.Get(c.Param("n"))\n'
    "\tif err != nil || x == nil { c.JSON(http.StatusNotFound, nil); return }\n"
    "\tif e := auth(c); e != nil { c.JSON(http.StatusUnauthorized, nil); return }\n"
)
_CRAFTED_LOOKUPS = {
    # Nested handlers, each a full instance of the shape.
    "nested.go": "package x\nfunc R(r *gin.Engine) {\n" + _LOOKUP_LEVEL * 2_200 + "})\n" * 2_200 + "}\n",
    # One handler holding a long run of `if` statements before its lookup.
    "ifs.go": 'package x\nfunc R(r *gin.Engine) {\nr.GET("/mcp", func(c *gin.Context) {\n'
    + "if a { c.JSON(http.StatusUnauthorized, auth(c)) }\n" * 9_000
    + _LOOKUP_LEVEL.split("\n", 1)[1] + "})\n}\n",
    # A long run of blocks on one line after a lookup: each is checked for an `if` once.
    "blocks.go": 'package x\nfunc R(r *gin.Engine) {\nr.GET("/mcp", func(c *gin.Context) {\n'
    + _LOOKUP_LEVEL.split("\n", 2)[1] + "\n" + "{}" * 230_000 + "\nStatusUnauthorized\n})\n}\n",
    # Many lookups on one long line, none followed by an `if`.
    "line.go": 'package x\nfunc R(r *gin.Engine) {\nr.GET("/mcp", func(c *gin.Context) {\n'
    + 's.Get(c.Param("n")); ' * 25_000 + "\nif x { c.JSON(http.StatusNotFound, nil); return }\n})\n}\n",
}


@pytest.mark.parametrize("name", sorted(_CRAFTED_LOOKUPS))
def test_a_crafted_handler_file_scans_in_linear_time(tmp_path: Path, name: str) -> None:
    """About 400-500 KB each, under the scanner's 512 KB cap; each takes well under a second."""
    (tmp_path / name).write_text(_CRAFTED_LOOKUPS[name], encoding="utf-8")
    started = time.perf_counter()
    mcp_middleware.scan(tmp_path)
    assert time.perf_counter() - started < 5.0


# ---------------------------------------------------------------------------
# Linear time: Group assignments, same-named handlers
# ---------------------------------------------------------------------------

# A child process scans each crafted file, so a quadratic path fails the test
# on its timeout instead of stalling the suite.
_CHILD = (
    "import sys, time\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.scanners import mcp_middleware\n"
    "started = time.perf_counter()\n"
    "findings, _ = mcp_middleware.scan(Path(sys.argv[1]))\n"
    "print(time.perf_counter() - started, len(findings))\n"
)


def _scan_in_child(tmp_path: Path, label: str, text: str) -> tuple[float, int]:
    root = tmp_path / label
    root.mkdir()
    (root / "router.go").write_text(text, encoding="utf-8")
    assert len(text) < 512_000, "under the scanner's 512 KB cap"
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _CHILD, str(root)], capture_output=True, text=True, timeout=60, env=env,
    )
    assert done.returncode == 0, done.stderr
    seconds, count = done.stdout.split()
    return float(seconds), int(count)


_GO_HEAD = 'package main\n\nimport (\n\t"io"\n\t"net/http"\n\t"github.com/gin-gonic/gin"\n)\n\n'


def test_a_line_of_group_calls_scans_in_linear_time(tmp_path: Path) -> None:
    """Each `.Group(` searched the whole line before it for its assignment: 128
    KB of `g := r.Group();` on one line took 13 seconds, 200 KB about 33."""
    text = _GO_HEAD + "// mcp\nfunc main() {\n\tr := gin.New(); " + "g := r.Group();" * 13_300 + '\n\tr.POST("/mcp", h)\n}\n'
    seconds, _count = _scan_in_child(tmp_path, "groups", text)
    assert seconds < 5.0


def _methods_and_routes(k: int, same: bool) -> str:
    names = ["h" if same else f"h{i}" for i in range(k)]
    return (
        _GO_HEAD + "// mcp\n" + "".join(f"func (s S) {n}(c *gin.Context) {{}}\n" for n in names)
        + 'func main() {\n\tc.Param("x")\n\t_ = http.StatusNotFound + http.StatusUnauthorized\n'
        + "".join(f'\tr.GET("/mcp", {n})\n' for n in names) + "}\n"
    )


def test_same_named_handlers_scan_in_linear_time(tmp_path: Path) -> None:
    """AAK-MCP-019 listed and checked every route naming a handler for each
    handler of that name, and Go methods on different receivers share names:
    8,500 methods named `h` with a route each took 6.5 seconds, against 0.4
    for distinct names."""
    t_same, _ = _scan_in_child(tmp_path, "same", _methods_and_routes(8_500, same=True))
    t_distinct, _ = _scan_in_child(tmp_path, "distinct", _methods_and_routes(8_500, same=False))
    assert t_same < 5.0
    assert t_same < 4 * t_distinct + 0.25, (t_distinct, t_same)


# ---------------------------------------------------------------------------
# AAK-MCP-019: handlers registered as method values and through a receiver
# ---------------------------------------------------------------------------

METHOD_VALUE = GATEWAY.replace(
    "func Register(r *gin.Engine, store AdapterStore) {\n\tadapters := r.Group(\"/api/v1/adapters\")\n"
    "\tadapters.GET(\"/:name/tools\", func(c *gin.Context) {\n\t\tlistMCPTools(c, store)\n\t})\n}\n",
    "type Server struct{ store AdapterStore }\n\nfunc (s *Server) Register(r *gin.Engine) {\n"
    "\tadapters := r.Group(\"/api/v1/adapters\")\n\tadapters.GET(\"/:name/tools\", s.listMCPTools)\n}\n",
).replace(
    "func listMCPTools(c *gin.Context, store AdapterStore) {\n",
    "func (s *Server) listMCPTools(c *gin.Context) {\n\tstore := s.store\n",
)
RECEIVER_DELEGATE = GATEWAY.replace("\t\tlistMCPTools(c, store)\n", "\t\th.listMCPTools(c, store)\n")


@pytest.mark.parametrize(("text", "line"), [(METHOD_VALUE, 22), (RECEIVER_DELEGATE, 21)],
                         ids=["method-value", "receiver-delegate"])
def test_a_handler_registered_as_a_method_value_or_through_a_receiver_is_read(
    tmp_path: Path, text: str, line: int,
) -> None:
    """The usual Go idiom for a struct-based server, `adapters.GET(path,
    s.listMCPTools)`, keyed the route as `s.listMCPTools`, which no handler is
    named, so the handler was never read."""
    assert text != GATEWAY
    assert _lookups(tmp_path, "gateway.go", text) == [("gateway.go", line)]


def test_a_method_value_on_an_authenticated_route_is_quiet(tmp_path: Path) -> None:
    text = METHOD_VALUE.replace('adapters.GET("/:name/tools", s.listMCPTools)',
                                'adapters.GET("/:name/tools", requireAuth(), s.listMCPTools)')
    assert _lookups(tmp_path, "gateway.go", text) == []
