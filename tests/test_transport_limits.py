"""AAK-MCP-016: an MCP endpoint that reads the whole request body with no limit.

AAK-MCPFRAME-001, the other rule in `transport_limits`, has its tests in
`test_cve_2026_39313.py`.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import transport_limits

RULE = "AAK-MCP-016"


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _hits(root: Path) -> list[tuple[str, int | None]]:
    findings, _ = transport_limits.scan(root)
    return [(f.file_path, f.line_number) for f in findings if f.rule_id == RULE]


FASTAPI = '''from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/mcp")
async def mcp(request: Request) -> dict:
    message = await request.json()
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": {}}
'''

STARLETTE = '''from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


async def handle(request: Request) -> JSONResponse:
    raw = await request.body()
    return JSONResponse({"ok": len(raw)})


app = Starlette(routes=[Route("/api/v1/mcp", endpoint=handle, methods=["POST"])])
'''

FLASK = '''from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/mcp", methods=["POST"])
def mcp():
    body = request.get_json(silent=True) or {}
    return jsonify({"jsonrpc": "2.0", "id": body.get("id")})
'''

GO_NETHTTP = '''package main

import (
	"encoding/json"
	"net/http"
)

type rpcRequest struct {
	Method string `json:"method"`
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}
}

func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/mcp", s.handleMCP)
}
'''

GO_GIN = '''package api

import "github.com/gin-gonic/gin"

func (h *Handler) mcp(c *gin.Context) {
	var req map[string]any
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad request"})
		return
	}
}

func (h *Handler) Register(r *gin.Engine) {
	r.POST("/mcp", h.mcp)
}
'''

GO_ECHO = '''package api

import "github.com/labstack/echo/v4"

func mcp(c echo.Context) error {
	var req map[string]any
	if err := c.Bind(&req); err != nil {
		return err
	}
	return nil
}

func Register(e *echo.Echo) {
	e.POST("/mcp", mcp)
}
'''

GO_DISPATCH = '''package mcp

import (
	"io"
	"net/http"
)

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	switch method(body) {
	case "initialize", "ping":
		w.Write([]byte("{}"))
	case "tools/call":
		w.Write([]byte("{}"))
	}
}
'''


# ---------------------------------------------------------------------------
# Detecting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "text", "line"), [
    ("server.py", FASTAPI, 8),
    ("app.py", STARLETTE, 8),
    ("flask_app.py", FLASK, 8),
    ("server.go", GO_NETHTTP, 14),
    ("api.go", GO_GIN, 7),
    ("echo_api.go", GO_ECHO, 7),
    ("mcp.go", GO_DISPATCH, 9),
])
def test_an_unbounded_read_on_an_mcp_endpoint_is_reported(tmp_path: Path, name: str, text: str, line: int) -> None:
    assert _hits(_write(tmp_path, {name: text})) == [(name, line)]


def test_a_python_handler_that_dispatches_mcp_methods_is_an_endpoint(tmp_path: Path) -> None:
    text = FASTAPI.replace('"/mcp"', '"/rpc"').replace(
        '    return {"jsonrpc"', '    if message.get("method") == "tools/call":\n        pass\n    return {"jsonrpc"'
    )
    assert _hits(_write(tmp_path, {"server.py": text})) == [("server.py", 8)]


def test_the_finding_names_the_route_and_the_read(tmp_path: Path) -> None:
    findings, _ = transport_limits.scan(_write(tmp_path, {"server.go": GO_NETHTTP}))
    finding = next(f for f in findings if f.rule_id == RULE)
    assert "'/mcp'" in finding.evidence and "json.NewDecoder(r.Body)" in finding.evidence
    assert finding.severity == RULES[RULE].severity


def test_a_limit_in_a_test_file_does_not_silence_the_server(tmp_path: Path) -> None:
    root = _write(tmp_path, {
        "server.go": GO_NETHTTP,
        "server_test.go": "package main\n\nvar _ = http.MaxBytesReader(nil, nil, 1)\n",
    })
    assert _hits(root) == [("server.go", 14)]


def test_a_middleware_that_only_logs_the_content_length_is_not_a_limit(tmp_path: Path) -> None:
    middleware = '''from starlette.middleware.base import BaseHTTPMiddleware


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if "content-length" in request.headers:
            size = int(request.headers["content-length"])
        return await call_next(request)
'''
    assert _hits(_write(tmp_path, {"server.py": FASTAPI, "logging_mw.py": middleware})) == [("server.py", 8)]


# ---------------------------------------------------------------------------
# Not detecting
# ---------------------------------------------------------------------------


def test_max_bytes_reader_in_the_handler_is_a_limit(tmp_path: Path) -> None:
    text = GO_NETHTTP.replace(
        "\tvar req rpcRequest\n", "\tr.Body = http.MaxBytesReader(w, r.Body, 1<<20)\n\tvar req rpcRequest\n"
    )
    assert _hits(_write(tmp_path, {"server.go": text})) == []


def test_a_limit_where_the_server_is_built_covers_every_handler(tmp_path: Path) -> None:
    main = 'package main\n\nfunc main() {\n\thttp.ListenAndServe(":8080", http.MaxBytesHandler(mux, 1<<20))\n}\n'
    assert _hits(_write(tmp_path, {"server.go": GO_NETHTTP, "main.go": main})) == []


@pytest.mark.parametrize("check", [
    "\tif r.ContentLength > maxBody {\n\t\treturn\n\t}\n",
    "\tlimitRequestBody(w, r, maxBody)\n",
    "\tr.Body = io.LimitReader(r.Body, maxBody)\n",
])
def test_a_size_check_in_the_handler_silences_it(tmp_path: Path, check: str) -> None:
    text = GO_NETHTTP.replace("\tvar req rpcRequest\n", check + "\tvar req rpcRequest\n")
    assert _hits(_write(tmp_path, {"server.go": text})) == []


@pytest.mark.parametrize("extra", [
    {"config.py": 'MAX_CONTENT_LENGTH = 1024 * 1024\n'},
    {"middleware.py": (
        "from starlette.responses import Response\n\n\n"
        '@app.middleware("http")\n'
        "async def cap(request, call_next):\n"
        '    if int(request.headers.get("content-length", 0)) > 1_000_000:\n'
        "        return Response(status_code=413)\n"
        "    return await call_next(request)\n"
    )},
    {"limits.py": (
        "class BodyLimitMiddleware:\n"
        "    async def __call__(self, scope, receive, send):\n"
        "        if self.over(scope):\n"
        "            return await self._too_large(send)\n"
        "        await self.app(scope, receive, send)\n"
    )},
])
def test_a_project_wide_python_limit_silences_it(tmp_path: Path, extra: dict[str, str]) -> None:
    assert _hits(_write(tmp_path, {"server.py": FASTAPI, **extra})) == []


@pytest.mark.parametrize("check", [
    "    if body_exceeds_limit(request):\n        return {}\n",
    '    if int(request.headers.get("content-length", "0")) > 10:\n        return {}\n',
])
def test_a_size_check_before_the_python_read_silences_it(tmp_path: Path, check: str) -> None:
    text = FASTAPI.replace("    message = await", check + "    message = await")
    assert _hits(_write(tmp_path, {"server.py": text})) == []


def test_a_length_test_on_what_was_read_counts_as_a_limit(tmp_path: Path) -> None:
    """The body is already in memory by then, but the developer chose a size."""
    text = FASTAPI.replace('    return {"jsonrpc"', '    if len(message) > 100:\n        return {}\n    return {"jsonrpc"')
    assert _hits(_write(tmp_path, {"server.py": text})) == []


@pytest.mark.parametrize("path", ["/api/upload", "/api/config/mcp", "/api/mcp/workflows/<id>", "/admin/mcp"])
def test_a_route_that_is_not_an_mcp_endpoint_is_not_read(tmp_path: Path, path: str) -> None:
    assert _hits(_write(tmp_path, {"server.py": FASTAPI.replace('"/mcp"', f'"{path}"')})) == []


def test_a_handler_that_only_sends_mcp_methods_as_a_client_is_not_an_endpoint(tmp_path: Path) -> None:
    text = FASTAPI.replace('"/mcp"', '"/connect"').replace(
        "    return {\"jsonrpc\"", "    outgoing = {\"method\": \"initialize\"}\n    return {\"jsonrpc\""
    )
    assert _hits(_write(tmp_path, {"server.py": text})) == []


@pytest.mark.parametrize("name", [
    "tests/test_server.py", "e2e/server.go", "internal/mcptest/server.go", "mock_mcp_server.py", "fakes/server.go",
])
def test_test_files_and_mock_servers_serve_no_endpoint(tmp_path: Path, name: str) -> None:
    text = GO_NETHTTP if name.endswith(".go") else FASTAPI
    assert _hits(_write(tmp_path, {name: text})) == []


# A language server speaks JSON-RPC too, and its handshake is also `initialize`:
# endomorphosis/ipfs_kit_py serves VS Code's LSP client this way.
GO_LSP = """package lsp

import (
	"io"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	switch method(body) {
	case "initialize":
		w.Write([]byte("{}"))
	case "notifications/initialized", "shutdown":
		w.Write([]byte("{}"))
	}
}

func main() {
	http.HandleFunc("/jsonrpc", handle)
}
"""
PY_LSP = FASTAPI.replace('"/mcp"', '"/jsonrpc"').replace(
    '    return {"jsonrpc"',
    '    if message.get("method") == "initialize":\n        pass\n'
    '    elif message.get("method") in ("initialized", "notifications/initialized"):\n        pass\n'
    '    return {"jsonrpc"',
)


@pytest.mark.parametrize(("name", "text"), [("lsp.go", GO_LSP), ("lsp.py", PY_LSP)])
def test_methods_mcp_shares_with_lsp_are_not_enough(tmp_path: Path, name: str, text: str) -> None:
    assert _hits(_write(tmp_path, {name: text})) == []


@pytest.mark.parametrize(("name", "text", "line"), [
    ("lsp.go", GO_LSP.replace('"shutdown"', '"tools/list"'), 9),
    ("lsp.py", PY_LSP.replace('("initialized", "notifications/initialized")', '("tools/call",)'), 8),
])
def test_an_mcp_only_method_beside_them_is_enough(tmp_path: Path, name: str, text: str, line: int) -> None:
    assert _hits(_write(tmp_path, {name: text})) == [(name, line)]


# The handshake in the HTTP handler and the rest of the methods in a function
# beside it, as internet-dot/pith and databrickslabs/ontos are written.
GO_HANDSHAKE_HANDLER = GO_LSP.replace(
    "func main() {",
    'func dispatch(m string) {\n\tswitch m {\n\tcase "tools/call":\n\t}\n}\n\nfunc main() {',
)
PY_HANDSHAKE_HANDLER = PY_LSP + '\n\nHANDLERS = {"tools/list": None}\n'


@pytest.mark.parametrize(("name", "text", "line"), [
    ("server.go", GO_HANDSHAKE_HANDLER, 9),
    ("server.py", PY_HANDSHAKE_HANDLER, 8),
])
def test_the_handshake_counts_in_a_file_that_names_an_mcp_only_method(
    tmp_path: Path, name: str, text: str, line: int,
) -> None:
    assert _hits(_write(tmp_path, {name: text})) == [(name, line)]


@pytest.mark.parametrize("framework", ["aiohttp", "quart"])
def test_frameworks_with_a_default_limit_are_not_read(tmp_path: Path, framework: str) -> None:
    text = f"import {framework}\n" + FASTAPI
    assert _hits(_write(tmp_path, {"server.py": text})) == []


# ---------------------------------------------------------------------------
# Linear time on crafted files
# ---------------------------------------------------------------------------

_CRAFTED = {
    # `case` read to the end of a line with no colon, once per `case`.
    "case.go": "func h(w http.ResponseWriter, r *http.Request) {\n\tio.ReadAll(r.Body)\n\t" + "case " * 100_000 + "\n}\n",
    # `^\s*` crossed blank lines, so each line start reread the run.
    "blank.py": "\n" * 400_000 + "x = 1\n",
    # A limit-helper test over one long word.
    "word.go": (
        "func h(w http.ResponseWriter, r *http.Request) {\n\t" + "limit" * 80_000
        + "\n\tio.ReadAll(r.Body)\n\t_ = \"tools/call\" == m\n}\n"
    ),
    # Many func heads with no body.
    "heads.go": "func (s *S) h(w http.ResponseWriter, r *http.Request)\n" * 8_000,
}


@pytest.mark.parametrize("name", sorted(_CRAFTED))
def test_a_crafted_file_scans_in_linear_time(tmp_path: Path, name: str) -> None:
    """Each is about 400 KB, under the scanner's 1 MB cap; each takes well
    under a second. The bound is loose for slow CI runners."""
    (tmp_path / name).write_text(_CRAFTED[name], encoding="utf-8")
    started = time.perf_counter()
    transport_limits.scan(tmp_path)
    assert time.perf_counter() - started < 5.0


def _seconds(run: Callable[[], object]) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best


def _grows_linearly(tmp_path: Path, name: str, build: Callable[[int], str], count: int) -> None:
    """``build(count)`` and ``build(10 * count)``: the second must not take a
    hundred times as long."""
    roots = []
    for label, n in (("small", count), ("large", 10 * count)):
        root = tmp_path / label
        root.mkdir()
        text = build(n)
        assert len(text) < 1_000_000, "under the scanner's 1 MB cap"
        (root / name).write_text(text, encoding="utf-8")
        roots.append(root)
    assert len(_hits(roots[1])) == 10 * len(_hits(roots[0])) > 0, "the shape reports every handler"
    t_small, t_large = _seconds(lambda: transport_limits.scan(roots[0])), _seconds(lambda: transport_limits.scan(roots[1]))
    assert t_large < 5.0
    assert t_large < 40 * t_small + 0.25, (t_small, t_large)


def _handlers_on_their_own_routes(n: int) -> str:
    one = "func h{i}(w http.ResponseWriter, r *http.Request) {{\n\tb, _ := io.ReadAll(r.Body)\n\t_ = b\n}}\n"
    routes = "".join(f'\thttp.HandleFunc("/t{i}/mcp", h{i})\n' for i in range(n))
    return 'package main\nimport ("io"; "net/http")\n' + "".join(one.format(i=i) for i in range(n)) + (
        "func main() {\n" + routes + "}\n"
    )


def _nested_handlers(n: int) -> str:
    level = 'f := func(w http.ResponseWriter, r *http.Request) {\nb, _ := io.ReadAll(r.Body)\n_ = b\n'
    return (
        'package main\nimport ("io"; "net/http")\nfunc main() {\n' + level * n
        + 'switch m { case "tools/call": }\n' + "}\n" * n + "}\n"
    )


def test_many_handlers_each_on_its_own_route_scan_in_linear_time(tmp_path: Path) -> None:
    """Every handler's name was searched for in every route's arguments: 4,000
    handlers on their own `/mcp` routes (509 KB) took 3.4 seconds, and 7,000
    (893 KB) about ten."""
    _grows_linearly(tmp_path, "main.go", _handlers_on_their_own_routes, 700)


def test_nested_handlers_scan_in_linear_time(tmp_path: Path) -> None:
    """Each handler's body was searched whole for its reads, an MCP method and a
    limit, and a handler's body holds the ones nested in it: 4,000 nested
    handlers (348 KB) took 29 seconds."""
    _grows_linearly(tmp_path, "main.go", _nested_handlers, 400)


def test_the_rule_states_what_it_reads() -> None:
    limitations = RULES[RULE].limitations
    assert "helper" in limitations and "reverse proxy" in limitations
