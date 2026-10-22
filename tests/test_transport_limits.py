"""AAK-MCP-016: an MCP endpoint that reads the whole request body with no limit.

AAK-MCPFRAME-001, the other rule in `transport_limits`, has its tests in
`test_cve_2026_39313.py`.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

import pytest

import agent_audit_kit
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import transport_limits
from agent_audit_kit.scanners import _http_routes
from agent_audit_kit.scanners._http_routes import is_mcp_endpoint_path

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
    # Each bound and skip, pinned by a test in this file.
    for stated in ("1,000,000 bytes", "160 characters", "aiohttp", "settings segment", "compares `len(body)`",
                   "RequestSizeLimiter", "io.LimitReader", "within 80 characters", "within 300 characters",
                   "on the comparison's own line", "no `}` between"):
        assert stated in limitations, stated


# A child process scans each crafted file, so a quadratic path fails the test on
# its timeout instead of stalling the suite. It prints the seconds `scan` took
# and the AAK-MCP-016 findings, and with "memory" scans once more under
# tracemalloc and prints the peak the scan allocated, in megabytes. The child's
# own peak RSS will not do: on Linux a process that subprocess starts keeps its
# parent's high-water mark through exec, so under pytest it reported the test
# worker's memory, 475 MB on CI, before the scan allocated anything.
_CHILD = (
    "import sys, time, tracemalloc\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.scanners import transport_limits\n"
    "root = Path(sys.argv[1])\n"
    "started = time.perf_counter()\n"
    "findings, _ = transport_limits.scan(root)\n"
    "seconds = time.perf_counter() - started\n"
    "peak = 0.0\n"
    "if sys.argv[2:] == ['memory']:\n"
    "    tracemalloc.start()\n"
    "    transport_limits.scan(root)\n"
    "    peak = tracemalloc.get_traced_memory()[1] / 2**20\n"
    "print(seconds, sum(f.rule_id == 'AAK-MCP-016' for f in findings), peak)\n"
)


def _scan_in_child(
    tmp_path: Path, name: str, text: str, memory: bool = False, label: str = "project",
) -> tuple[float, int, float]:
    root = tmp_path / label
    root.mkdir()
    (root / name).write_text(text, encoding="utf-8")
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    command = [sys.executable, "-c", _CHILD, str(root)] + (["memory"] if memory else [])
    done = subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)
    assert done.returncode == 0, done.stderr
    seconds, count, peak = done.stdout.split()
    return float(seconds), int(count), float(peak)


_GO_HEAD = 'package main\n\nimport (\n\t"io"\n\t"net/http"\n\t"github.com/gin-gonic/gin"\n)\n\n'
_READ_HANDLER = "func h(w http.ResponseWriter, r *http.Request) { io.ReadAll(r.Body) }\n"


def test_a_route_path_of_many_mcp_segments_scans_in_linear_time(tmp_path: Path) -> None:
    """Each `mcp` segment rescanned the segments before it and rejoined those
    after it: 100 KB of `/mcp` took about 30 seconds."""
    text = _GO_HEAD + _READ_HANDLER + 'func main() { http.HandleFunc("' + "/mcp" * 25_000 + '/zz", h) }\n'
    seconds, count, _peak = _scan_in_child(tmp_path, "main.go", text)
    assert count == 0 and seconds < 5.0


def test_nested_func_types_scan_in_linear_time(tmp_path: Path) -> None:
    """Each `func` searched its whole parameter list for a request parameter,
    and a parameter list holds the func types nested in it: 128 KB took about
    24 seconds."""
    k = 14_000
    text = _GO_HEAD + _READ_HANDLER + "func f(cb " + "func(x " * k + "int" + ")" * k + ") {}\n"
    seconds, count, _peak = _scan_in_child(tmp_path, "main.go", text)
    assert count == 0 and seconds < 5.0


def _nested_routes(k: int) -> str:
    return (
        _GO_HEAD + "func main() {\n\tg := gin.New()\n" + '\tg.POST("/mcp", func(c *gin.Context) {\n' * k
        + "\t\tc.BindJSON(nil)\n" + "\t})\n" * k + "}\n"
    )


def test_nested_route_calls_scan_in_linear_time_and_memory(tmp_path: Path) -> None:
    """Every route copied the text of its arguments, and an inline handler's
    holds every route nested in it: 23,000 nested routes (999 KB) copied 11.6
    GB and took 5 to 12 seconds; they now take under a second. Memory is
    measured on a smaller file, as the peak tracemalloc sees during the scan:
    8,000 nested routes (344 KB) peaked at 1.3 GB and now at about 13 MB."""
    text = _nested_routes(23_000)
    assert len(text) < 1_000_000
    seconds, count, _peak = _scan_in_child(tmp_path, "main.go", text, label="time")
    assert count == 1 and seconds < 5.0
    _seconds, count, peak = _scan_in_child(tmp_path, "main.go", _nested_routes(8_000), memory=True, label="memory")
    assert count == 1 and peak < 200, peak


def test_a_run_of_unmatched_closes_after_a_func_literal_scans_in_little_memory(tmp_path: Path) -> None:
    """The signature walk kept every point it passed just after a `)`, one that
    closes nothing included, so a func literal followed by 999 KB of unmatched
    `)` peaked at 99.5 MB, against 1.9 MB before the walk kept anything. Only
    a point after a `)` that closes a `(` is kept now."""
    head = _GO_HEAD + _READ_HANDLER + "// mcp\nvar x = func(r *http.Request)"
    text = head + ")" * (999_000 - len(head)) + "\n"
    _seconds, _count, peak = _scan_in_child(tmp_path, "main.go", text, memory=True)
    assert peak < 20, peak


def _distinct_request_names(n: int, gin: bool) -> str:
    funcs, routes = [], []
    for i in range(n):
        if gin:
            funcs.append(f"func h{i}(r{i} *gin.Context) {{ r{i}.BindJSON(nil) }}\n")
            routes.append(f'\tg.POST("/mcp", h{i})\n')
        else:
            funcs.append(f"func h{i}(w http.ResponseWriter, r{i} *http.Request) {{ io.ReadAll(r{i}.Body) }}\n")
            routes.append(f'\thttp.HandleFunc("/mcp", h{i})\n')
    return _GO_HEAD + "".join(funcs) + "\nfunc main() {\n\tg := gin.New()\n" + "".join(routes) + "}\n"


@pytest.mark.parametrize(("gin", "n"), [(False, 4_000), (True, 5_000)])
def test_handlers_with_distinct_request_names_scan_in_linear_time(tmp_path: Path, gin: bool, n: int) -> None:
    """Each request name got a read pattern of its own, swept from its first
    handler to the end of the file, and a limit pattern swept over all of it:
    4,000 net/http handlers named `r0`, `r1`, ... (452 KB) took 27 seconds,
    5,000 gin handlers (386 KB) 30."""
    seconds, count, _peak = _scan_in_child(tmp_path, "main.go", _distinct_request_names(n, gin))
    assert count == n and seconds < 5.0


def test_same_named_python_route_functions_scan_in_linear_time(tmp_path: Path) -> None:
    """Each function listed and tested every route registered for its name: 5,000
    FastAPI functions named `h` (280 KB) took 8 seconds, 10,000 about 32."""
    unit = '@app.post("/x")\nasync def h(request: Request):\n    pass\n'
    text = (
        "from fastapi import FastAPI, Request\napp = FastAPI()\n"
        "async def r(request: Request):\n    return await request.json()\n" + unit * 10_000
    )
    seconds, count, _peak = _scan_in_child(tmp_path, "app.py", text)
    assert count == 0 and seconds < 5.0


@pytest.mark.parametrize(("cap", "capped"), [
    ("r.ContentLength", True),
    ("r.Request.ContentLength", True),
    ("Request.ContentLength", False),
    ("xr.ContentLength", False),
    ("r.ContentLengthX", False),
    ("io.LimitReader(x, 1)", True),
    ("http.MaxBytesReader(w, x, 1)", True),
])
def test_a_content_length_check_counts_only_on_the_handlers_request(tmp_path: Path, cap: str, capped: bool) -> None:
    text = GO_NETHTTP.replace("\tvar req rpcRequest\n", f"\t_ = {cap}\n\tvar req rpcRequest\n")
    assert _hits(_write(tmp_path, {"server.go": text})) == ([] if capped else [("server.go", 15)])


@pytest.mark.parametrize(("cap", "capped"), [
    ("c.Request.ContentLength", True),
    ("c.ContentLength", True),
    ("c.Request().ContentLength", True),
    ("Request.ContentLength", False),
])
def test_a_framework_request_content_length_counts(tmp_path: Path, cap: str, capped: bool) -> None:
    text = GO_GIN.replace("\tvar req map[string]any\n", f"\t_ = {cap}\n\tvar req map[string]any\n")
    assert _hits(_write(tmp_path, {"api.go": text})) == ([] if capped else [("api.go", 8)])


# A file the parser cannot build a tree for: `ast.parse` raises MemoryError on
# deep unary nesting (Python 3.9 to 3.12) and RecursionError on a long flat
# expression (3.11 and later; 3.9 and 3.10 crash on it instead). Either escaped
# `scan()`, losing every AAK-MCP-016 and AAK-MCPFRAME-001 finding of the project.
_DEEP = "x = " + "-" * 140_000 + "1\n"
_FLAT = "x = " + "a+" * 140_000 + "a\n"
_SIZE_HINTS = "# a middleware that answers 413\n"
_HANDLER_HEAD = "from fastapi import FastAPI, Request\napp = FastAPI()\n"


@pytest.mark.parametrize("error", [RecursionError, MemoryError])
def test_a_file_the_parser_gives_up_on_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[BaseException],
) -> None:
    real_parse = transport_limits.ast.parse
    # Built here, not written out: pytest parses this file to report a failure,
    # and must not meet the marker while the patch is in place.
    marker = "# give " + "up"

    def parse(source: str, *args: object, **kwargs: object) -> object:
        if marker in source:
            raise error()
        return real_parse(source, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(transport_limits.ast, "parse", parse)
    root = _write(tmp_path, {
        "server.py": FASTAPI,
        "size_mw.py": _SIZE_HINTS + marker + "\n",
        "other.py": _HANDLER_HEAD + marker + "\nasync def h(request: Request):\n    return await request.json()\n",
    })
    # Caught here so that a regression fails the test plainly: pytest cannot
    # format a RecursionError's traceback, and stops the whole run.
    escaped = None
    try:
        hits = _hits(root)
    except (RecursionError, MemoryError) as exc:
        escaped = type(exc).__name__
    assert escaped is None, f"{escaped} escaped scan()"
    assert hits == [("server.py", 8)]


@pytest.mark.parametrize("shape", [
    "deep",
    pytest.param("flat", marks=pytest.mark.skipif(sys.version_info < (3, 11), reason="the parser crashes before 3.11")),
])
def test_a_crafted_file_the_parser_gives_up_on_leaves_the_rest_of_the_scan(tmp_path: Path, shape: str) -> None:
    expression = _DEEP if shape == "deep" else _FLAT
    root = tmp_path / "project"
    for name, text in {
        "server.py": FASTAPI,
        "size_mw.py": _SIZE_HINTS + expression,
        "other.py": _HANDLER_HEAD + "async def h(request: Request):\n    return await request.json()\n" + expression,
    }.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _CHILD, str(root)], capture_output=True, text=True, timeout=60, env=env,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.split()[1] == "1"


# ---------------------------------------------------------------------------
# Stated bounds and skips, each pinned on both sides
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("size", "read"), [(1_000_000, True), (1_000_001, False)])
def test_files_over_a_million_bytes_are_not_read(tmp_path: Path, size: int, read: bool) -> None:
    text = GO_NETHTTP + "//"
    text += "x" * (size - len(text) - 1) + "\n"
    assert len(text.encode()) == size
    assert _hits(_write(tmp_path, {"server.go": text})) == ([("server.go", 14)] if read else [])


def _case_list(gap: int) -> str:
    """A handler on no route that dispatches on `tools/call` in a `case` list,
    the method's string starting ``gap`` characters after `case `."""
    before = '"' + "x" * (gap - 4) + '", '
    assert len(before) == gap
    return (
        'package mcp\n\nimport (\n\t"io"\n\t"net/http"\n)\n\n'
        "func ServeHTTP(w http.ResponseWriter, r *http.Request) {\n\tbody, _ := io.ReadAll(r.Body)\n"
        f'\tswitch method(body) {{\n\tcase {before}"tools/call", "z":\n\t}}\n}}\n'
    )


@pytest.mark.parametrize(("gap", "read"), [(160, True), (161, False)])
def test_a_case_names_an_mcp_method_within_160_characters(tmp_path: Path, gap: int, read: bool) -> None:
    assert _hits(_write(tmp_path, {"mcp.go": _case_list(gap)})) == ([("mcp.go", 9)] if read else [])


def _content_length_middleware(before_brace: int, before_413: int) -> str:
    """A size-limit middleware in its own file: ``before_brace`` characters
    between the Content-Length comparison and its `{`, ``before_413`` between
    that `{` and the 413."""
    test = "if r.ContentLength > " + "1" * (before_brace - 2) + " {"
    assert len(test) - test.index(">") - 2 == before_brace
    call = " " * (before_413 - len("w.WriteHeader(")) + "w.WriteHeader(413)"
    assert call.index("413") == before_413
    return (
        "package main\n\nimport \"net/http\"\n\nfunc limit(next http.Handler) http.Handler {\n"
        "\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
        f"\t\t{test}{call}\n\t\t\treturn\n\t\t}}\n\t\tnext.ServeHTTP(w, r)\n\t}})\n}}\n"
    )


@pytest.mark.parametrize(("before_brace", "before_413", "silenced"), [
    (80, 300, True), (81, 300, False), (80, 301, False),
])
def test_a_content_length_middleware_counts_within_its_windows(
    tmp_path: Path, before_brace: int, before_413: int, silenced: bool,
) -> None:
    """A Go middleware that compares Content-Length and answers 413 is a
    project-wide limit when its `{` opens within 80 characters of the
    comparison and the 413 comes within 300 characters after it."""
    root = _write(tmp_path, {"server.go": GO_NETHTTP, "mw.go": _content_length_middleware(before_brace, before_413)})
    assert _hits(root) == ([] if silenced else [("server.go", 14)])


def _limit_middleware(test: str, respond: str) -> str:
    return (
        "package main\n\nimport \"net/http\"\n\nfunc limit(next http.Handler) http.Handler {\n"
        "\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"
        f"\t\t{test}\n\t\t\t{respond}\n\t\t\treturn\n\t\t}}\n\t\tnext.ServeHTTP(w, r)\n\t}})\n}}\n"
    )


@pytest.mark.parametrize(("test", "respond", "silenced"), [
    ("if r.ContentLength > maxBody {", 'http.Error(w, "too large", 413)', True),
    # A `}` between the `{` and the 413, as a map literal before it has.
    ("if r.ContentLength > maxBody {", 'writeJSON(w, map[string]string{"error": "too large"}, 413)', False),
    # The `{` on the line after the comparison.
    ("if r.ContentLength >\n\t\t\tmaxBody {", 'http.Error(w, "too large", 413)', False),
], ids=["plain", "map-literal", "next-line"])
def test_a_content_length_middleware_needs_its_brace_on_the_line_and_no_brace_before_the_413(
    tmp_path: Path, test: str, respond: str, silenced: bool,
) -> None:
    root = _write(tmp_path, {"server.go": GO_NETHTTP, "mw.go": _limit_middleware(test, respond)})
    assert _hits(root) == ([] if silenced else [("server.go", 14)])


@pytest.mark.parametrize("limit", [
    "gin.RequestSizeLimiter(1 << 20)",
    "r.Body = io.LimitReader(r.Body, 1<<20)",
    "r.Body = io.NopCloser(io.LimitReader(r.Body, 1<<20))",
])
def test_other_project_wide_go_limits_silence_it(tmp_path: Path, limit: str) -> None:
    middleware = f"package main\n\nfunc setup() {{\n\t_ = {limit}\n}}\n"
    assert _hits(_write(tmp_path, {"server.go": GO_NETHTTP, "limits.go": middleware})) == []


GO_LEN = GO_NETHTTP.replace(
    '\tvar req rpcRequest\n\tif err := json.NewDecoder(r.Body).Decode(&req); err != nil {\n',
    '\tbody, err := io.ReadAll(r.Body)\n\tif err != nil || len(body) > maxBody {\n',
)


def test_a_go_length_test_after_the_read_is_still_reported(tmp_path: Path) -> None:
    """Only Python counts a length test on what was read as a limit (the rule's
    limitation says so); a Go handler that compares `len(body)` after reading
    it whole is reported."""
    assert GO_LEN != GO_NETHTTP
    assert _hits(_write(tmp_path, {"server.go": GO_LEN})) == [("server.go", 13)]


def test_a_python_file_that_imports_another_framework_as_a_client_is_skipped(tmp_path: Path) -> None:
    """The skip is by import, not by what the file serves: a FastAPI server that
    calls an upstream API through aiohttp is not read (stated in the limitation)."""
    text = FASTAPI.replace("from fastapi import FastAPI, Request\n", "from fastapi import FastAPI, Request\nimport aiohttp\n")
    assert _hits(_write(tmp_path, {"server.py": text})) == []


def _segments_reference(path: str) -> bool:
    """The rule as first written: every `mcp` segment rescans the ones before it."""
    segments = [s for s in path.rsplit(" ", 1)[-1].split("/") if s]
    for i, segment in enumerate(segments):
        if _http_routes._MCP_SEGMENT_RE.fullmatch(segment):
            if any(s.lower() in _http_routes._ADMIN_SEGMENTS for s in segments[:i]):
                return False
            rest = "/".join(segments[i + 1:])
            if not rest or _http_routes._MCP_TAIL_RE.fullmatch(rest):
                return True
    return False


def test_the_linear_path_reading_answers_as_before() -> None:
    pieces = ["mcp", "api", "v1", "v2", "admin", "Settings", "messages", "sse", "tools", "call", "list", "{id}",
              ":name", "<x>", "x-mcp", "mcp_rpc", "MCP", "zz", "initialize", "resources", "read", ""]
    rnd = random.Random(16)
    paths = ["/" + "/".join(rnd.choice(pieces) for _ in range(rnd.randint(0, 8))) for _ in range(20_000)]
    paths += ["GET /mcp", "POST /api/mcp/v1/tools/call", "/mcp/a/b/c/d", "/a/mcp/tools/call/x"]
    for path in paths:
        assert is_mcp_endpoint_path(path) == _segments_reference(path), path


def test_read_texts_enforces_the_cap_in_the_read(tmp_path: Path) -> None:
    """`_project_files` drops a file whose stat says it is over the cap; `_read_texts`
    refuses one whose bytes are, so a stat that understates the size (a file that grew
    after it, or a filesystem that lies) no longer has the file read in full (#1060)."""
    cap = transport_limits._MCP016_MAX_BYTES
    at = tmp_path / "at.go"
    over = tmp_path / "over.go"
    at.write_bytes(b"package main\n" + b"/" * (cap - len(b"package main\n") - 1) + b"\n")
    over.write_bytes(at.read_bytes() + b"\n")
    assert (at.stat().st_size, over.stat().st_size) == (cap, cap + 1)
    read = transport_limits._read_texts([at, over], tmp_path)
    assert [(rel, len(text)) for _, rel, text in read] == [("at.go", cap)]
    assert transport_limits._project_files(tmp_path, ".go") == [at]
