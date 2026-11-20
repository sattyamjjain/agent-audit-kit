"""AAK-DNS-REBIND-003: state-changing routes beside an MCP endpoint, with no Host or Origin check.

CVE-2026-77359 (jupyter-mcp-server before 1.0.3, NVD 2026-11-19): standalone streamable-http
mode checked the Host and Origin of requests to its MCP endpoint and not of those to the
state-changing management routes, /api/connect and /api/stop. The SDK's
DNS-rebinding check runs inside the MCP transport, so it never sees a request to another
route on the same listener. AAK-DNS-REBIND-001 reads the transport; this rule reads the
routes beside it, protected endpoint or not.

The fixtures under tests/fixtures/dns_rebind/ are the order's shapes and their twins. The
upstream files were read too, on 2026-11-20: jupyter-mcp-server 1.0.2's server.py fires on
line 143 (`@mcp.custom_route("/api/connect", ["PUT"])`), naming both routes, and 1.0.3's,
whose middleware reads the Origin header, does not. Those files are not committed here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.dns_rebind import scan

FIXTURES = Path(__file__).parent / "fixtures" / "dns_rebind"
RULE = "AAK-DNS-REBIND-003"
ENDPOINT_RULE = "AAK-DNS-REBIND-001"
# Built here so this file reads as no MCP server to AAK's own self-scan.
ENDPOINT = "/" + "mcp"
ANY_HOST = ".".join("0" * 4)
EVERY_ORIGIN = "allow_origins=" + "['*']"
TRANSPORT = "StreamableHTTP" + "ServerTransport"


def _found(root: Path, rule: str = RULE) -> list:
    return [f for f in scan(root)[0] if f.rule_id == rule]


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


# ---- the registry -----------------------------------------------------------------------


def test_the_rule_is_critical_transport_security_and_names_the_cve() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.CRITICAL
    assert rule.category.value == RULES[ENDPOINT_RULE].category.value
    assert rule.cve_references == ["CVE-2026-77359"]
    assert rule.owasp_mcp_references == RULES[ENDPOINT_RULE].owasp_mcp_references
    assert "/api/connect" in rule.description and "/api/stop" in rule.description


def test_the_compliance_map_matches_the_endpoint_rule() -> None:
    from agent_audit_kit.rules import builtin

    source = Path(builtin.__file__).read_text(encoding="utf-8")
    assert '"AAK-DNS-REBIND-003": ["IVS-04", "CEK-08"],' in source
    assert '"AAK-DNS-REBIND-001": ["IVS-04", "CEK-08"],' in source


# ---- the order's fixtures ---------------------------------------------------------------


def test_fixture_a_fires_once_naming_both_management_routes() -> None:
    findings = _found(FIXTURES / "management_routes_py")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.file_path == "server.py"
    assert finding.evidence.startswith("PUT /api/connect, DELETE /api/stop: ")
    assert "CVE-2026-77359" in finding.evidence
    assert "healthz" not in finding.evidence
    lines = (FIXTURES / "management_routes_py" / "server.py").read_text().splitlines()
    assert 'Route("/api/connect"' in lines[finding.line_number - 1]


def test_fixture_a_gets_no_endpoint_finding_because_its_mcp_endpoint_is_protected() -> None:
    """mcp==1.25.0 on a loopback host: the SDK checks the MCP endpoint, which is the point."""
    assert _found(FIXTURES / "management_routes_py", ENDPOINT_RULE) == []


@pytest.mark.parametrize("twin", [
    "management_routes_py_trusted_host",           # TrustedHostMiddleware on the outer app
    "management_routes_py_get_only",               # nothing changes state
    "management_routes_py_authorization",          # each route reads the authorization header
    "management_routes_py_custom_route_origin_check",  # 1.0.3's middleware: Host and Origin read
    "management_routes_py_custom_route_trusted_host",  # allow-list on the app that serves the custom routes
    "management_routes_ts_origin_check",           # an Origin check in front of every route
    "management_routes_ts_sdk_app",                # createMcpExpressApp on its loopback default
])
def test_a_covered_twin_is_silent(twin: str) -> None:
    assert _found(FIXTURES / twin) == []


@pytest.mark.parametrize("project, label", [
    ("management_routes_py_mcp_app_trusted_host", "PUT /api/connect, DELETE /api/stop"),
    ("management_routes_py_custom_route", "PUT /api/connect, DELETE /api/stop"),
    ("management_routes_ts", "POST /api/config"),
])
def test_an_uncovered_project_fires(project: str, label: str) -> None:
    findings = _found(FIXTURES / project)
    assert [f.evidence.split(": ", 1)[0] for f in findings] == [label]


def test_the_allow_list_on_the_mounted_mcp_app_does_not_reach_the_outer_routes() -> None:
    """The order's distinction: the sub-app's middleware sees the MCP endpoint only."""
    root = FIXTURES / "management_routes_py_mcp_app_trusted_host"
    assert "mcp_app.add_middleware(TrustedHostMiddleware" in (root / "server.py").read_text()
    assert len(_found(root)) == 1


def test_control_c_fires_the_endpoint_rule_and_not_this_one() -> None:
    root = FIXTURES / "unprotected_mcp_ts"
    assert len(_found(root, ENDPOINT_RULE)) == 1
    assert _found(root) == []


def test_the_engine_reports_it_end_to_end() -> None:
    result = run_scan(project_root=FIXTURES / "management_routes_py", rules=[RULE])
    assert [f.rule_id for f in result.findings] == [RULE]


# ---- Python: what is a route ------------------------------------------------------------

_FASTMCP = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
_SERVED = _FASTMCP + "app = mcp.streamable_http_app()\n"


def test_fastapi_decorators_fire(tmp_path: Path) -> None:
    root = _write(tmp_path, {"server.py": _SERVED + (
        f"from fastapi import FastAPI\napi = FastAPI()\napi.mount('{ENDPOINT}', app)\n\n"
        "@api.post('/admin/reload')\ndef reload():\n    return {}\n\n"
        "@api.delete('/admin/cache')\ndef clear():\n    return {}\n\n"
        "@api.get('/admin/status')\ndef status():\n    return {}\n")})
    assert [f.evidence.split(": ", 1)[0] for f in _found(root)] == ["POST /admin/reload, DELETE /admin/cache"]


@pytest.mark.parametrize("registration, label", [
    ("@api.route('/admin/x', methods=['POST', 'GET'])\ndef x():\n    return ''\n", "POST /admin/x"),
    ("@api.api_route('/admin/x', methods=['PATCH'])\ndef x():\n    return ''\n", "PATCH /admin/x"),
    ("def x():\n    return ''\napi.add_api_route('/admin/x', x, methods=['PUT'])\n", "PUT /admin/x"),
    ("def x():\n    return ''\napi.add_url_rule('/admin/x', view_func=x, methods=['DELETE'])\n", "DELETE /admin/x"),
    ("def x(r):\n    return ''\napi.add_route('/admin/x', x, ['POST'])\n", "POST /admin/x"),
    ("@mcp.custom_route('/admin/x', methods=['POST'])\nasync def x(r):\n    return ''\n", "POST /admin/x"),
])
def test_each_registration_form_is_read(tmp_path: Path, registration: str, label: str) -> None:
    root = _write(tmp_path, {"server.py": _SERVED + "api = object()\n" + registration})
    assert [f.evidence.split(": ", 1)[0] for f in _found(root)] == [label]


@pytest.mark.parametrize("registration", [
    "@api.route('/admin/x')\ndef x():\n    return ''\n",                       # Flask's GET default
    "from starlette.routing import Route\nroutes = [Route('/admin/x', x)]\n",   # Starlette's GET default
    "@api.route('/admin/x', methods=METHODS)\ndef x():\n    return ''\n",      # not a literal list
    "@api.post(PATH)\ndef x():\n    return ''\n",                               # not a literal path
    f"@api.post('{ENDPOINT}')\ndef x():\n    return ''\n",                         # the transport's own path
    "@api.post('/messages/')\ndef x():\n    return ''\n",                       # the SSE message path
    "import requests\nrequests.post('/admin/x', json={})\n",                    # a client call, not a route
])
def test_what_is_not_a_state_changing_route(tmp_path: Path, registration: str) -> None:
    root = _write(tmp_path, {"server.py": _SERVED + "api = object()\nx = None\n" + registration})
    assert _found(root) == []


def test_custom_route_counts_only_beside_an_mcp_server(tmp_path: Path) -> None:
    body = "@app.custom_route('/admin/x', ['POST'])\nasync def x(r):\n    return ''\n"
    assert _found(_write(tmp_path / "other", {"server.py": "app = Something()\n" + body})) == []
    for head in ("from mcp.server.fastmcp import FastMCP\n", "from fastmcp import FastMCP\n",
                 "from mcp.server import FastMCP\n"):
        root = _write(tmp_path / str(len(head)), {"server.py": head + "app = FastMCP('x')\n" + body})
        assert len(_found(root)) == 1, head


def test_a_file_with_routes_and_no_mcp_endpoint_is_not_read(tmp_path: Path) -> None:
    root = _write(tmp_path, {"server.py": "from fastapi import FastAPI\napi = FastAPI()\n\n"
                                          "@api.post('/admin/x')\ndef x():\n    return ''\n"})
    assert _found(root) == []


def test_test_files_are_skipped(tmp_path: Path) -> None:
    body = _SERVED + "@mcp.custom_route('/admin/x', ['POST'])\nasync def x(r):\n    return ''\n"
    root = _write(tmp_path, {"tests/server.py": body, "test_server.py": body, "conftest.py": body})
    assert _found(root) == []
    assert len(_found(_write(tmp_path / "real", {"server.py": body}))) == 1


# ---- Python: what covers a route --------------------------------------------------------

_ROUTE = "@mcp.custom_route('/admin/x', ['POST'])\nasync def x(request):\n    return ''\n"


@pytest.mark.parametrize("read", [
    "def check(request):\n    return request.headers.get('origin')\n",
    "def check(request):\n    return request.headers.get('Host')\n",
    "def check(request):\n    return request.headers['host']\n",
    "def check(request):\n    return request.url.hostname\n",
    "def check(environ):\n    return environ['HTTP_HOST']\n",
    "def check(request):\n    return request.get_host()\n",
    "def check():\n    return request.host\n",
])
def test_a_host_or_origin_read_anywhere_covers_every_route(tmp_path: Path, read: str) -> None:
    assert _found(_write(tmp_path, {"server.py": _SERVED + _ROUTE + read})) == []


def test_a_header_read_in_a_comment_does_not(tmp_path: Path) -> None:
    root = _write(tmp_path, {"server.py": _SERVED + _ROUTE + "# TODO: check request.headers.get('origin')\n"})
    assert len(_found(root)) == 1


def test_cors_settings_are_not_an_origin_check(tmp_path: Path) -> None:
    """CORS answers a browser's preflight; a rebound page is same-origin and needs none."""
    root = _write(tmp_path, {"server.py": _SERVED + _ROUTE + (
        "from starlette.middleware.cors import CORSMiddleware\n"
        f"app.add_middleware(CORSMiddleware, {EVERY_ORIGIN}, allow_methods=['*'])\n")})
    assert len(_found(root)) == 1


@pytest.mark.parametrize("hosts, covered", [
    ("allowed_hosts=['127.0.0.1', 'localhost']", True),
    ("allowed_hosts=HOSTS", True),                       # not a literal: taken to name hosts
    ("allowed_hosts=['*']", False),                      # every host
    ("", False),                                          # left out: Starlette's default is ['*']
])
def test_trusted_host_middleware_counts_only_when_it_names_hosts(tmp_path: Path, hosts: str, covered: bool) -> None:
    sep = ", " if hosts else ""
    root = _write(tmp_path, {"server.py": _SERVED + _ROUTE + (
        "from starlette.middleware.trustedhost import TrustedHostMiddleware\n"
        f"app.add_middleware(TrustedHostMiddleware{sep}{hosts})\n")})
    assert (_found(root) == []) is covered


@pytest.mark.parametrize("applied", [
    "outer = TrustedHostMiddleware(Starlette(routes=routes), allowed_hosts=['localhost'])\n",
    "outer = Starlette(routes=routes, middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=['localhost'])])\n",
    "outer = Starlette(routes=routes)\nouter.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost'])\n",
])
def test_an_allow_list_on_the_outer_app_covers_its_routes(tmp_path: Path, applied: str) -> None:
    head = ("from starlette.applications import Starlette\nfrom starlette.middleware import Middleware\n"
            "from starlette.middleware.trustedhost import TrustedHostMiddleware\n"
            "from starlette.routing import Mount, Route\n")
    routes = f"routes = [Route('/admin/x', x, methods=['POST']), Mount('{ENDPOINT}', app=app)]\n"
    body = _SERVED + head + "async def x(r):\n    return ''\n" + routes
    assert len(_found(_write(tmp_path / "open", {"server.py": body}))) == 1
    assert _found(_write(tmp_path / "covered", {"server.py": body + applied})) == []


def test_an_allow_list_applied_in_an_override_belongs_to_the_mcp_app(tmp_path: Path) -> None:
    """`app` inside the `streamable_http_app` override is the MCP app; the module's own
    `app` is the outer one. Each name is resolved in its own scope."""
    body = (_FASTMCP + "from starlette.applications import Starlette\n"
            "from starlette.middleware.trustedhost import TrustedHostMiddleware\n"
            "from starlette.routing import Mount, Route\n\n"
            "class Guarded(FastMCP):\n    def streamable_http_app(self):\n"
            "        app = super().streamable_http_app()\n"
            "        app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost'])\n"
            "        return app\n\n"
            "async def x(r):\n    return ''\n"
            f"app = Starlette(routes=[Route('/admin/x', x, methods=['POST']), Mount('{ENDPOINT}', app=Guarded('x').streamable_http_app())])\n")
    assert len(_found(_write(tmp_path / "outer", {"server.py": body}))) == 1
    custom = body.replace("app = Starlette(routes=[Route('/admin/x', x, methods=['POST']), ",
                          "server = Guarded('x')\n@server.custom_route('/admin/y', ['POST'])\nasync def y(r):\n"
                          "    return ''\napp = Starlette(routes=[")
    assert _found(_write(tmp_path / "custom", {"server.py": custom})) == []


def test_an_allow_list_on_the_outer_app_covers_custom_routes_mounted_under_it(tmp_path: Path) -> None:
    """The outer app's middleware runs before the mount hands a request to the MCP app,
    so it covers the MCP app's own custom routes too."""
    body = (_SERVED + _ROUTE + "from starlette.applications import Starlette\n"
            "from starlette.middleware.trustedhost import TrustedHostMiddleware\n"
            "from starlette.routing import Mount\n"
            "outer = Starlette(routes=[Mount('/', app=app)])\n")
    assert len(_found(_write(tmp_path / "open", {"server.py": body}))) == 1
    covered = body + "outer.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost'])\n"
    assert _found(_write(tmp_path / "covered", {"server.py": covered})) == []


def test_names_are_resolved_in_their_own_function(tmp_path: Path) -> None:
    """`app` is the MCP app at module level and the outer app inside `outer_app()`; the
    allow-list applied there belongs to the outer one and covers its route."""
    body = (_FASTMCP + "from starlette.applications import Starlette\n"
            "from starlette.middleware.trustedhost import TrustedHostMiddleware\n"
            "from starlette.routing import Mount, Route\n"
            "app = mcp.streamable_http_app()\n\n"
            "async def x(r):\n    return ''\n\n"
            "def outer_app():\n"
            f"    app = Starlette(routes=[Route('/admin/x', x, methods=['POST']), Mount('{ENDPOINT}', app=MCP_APP)])\n"
            "    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost'])\n"
            "    return app\n")
    assert _found(_write(tmp_path, {"server.py": body})) == []


def test_a_credential_in_the_registration_covers_the_route(tmp_path: Path) -> None:
    body = (_SERVED + f"from fastapi import Depends, FastAPI\napi = FastAPI()\napi.mount('{ENDPOINT}', app)\n\n"
            "@api.post('/admin/x', dependencies=[Depends(require_api_key)])\ndef x():\n    return {}\n")
    assert _found(_write(tmp_path, {"server.py": body})) == []
    assert len(_found(_write(tmp_path / "open", {"server.py": body.replace(", dependencies=[Depends(require_api_key)]", "")}))) == 1


@pytest.mark.parametrize("handler", [
    "async def x(request):\n    if request.headers.get('authorization') != EXPECTED:\n        raise PermissionError\n    return ''\n",
    "async def x(request, key=Depends(require_api_key)):\n    return ''\n",
    "async def x(request):\n    token = request.query_params['token']\n    return token\n",
])
def test_a_credential_read_on_the_route_covers_it(tmp_path: Path, handler: str) -> None:
    body = _SERVED + "@mcp.custom_route('/admin/x', ['POST'])\n" + handler
    assert _found(_write(tmp_path, {"server.py": body})) == []


def test_a_credential_read_on_another_route_does_not_cover_this_one(tmp_path: Path) -> None:
    body = (_SERVED + "@mcp.custom_route('/admin/x', ['POST'])\nasync def x(request):\n    return ''\n\n"
            "@mcp.custom_route('/admin/y', ['POST'])\nasync def y(request):\n"
            "    return request.headers['authorization']\n")
    assert [f.evidence.split(": ", 1)[0] for f in _found(_write(tmp_path, {"server.py": body}))] == ["POST /admin/x"]


def test_a_handler_registered_by_name_is_read_where_it_is_defined(tmp_path: Path) -> None:
    head = _SERVED + "from starlette.routing import Route\n"
    checked = "async def x(request):\n    return request.headers['authorization']\n"
    routes = "routes = [Route('/admin/x', x, methods=['POST'])]\n"
    assert _found(_write(tmp_path / "checked", {"server.py": head + checked + routes})) == []
    assert len(_found(_write(tmp_path / "open", {"server.py": head + "async def x(request):\n    return ''\n" + routes}))) == 1


def test_many_routes_are_listed_up_to_eight(tmp_path: Path) -> None:
    body = _SERVED + "".join(f"@mcp.custom_route('/admin/r{i}', ['POST'])\nasync def r{i}(q):\n    return ''\n"
                             for i in range(11))
    (finding,) = _found(_write(tmp_path, {"server.py": body}))
    assert finding.evidence.startswith(", ".join(f"POST /admin/r{i}" for i in range(8)) + " and 3 more: ")


def test_an_unparsable_file_is_skipped(tmp_path: Path) -> None:
    root = _write(tmp_path, {"server.py": _SERVED + "@mcp.custom_route('/admin/x', ['POST'])\ndef x(:\n"})
    assert _found(root) == []


# ---- TS/JS -------------------------------------------------------------------------------

_TS_HEAD = (
    'import express from "express";\n'
    "import { " + TRANSPORT + ' } from "@modelcontextprotocol/sdk/server/streamableHttp.js";\n'
    "const app = express();\n"
    'app.post("' + ENDPOINT + '", (req, res) => new ' + TRANSPORT + '({ allowedHosts: ["localhost"] }));\n'
)
_TS_ROUTE = 'app.post("/api/config", (req, res) => { settings.url = req.body.url; res.json({}); });\n'


def _ts(tmp_path: Path, body: str, head: str = _TS_HEAD) -> list:
    return _found(_write(tmp_path, {"server.ts": head + body}))


@pytest.mark.parametrize("route, label", [
    ('app.put("/api/x", h);\n', "PUT /api/x"),
    ('app.patch("/api/x", h);\n', "PATCH /api/x"),
    ('app.delete("/api/x", h);\n', "DELETE /api/x"),
    ('app.all("/api/x", h);\n', "POST/PUT/PATCH/DELETE /api/x"),
    ('router.post("/api/x", h);\n', "POST /api/x"),
    ('this.app.post("/api/x", h);\n', "POST /api/x"),
])
def test_each_ts_route_form_is_read(tmp_path: Path, route: str, label: str) -> None:
    assert [f.evidence.split(": ", 1)[0] for f in _ts(tmp_path, route)] == [label]


@pytest.mark.parametrize("route", [
    'app.get("/api/x", h);\n',
    'app.post("' + ENDPOINT + '/messages", h);\n',
    'app.post("/sse", h);\n',
    'axios.post("/api/x", body);\n',          # an HTTP client, not an app
    "app.post(path, h);\n",                    # not a literal path
    '// app.post("/api/x", h);\n',             # a comment
])
def test_what_is_not_a_ts_route(tmp_path: Path, route: str) -> None:
    assert _ts(tmp_path, route) == []


def test_a_bound_app_of_another_name_is_read(tmp_path: Path) -> None:
    head = _TS_HEAD.replace("const app = express();", "const gateway = express();")
    assert len(_ts(tmp_path / "bound", 'gateway.post("/api/x", h);\n', head)) == 1
    assert _ts(tmp_path / "unbound", 'client.post("/api/x", h);\n', head) == []


@pytest.mark.parametrize("cover", [
    "app.use(hostHeaderValidation([\"localhost\"]));\n",
    "app.use(localhostOriginValidation());\n",
    "app.use(requireAuth);\n",
    'app.use("/api", validateOrigin);\n',
    'app.use("/api/", validateOrigin);\n',
    'app.use("/", validateOrigin);\n',
    "const { origin } = req.headers;\n",
    'if (req.get("host") !== expected) throw new Error();\n',
    "if (!allowed.has(req.hostname)) throw new Error();\n",
])
def test_what_covers_a_ts_route(tmp_path: Path, cover: str) -> None:
    assert _ts(tmp_path, cover + _TS_ROUTE) == []


@pytest.mark.parametrize("not_cover", [
    'app.use(cors({ origin: "http://localhost:3000" }));\n',   # CORS is no origin check
    'app.use("/admin", hostHeaderValidation(["localhost"]));\n',  # another path
    'app.use("/ap", hostHeaderValidation(["localhost"]));\n',     # a prefix of a segment, not a mount over it
    "app.use(express.json());\n",
])
def test_what_does_not_cover_a_ts_route(tmp_path: Path, not_cover: str) -> None:
    assert len(_ts(tmp_path, not_cover + _TS_ROUTE)) == 1


@pytest.mark.parametrize("route", [
    'app.post("/api/config", requireAuth, (req, res) => res.json({}));\n',
    'app.post("/api/config", verifyApiKey(keys), (req, res) => res.json({}));\n',
    'app.post("/api/config", (req, res) => { if (req.headers.authorization !== expected) return; res.json({}); });\n',
])
def test_a_credential_on_the_ts_route_covers_it(tmp_path: Path, route: str) -> None:
    assert _ts(tmp_path, route) == []


@pytest.mark.parametrize("options, fires", [
    ("", False),                                            # loopback default: both checks on
    ('{ host: "127.0.0.1" }', False),
    ('{ host: "' + ANY_HOST + '", allowedHosts: ["example.com"] }', False),
    ('{ host: "' + ANY_HOST + '" }', True),                 # every interface, no allow-list
    ("{ host: process.env.HOST }", False),                  # not read: taken as checked
])
def test_create_mcp_express_app(tmp_path: Path, options: str, fires: bool) -> None:
    head = _TS_HEAD.replace("const app = express();", f"const app = createMcpExpressApp({options});")
    assert (len(_ts(tmp_path, _TS_ROUTE, head)) == 1) is fires
