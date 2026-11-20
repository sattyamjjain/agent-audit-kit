"""AAK-WEBSOCKET-SERVER-002: a Node `ws` server for MCP, model or policy traffic with no Origin check.

CVE-2026-132121 (Supergateway 2.4.0 through 4.2.2, NVD 2026-11-18): "cross-site WebSocket
hijacking ... in stdio-to-WebSocket mode ... missing Origin header validation"; a page opens
`/message`, even against a localhost-bound gateway, and calls the wrapped stdio MCP tools.

Read in Supergateway's own source on 2026-11-20: every release from 2.4.0 to 4.1.0 builds
`new WebSocketServer({ path, server })` in src/server/websocket.ts, with no `verifyClient`,
and spawns the stdio server in src/gateways/stdioToWs.ts. 4.2.0 to 4.2.2 build it with
`...(verifyClient ? { verifyClient } : {})` and pass a check of an API key that lets every
request through when no key is configured. The rule fires HIGH on websocket.ts in all seven
releases read (2.4.0, 3.4.3, 4.0.0, 4.1.0, 4.2.0, 4.2.1, 4.2.2); the upstream files are not
committed here, and the two transport fixtures below are written in their shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Severity
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.websocket_server import scan

FIXTURES = Path(__file__).parent / "fixtures" / "websocket_server"
RULE = "AAK-WEBSOCKET-SERVER-002"


def _found(root: Path) -> list:
    return [f for f in scan(root)[0] if f.rule_id == RULE]


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_the_rule_is_high_and_names_the_cve() -> None:
    rule = RULES[RULE]
    assert rule.severity is Severity.HIGH
    assert rule.cve_references == ["CVE-2026-132121"]
    assert rule.category.value == RULES["AAK-WEBSOCKET-SERVER-001"].category.value


# ---- the order's fixtures ---------------------------------------------------------------


def test_the_stdio_bridge_fires_once_at_critical() -> None:
    (finding,) = _found(FIXTURES / "ws_stdio_bridge")
    assert finding.severity is Severity.CRITICAL
    assert finding.file_path == "gateway.ts"
    assert "no `verifyClient`" in finding.evidence
    assert "`spawn` from child_process" in finding.evidence
    assert "CVE-2026-132121" in finding.evidence
    line = (FIXTURES / "ws_stdio_bridge" / "gateway.ts").read_text().splitlines()[finding.line_number - 1]
    assert "new WebSocketServer(" in line


def test_verify_client_checking_the_origin_clears_it() -> None:
    assert _found(FIXTURES / "ws_stdio_bridge_verify_client") == []


def test_a_server_that_starts_no_process_is_high() -> None:
    (finding,) = _found(FIXTURES / "ws_mcp_server")
    assert finding.severity is Severity.HIGH
    assert "child_process" not in finding.evidence


def test_a_verify_client_set_only_when_a_caller_passes_one_does_not_clear_it() -> None:
    (finding,) = _found(FIXTURES / "ws_conditional_verify_client")
    assert finding.severity is Severity.HIGH
    assert "set only when its caller passes one" in finding.evidence


def test_the_engine_reports_it_end_to_end() -> None:
    result = run_scan(project_root=FIXTURES / "ws_stdio_bridge", rules=[RULE])
    assert [(f.rule_id, f.severity) for f in result.findings] == [(RULE, Severity.CRITICAL)]


# ---- what builds a server ----------------------------------------------------------------

_MCP = 'import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";\n'


@pytest.mark.parametrize("source", [
    'import { WebSocketServer } from "ws";\nconst wss = new WebSocketServer({ port: 8080 });\n',
    'import { WebSocketServer as Wss } from "ws";\nconst wss = new Wss({ port: 8080 });\n',
    'import WebSocket from "ws";\nconst wss = new WebSocket.Server({ port: 8080 });\n',
    'import * as ws from "ws";\nconst wss = new ws.WebSocketServer({ port: 8080 });\n',
    'import { WebSocket } from "ws";\nconst wss = new WebSocket.Server({ port: 8080 });\n',
    'const WebSocket = require("ws");\nconst wss = new WebSocket.Server({ port: 8080 });\n',
    'const { Server } = require("ws");\nconst wss = new Server({ port: 8080 });\n',
    'const { WebSocketServer: Wss } = require("ws");\nconst wss = new Wss({ port: 8080 });\n',
    'const Wss = require("ws").Server;\nconst wss = new Wss({ port: 8080 });\n',
    'import { WebSocketServer } from "isomorphic-ws";\nconst wss = new WebSocketServer({ port: 8080 });\n',
    'import { WebSocketServer } from "ws";\nconst wss = new WebSocketServer();\n',
])
def test_each_way_of_building_the_server_is_read(tmp_path: Path, source: str) -> None:
    assert len(_found(_write(tmp_path, {"bridge.ts": _MCP + source}))) == 1


@pytest.mark.parametrize("source", [
    'import { WebSocket } from "ws";\nconst client = new WebSocket("ws://localhost:8080");\n',   # a client
    'import { WebSocketServer } from "some-other-ws";\nconst wss = new WebSocketServer({});\n',  # not ws
    'import { WebSocketServer } from "ws";\n// const wss = new WebSocketServer({ port: 8080 });\n',
    'import { WebSocketServer } from "ws";\nconst s = "new WebSocketServer({ port: 8080 })";\n',
])
def test_what_is_not_a_ws_server(tmp_path: Path, source: str) -> None:
    assert _found(_write(tmp_path, {"bridge.ts": _MCP + source})) == []


# ---- what checks it ----------------------------------------------------------------------

_SERVER = 'import { WebSocketServer } from "ws";\n'


@pytest.mark.parametrize("built", [
    "const wss = new WebSocketServer({ port: 8080, verifyClient: checkOrigin });\n",
    "const wss = new WebSocketServer({ port: 8080, verifyClient });\n",
    "const wss = new WebSocketServer(options);\n",                       # not a literal: may hold one
    "const wss = new WebSocketServer({ ...defaults, port: 8080 });\n",   # a spread that may hold one
    "const wss = new WebSocketServer({ noServer: true });\n"
    "server.on('upgrade', (req, socket, head) => {\n"
    "  if (!allowed.has(req.headers.origin)) return socket.destroy();\n"
    "  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));\n"
    "});\n",
    "const wss = new WebSocketServer({ port: 8080 });\n"
    "wss.on('connection', (ws, req) => { if (req.headers.authorization !== expected) ws.close(); });\n",
])
def test_what_answers_it(tmp_path: Path, built: str) -> None:
    assert _found(_write(tmp_path, {"bridge.ts": _MCP + _SERVER + built})) == []


def test_a_cors_option_is_not_an_origin_check(tmp_path: Path) -> None:
    body = _MCP + _SERVER + 'const wss = new WebSocketServer({ port: 8080 });\napp.use(cors({ origin: "*" }));\n'
    assert len(_found(_write(tmp_path, {"bridge.ts": body}))) == 1


# ---- scope and severity ------------------------------------------------------------------

_PLAIN = _SERVER + "const wss = new WebSocketServer({ port: 8080 });\n"


@pytest.mark.parametrize("rel, text, fires", [
    ("src/chat/server.ts", _PLAIN, False),                       # no MCP, model or agent word, no import
    ("src/mcp/server.ts", _PLAIN, True),                          # a path word
    ("src/agent-gateway.js", _PLAIN, True),
    ("src/chat/server.ts", _MCP + _PLAIN, True),                  # an MCP import
    ("src/chat/server.ts", 'import { spawn } from "node:child_process";\nspawn("x", []);\n' + _PLAIN, True),
    ("tests/mcp/server.ts", _MCP + _PLAIN, False),
    ("examples/mcp_server.ts", _MCP + _PLAIN, False),
    ("src/mcp/server.test.ts", _MCP + _PLAIN, False),
    ("src/mcp/server.spec.js", _MCP + _PLAIN, False),
])
def test_scope(tmp_path: Path, rel: str, text: str, fires: bool) -> None:
    assert (len(_found(_write(tmp_path, {rel: text}))) == 1) is fires


@pytest.mark.parametrize("processes, critical", [
    ('import { spawn } from "child_process";\nspawn(cmd, args);\n', True),
    ('import { execFile as run } from "node:child_process";\nrun(cmd, args);\n', True),
    ('import * as cp from "child_process";\ncp.fork(script);\n', True),
    ('const cp = require("child_process");\ncp.execSync(cmd);\n', True),
    ('const { exec } = require("child_process");\nexec(cmd);\n', True),
    ('import { spawn } from "child_process";\n', False),                    # imported, never called
    ('const m = /x/.exec(s);\n', False),                                     # RegExp.exec, not child_process
    ('import { spawn } from "cross-spawn-like";\nspawn(cmd);\n', False),     # another module
])
def test_critical_needs_a_child_process_call_in_the_file(tmp_path: Path, processes: str, critical: bool) -> None:
    (finding,) = _found(_write(tmp_path, {"mcp_bridge.ts": processes + _PLAIN}))
    assert (finding.severity is Severity.CRITICAL) is critical


def test_each_server_in_a_file_is_reported(tmp_path: Path) -> None:
    body = _MCP + _SERVER + "const a = new WebSocketServer({ port: 1 });\nconst b = new WebSocketServer({ port: 2 });\n"
    assert [f.line_number for f in _found(_write(tmp_path, {"bridge.ts": body}))] == [3, 4]


def test_python_websockets_servers_stay_with_001(tmp_path: Path) -> None:
    root = _write(tmp_path, {"mcp_server.py": "import websockets\n\nasync def main():\n"
                                              "    await websockets.serve(h, '127.0.0.1', 80)\n"})
    findings = scan(root)[0]
    assert [f.rule_id for f in findings] == ["AAK-WEBSOCKET-SERVER-001"]
