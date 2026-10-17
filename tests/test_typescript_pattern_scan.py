"""Which files the TypeScript/JavaScript pattern scanner reads.

It globbed `*.ts` and `*.tsx` only, though it is described as a TypeScript and
JavaScript scanner and AAK-MCP-TOOL-ARG-OSCMD-001 says so, so a repository of
`.js`, `.mjs` or `.cjs` MCP servers had no file read at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.scanners.typescript_pattern_scan import scan

_EVAL_SERVER = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    "\n"
    'const server = new McpServer({ name: "calc", version: "1.0.0" });\n'
    "\n"
    'server.tool("calc", async ({ expr }) => {\n'
    "  const result = eval(expr);\n"
    '  return { content: [{ type: "text", text: String(result) }] };\n'
    "});\n"
)

_OSCMD_HANDLER = (
    'import { exec } from "node:child_process";\n'
    "\n"
    "export async function handleToolCall(name, args) {\n"
    "  exec(`ffmpeg -i ${args.input} -f ${args.format} out.mp4`);\n"
    "}\n"
)

_EXEC_SERVER = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'import { exec } from "node:child_process";\n'
    "\n"
    'const server = new McpServer({ name: "run", version: "1.0.0" });\n'
    "\n"
    'server.tool("run", async ({ command }) => {\n'
    "  exec(command);\n"
    '  return { content: [{ type: "text", text: "ok" }] };\n'
    "});\n"
)

EXTENSIONS = ("ts", "tsx", "js", "jsx", "mjs", "cjs")


@pytest.mark.parametrize("ext", EXTENSIONS)
def test_an_exec_server_is_read_in_every_extension(tmp_path: Path, ext: str) -> None:
    (tmp_path / f"server.{ext}").write_text(_EXEC_SERVER, encoding="utf-8")
    findings, scanned = scan(tmp_path)
    assert [(f.rule_id, f.file_path, f.line_number) for f in findings] == [
        ("AAK-TAINT-001", f"server.{ext}", 7)
    ]
    assert scanned == {f"server.{ext}"}


@pytest.mark.parametrize("ext", EXTENSIONS)
def test_eval_is_reported_in_typescript_only(tmp_path: Path, ext: str) -> None:
    """AAK-TAINT-002 stays out of JavaScript. In JavaScript MCP servers from code
    search, 1 of 12 `eval(` matches was an eval call: the rest sat in strings or
    regular expressions, or named a method `eval`."""
    (tmp_path / f"server.{ext}").write_text(_EVAL_SERVER, encoding="utf-8")
    findings, scanned = scan(tmp_path)
    expected = [("AAK-TAINT-002", 6)] if ext in ("ts", "tsx") else []
    assert [(f.rule_id, f.line_number) for f in findings] == expected
    assert scanned == {f"server.{ext}"}


@pytest.mark.parametrize("ext", EXTENSIONS)
def test_a_composed_shell_command_is_read_in_every_extension(tmp_path: Path, ext: str) -> None:
    (tmp_path / f"handlers.{ext}").write_text(_OSCMD_HANDLER, encoding="utf-8")
    findings, _ = scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-MCP-TOOL-ARG-OSCMD-001", 4)]


@pytest.mark.parametrize("name", ["server.py", "server.mts", "server.js.map", "server.json"])
def test_other_files_are_not_read(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text(_EVAL_SERVER, encoding="utf-8")
    assert scan(tmp_path) == ([], set())


@pytest.mark.parametrize("vendored", ["node_modules/pkg", "dist", "build"])
def test_javascript_in_a_vendored_tree_is_still_skipped(tmp_path: Path, vendored: str) -> None:
    (tmp_path / vendored).mkdir(parents=True)
    (tmp_path / vendored / "server.js").write_text(_EVAL_SERVER, encoding="utf-8")
    assert scan(tmp_path) == ([], set())


def test_a_javascript_file_without_an_mcp_marker_is_read_but_not_reported(tmp_path: Path) -> None:
    (tmp_path / "build.js").write_text(
        "require('child_process').execSync(process.argv[2]);\n", encoding="utf-8"
    )
    assert scan(tmp_path) == ([], {"build.js"})


# Review findings (2026-10-17): reading `.js` exposed two loose patterns. The
# server gate matched Node's `http.createServer`, and AAK-TAINT-001 matched
# `RegExp.prototype.exec`, so ordinary Node files got CRITICAL findings. Naming
# the SDK did not make a server either: on 2,016 JavaScript files from code
# search, a gate of `McpServer`, `@modelcontextprotocol/sdk`, `server.tool(` or
# `CallToolRequestSchema` reported 500 findings and a third of them were not in
# a server or tool handler (clients, hosts, build and eval scripts).

_NON_MCP = {
    # A static dev server, the kind a docs site or a demo ships.
    "scripts/serve.js": (
        "const http = require('http');\nconst fs = require('fs');\n"
        "const { exec } = require('child_process');\n"
        "const server = http.createServer((req, res) => {\n"
        "  const m = /^\\/files\\/(.+)$/.exec(req.url);\n"
        "  res.end(m ? fs.readFileSync(m[1]) : 'not found');\n"
        "});\n"
        "server.listen(8080, () => exec('open http://localhost:8080'));\n"
    ),
    # A test helper that writes a fixture file.
    "test/helpers/mock-server.js": (
        "import http from 'node:http';\nimport { writeFileSync } from 'node:fs';\n"
        "export function start(port) {\n"
        "  writeFileSync('/tmp/port', String(port));\n"
        "  return http.createServer((q, s) => s.end('ok')).listen(port);\n}\n"
    ),
    # An Electron main process with a local callback server.
    "app/main.js": (
        "const { app } = require('electron');\nconst http = require('http');\n"
        "const { spawn } = require('child_process');\n"
        "http.createServer((req, res) => res.end()).listen(0);\n"
        "app.whenReady().then(() => spawn(process.execPath, ['--updater']));\n"
    ),
}


@pytest.mark.parametrize("rel", sorted(_NON_MCP))
def test_an_ordinary_node_file_is_not_an_mcp_server(tmp_path: Path, rel: str) -> None:
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text(_NON_MCP[rel], encoding="utf-8")
    assert scan(tmp_path)[0] == []


@pytest.mark.parametrize("marker", [
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
    "import {McpServer} from '@modelcontextprotocol/sdk/server/mcp';",
    'const { Server } = require("@modelcontextprotocol/sdk/server/index.js");',
    'const { Server } = await import("@modelcontextprotocol/sdk/dist/esm/server/index.js");',
    'server.tool("calc", {}, async () => ({}));',
    'server.registerTool("calc", { inputSchema }, async () => ({}));',
    "server.setRequestHandler(CallToolRequestSchema, async (request) => ({}));",
])
def test_a_javascript_mcp_server_is_read(tmp_path: Path, marker: str) -> None:
    (tmp_path / "server.js").write_text(marker + "\nfs.writeFileSync(path, text);\n", encoding="utf-8")
    assert [f.rule_id for f in scan(tmp_path)[0]] == ["AAK-TAINT-003"]


_NOT_A_SERVER = {
    # An MCP client: it spawns the server it talks to, and calls its tools.
    "client.js": (
        'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
        'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\n'
        'import { spawn } from "node:child_process";\n'
        'const transport = new StdioClientTransport({ command: "node", args: ["server.js"] });\n'
        'const client = new Client({ name: "host", version: "1.0.0" });\n'
        "await client.connect(transport);\n"
        'const out = await client.callTool({ name: "calc", arguments: { expr } });\n'
        'spawn("open", [out.url]);\n'
    ),
    # A host with its own `McpServer` class, one per configured server.
    "host/servers.js": (
        "const { spawn } = require('child_process');\n"
        "class McpServer {\n"
        "  constructor(cfg) { this.proc = spawn(cfg.command, cfg.args); }\n"
        "}\n"
        "module.exports = { McpServer };\n"
    ),
    # Types only, and a request schema handed to a client's request().
    "scripts/list-tools.mjs": (
        "import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';\n"
        "import { execSync } from 'node:child_process';\n"
        "const tools = JSON.parse(execSync('node server.js --list'));\n"
        "console.log(CallToolRequestSchema.parse({ method: 'tools/call', params: tools[0] }));\n"
    ),
}


@pytest.mark.parametrize("rel", sorted(_NOT_A_SERVER))
def test_a_javascript_file_that_names_the_sdk_but_serves_nothing_is_not_reported(
    tmp_path: Path, rel: str
) -> None:
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text(_NOT_A_SERVER[rel], encoding="utf-8")
    assert scan(tmp_path)[0] == []


_CLIENT_CALL = (
    "import { exec } from 'node:child_process';\n"
    "export async function run(rpc, name, args) {\n"
    "  const out = await rpc.request({ method: 'tools/call', params: { name, arguments: args } });\n"
    "  exec(`open ${out.url}`);\n"
    "}\n"
)


def test_a_javascript_tools_call_request_is_not_a_tool_handler(tmp_path: Path) -> None:
    """`'tools/call'` is the method a client sends; in JavaScript it no longer
    makes a tool handler. TypeScript keeps the marker."""
    (tmp_path / "rpc.js").write_text(_CLIENT_CALL, encoding="utf-8")
    (tmp_path / "rpc.ts").write_text(_CLIENT_CALL, encoding="utf-8")
    assert [(f.rule_id, f.file_path) for f in scan(tmp_path)[0]] == [
        ("AAK-MCP-TOOL-ARG-OSCMD-001", "rpc.ts")
    ]


@pytest.mark.parametrize("text", [
    "import x from '" + "a" * 1_000_000,
    "from '" + "@" * 1_000_000,
    "from " * 200_000,
    "require(" + " " * 1_000_000 + "x",
    "server." + " " * 1_000_000 + "tool",
])
def test_the_javascript_server_gate_reads_in_linear_time(tmp_path: Path, text: str) -> None:
    import time

    (tmp_path / "server.js").write_text(text + "\nfs.writeFileSync(path, text);\n", encoding="utf-8")
    started = time.perf_counter()
    assert scan(tmp_path)[0] == []
    assert time.perf_counter() - started < 5.0


def test_typescript_keeps_its_server_gate(tmp_path: Path) -> None:
    """Only JavaScript moved to the MCP-marker gate; a `.ts` file is gated as before."""
    (tmp_path / "server.ts").write_text(
        "import http from 'node:http';\nhttp.createServer(() => eval(code));\n", encoding="utf-8"
    )
    assert [f.rule_id for f in scan(tmp_path)[0]] == ["AAK-TAINT-002"]


@pytest.mark.parametrize("name", [
    "public/js/server.bundle.min.js",
    "vendor-free/app.min.mjs",
    "public/js/server.bundle.js",
])
def test_a_minified_or_one_line_bundle_is_skipped(tmp_path: Path, name: str) -> None:
    bundle = (
        "var h=require('@modelcontextprotocol/sdk');"
        + "function a(b){return b.replace(/x/g,'y')}" * 2_000
        + "h.server.tool('x',{},function(q){var m=/(\\d+)/.exec(q);eval(m[1])});"
    )
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(bundle, encoding="utf-8")
    assert scan(tmp_path) == ([], set())


def test_a_bundle_with_a_banner_and_a_source_map_line_is_skipped(tmp_path: Path) -> None:
    """A bundler writes its licence banner and its source-map comment on lines of
    their own; the code line between them is what makes the file a bundle."""
    code = (
        "var h=require('@modelcontextprotocol/sdk/server/mcp.js');"
        + "function a(b){return b.replace(/x/g,'y')}" * 2_000
        + "h.server.tool('x',{},function(q){require('child_process').exec(q)});"
    )
    bundle = "/*! For license information please see main.js.LICENSE.txt */\n" + code + "\n//# sourceMappingURL=main.js.map\n"
    (tmp_path / "server.js").write_text(bundle, encoding="utf-8")
    assert scan(tmp_path) == ([], set())


def test_a_bundle_split_by_its_template_literals_is_skipped(tmp_path: Path) -> None:
    """A minifier keeps the newlines inside template literals, so a bundle can be
    mostly short lines (`plugin/scripts/search-server.cjs`: 77 lines, median 40
    characters, 98% of its 340 KB in seven lines of code). The long lines are
    minified code, dense in `(` and `;`, and they hold most of the file."""
    code = (
        '"use strict";var h=require("@modelcontextprotocol/sdk/server/mcp.js");'
        + "function f(b){return b.replace(/x/g,'y')};" * 1_500
    )
    template = "var t=`\n" + "".join(f"  row {i}: ${{v}}\n" for i in range(120)) + "`;"
    tail = "h.server.tool('x',{},function(q){require('child_process').exec(q)});"
    (tmp_path / "server.cjs").write_text(code + template + code + tail + "\n", encoding="utf-8")
    assert scan(tmp_path) == ([], set())


def test_a_hand_written_server_with_an_inlined_asset_is_read(tmp_path: Path) -> None:
    """The bundle check took the mean line length, so one inlined 150 KB base64
    image in a 190-line server averaged about 800 characters a line, and the file
    was skipped with its `exec(cmd)`. The median line is short, and the long one
    is data, not minified code."""
    lines = [
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
        'import { exec } from "node:child_process";',
        'const server = new McpServer({ name: "shot", version: "1.0.0" });',
        "const LOGO = 'data:image/png;base64," + "QUJD" * 37_500 + "';",
    ]
    lines += [f"const option{i} = process.env.OPTION_{i} ?? 'default';" for i in range(185)]
    lines += ['server.tool("run", async ({ cmd }) => { exec(cmd); return { content: [] }; });']
    (tmp_path / "server.js").write_text("\n".join(lines) + "\n", encoding="utf-8")
    findings, scanned = scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-TAINT-001", len(lines))]
    assert scanned == {"server.js"}


_MCP_HEAD = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'


@pytest.mark.parametrize(("code", "fires"), [
    # A regular expression's exec is not a process.
    ("const m = /^v(\\d+)$/.exec(version);", False),
    ("const m = pattern.exec(input);", False),
    ("function exec(sql) { return db.run(sql); }\nexec(query);", False),
    # child_process, by module, alias, destructuring, rename or import.
    ("child_process.exec(cmd);", True),
    ("const cp = require('node:child_process');\ncp.spawn(cmd, { shell: true });", True),
    ("const { exec } = require('child_process');\nexec(cmd);", True),
    ("const { spawnSync: run } = require('child_process');\nrun(cmd);", True),
    ("import { execSync as sh } from 'node:child_process';\nsh(cmd);", True),
    ("import * as cp from 'child_process';\ncp.execSync(cmd);", True),
    ("const exec = require('child_process').exec;\nexec(cmd);", True),
    ("require('child_process').spawn(cmd);", True),
    # A dynamic import, the form five real MCP servers in the measurement use.
    ("const { execSync } = await import('node:child_process');\nexecSync(cmd);", True),
    ("const cp = await import('child_process');\ncp.spawn(cmd);", True),
    ("let { spawn: run } = await import(\"child_process\");\nrun(cmd);", True),
])
def test_taint_001_reads_exec_and_spawn_from_child_process_only(tmp_path: Path, code: str, fires: bool) -> None:
    for ext in ("js", "ts"):
        (tmp_path / f"server.{ext}").write_text(_MCP_HEAD + code + "\n", encoding="utf-8")
        hits = [f.rule_id for f in scan(tmp_path)[0] if f.rule_id == "AAK-TAINT-001"]
        (tmp_path / f"server.{ext}").unlink()
        assert bool(hits) is fires, (ext, code)


@pytest.mark.parametrize("text", [
    "const { " + "a, " * 200_000 + "} = require('child_process');",
    "import { " + "x as y, " * 100_000 + "} from 'child_process';",
    "const cp = require(" + " " * 1_000_000 + "'child_process');",
])
def test_child_process_bindings_read_in_linear_time(tmp_path: Path, text: str) -> None:
    import time

    (tmp_path / "server.ts").write_text(_MCP_HEAD + text + "\nexec(cmd);\n", encoding="utf-8")
    started = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - started < 5.0
