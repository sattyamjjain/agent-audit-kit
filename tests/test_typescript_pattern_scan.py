"""Which files the TypeScript/JavaScript pattern scanner reads.

It globbed `*.ts` and `*.tsx` only, though it is described as a TypeScript and
JavaScript scanner and AAK-MCP-TOOL-ARG-OSCMD-001 says so, so a repository of
`.js`, `.mjs` or `.cjs` MCP servers had no file read at all.

The TypeScript gates, the MCP-server one in front of the AAK-TAINT-* sink
patterns and the tool-handler one in front of AAK-MCP-TOOL-ARG-OSCMD-001, wrote
`\\b(...|@tool)\\b`. A word boundary before `@` needs a word character in
front of it, so a TypeScript file whose only marker was a `@tool` decorator was
never read.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

import agent_audit_kit
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

EXTENSIONS = ("ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs")


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
    expected = [("AAK-TAINT-002", 6)] if ext in ("ts", "tsx", "mts", "cts") else []
    assert [(f.rule_id, f.line_number) for f in findings] == expected
    assert scanned == {f"server.{ext}"}


@pytest.mark.parametrize("ext", EXTENSIONS)
def test_a_composed_shell_command_is_read_in_every_extension(tmp_path: Path, ext: str) -> None:
    (tmp_path / f"handlers.{ext}").write_text(_OSCMD_HANDLER, encoding="utf-8")
    findings, _ = scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings] == [("AAK-MCP-TOOL-ARG-OSCMD-001", 4)]


@pytest.mark.parametrize("name", ["server.py", "server.js.map", "server.json", "server.mjs.map"])
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


# A client registers request handlers too, with the same `setRequestHandler`: an
# elicitation handler that opens the URL a server sent got a CRITICAL as a tool
# handler composing a shell command. A types-only import of CallToolRequestSchema
# is no handler either.
_CLIENT_HANDLERS = {
    "host/client.js": (
        'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\n'
        'import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";\n'
        'import { exec } from "node:child_process";\n'
        'const client = new Client({ name: "host", version: "1.0.0" });\n'
        "client.setRequestHandler(ElicitRequestSchema, async (request) => {\n"
        '  exec(`open "${request.params.url}"`);\n'
        '  return { action: "accept" };\n'
        "});\n"
    ),
    "scripts/call.mjs": (
        "import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';\n"
        "import { execSync } from 'node:child_process';\n"
        "const request = CallToolRequestSchema.parse(JSON.parse(process.argv[2]));\n"
        "execSync(`node server.js --call ${request.params.name}`);\n"
    ),
}


@pytest.mark.parametrize("rel", sorted(_CLIENT_HANDLERS))
def test_a_javascript_client_handler_is_not_a_tool_handler(tmp_path: Path, rel: str) -> None:
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text(_CLIENT_HANDLERS[rel], encoding="utf-8")
    assert scan(tmp_path)[0] == []


@pytest.mark.parametrize("registration", [
    "server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {",
    "server.setRequestHandler(\n  CallToolRequestSchema,\n  async ({ params }) => {",
])
def test_a_javascript_call_tool_handler_is_a_tool_handler(tmp_path: Path, registration: str) -> None:
    (tmp_path / "handlers.js").write_text(
        "import { exec } from 'node:child_process';\n"
        + registration
        + "\n  exec(`ffmpeg -i ${params.arguments.input}`);\n});\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in scan(tmp_path)[0]] == ["AAK-MCP-TOOL-ARG-OSCMD-001"]


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


@pytest.mark.parametrize(("size", "read"), [(10_000, True), (10_001, False)])
def test_a_one_line_bundle_is_skipped_only_over_10000_characters(tmp_path: Path, size: int, read: bool) -> None:
    """The limitation states the floor: a smaller one-line bundle is read."""
    head = "var h=require('@modelcontextprotocol/sdk/server/mcp.js');"
    tail = "h.server.tool('x',{},function(q){require('child_process').exec(q)});\n"
    text = head + "a();" * ((size - len(head) - len(tail)) // 4)
    text += ";" * (size - len(text) - len(tail)) + tail
    assert len(text) == size
    (tmp_path / "server.js").write_text(text, encoding="utf-8")
    findings, scanned = scan(tmp_path)
    assert bool(scanned) is read
    assert [f.rule_id for f in findings] == (["AAK-TAINT-001"] if read else [])


@pytest.mark.parametrize(("short", "bundle"), [(10, True), (11, False)])
def test_a_bundle_is_judged_by_the_upper_median_line(short: int, bundle: bool) -> None:
    """With an even number of lines the median is the longer of the middle two, as
    the limitation says: ten lines of 100 characters and ten of 900 make a bundle,
    though the middle two average 500. One more short line makes the median short."""
    from agent_audit_kit.scanners.typescript_pattern_scan import _is_bundle

    text = "\n".join(["x" * 100] * short + ["y" * 900] * 10) + "\n"
    assert len(text) > 10_000
    assert _is_bundle("server.js", text) is bundle


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
    # A dynamic import's promise, its callback naming the module or its members.
    ("import('node:child_process').then((cp) => cp.exec(cmd));", True),
    ("import('child_process').then(cp => cp.spawn(cmd));", True),
    ("import('child_process').then(async function (cp) { cp.execSync(cmd); });", True),
    ("import('node:child_process').then(({ execSync }) => execSync(cmd));", True),
    ("import('child_process').then(function load(cp) { cp.exec(cmd); });", True),
    # A callback that names no parameter binds nothing: neither a letter of its
    # function's name (`d`, after `load` was cut short) nor the name itself.
    ("import('child_process').then(function load() { ready(); });\nconst d = new Database(':memory:');\nd.exec(sql);", False),
    ("import('child_process').then(async function load() {});\nload.exec(cmd);", False),
    ("import('child_process').then(function () {});\nconst d = db;\nd.exec(sql);", False),
    # Optional chaining.
    ("const cp = require('child_process');\ncp?.exec(cmd);", True),
    ("child_process?.spawn(cmd);", True),
    ("require('child_process')?.exec(cmd);", True),
])
def test_taint_001_reads_exec_and_spawn_from_child_process_only(tmp_path: Path, code: str, fires: bool) -> None:
    for ext in ("js", "ts"):
        (tmp_path / f"server.{ext}").write_text(_MCP_HEAD + code + "\n", encoding="utf-8")
        hits = [f.rule_id for f in scan(tmp_path)[0] if f.rule_id == "AAK-TAINT-001"]
        (tmp_path / f"server.{ext}").unlink()
        assert bool(hits) is fires, (ext, code)


def test_taint_001_reads_a_typescript_import_equals(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        _MCP_HEAD + "import cp = require('child_process');\ncp.exec(cmd);\n", encoding="utf-8"
    )
    assert [(f.rule_id, f.line_number) for f in scan(tmp_path)[0]] == [("AAK-TAINT-001", 3)]


# Verification of the child_process sink: seven ways of binding the module that
# main reported in TypeScript (it took any `.exec(`) and the branch had lost.
# Each case gives the line the call is on, counted after _MCP_HEAD.
_MORE_BINDINGS = {
    "second declarator": ("const fs = require('fs'), cp = require('child_process');\ncp.exec(cmd);", 3),
    "destructured from a bound name": (
        "const cp = require('child_process');\nconst { exec } = cp;\nexec(cmd);", 4
    ),
    "declared, then assigned": ("let cp;\ncp = require('child_process');\ncp.exec(cmd);", 4),
    "this property": ("this.cp = require('child_process');\nthis.cp.exec(cmd);", 3),
    "awaited in parentheses": ("const cp = (await import('child_process'));\ncp.exec(cmd);", 3),
    "a .then default item": ("import('child_process').then(({ default: cp }) => cp.exec(cmd));", 2),
    "a call split before the dot": ("const cp = require('child_process');\ncp\n  .exec(cmd);", 4),
    # The same split after the dot, on `this` and on the require itself.
    "a call split after the dot": ("const cp = require('child_process');\ncp.\n  spawn(cmd);", 4),
    "this, split": ("this.cp = require('child_process');\nthis.cp\n  ?.exec(cmd);", 4),
    "require, split": ("require('child_process')\n  .execSync(cmd);", 3),
    "a default import item": ("import { default as cp } from 'child_process';\ncp.spawn(cmd);", 3),
    "a parenthesised import, called": ("(await import('child_process')).exec(cmd);", 2),
}


@pytest.mark.parametrize("case", sorted(_MORE_BINDINGS))
@pytest.mark.parametrize("ext", ["ts", "js"])
def test_taint_001_reads_more_child_process_bindings(tmp_path: Path, case: str, ext: str) -> None:
    code, line = _MORE_BINDINGS[case]
    (tmp_path / f"server.{ext}").write_text(_MCP_HEAD + code + "\n", encoding="utf-8")
    assert [(f.rule_id, f.line_number) for f in scan(tmp_path)[0]] == [("AAK-TAINT-001", line)]


# Still not read, as the limitation says. A name only looks bound when nothing
# binds it: `run.exec(cmd)` below calls a property of something else.
_UNREAD_BINDINGS = {
    "module.require": "const cp = module.require('child_process');\ncp.exec(cmd);",
    "a default value in the list": "const { exec = null } = require('child_process');\nexec(cmd);",
    "a member copied from a bound name": "const cp = require('child_process');\nconst run = cp.exec;\nrun(cmd);",
    "another object's property": "deps.cp = require('child_process');\ndeps.cp.exec(cmd);",
    "a comparison, not an assignment": "if (cp == require('child_process')) {}\ncp.exec(cmd);",
    "a split call on an unbound name": "const cp = require('child_process');\nrun\n  .exec(cmd);",
    "a property assigned on another name": "other.cp = require('child_process');\nthis.cp.exec(cmd);",
}


@pytest.mark.parametrize("case", sorted(_UNREAD_BINDINGS))
def test_taint_001_does_not_read_other_bindings(tmp_path: Path, case: str) -> None:
    (tmp_path / "server.ts").write_text(_MCP_HEAD + _UNREAD_BINDINGS[case] + "\n", encoding="utf-8")
    assert [f.rule_id for f in scan(tmp_path)[0] if f.rule_id == "AAK-TAINT-001"] == []


_HEAD = 'const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");\n'

# Each case at a size and at ten times it, under the 1 MB the scanner reads.
_CRAFTED = {
    # An unclosed destructuring or import list: `[^}]*` read to the end of the
    # file from every one, so 80,000 of them (0.48 MB) took 183 s.
    "unclosed let": (4_000, lambda k: "let {\n" * k),
    "unclosed import": (4_000, lambda k: "import a, {\n" * k),
    # Names bound to child_process, each called: they became one alternation,
    # tried at every position of every line.
    "aliases": (1_500, lambda k: "".join(f"const cp{i} = require('child_process');\n" for i in range(k))
                + "".join(f"cp{i}.exec(cmd);\n" for i in range(k))),
    "renamed imports": (1_500, lambda k: "".join(f"const {{ exec: e{i} }} = require('child_process');\n" for i in range(k))
                        + "".join(f"e{i}(cmd);\n" for i in range(k))),
    # An import item padded with blanks: two adjacent `\s*` split them every way.
    # Short lines between keep a JavaScript file from reading as a bundle.
    "padded import item": (40, lambda k: (
        "import { exec" + " " * 1_900 + "! } from 'child_process';\nconst a = 1;\nconst b = 2;\n"
    ) * k),
}


@pytest.mark.parametrize("case", sorted(_CRAFTED))
@pytest.mark.parametrize("ext", ["js", "ts"])
def test_child_process_bindings_scale_linearly(tmp_path: Path, case: str, ext: str) -> None:
    """At ten times the size a linear reader takes about ten times as long, and a
    quadratic one a hundred. The bounds are loose for slow CI runners."""
    import time

    size, build = _CRAFTED[case]
    timings = []
    for k in (size, size * 10):
        root = tmp_path / str(k)
        root.mkdir()
        (root / f"server.{ext}").write_text(_HEAD + build(k), encoding="utf-8")
        started = time.perf_counter()
        _, scanned = scan(root)
        timings.append(time.perf_counter() - started)
        assert scanned == {f"server.{ext}"}, "the file must be read, not skipped"
    small, large = timings
    assert large < 30 * small + 1.0, (small, large)
    assert large < 10.0, large


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


# A child process scans each crafted file, so a pattern that backtracks for
# minutes fails the test on its timeout instead of hanging the suite.
_CHILD_SCAN = (
    "import sys, time\n"
    "from pathlib import Path\n"
    "from agent_audit_kit.scanners.typescript_pattern_scan import scan\n"
    "started = time.perf_counter()\n"
    "_, scanned = scan(Path(sys.argv[1]))\n"
    "print(time.perf_counter() - started, len(scanned))\n"
)


def _scan_in_child(root: Path) -> float:
    package_root = Path(agent_audit_kit.__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(package_root)}
    done = subprocess.run(
        [sys.executable, "-c", _CHILD_SCAN, str(root)], capture_output=True, text=True, timeout=120, env=env
    )
    assert done.returncode == 0, done.stderr
    elapsed, scanned = done.stdout.split()
    assert scanned == "1", "the file must be read, not skipped"
    return float(elapsed)


# A dynamic import's `.then(` callback that never names a parameter. Its pattern
# had two `\s*` side by side wherever an optional token was absent, so a run of
# blanks was split every way before the match failed: 160,000 blanks took 224 s,
# and `.then(function` followed by 4,000 blanks, a 4 KB file, 177 s, three `\s*`
# side by side. Short lines after the head keep a JavaScript file from reading as
# a bundle.
_THEN = "import('child_process').then("
_THEN_SHAPES = {
    "blanks": (_THEN, " "),
    "newlines": (_THEN, "\n"),
    "function": (_THEN + "function", " "),
    "named function": (_THEN + "function load", " "),
    "async": (_THEN + "async", " "),
    "async function": (_THEN + "async function", " "),
}


@pytest.mark.parametrize(("shape", "ext"), [(shape, "ts") for shape in _THEN_SHAPES] + [("function", "js")])
def test_a_then_callback_without_a_parameter_reads_in_linear_time(tmp_path: Path, shape: str, ext: str) -> None:
    """At the 1 MB the scanner reads, and at a tenth of it."""
    prefix, filler = _THEN_SHAPES[shape]
    timings = []
    for k in (99_000, 990_000):
        root = tmp_path / str(k)
        root.mkdir()
        text = _HEAD + "const a = 1;\nconst b = 2;\nconst c = 3;\n" + prefix + filler * k + "!\n"
        (root / f"server.{ext}").write_text(text, encoding="utf-8")
        timings.append(_scan_in_child(root))
    small, large = timings
    assert large < 30 * small + 1.0, (small, large)
    assert large < 10.0, large


# The binding and call patterns added for the seven forms above, each on input
# that keeps a match failing to the end: a run of blanks after a name being
# assigned, a long run of assignments, and lines that each split a call at its
# dot. Each builder takes a size in characters.
_BINDING_SHAPES = {
    "a name, then blanks": lambda k: "cp" + " " * k + "!",
    "an assignment, then blanks": lambda k: "cp =" + " " * k + "!",
    "an open parenthesis, then blanks": lambda k: "cp = (" + " " * k + "!",
    "a this property, then blanks": lambda k: "this.cp =" + " " * k + "!",
    "a destructuring, then blanks": lambda k: "const { exec } =" + " " * k + "!",
    "a run of assignments": lambda k: "a=" * (k // 2) + "!",
    "split calls": lambda k: "cp\n  .exec(cmd);\nrun.\n  spawn(cmd);\n" * (k // 36),
}


@pytest.mark.parametrize("shape", sorted(_BINDING_SHAPES))
def test_the_binding_patterns_read_in_linear_time(tmp_path: Path, shape: str) -> None:
    """At the 1 MB the scanner reads, and at a tenth of it."""
    timings = []
    for k in (99_000, 990_000):
        root = tmp_path / str(k)
        root.mkdir()
        text = _HEAD + "const cp = require('child_process');\n" + _BINDING_SHAPES[shape](k) + "\n"
        (root / "server.ts").write_text(text, encoding="utf-8")
        timings.append(_scan_in_child(root))
    small, large = timings
    assert large < 30 * small + 1.0, (small, large)
    assert large < 10.0, large


# Verification of a323344c (2026-10-17, Low): one `rglob` per suffix walked the
# tree eight times, into `node_modules` too, filtering its files afterwards
# (2.55 s for 50,000 files; main, with two suffixes, 0.82 s). The tree is walked
# once now, and a skipped directory is not entered.
def test_the_tree_is_walked_once_and_a_skipped_directory_not_at_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for rel in ("src/server.ts", "src/lib/util.mjs", "src/lib/types.d.ts", "node_modules/pkg/index.js", "README.md"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("export {};\n", encoding="utf-8")
    listed: Counter[str] = Counter()
    real_scandir = os.scandir

    def counting_scandir(path: str = ".") -> object:
        listed[os.fspath(path)] += 1
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", counting_scandir)
    _, scanned = scan(tmp_path)
    assert scanned == {os.path.join("src", "server.ts"), os.path.join("src", "lib", "util.mjs"),
                       os.path.join("src", "lib", "types.d.ts")}
    assert listed and max(listed.values()) == 1, listed
    assert not any("node_modules" in path for path in listed), listed


def _ids(tmp_path: Path, decorator: str, body: str) -> set[str]:
    (tmp_path / "tools.ts").write_text(
        "import { exec } from 'node:child_process';\n\n"
        f"export class Tools {{\n  {decorator}\n  {body}\n}}\n",
        encoding="utf-8",
    )
    return {f.rule_id for f in scan(tmp_path)[0]}


@pytest.mark.parametrize(("decorator", "read"), [
    ("@tool()", True),
    ("@Tool({ name: 'calc' })", True),
    ("@toolbox()", False),
])
def test_a_tool_decorator_alone_marks_an_mcp_server_file(tmp_path: Path, decorator: str, read: bool) -> None:
    ids = _ids(tmp_path, decorator, "calc(expr: string) { return eval(expr); }")
    assert ("AAK-TAINT-002" in ids) is read


@pytest.mark.parametrize(("decorator", "read"), [
    ("@tool()", True),
    ("@toolbox()", False),
])
def test_a_tool_decorator_alone_marks_a_tool_handler_file(tmp_path: Path, decorator: str, read: bool) -> None:
    ids = _ids(tmp_path, decorator, "convert(format: string) { exec(`ffmpeg -f ${format} out`); }")
    assert ("AAK-MCP-TOOL-ARG-OSCMD-001" in ids) is read
