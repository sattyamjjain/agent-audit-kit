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

EXTENSIONS = ("ts", "tsx", "js", "jsx", "mjs", "cjs")


@pytest.mark.parametrize("ext", EXTENSIONS)
def test_an_eval_server_is_read_in_every_extension(tmp_path: Path, ext: str) -> None:
    (tmp_path / f"server.{ext}").write_text(_EVAL_SERVER, encoding="utf-8")
    findings, scanned = scan(tmp_path)
    assert [(f.rule_id, f.file_path, f.line_number) for f in findings] == [
        ("AAK-TAINT-002", f"server.{ext}", 6)
    ]
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
    (tmp_path / "build.js").write_text("const x = eval(process.argv[2]);\n", encoding="utf-8")
    assert scan(tmp_path) == ([], {"build.js"})
