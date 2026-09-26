"""CVE-2026-94044: path traversal in a TypeScript MCP tool handler.

NVD: "This issue affects the function create_file of the file
app/api/mcp/route.ts. Such manipulation of the argument filePath/content leads to
path traversal." Deferred on 2026-09-26 (#787) because a full scan of the upstream
file reported nothing: the scanner's MCP-server gate did not know Vercel's
`createMcpHandler`, `AAK-MCP-015` wanted the request value as the direct first
argument of `open` / `fs.readFile`, and `fs.writeFile` was not a sink it knew.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.mcp_auth_patterns import scan

FIX = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-94044-mcp-route"
RULE = "AAK-MCP-015"
ROUTE = "app/api/mcp/route.ts"


def _findings(root: Path):
    findings, _ = scan(root)
    return [f for f in findings if f.rule_id == RULE]


def test_each_file_tool_is_reported_at_its_join() -> None:
    """Both tools join `filePath` onto the upload directory unchecked.

    Reported at the `path.join`, where the fix belongs, one finding per tool.
    """
    text = (FIX / "vulnerable" / ROUTE).read_text(encoding="utf-8")
    joins = [
        n for n, line in enumerate(text.splitlines(), 1)
        if "path.join(UPLOAD_DIR, filePath)" in line
    ]
    found = _findings(FIX / "vulnerable")
    assert len(joins) == 2
    assert sorted((f.file_path, f.line_number) for f in found) == [(ROUTE, n) for n in joins]


def test_the_write_sink_is_named() -> None:
    evidence = " ".join(f.evidence for f in _findings(FIX / "vulnerable"))
    assert "fs.readFile" in evidence and "fs.writeFile" in evidence


def test_a_containment_check_silences_it() -> None:
    """`startsWith` against the resolved base, directly or through a helper."""
    assert _findings(FIX / "negative") == []


def test_node_code_that_is_not_an_mcp_server_is_silent() -> None:
    """The same calls in a build script: no tool handler, so no tool argument."""
    assert _findings(FIX / "not-mcp") == []


def test_the_join_inline_in_the_sink_is_reported(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"\n'
        'import { promises as fs } from "fs"\n'
        'import path from "path"\n'
        'const server = new McpServer({ name: "files", version: "1.0.0" })\n'
        'server.tool("read", { name: z.string() }, async ({ name }) => {\n'
        '  const text = await fs.readFile(path.join(ROOT, name), "utf-8")\n'
        '  return { content: [{ type: "text", text }] }\n'
        "})\n",
        encoding="utf-8",
    )
    found = _findings(tmp_path)
    assert [f.line_number for f in found] == [6]


def test_a_path_relative_check_silences_it(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"\n'
        'import { promises as fs } from "fs"\n'
        'import path from "path"\n'
        'const server = new McpServer({ name: "files", version: "1.0.0" })\n'
        'server.tool("read", { name: z.string() }, async ({ name }) => {\n'
        "  const target = path.join(ROOT, name)\n"
        '  if (path.relative(ROOT, target).startsWith("..")) throw new Error("outside")\n'
        '  const text = await fs.readFile(target, "utf-8")\n'
        '  return { content: [{ type: "text", text }] }\n'
        "})\n",
        encoding="utf-8",
    )
    assert _findings(tmp_path) == []
