"""Tests for AAK-TAINT-005 SQL-sink coverage in the TS/JS pattern scanner.

Context: the Python taint engine (cursor/connection/session.execute) and the
Rust scanner (sql!/query! with format!) both implement AAK-TAINT-005, but the
TypeScript/JavaScript pattern scanner historically omitted it — despite its
own module docstring claiming "SQL template" coverage. The OX Security MCP
disclosure class includes Node/TS MCP servers with SQL injection
(e.g. astro-mcp-server, CVE-2026-7591), so the TS scanner must flag the same
raw/interpolated-SQL shape.

These tests pin the parity: a deliberately vulnerable TS MCP server fixture
must be caught, and a parameterized (patched) fixture must pass clean.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.typescript_pattern_scan import scan


def _write(tmp_path: Path, name: str, src: str) -> None:
    (tmp_path / name).write_text(src, encoding="utf-8")


def _taint_005(findings: list) -> list:
    return [f for f in findings if f.rule_id == "AAK-TAINT-005"]


# ---------------------------------------------------------------------------
# Vulnerable fixtures — each must fire AAK-TAINT-005.
# ---------------------------------------------------------------------------


def test_interpolated_template_sql_is_caught(tmp_path: Path) -> None:
    """SQL built with a `${}` template literal reaching .query() — the classic
    injection shape from the OX MCP-server disclosure."""
    _write(tmp_path, "server.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "users", version: "1.0.0" });

server.tool("lookup_user", async ({ name }) => {
  // VULNERABLE: untrusted `name` interpolated straight into SQL
  const rows = await db.query(`SELECT * FROM users WHERE name = '${name}'`);
  return rows;
});
""")
    findings, scanned = scan(tmp_path)
    assert "server.ts" in scanned
    hits = _taint_005(findings)
    assert hits, f"interpolated SQL should fire AAK-TAINT-005; got {[f.rule_id for f in findings]}"


def test_string_concatenated_sql_is_caught(tmp_path: Path) -> None:
    _write(tmp_path, "tool.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer();
server.tool("by_id", async ({ id }) => {
  return connection.execute("SELECT * FROM accounts WHERE id = " + id);
});
""")
    findings, _ = scan(tmp_path)
    assert _taint_005(findings), "string-concatenated SQL should fire AAK-TAINT-005"


def test_prisma_query_raw_unsafe_is_caught(tmp_path: Path) -> None:
    _write(tmp_path, "prisma.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer();
server.tool("search", async ({ q }) => {
  // VULNERABLE: Prisma's explicitly-unsafe raw API
  return prisma.$queryRawUnsafe(`SELECT * FROM docs WHERE body LIKE '%${q}%'`);
});
""")
    findings, _ = scan(tmp_path)
    assert _taint_005(findings), "$queryRawUnsafe should fire AAK-TAINT-005"


def test_knex_raw_interpolation_is_caught(tmp_path: Path) -> None:
    _write(tmp_path, "knex.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer();
server.tool("dump", async ({ table }) => {
  return knex.raw(`SELECT * FROM ${table}`);
});
""")
    findings, _ = scan(tmp_path)
    assert _taint_005(findings), "knex.raw with interpolation should fire AAK-TAINT-005"


# ---------------------------------------------------------------------------
# Patched / benign fixtures — must NOT fire AAK-TAINT-005.
# ---------------------------------------------------------------------------


def test_parameterized_query_passes(tmp_path: Path) -> None:
    """Parameterized query with placeholder + separate args must NOT fire —
    this is the patched form the remediation recommends."""
    _write(tmp_path, "safe.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "users", version: "1.0.0" });

server.tool("lookup_user", async ({ name }) => {
  // PATCHED: placeholder + args array, no interpolation
  const rows = await db.query("SELECT * FROM users WHERE name = $1", [name]);
  return rows;
});
""")
    findings, scanned = scan(tmp_path)
    assert "safe.ts" in scanned
    assert not _taint_005(findings), (
        f"parameterized query must produce zero AAK-TAINT-005 findings; "
        f"got {[(f.rule_id, f.evidence) for f in findings]}"
    )


def test_non_mcp_file_is_not_scanned(tmp_path: Path) -> None:
    """A file with interpolated SQL but no MCP-server marker must be skipped —
    the scanner only audits files that look like MCP servers."""
    _write(tmp_path, "util.ts", """
export function lookup(name: string) {
  return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
""")
    findings, _ = scan(tmp_path)
    assert not _taint_005(findings), "non-MCP file must not be scanned for sinks"


def test_static_string_query_passes(tmp_path: Path) -> None:
    """A fully static SQL string (no interpolation, no concat, no raw-unsafe)
    must not fire — guards against over-broad matching of `.query(`."""
    _write(tmp_path, "static.ts", """
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer();
server.tool("count", async () => {
  return db.query("SELECT COUNT(*) FROM users");
});
""")
    findings, _ = scan(tmp_path)
    assert not _taint_005(findings), "static parameter-free SQL must not fire"
