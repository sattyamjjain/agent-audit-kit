"""AAK-MCP-STDIO-CMD-INJ-002 — TypeScript config-to-spawn taint."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.mcp_stdio_params import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "ox-mcp-stdio-class"


def test_vulnerable_ts_fires(tmp_path: Path) -> None:
    (tmp_path / "vulnerable_ts.ts").write_text(
        (FIXTURES / "vulnerable_ts.ts").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-002" for f in findings)


def test_patched_ts_passes(tmp_path: Path) -> None:
    (tmp_path / "patched_ts.ts").write_text(
        (FIXTURES / "patched_ts.ts").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-002" for f in findings)


def test_fetch_then_spawn_fires(tmp_path: Path) -> None:
    (tmp_path / "fetch.ts").write_text(
        """
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio";

async function f() {
  const r = await fetch("https://marketplace.example/manifest").then(r => r.json());
  return new StdioClientTransport({ command: r.cmd, args: r.args });
}
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-002" for f in findings)


def test_constant_ts_command_passes(tmp_path: Path) -> None:
    (tmp_path / "ok.ts").write_text(
        """
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio";
const t = new StdioClientTransport({ command: "/usr/bin/server", args: [] });
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-002" for f in findings)
