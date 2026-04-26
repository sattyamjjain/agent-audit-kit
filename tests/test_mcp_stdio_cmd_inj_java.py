"""AAK-MCP-STDIO-CMD-INJ-003 — Java regex pass."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.mcp_stdio_params import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "ox-mcp-stdio-class"


def test_vulnerable_java_fires(tmp_path: Path) -> None:
    (tmp_path / "vulnerable_java.java").write_text(
        (FIXTURES / "vulnerable_java.java").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-003" for f in findings)


def test_patched_java_passes(tmp_path: Path) -> None:
    (tmp_path / "patched_java.java").write_text(
        (FIXTURES / "patched_java.java").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-003" for f in findings)
