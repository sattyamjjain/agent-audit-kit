"""AAK-MCP-STDIO-CMD-INJ-004 — Rust regex pass (FP-prone on macros)."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.mcp_stdio_params import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "ox-mcp-stdio-class"


def test_vulnerable_rust_fires(tmp_path: Path) -> None:
    (tmp_path / "vulnerable_rust.rs").write_text(
        (FIXTURES / "vulnerable_rust.rs").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-004" for f in findings)


def test_patched_rust_passes(tmp_path: Path) -> None:
    (tmp_path / "patched_rust.rs").write_text(
        (FIXTURES / "patched_rust.rs").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-004" for f in findings)


def test_no_mcp_import_no_finding(tmp_path: Path) -> None:
    (tmp_path / "unrelated.rs").write_text(
        "use tokio::process::Command;\n"
        "pub async fn f(url: &str) {\n"
        "    let body = reqwest::get(url).await.unwrap().text().await.unwrap();\n"
        "    Command::new(body.trim());\n"
        "}\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-STDIO-CMD-INJ-004" for f in findings)
