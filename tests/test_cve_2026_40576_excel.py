"""CVE-2026-40576 — excel-mcp-server <= 0.1.7 path traversal."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.supply_chain import scan


def test_vulnerable_excel_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "excel-mcp-server==0.1.7\n", encoding="utf-8"
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-EXCEL-MCP-001" for f in findings)


def test_patched_excel_pin_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "excel-mcp-server==0.1.8\n", encoding="utf-8"
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-EXCEL-MCP-001" for f in findings)


def test_excel_pin_in_pyproject_fires(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["excel-mcp-server==0.1.6"]\n',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-EXCEL-MCP-001" for f in findings)


def test_unrelated_package_passes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "numpy==1.26.0\n", encoding="utf-8"
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-EXCEL-MCP-001" for f in findings)
