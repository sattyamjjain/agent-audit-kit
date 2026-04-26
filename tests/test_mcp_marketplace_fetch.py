"""AAK-MCP-MARKETPLACE-CONFIG-FETCH-001 — marketplace-fetch → spawn."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.mcp_marketplace_fetch import scan

FIXTURES = Path(__file__).parent / "fixtures" / "incidents" / "ox-mcp-marketplace-fetch"


def _copy(fixture: str, into: Path) -> None:
    src = FIXTURES / fixture
    (into / src.name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")


def test_vulnerable_python_fires(tmp_path: Path) -> None:
    _copy("vulnerable.py", tmp_path)
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001" for f in findings)


def test_patched_python_passes(tmp_path: Path) -> None:
    _copy("patched.py", tmp_path)
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001" for f in findings)


def test_vulnerable_ts_fires(tmp_path: Path) -> None:
    _copy("vulnerable.ts", tmp_path)
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001" for f in findings)


def test_trust_allowlist_suppresses(tmp_path: Path) -> None:
    _copy("vulnerable.py", tmp_path)
    (tmp_path / ".aak-mcp-marketplace-trust.yml").write_text(
        """
trust:
  - url: "https://marketplace.example/manifest"
    justification: "Internal artifact registry; signatures verified separately."
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001" for f in findings)


def test_trust_without_justification_does_not_suppress(tmp_path: Path) -> None:
    _copy("vulnerable.py", tmp_path)
    (tmp_path / ".aak-mcp-marketplace-trust.yml").write_text(
        """
trust:
  - url: "https://marketplace.example/manifest"
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-MCP-MARKETPLACE-CONFIG-FETCH-001" for f in findings)
