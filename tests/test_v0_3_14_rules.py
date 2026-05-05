"""v0.3.14 — DocsGPT MCP transport-flip + pin tests
(AAK-DOCSGPT-MCP-STDIO-MITM-001, OX 2026-05-01 disclosure batch)."""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.docsgpt_transport_flip import scan as docsgpt_transport_scan
from agent_audit_kit.scanners.supply_chain import scan as supply_chain_scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-26015-docsgpt"
RULE = "AAK-DOCSGPT-MCP-STDIO-MITM-001"


# -------------------- Pin-arm (supply_chain.py) --------------------


def test_docsgpt_npm_vulnerable_pin_fires(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "pin-vulnerable" / "package.json", tmp_path / "package.json")
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == RULE]
    assert len(fires) == 1
    assert "0.6.3" in fires[0].evidence


def test_docsgpt_git_url_pin_fires(tmp_path: Path) -> None:
    shutil.copy(
        FIXTURES / "pin-vulnerable-git" / "package.json",
        tmp_path / "package.json",
    )
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == RULE]
    assert len(fires) == 1
    assert "arc53/DocsGPT" in fires[0].evidence


def test_docsgpt_safe_pin_passes(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "pin-safe" / "package.json", tmp_path / "package.json")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


# -------------------- Config-arm (docsgpt_transport_flip.py) --------------------


def test_docsgpt_unsafe_config_fires(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "config-unsafe" / ".mcp.json", tmp_path / ".mcp.json")
    findings, scanned = docsgpt_transport_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == RULE]
    assert len(fires) == 1
    assert ".mcp.json" in scanned
    assert fires[0].line_number is not None


def test_docsgpt_config_with_explicit_reject_passes(tmp_path: Path) -> None:
    """Setting `deny_stdio_transport: true` must short-circuit the rule."""
    shutil.copy(
        FIXTURES / "config-safe-rejected" / ".mcp.json",
        tmp_path / ".mcp.json",
    )
    findings, _ = docsgpt_transport_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


def test_docsgpt_config_with_no_override_field_passes(tmp_path: Path) -> None:
    """A clean SSE-only config without an override field must not fire."""
    shutil.copy(
        FIXTURES / "config-safe-no-override" / ".mcp.json",
        tmp_path / ".mcp.json",
    )
    findings, _ = docsgpt_transport_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


def test_docsgpt_config_without_docsgpt_hint_passes(tmp_path: Path) -> None:
    """Scope gate: a config with the override-permit pattern but no
    DocsGPT hint must not fire (those are the responsibility of the
    other 3 OX MCP 2026-05-01 batch rules queued for v0.3.15)."""
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"unrelated": {"transport": "sse", "stdio_fallback": true}}}',
        encoding="utf-8",
    )
    findings, _ = docsgpt_transport_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)
