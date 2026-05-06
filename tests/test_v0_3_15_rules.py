"""v0.3.15 — GPT-Researcher MCP transport-flip + pin tests
(AAK-GPTRESEARCHER-MCP-STDIO-MITM-001) and MCP 2026 Roadmap
conformance value (--compliance mcp-2026-roadmap)."""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.output.compliance import FRAMEWORKS, format_results
from agent_audit_kit.scanners.gpt_researcher_transport_flip import scan as gptr_transport_scan
from agent_audit_kit.scanners.supply_chain import scan as supply_chain_scan
from agent_audit_kit.models import ScanResult

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2025-65720-gpt-researcher"
RULE = "AAK-GPTRESEARCHER-MCP-STDIO-MITM-001"


# -------------------- Pin-arm (supply_chain.py) --------------------


def test_gptr_pypi_vulnerable_pin_fires(tmp_path: Path) -> None:
    """gpt-researcher pinned in requirements.txt fires (no upstream patch)."""
    shutil.copy(
        FIXTURES / "pin-vulnerable-pypi" / "requirements.txt",
        tmp_path / "requirements.txt",
    )
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == RULE]
    assert len(fires) == 1
    assert "0.14.8" in fires[0].evidence


def test_gptr_git_url_pin_fires(tmp_path: Path) -> None:
    """package.json with `git+https://github.com/assafelovic/gpt-researcher.git` fires."""
    shutil.copy(
        FIXTURES / "pin-vulnerable-git" / "package.json",
        tmp_path / "package.json",
    )
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == RULE]
    assert len(fires) == 1
    assert "assafelovic/gpt-researcher" in fires[0].evidence


def test_gptr_no_manifest_passes(tmp_path: Path) -> None:
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


# -------------------- Config-arm (gpt_researcher_transport_flip.py) --------


def test_gptr_unsafe_config_fires(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "config-unsafe" / ".mcp.json", tmp_path / ".mcp.json")
    findings, scanned = gptr_transport_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == RULE]
    assert len(fires) == 1
    assert ".mcp.json" in scanned
    assert fires[0].line_number is not None


def test_gptr_config_with_explicit_reject_passes(tmp_path: Path) -> None:
    """Setting `deny_stdio_transport: true` must short-circuit the rule."""
    shutil.copy(
        FIXTURES / "config-safe-rejected" / ".mcp.json",
        tmp_path / ".mcp.json",
    )
    findings, _ = gptr_transport_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


def test_gptr_config_without_gptr_hint_passes(tmp_path: Path) -> None:
    """Scope gate: a config with the override-permit pattern but no
    GPT-Researcher hint must not fire."""
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"unrelated": {"transport": "sse", "stdio_fallback": true}}}',
        encoding="utf-8",
    )
    findings, _ = gptr_transport_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


# -------------------- A2-lite: --compliance mcp-2026-roadmap --------


def test_mcp_2026_roadmap_framework_registered() -> None:
    """The new framework must be reachable via the FRAMEWORKS dict."""
    assert "mcp-2026-roadmap" in FRAMEWORKS
    fw = FRAMEWORKS["mcp-2026-roadmap"]
    assert fw["name"] == "MCP 2026 Roadmap"
    controls = fw["controls"]
    assert isinstance(controls, dict)
    assert len(controls) == 5
    # Transport hardening must be the leading control
    assert any("Transport Hardening" in c for c in controls)


def test_mcp_2026_roadmap_compliance_report_renders() -> None:
    """`--compliance mcp-2026-roadmap` should produce a controls-met report."""
    result = ScanResult(findings=[], scan_duration_ms=1.0, files_scanned=0, rules_evaluated=0)
    out = format_results(result, "mcp-2026-roadmap")
    assert "MCP 2026 Roadmap" in out
    assert "Transport Hardening" in out
    assert "Controls met:" in out
    # Empty findings → all controls pass
    assert "5/5" in out or "100%" in out
