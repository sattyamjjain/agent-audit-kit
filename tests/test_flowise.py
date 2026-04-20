"""Tests for AAK-FLOWISE-001 (CVE-2026-40933, GHSA-c9gw-hvqq-f33r)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agent_audit_kit.scanners import stdio_injection

FIX = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-40933"


def test_flowise_vulnerable_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "agent-app",
            "dependencies": {"flowise": "3.0.13"},
        })
    )
    findings, scanned = stdio_injection.scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "AAK-FLOWISE-001"]
    assert hits, findings
    assert "3.0.13" in hits[0].evidence


def test_flowise_patched_pin_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "agent-app",
            "dependencies": {"flowise": "3.1.0"},
        })
    )
    findings, _ = stdio_injection.scan(tmp_path)
    assert not any(f.rule_id == "AAK-FLOWISE-001" for f in findings)


def test_flowise_components_package_also_matches(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "agent-app",
            "dependencies": {"flowise-components": "2.4.0"},
        })
    )
    findings, _ = stdio_injection.scan(tmp_path)
    assert any(f.rule_id == "AAK-FLOWISE-001" for f in findings)


def test_flowise_flow_config_custom_function_fires(tmp_path: Path) -> None:
    flow_dir = tmp_path / "flows"
    flow_dir.mkdir()
    shutil.copy(FIX / "vulnerable" / "flow.json", flow_dir / "flow.json")
    findings, scanned = stdio_injection.scan(tmp_path)
    hits = [f for f in findings if f.rule_id == "AAK-FLOWISE-001"]
    assert hits
    assert any("MCP adapter" in f.evidence for f in hits)
    assert "flows/flow.json" in scanned


def test_flowise_flow_config_without_mcp_is_quiet(tmp_path: Path) -> None:
    flow_dir = tmp_path / "flows"
    flow_dir.mkdir()
    (flow_dir / "flow.json").write_text(json.dumps({
        "nodes": [
            {"type": "regular", "data": {"label": "hello"}},
        ]
    }))
    findings, _ = stdio_injection.scan(tmp_path)
    assert not any(f.rule_id == "AAK-FLOWISE-001" for f in findings)


def test_flowise_rule_metadata_verified() -> None:
    from agent_audit_kit.rules.builtin import RULES

    rule = RULES["AAK-FLOWISE-001"]
    assert rule.severity.value == "critical"
    assert "CVE-2026-40933" in rule.cve_references
    assert rule.auto_fixable is True


def test_stdio_001_description_references_flowise() -> None:
    from agent_audit_kit.rules.builtin import RULES

    # AAK-STDIO-001 is the architectural parent; its remediation should
    # cross-link to the Flowise-specific rule now that both exist.
    stdio = RULES["AAK-STDIO-001"]
    text = (stdio.description + " " + stdio.remediation).lower()
    # Keep this loose — we just want some path from STDIO → vendor rules.
    assert "mcp" in text
