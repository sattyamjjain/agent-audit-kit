"""v0.3.18 — AAK-MCPCALC-CVE-2026-44717-PIN-001.

MCP Calculate Server <0.1.1 routes tool input through `eval()`
(SymPy-backed without local_dict pinning), reaching RCE. CVSS 9.8
CRITICAL, NVD 2026-05-15, patched in 0.1.1.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.supply_chain import scan as supply_chain_scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-44717-mcp-calculate-server"
RULE = "AAK-MCPCALC-CVE-2026-44717-PIN-001"


def test_mcp_calc_vulnerable_pin_fires(tmp_path: Path) -> None:
    """`mcp-calculate-server == 0.1.0` (pre-patch) must fire CRITICAL."""
    shutil.copy(FIXTURES / "pin-vulnerable" / "requirements.txt", tmp_path / "requirements.txt")
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == RULE]
    assert len(fires) == 1
    assert "0.1.0" in fires[0].evidence
    assert fires[0].severity.name == "CRITICAL"


def test_mcp_calc_patched_pin_passes(tmp_path: Path) -> None:
    """`mcp-calculate-server == 0.1.1` (exact patched) must not fire."""
    shutil.copy(FIXTURES / "pin-safe" / "requirements.txt", tmp_path / "requirements.txt")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


def test_mcp_calc_floor_pin_passes(tmp_path: Path) -> None:
    """`mcp-calculate-server >= 0.1.1` floor pin must not fire."""
    shutil.copy(FIXTURES / "pin-safe-floor" / "requirements.txt", tmp_path / "requirements.txt")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


def test_mcp_calc_no_dep_passes(tmp_path: Path) -> None:
    """requirements.txt without mcp-calculate-server must not fire."""
    (tmp_path / "requirements.txt").write_text("sympy>=1.12\nfastapi>=0.100.0\n")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)
