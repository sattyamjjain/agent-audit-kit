"""v0.3.17 — AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001.

Microsoft Semantic Kernel Python SDK <1.39.4 RCE in InMemoryVectorStore
filter functionality (CVSS 9.9 CRITICAL). MSRC disclosure 2026-05-07,
patched in `python-1.39.4`. Companion .NET CVE-2026-25592 is out of
scope (AAK doesn't scan NuGet).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners.supply_chain import scan as supply_chain_scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-26030-semantic-kernel"
RULE = "AAK-SK-INMEMORY-VECTORSTORE-FILTER-CVE-2026-26030-PIN-001"


def test_semantic_kernel_vulnerable_pin_fires(tmp_path: Path) -> None:
    """`semantic-kernel == 1.39.3` (pre-patch) must fire."""
    shutil.copy(
        FIXTURES / "pin-vulnerable" / "requirements.txt",
        tmp_path / "requirements.txt",
    )
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == RULE]
    assert len(fires) == 1
    assert "1.39.3" in fires[0].evidence
    assert fires[0].severity.name == "CRITICAL"


def test_semantic_kernel_patched_pin_passes(tmp_path: Path) -> None:
    """`semantic-kernel == 1.39.4` (exact patched version) must not fire."""
    shutil.copy(
        FIXTURES / "pin-safe" / "requirements.txt",
        tmp_path / "requirements.txt",
    )
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


def test_semantic_kernel_floor_pin_passes(tmp_path: Path) -> None:
    """`semantic-kernel >= 1.39.4,<2.0` floor pin must not fire."""
    shutil.copy(
        FIXTURES / "pin-safe-floor" / "requirements.txt",
        tmp_path / "requirements.txt",
    )
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)


def test_semantic_kernel_no_dep_passes(tmp_path: Path) -> None:
    """requirements.txt without semantic-kernel must not fire."""
    (tmp_path / "requirements.txt").write_text("openai>=1.0.0\nfastapi>=0.100.0\n")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == RULE for f in findings)
