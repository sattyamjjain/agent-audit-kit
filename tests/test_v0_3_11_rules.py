"""v0.3.11 SAST tests — astro-mcp-server CVE-2026-7591 (pin + source) and
LiteLLM CVE-2026-30623 pin floor."""
from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.fix import run_cve_fixes
from agent_audit_kit.scanners.supply_chain import scan as supply_chain_scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves"

ASTRO_RULE = "AAK-ASTROMCP-SQLI-CVE-2026-7591-001"
LITELLM_RULE = "AAK-LITELLM-CVE-2026-30623-PIN-001"


# -------------------- AAK-ASTROMCP-SQLI-CVE-2026-7591-001 --------------------


def test_astro_mcp_vulnerable_pin_fires(tmp_path: Path) -> None:
    src = FIXTURES / "cve-2026-7591-astro-mcp" / "vulnerable" / "package.json"
    shutil.copy(src, tmp_path / "package.json")
    findings, _ = supply_chain_scan(tmp_path)
    pin_fires = [f for f in findings if f.rule_id == ASTRO_RULE]
    assert pin_fires, "expected astro-mcp pin-check to fire"
    assert all("HIGH" in f.severity.name for f in pin_fires)


def test_astro_mcp_concat_source_fires(tmp_path: Path) -> None:
    src = FIXTURES / "cve-2026-7591-astro-mcp" / "source-unsafe" / "index.ts"
    shutil.copy(src, tmp_path / "index.ts")
    findings, _ = supply_chain_scan(tmp_path)
    src_fires = [f for f in findings if f.rule_id == ASTRO_RULE]
    # The fixture has two unsafe shapes (concat + untagged-template).
    assert len(src_fires) >= 1
    assert all("CVE-2026-7591" in f.evidence for f in src_fires)


def test_astro_mcp_parametrized_source_passes(tmp_path: Path) -> None:
    src = FIXTURES / "cve-2026-7591-astro-mcp" / "source-safe" / "parametrized.ts"
    shutil.copy(src, tmp_path / "parametrized.ts")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == ASTRO_RULE for f in findings)


def test_astro_mcp_tagged_template_passes(tmp_path: Path) -> None:
    src = FIXTURES / "cve-2026-7591-astro-mcp" / "source-safe" / "tagged_template.ts"
    shutil.copy(src, tmp_path / "tagged_template.ts")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == ASTRO_RULE for f in findings)


def test_astro_mcp_no_import_passes(tmp_path: Path) -> None:
    """Scope gate: file does not import astro-mcp-server, so the source
    detector must not fire even when the SQL shape is unsafe."""
    src = FIXTURES / "cve-2026-7591-astro-mcp" / "source-safe" / "no_import.ts"
    shutil.copy(src, tmp_path / "no_import.ts")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == ASTRO_RULE for f in findings)


def test_astro_mcp_pin_plus_source_both_fire(tmp_path: Path) -> None:
    """Pin-check + source detector should fire side-by-side. The rule
    fires regardless of pin floor when the source pattern matches,
    because consumers can hand-write the unsafe shape under any version."""
    pin = FIXTURES / "cve-2026-7591-astro-mcp" / "vulnerable" / "package.json"
    src = FIXTURES / "cve-2026-7591-astro-mcp" / "source-unsafe" / "index.ts"
    shutil.copy(pin, tmp_path / "package.json")
    shutil.copy(src, tmp_path / "index.ts")
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == ASTRO_RULE]
    by_file = {f.file_path for f in fires}
    assert "package.json" in by_file
    assert "index.ts" in by_file


# -------------------- AAK-LITELLM-CVE-2026-30623-PIN-001 --------------------


def test_litellm_vulnerable_pin_fires(tmp_path: Path) -> None:
    src = FIXTURES / "cve-2026-30623-litellm" / "vulnerable" / "requirements.txt"
    shutil.copy(src, tmp_path / "requirements.txt")
    findings, _ = supply_chain_scan(tmp_path)
    fires = [f for f in findings if f.rule_id == LITELLM_RULE]
    assert len(fires) == 1
    assert "1.83.6" in fires[0].evidence


def test_litellm_safe_pin_passes(tmp_path: Path) -> None:
    src = FIXTURES / "cve-2026-30623-litellm" / "patched" / "requirements.txt"
    shutil.copy(src, tmp_path / "requirements.txt")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == LITELLM_RULE for f in findings)


def test_litellm_floor_pin_passes(tmp_path: Path) -> None:
    src = FIXTURES / "cve-2026-30623-litellm" / "patched" / "requirements-floor.txt"
    shutil.copy(src, tmp_path / "requirements.txt")
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == LITELLM_RULE for f in findings)


def test_litellm_cve_autofix_bumps_pin(tmp_path: Path) -> None:
    src = FIXTURES / "cve-2026-30623-litellm" / "vulnerable" / "requirements.txt"
    shutil.copy(src, tmp_path / "requirements.txt")
    fixes = run_cve_fixes(tmp_path, dry_run=False)
    litellm_fixes = [f for f in fixes if f.rule_id == LITELLM_RULE]
    assert litellm_fixes, "expected litellm CVE auto-fix to run"
    assert all(f.applied for f in litellm_fixes)
    new_text = (tmp_path / "requirements.txt").read_text(encoding="utf-8")
    assert "litellm>=1.83.7" in new_text
    # Re-scan: pin-check should now be silent.
    findings, _ = supply_chain_scan(tmp_path)
    assert not any(f.rule_id == LITELLM_RULE for f in findings)
