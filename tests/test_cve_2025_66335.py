"""AAK-DORIS-001 / CVE-2025-66335 tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners import supply_chain

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2025-66335"


def _copy(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        if entry.is_file():
            shutil.copy2(entry, dst / entry.name)


def test_vulnerable_pin_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "vulnerable", tmp_path)
    findings, _ = supply_chain.scan(tmp_path)
    assert any(f.rule_id == "AAK-DORIS-001" for f in findings)


def test_patched_pin_is_quiet(tmp_path: Path) -> None:
    _copy(FIXTURES / "patched", tmp_path)
    findings, _ = supply_chain.scan(tmp_path)
    assert not any(f.rule_id == "AAK-DORIS-001" for f in findings)


def test_pyproject_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["apache-doris-mcp-server==0.6.0"]\n',
        encoding="utf-8",
    )
    findings, _ = supply_chain.scan(tmp_path)
    assert any(f.rule_id == "AAK-DORIS-001" for f in findings)


def test_unrelated_dep_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("click==8.1\n", encoding="utf-8")
    findings, _ = supply_chain.scan(tmp_path)
    assert not any(f.rule_id == "AAK-DORIS-001" for f in findings)
