"""Tests for the India PII scanner (AAK-INDIA-PII-001..006)."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.scanners import india_pii

FIX = Path(__file__).parent / "fixtures" / "cves" / "india_pii"


def test_verhoeff_validates_known_valid() -> None:
    # 234567897432 — constructed to pass Verhoeff
    assert india_pii._verhoeff_check("234567897432")


def test_verhoeff_rejects_invalid() -> None:
    assert not india_pii._verhoeff_check("234567897437")
    assert not india_pii._verhoeff_check("234567897431")  # off-by-one on last digit


def test_vulnerable_fires_all_six_rules(tmp_path: Path) -> None:
    shutil.copy(FIX / "vulnerable.txt", tmp_path / "data.txt")
    findings, _ = india_pii.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    expected = {f"AAK-INDIA-PII-00{i}" for i in range(1, 7)}
    missing = expected - ids
    assert not missing, f"missing: {missing}, got {ids}"


def test_safe_fires_nothing(tmp_path: Path) -> None:
    shutil.copy(FIX / "safe.txt", tmp_path / "data.txt")
    findings, _ = india_pii.scan(tmp_path)
    assert findings == []


def test_aadhaar_masked_in_evidence(tmp_path: Path) -> None:
    (tmp_path / "d.txt").write_text("aadhaar: 234567897432")
    findings, _ = india_pii.scan(tmp_path)
    aadhaar = next(f for f in findings if f.rule_id == "AAK-INDIA-PII-001")
    assert "****" in aadhaar.evidence
    assert "234567897432" not in aadhaar.evidence


def test_pan_masked_in_evidence(tmp_path: Path) -> None:
    (tmp_path / "d.txt").write_text("pan: ABCDE1234F")
    findings, _ = india_pii.scan(tmp_path)
    pan = next(f for f in findings if f.rule_id == "AAK-INDIA-PII-002")
    assert "ABCDE1234F" not in pan.evidence
    assert "ABC****F" in pan.evidence


def test_verhoeff_false_aadhaar_not_flagged(tmp_path: Path) -> None:
    # 12 digits starting 2-9 but NOT passing Verhoeff — should not fire 001
    (tmp_path / "d.txt").write_text("aadhaar: 234567897437")
    findings, _ = india_pii.scan(tmp_path)
    assert not any(f.rule_id == "AAK-INDIA-PII-001" for f in findings)


def test_bare_12_digit_id_without_context_not_flagged(tmp_path: Path) -> None:
    """FP guard: a bare 12-digit numeric id that coincidentally passes the
    Verhoeff checksum, with no Aadhaar/UID cue nearby, must not fire 001."""
    n = next(c for c in range(200000000000, 200000000300) if india_pii._verhoeff_check(str(c)))
    (tmp_path / "config.py").write_text(f"REQUEST_ID = {n}\nMAX_ROWS = {n}\n", encoding="utf-8")
    findings, _ = india_pii.scan(tmp_path)
    assert not any(f.rule_id == "AAK-INDIA-PII-001" for f in findings), (
        f"bare verhoeff-valid id {n} without aadhaar context must not fire"
    )


def test_bare_12_digit_with_aadhaar_context_fires(tmp_path: Path) -> None:
    """The same bare number labeled `aadhaar` must fire."""
    n = next(c for c in range(200000000000, 200000000300) if india_pii._verhoeff_check(str(c)))
    (tmp_path / "d.py").write_text(f"aadhaar_number = {n}\n", encoding="utf-8")
    findings, _ = india_pii.scan(tmp_path)
    assert any(f.rule_id == "AAK-INDIA-PII-001" for f in findings)
