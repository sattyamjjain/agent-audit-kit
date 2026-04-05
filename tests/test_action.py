"""Tests for the core model layer: Severity comparison operators,
ScanResult threshold checks, and finding filtering.

These validate the Python-side logic that backs the ``--fail-on`` CLI
behaviour and the GitHub Action entrypoint argument parsing.
"""
from __future__ import annotations

from agent_audit_kit.models import Category, Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Severity comparison operators
# ---------------------------------------------------------------------------


def test_severity_comparison_operators() -> None:
    assert Severity.CRITICAL >= Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.LOW <= Severity.MEDIUM
    assert Severity.INFO < Severity.LOW
    assert not (Severity.LOW >= Severity.HIGH)


def test_severity_numeric() -> None:
    assert Severity.CRITICAL.numeric() == 5
    assert Severity.HIGH.numeric() == 4
    assert Severity.MEDIUM.numeric() == 3
    assert Severity.LOW.numeric() == 2
    assert Severity.INFO.numeric() == 1


# ---------------------------------------------------------------------------
# ScanResult helpers
# ---------------------------------------------------------------------------


def _make_finding(rule_id: str, severity: Severity, file_path: str = "x") -> Finding:
    """Convenience factory for minimal Finding instances."""
    return Finding(
        rule_id=rule_id,
        title="",
        description="",
        severity=severity,
        category=Category.MCP_CONFIG,
        file_path=file_path,
    )


def test_scan_result_max_severity() -> None:
    result = ScanResult()
    assert result.max_severity is None

    result.findings = [
        _make_finding("A", Severity.LOW, "x"),
        _make_finding("B", Severity.HIGH, "y"),
    ]
    assert result.max_severity == Severity.HIGH


def test_scan_result_exceeds_threshold() -> None:
    result = ScanResult()
    result.findings = [
        _make_finding("A", Severity.MEDIUM, "x"),
    ]
    assert result.exceeds_threshold(Severity.MEDIUM) is True
    assert result.exceeds_threshold(Severity.LOW) is True
    assert result.exceeds_threshold(Severity.HIGH) is False
    assert result.exceeds_threshold(Severity.CRITICAL) is False


def test_findings_at_or_above_uses_comparison() -> None:
    result = ScanResult()
    result.findings = [
        _make_finding("C", Severity.CRITICAL, "a"),
        _make_finding("H", Severity.HIGH, "b"),
        _make_finding("M", Severity.MEDIUM, "c"),
        _make_finding("L", Severity.LOW, "d"),
    ]
    high_plus = result.findings_at_or_above(Severity.HIGH)
    assert len(high_plus) == 2
    assert {f.rule_id for f in high_plus} == {"C", "H"}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_scan_result_exceeds_threshold_empty() -> None:
    """An empty ScanResult should never exceed any threshold."""
    result = ScanResult()
    assert result.exceeds_threshold(Severity.INFO) is False


def test_findings_at_or_above_returns_all_when_info() -> None:
    """Filtering at INFO level should return every finding."""
    result = ScanResult()
    result.findings = [
        _make_finding("C", Severity.CRITICAL, "a"),
        _make_finding("I", Severity.INFO, "b"),
    ]
    assert len(result.findings_at_or_above(Severity.INFO)) == 2


def test_severity_equality() -> None:
    """Same severity values should satisfy >= and <= but not > or <."""
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.HIGH <= Severity.HIGH
    assert not (Severity.HIGH > Severity.HIGH)
    assert not (Severity.HIGH < Severity.HIGH)


def test_scan_result_count_properties() -> None:
    """Verify per-severity count properties."""
    result = ScanResult()
    result.findings = [
        _make_finding("C1", Severity.CRITICAL, "a"),
        _make_finding("C2", Severity.CRITICAL, "b"),
        _make_finding("H1", Severity.HIGH, "c"),
        _make_finding("M1", Severity.MEDIUM, "d"),
        _make_finding("L1", Severity.LOW, "e"),
        _make_finding("I1", Severity.INFO, "f"),
    ]
    assert result.critical_count == 2
    assert result.high_count == 1
    assert result.medium_count == 1
    assert result.low_count == 1
    assert result.info_count == 1
