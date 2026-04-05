"""Tests for agent_audit_kit.scoring module."""
from __future__ import annotations

from agent_audit_kit.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
)
from agent_audit_kit.scoring import compute_score, generate_badge


def _make_finding(severity: Severity) -> Finding:
    """Helper to create a minimal Finding with the given severity."""
    return Finding(
        rule_id="AAK-TEST-001",
        title="Test finding",
        description="Test description",
        severity=severity,
        category=Category.MCP_CONFIG,
        file_path="test.json",
    )


# ---------------------------------------------------------------------------
# compute_score
# ---------------------------------------------------------------------------


class TestComputeScore:
    def test_empty_findings_returns_100_A(self) -> None:
        result = ScanResult()
        compute_score(result)
        assert result.score == 100
        assert result.grade == "A"

    def test_single_critical_deducts_20(self) -> None:
        result = ScanResult(findings=[_make_finding(Severity.CRITICAL)])
        compute_score(result)
        assert result.score == 80

    def test_single_high_deducts_10(self) -> None:
        result = ScanResult(findings=[_make_finding(Severity.HIGH)])
        compute_score(result)
        assert result.score == 90

    def test_single_medium_deducts_5(self) -> None:
        result = ScanResult(findings=[_make_finding(Severity.MEDIUM)])
        compute_score(result)
        assert result.score == 95

    def test_single_low_deducts_2(self) -> None:
        result = ScanResult(findings=[_make_finding(Severity.LOW)])
        compute_score(result)
        assert result.score == 98

    def test_info_does_not_deduct(self) -> None:
        result = ScanResult(findings=[_make_finding(Severity.INFO)])
        compute_score(result)
        assert result.score == 100

    def test_mixed_findings_correct_score(self) -> None:
        result = ScanResult(
            findings=[
                _make_finding(Severity.CRITICAL),
                _make_finding(Severity.HIGH),
                _make_finding(Severity.MEDIUM),
                _make_finding(Severity.LOW),
            ]
        )
        compute_score(result)
        # 100 - 20 - 10 - 5 - 2 = 63
        assert result.score == 63

    def test_score_clamped_to_zero(self) -> None:
        # 6 CRITICAL findings = 100 - 120 = -20, clamped to 0
        result = ScanResult(
            findings=[_make_finding(Severity.CRITICAL) for _ in range(6)]
        )
        compute_score(result)
        assert result.score == 0

    def test_score_never_above_100(self) -> None:
        result = ScanResult()
        compute_score(result)
        assert result.score <= 100

    # Grade boundary tests
    def test_grade_A_at_90(self) -> None:
        # 1 HIGH = 90
        result = ScanResult(findings=[_make_finding(Severity.HIGH)])
        compute_score(result)
        assert result.grade == "A"

    def test_grade_B_at_75(self) -> None:
        # 100 - 10 - 10 - 5 = 75
        result = ScanResult(
            findings=[
                _make_finding(Severity.HIGH),
                _make_finding(Severity.HIGH),
                _make_finding(Severity.MEDIUM),
            ]
        )
        compute_score(result)
        assert result.score == 75
        assert result.grade == "B"

    def test_grade_C_at_60(self) -> None:
        # 100 - 20 - 20 = 60
        result = ScanResult(
            findings=[
                _make_finding(Severity.CRITICAL),
                _make_finding(Severity.CRITICAL),
            ]
        )
        compute_score(result)
        assert result.score == 60
        assert result.grade == "C"

    def test_grade_D_at_40(self) -> None:
        # 100 - 20 - 20 - 20 = 40
        result = ScanResult(
            findings=[_make_finding(Severity.CRITICAL) for _ in range(3)]
        )
        compute_score(result)
        assert result.score == 40
        assert result.grade == "D"

    def test_grade_F_below_40(self) -> None:
        # 100 - 20*4 = 20
        result = ScanResult(
            findings=[_make_finding(Severity.CRITICAL) for _ in range(4)]
        )
        compute_score(result)
        assert result.score == 20
        assert result.grade == "F"

    def test_grade_F_at_zero(self) -> None:
        result = ScanResult(
            findings=[_make_finding(Severity.CRITICAL) for _ in range(6)]
        )
        compute_score(result)
        assert result.score == 0
        assert result.grade == "F"


# ---------------------------------------------------------------------------
# generate_badge
# ---------------------------------------------------------------------------


class TestGenerateBadge:
    def test_returns_svg_string(self) -> None:
        svg = generate_badge(95, "A")
        assert svg.startswith("<svg")
        assert svg.strip().endswith("</svg>")

    def test_contains_score_and_grade(self) -> None:
        svg = generate_badge(95, "A")
        assert "A 95/100" in svg

    def test_grade_A_uses_green(self) -> None:
        svg = generate_badge(95, "A")
        assert "#4c1" in svg

    def test_grade_B_uses_yellowgreen(self) -> None:
        svg = generate_badge(80, "B")
        assert "#97CA00" in svg

    def test_grade_C_uses_yellow(self) -> None:
        svg = generate_badge(65, "C")
        assert "#dfb317" in svg

    def test_grade_D_uses_orange(self) -> None:
        svg = generate_badge(45, "D")
        assert "#fe7d37" in svg

    def test_grade_F_uses_red(self) -> None:
        svg = generate_badge(10, "F")
        assert "#e05d44" in svg

    def test_unknown_grade_uses_grey(self) -> None:
        svg = generate_badge(50, "X")
        assert "#9f9f9f" in svg

    def test_contains_agent_audit_label(self) -> None:
        svg = generate_badge(100, "A")
        assert "agent-audit" in svg
