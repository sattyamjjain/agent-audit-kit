"""Tests for agent_audit_kit.output.owasp_report module."""
from __future__ import annotations

from agent_audit_kit.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
)
from agent_audit_kit.output.owasp_report import format_results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_empty_result() -> ScanResult:
    """Return a ScanResult with no findings."""
    return ScanResult(
        findings=[],
        files_scanned=0,
        rules_evaluated=0,
        score=None,
        grade=None,
    )


def _make_result_with_findings() -> ScanResult:
    """Return a ScanResult with a representative finding."""
    finding = Finding(
        rule_id="AAK-MCP-001",
        title="Remote MCP no auth",
        description="Test",
        severity=Severity.CRITICAL,
        category=Category.MCP_CONFIG,
        file_path=".mcp.json",
    )
    return ScanResult(
        findings=[finding],
        files_scanned=5,
        rules_evaluated=50,
        score=80,
        grade="B",
    )


# ---------------------------------------------------------------------------
# OWASP Agentic section
# ---------------------------------------------------------------------------


class TestOwaspAgenticSection:
    def test_output_contains_owasp_agentic_heading(self) -> None:
        result = _make_result_with_findings()
        output = format_results(result)
        assert "OWASP" in output
        assert "Agentic" in output or "agentic" in output.lower()

    def test_contains_asi01_through_asi10(self) -> None:
        result = _make_result_with_findings()
        output = format_results(result)
        for i in range(1, 11):
            asi_code = f"ASI{i:02d}"
            assert asi_code in output, f"{asi_code} not found in report"


# ---------------------------------------------------------------------------
# OWASP MCP section
# ---------------------------------------------------------------------------


class TestOwaspMcpSection:
    def test_contains_mcp01_through_mcp10(self) -> None:
        result = _make_result_with_findings()
        output = format_results(result)
        for i in range(1, 11):
            mcp_code = f"MCP{i:02d}"
            assert mcp_code in output, f"{mcp_code} not found in report"


# ---------------------------------------------------------------------------
# Coverage percentages
# ---------------------------------------------------------------------------


class TestCoveragePercentages:
    def test_shows_agentic_coverage_percentage(self) -> None:
        result = _make_result_with_findings()
        output = format_results(result)
        # The output should contain a "Coverage: X/10 (NN%)" line
        assert "Coverage:" in output
        assert "%" in output

    def test_shows_mcp_coverage_percentage(self) -> None:
        result = _make_result_with_findings()
        output = format_results(result)
        # There should be at least two coverage lines (agentic + MCP)
        lines = [line for line in output.splitlines() if "Coverage:" in line]
        assert len(lines) >= 2


# ---------------------------------------------------------------------------
# Empty scan result
# ---------------------------------------------------------------------------


class TestEmptyScanResult:
    def test_produces_valid_report(self) -> None:
        result = _make_empty_result()
        output = format_results(result)
        assert isinstance(output, str)
        assert len(output) > 0
        # Should still have structure
        assert "OWASP" in output
        assert "Coverage:" in output

    def test_empty_result_shows_total_findings_zero(self) -> None:
        result = _make_empty_result()
        output = format_results(result)
        assert "Total findings: 0" in output


# ---------------------------------------------------------------------------
# Score display
# ---------------------------------------------------------------------------


class TestScoreDisplay:
    def test_score_and_grade_shown_when_present(self) -> None:
        result = _make_result_with_findings()
        output = format_results(result)
        assert "Security Score: 80/100" in output
        assert "Grade: B" in output

    def test_no_score_when_none(self) -> None:
        result = _make_empty_result()
        output = format_results(result)
        assert "Security Score:" not in output


# ---------------------------------------------------------------------------
# Adversa section
# ---------------------------------------------------------------------------


class TestAdversaSection:
    def test_adversa_section_present(self) -> None:
        result = _make_result_with_findings()
        output = format_results(result)
        assert "Adversa" in output

    def test_adversa_coverage_count(self) -> None:
        result = _make_result_with_findings()
        output = format_results(result)
        assert "categories mapped" in output
