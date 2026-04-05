"""Tests for agent_audit_kit.output.owasp_report module."""
from __future__ import annotations

from agent_audit_kit.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
)
from agent_audit_kit.output.owasp_report import (
    OWASP_AGENTIC,
    OWASP_MCP,
    format_results,
)


def _make_finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test",
        description="Test",
        severity=Severity.HIGH,
        category=Category.MCP_CONFIG,
        file_path="test.json",
    )


class TestFormatResults:
    def test_generates_coverage_matrix(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        assert "OWASP Coverage Report" in output

    def test_contains_asi_sections(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        for code in OWASP_AGENTIC:
            assert code in output, f"Missing {code} in OWASP report"

    def test_contains_mcp_sections(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        for code in OWASP_MCP:
            assert code in output, f"Missing {code} in OWASP report"

    def test_shows_agentic_coverage_percentage(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        # Coverage line format: "Coverage: X/10 (YY%)"
        assert "Coverage:" in output
        assert "/10" in output or "/10 " in output

    def test_shows_mcp_coverage_percentage(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        assert "%" in output

    def test_shows_adversa_coverage(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        assert "Adversa" in output
        assert "categories mapped" in output

    def test_shows_total_findings_count(self) -> None:
        findings = [_make_finding("AAK-MCP-001"), _make_finding("AAK-MCP-002")]
        result = ScanResult(findings=findings, rules_evaluated=50)
        output = format_results(result)
        assert "Total findings: 2" in output

    def test_shows_rules_evaluated(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=42)
        output = format_results(result)
        assert "Total rules evaluated: 42" in output

    def test_score_displayed_when_set(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50, score=88, grade="B")
        output = format_results(result)
        assert "88/100" in output
        assert "Grade: B" in output

    def test_score_not_displayed_when_none(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        assert "Security Score" not in output

    def test_covered_rules_listed(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        # Covered items should show "rule(s)" text
        assert "rule(s)" in output

    def test_agentic_section_header(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        assert "OWASP Agentic Top 10 (ASI01-ASI10):" in output

    def test_mcp_section_header(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50)
        output = format_results(result)
        assert "OWASP MCP Top 10:" in output
