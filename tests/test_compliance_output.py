"""Tests for agent_audit_kit.output.compliance module."""
from __future__ import annotations

import pytest

from agent_audit_kit.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
)
from agent_audit_kit.output.compliance import FRAMEWORKS, format_results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(rule_id: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test finding",
        description="Test",
        severity=severity,
        category=Category.MCP_CONFIG,
        file_path="test.json",
    )


def _make_empty_result() -> ScanResult:
    return ScanResult(findings=[], rules_evaluated=50)


# ---------------------------------------------------------------------------
# format_results -- parametrized per framework
# ---------------------------------------------------------------------------


class TestFormatResults:
    @pytest.mark.parametrize("framework_key", list(FRAMEWORKS.keys()))
    def test_each_framework_generates_output(self, framework_key: str) -> None:
        result = _make_empty_result()
        output = format_results(result, framework_key)
        assert isinstance(output, str)
        assert len(output) > 0

    @pytest.mark.parametrize("framework_key", list(FRAMEWORKS.keys()))
    def test_contains_framework_name(self, framework_key: str) -> None:
        result = _make_empty_result()
        output = format_results(result, framework_key)
        framework_name = FRAMEWORKS[framework_key]["name"]
        assert framework_name in output


# ---------------------------------------------------------------------------
# EU AI Act
# ---------------------------------------------------------------------------


class TestEuAiAct:
    def test_produces_output_with_control_ids(self) -> None:
        output = format_results(_make_empty_result(), "eu-ai-act")
        assert "EU AI Act" in output
        assert "Art. 9" in output
        assert "Art. 10" in output
        assert "Art. 13" in output
        assert "Art. 14" in output
        assert "Art. 15" in output


# ---------------------------------------------------------------------------
# SOC 2
# ---------------------------------------------------------------------------


class TestSoc2:
    def test_produces_output_with_control_ids(self) -> None:
        output = format_results(_make_empty_result(), "soc2")
        assert "SOC 2" in output
        assert "CC6.1" in output
        assert "CC7.2" in output


# ---------------------------------------------------------------------------
# ISO 27001
# ---------------------------------------------------------------------------


class TestIso27001:
    def test_produces_output_with_control_ids(self) -> None:
        output = format_results(_make_empty_result(), "iso27001")
        assert "ISO 27001" in output
        assert "A.8.9" in output
        assert "A.8.24" in output


# ---------------------------------------------------------------------------
# HIPAA
# ---------------------------------------------------------------------------


class TestHipaa:
    def test_produces_output_with_control_ids(self) -> None:
        output = format_results(_make_empty_result(), "hipaa")
        assert "HIPAA" in output
        assert "164.312(a)" in output
        assert "164.312(e)" in output


# ---------------------------------------------------------------------------
# NIST AI RMF
# ---------------------------------------------------------------------------


class TestNistAiRmf:
    def test_produces_output_with_control_ids(self) -> None:
        output = format_results(_make_empty_result(), "nist-ai-rmf")
        assert "NIST AI RMF" in output
        assert "GOVERN 1.1" in output
        assert "MANAGE 4.1" in output


# ---------------------------------------------------------------------------
# PASS / FAIL indicators
# ---------------------------------------------------------------------------


class TestPassFailIndicators:
    def test_pass_status_for_clean_result(self) -> None:
        output = format_results(_make_empty_result(), "eu-ai-act")
        assert "PASS" in output

    def test_fail_status_when_findings_present(self) -> None:
        # AAK-MCP-001 maps to ASI03 via owasp_agentic_references
        # ASI03 is mapped in eu-ai-act Art. 15
        finding = _make_finding("AAK-MCP-001", Severity.CRITICAL)
        result = ScanResult(findings=[finding], rules_evaluated=50)
        output = format_results(result, "eu-ai-act")
        assert "FAIL" in output

    def test_output_contains_pass_or_fail_for_every_framework(self) -> None:
        for key in FRAMEWORKS:
            result = _make_empty_result()
            output = format_results(result, key)
            has_indicator = "PASS" in output or "FAIL" in output
            assert has_indicator, f"Framework {key!r} output lacks PASS/FAIL indicator"


# ---------------------------------------------------------------------------
# Metadata display
# ---------------------------------------------------------------------------


class TestMetadataDisplay:
    def test_controls_met_count(self) -> None:
        output = format_results(_make_empty_result(), "eu-ai-act")
        assert "Controls met:" in output

    def test_score_displayed_when_set(self) -> None:
        result = ScanResult(findings=[], rules_evaluated=50, score=95, grade="A")
        output = format_results(result, "eu-ai-act")
        assert "95/100" in output
        assert "Grade: A" in output

    def test_mapped_rules_shown(self) -> None:
        output = format_results(_make_empty_result(), "soc2")
        assert "Mapped rules:" in output


# ---------------------------------------------------------------------------
# Unknown framework
# ---------------------------------------------------------------------------


class TestUnknownFramework:
    def test_returns_error_message(self) -> None:
        result = _make_empty_result()
        output = format_results(result, "nonexistent-framework")
        assert "Unknown compliance framework" in output
        assert "Available:" in output
