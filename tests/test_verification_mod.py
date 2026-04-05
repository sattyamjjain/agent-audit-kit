"""Tests for agent_audit_kit.verification module -- extended coverage."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from agent_audit_kit.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
)
from agent_audit_kit.verification import (
    _extract_key,
    _mask_key,
    verify_findings,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_secret_finding(
    rule_id: str,
    evidence: str,
    severity: Severity = Severity.HIGH,
) -> Finding:
    """Create a minimal secret-exposure finding."""
    return Finding(
        rule_id=rule_id,
        title="Secret exposure",
        description="Found a secret",
        severity=severity,
        category=Category.SECRET_EXPOSURE,
        file_path=".env",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# _extract_key
# ---------------------------------------------------------------------------


class TestExtractKey:
    def test_extracts_anthropic_key_pattern(self) -> None:
        evidence = "Found Anthropic API key: sk-ant-api03-abc123def456"
        key = _extract_key("AAK-SECRET-001", evidence)
        assert key is not None
        assert key.startswith("sk-ant-api")

    def test_extracts_openai_key_from_evidence(self) -> None:
        evidence = "Found OpenAI key: sk-ABCDEFGHIJ1234567890extra"
        key = _extract_key("AAK-SECRET-002", evidence)
        assert key is not None
        assert key.startswith("sk-")

    def test_extracts_aws_key_from_evidence(self) -> None:
        evidence = "Found AWS access key: AKIAIOSFODNN7EXAMPLE in .env"
        key = _extract_key("AAK-SECRET-003", evidence)
        assert key is not None
        assert key.startswith("AKIA")
        assert len(key) == 20

    def test_returns_none_for_unknown_rule(self) -> None:
        key = _extract_key("AAK-SECRET-099", "some evidence with sk-ant-api03-xxx")
        assert key is None

    def test_returns_none_when_no_match(self) -> None:
        key = _extract_key("AAK-SECRET-001", "no recognizable key here")
        assert key is None


# ---------------------------------------------------------------------------
# _mask_key
# ---------------------------------------------------------------------------


class TestMaskKey:
    def test_returns_first_8_chars_plus_stars(self) -> None:
        masked = _mask_key("sk-ant-api03-abc123def456")
        assert masked == "sk-ant-a***"
        assert len(masked) == 11

    def test_short_key_still_works(self) -> None:
        masked = _mask_key("12345678")
        assert masked == "12345678***"

    def test_very_short_key(self) -> None:
        masked = _mask_key("abc")
        assert masked == "abc***"


# ---------------------------------------------------------------------------
# verify_findings
# ---------------------------------------------------------------------------


class TestVerifyFindings:
    def test_no_verifiable_findings_returns_unchanged(self) -> None:
        """Findings with non-secret rule IDs should be left untouched."""
        finding = Finding(
            rule_id="AAK-MCP-001",
            title="Non-secret finding",
            description="Not a secret",
            severity=Severity.HIGH,
            category=Category.MCP_CONFIG,
            file_path=".mcp.json",
            evidence="original evidence only",
        )
        result = ScanResult(findings=[finding])
        verified = verify_findings(result)
        assert verified.findings[0].evidence == "original evidence only"

    def test_aws_key_gets_sts_annotation(self) -> None:
        """AWS key (AAK-SECRET-003) gets annotation about STS."""
        finding = _make_secret_finding(
            "AAK-SECRET-003",
            "Found AWS key: AKIAIOSFODNN7EXAMPLE in config",
        )
        result = ScanResult(findings=[finding])
        verified = verify_findings(result)

        ev = verified.findings[0].evidence
        assert "verification:" in ev
        assert "AWS key" in ev
        assert "STS" in ev

    def test_severity_auto_upgrade_when_key_confirmed_active(self) -> None:
        """Severity auto-upgrades to CRITICAL when key is confirmed active."""
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
            severity=Severity.HIGH,
        )
        assert finding.severity == Severity.HIGH

        result = ScanResult(findings=[finding])

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("agent_audit_kit.verification.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = mock_resp
            verified = verify_findings(result)

        assert verified.findings[0].severity == Severity.CRITICAL
        assert "CONFIRMED ACTIVE" in verified.findings[0].evidence

    def test_severity_not_upgraded_when_inactive(self) -> None:
        """Severity stays at HIGH when key is inactive/rotated."""
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
            severity=Severity.HIGH,
        )
        result = ScanResult(findings=[finding])

        mock_verifier = lambda key: "INACTIVE/ROTATED"
        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-001": mock_verifier}):
            verified = verify_findings(result)

        assert verified.findings[0].severity == Severity.HIGH
        assert "INACTIVE/ROTATED" in verified.findings[0].evidence

    def test_openai_key_verification_with_mock(self) -> None:
        """OpenAI key verification calls the correct verifier."""
        finding = _make_secret_finding(
            "AAK-SECRET-002",
            "Found OpenAI key: sk-ABCDEFGHIJ1234567890extra",
            severity=Severity.HIGH,
        )
        result = ScanResult(findings=[finding])

        mock_verifier = lambda key: "CONFIRMED ACTIVE"
        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-002": mock_verifier}):
            verified = verify_findings(result)

        assert "CONFIRMED ACTIVE" in verified.findings[0].evidence
        assert verified.findings[0].severity == Severity.CRITICAL

    def test_masked_key_appears_in_evidence(self) -> None:
        """The masked key (first 8 chars + ***) should appear in evidence."""
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
        )
        result = ScanResult(findings=[finding])

        mock_verifier = lambda key: "CONFIRMED ACTIVE"
        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-001": mock_verifier}):
            verified = verify_findings(result)

        assert "sk-ant-a***" in verified.findings[0].evidence

    def test_verifier_exception_handled_gracefully(self) -> None:
        """When verifier raises, evidence shows VERIFICATION FAILED."""
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
        )
        result = ScanResult(findings=[finding])

        def _raise(key: str) -> str:
            raise ConnectionError("boom")

        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-001": _raise}):
            verified = verify_findings(result)

        assert "VERIFICATION FAILED" in verified.findings[0].evidence
