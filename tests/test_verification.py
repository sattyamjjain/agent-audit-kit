"""Tests for agent_audit_kit.verification module."""
from __future__ import annotations

import unittest.mock
from unittest.mock import patch

from agent_audit_kit.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
)
from agent_audit_kit.verification import (
    _extract_key,
    _mask_key,
    _verify_anthropic,
    _verify_gcp,
    _verify_openai,
    verify_findings,
)


def _make_secret_finding(
    rule_id: str,
    evidence: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Secret exposure",
        description="Found a secret",
        severity=Severity.CRITICAL,
        category=Category.SECRET_EXPOSURE,
        file_path=".env",
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# _extract_key
# ---------------------------------------------------------------------------


class TestExtractKey:
    def test_extracts_anthropic_key(self) -> None:
        evidence = "Found Anthropic API key: sk-ant-api03-abc123def456"
        key = _extract_key("AAK-SECRET-001", evidence)
        assert key == "sk-ant-api03-abc123def456"

    def test_extracts_openai_key(self) -> None:
        evidence = "Found OpenAI key: sk-ABCDEFGHIJ1234567890extra"
        key = _extract_key("AAK-SECRET-002", evidence)
        assert key == "sk-ABCDEFGHIJ1234567890extra"

    def test_extracts_aws_key(self) -> None:
        evidence = "Found AWS key: AKIAIOSFODNN7EXAMPLE"
        key = _extract_key("AAK-SECRET-003", evidence)
        assert key == "AKIAIOSFODNN7EXAMPLE"

    def test_returns_none_for_unknown_rule(self) -> None:
        key = _extract_key("AAK-UNKNOWN-999", "some evidence")
        assert key is None

    def test_returns_none_when_no_match(self) -> None:
        key = _extract_key("AAK-SECRET-001", "no key here")
        assert key is None


# ---------------------------------------------------------------------------
# _mask_key
# ---------------------------------------------------------------------------


class TestMaskKey:
    def test_returns_first_8_chars_plus_stars(self) -> None:
        masked = _mask_key("sk-ant-api03-abc123def456")
        assert masked == "sk-ant-a***"

    def test_short_key(self) -> None:
        masked = _mask_key("abcdefgh")
        assert masked == "abcdefgh***"

    def test_very_short_key(self) -> None:
        masked = _mask_key("ab")
        assert masked == "ab***"


# ---------------------------------------------------------------------------
# verify_findings
# ---------------------------------------------------------------------------


class TestVerifyFindings:
    def test_no_verifiable_findings_returns_unchanged(self) -> None:
        finding = Finding(
            rule_id="AAK-MCP-001",
            title="Non-secret finding",
            description="Not a secret",
            severity=Severity.HIGH,
            category=Category.MCP_CONFIG,
            file_path=".mcp.json",
            evidence="original evidence",
        )
        result = ScanResult(findings=[finding])
        verified = verify_findings(result)
        assert verified.findings[0].evidence == "original evidence"

    def test_aws_key_gets_skip_annotation(self) -> None:
        finding = _make_secret_finding(
            "AAK-SECRET-003",
            "Found AWS key: AKIAIOSFODNN7EXAMPLE in config",
        )
        result = ScanResult(findings=[finding])
        verified = verify_findings(result)
        assert "verification:" in verified.findings[0].evidence
        assert "AWS key" in verified.findings[0].evidence
        assert "skipped" in verified.findings[0].evidence.lower()

    def test_anthropic_key_verified_active(self) -> None:
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
        )
        result = ScanResult(findings=[finding])

        mock_verifier = lambda key: "CONFIRMED ACTIVE"
        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-001": mock_verifier}):
            verified = verify_findings(result)

        assert "CONFIRMED ACTIVE" in verified.findings[0].evidence

    def test_anthropic_key_verified_inactive(self) -> None:
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
        )
        result = ScanResult(findings=[finding])

        mock_verifier = lambda key: "INACTIVE/ROTATED"
        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-001": mock_verifier}):
            verified = verify_findings(result)

        assert "INACTIVE/ROTATED" in verified.findings[0].evidence

    def test_openai_key_verification(self) -> None:
        finding = _make_secret_finding(
            "AAK-SECRET-002",
            "Found OpenAI key: sk-ABCDEFGHIJ1234567890extra",
        )
        result = ScanResult(findings=[finding])

        mock_verifier = lambda key: "CONFIRMED ACTIVE"
        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-002": mock_verifier}):
            verified = verify_findings(result)

        assert "CONFIRMED ACTIVE" in verified.findings[0].evidence

    def test_key_extraction_failure_annotated(self) -> None:
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found a secret but no extractable key pattern",
        )
        result = ScanResult(findings=[finding])
        verified = verify_findings(result)
        assert "could not extract key" in verified.findings[0].evidence

    def test_verifier_exception_handled(self) -> None:
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
        )
        result = ScanResult(findings=[finding])

        def _raise(key: str) -> str:
            raise ConnectionError("Network error")

        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-001": _raise}):
            verified = verify_findings(result)

        assert "VERIFICATION FAILED" in verified.findings[0].evidence

    def test_masked_key_in_evidence(self) -> None:
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
        )
        result = ScanResult(findings=[finding])

        mock_verifier = lambda key: "CONFIRMED ACTIVE"
        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-001": mock_verifier}):
            verified = verify_findings(result)

        evidence = verified.findings[0].evidence
        # The masked key should appear (first 8 chars + ***)
        assert "sk-ant-a***" in evidence
        # The full key should NOT appear in the verification annotation portion
        # (it may still be in the original evidence prefix, which is expected)

    def test_returns_same_result_object(self) -> None:
        result = ScanResult(findings=[])
        verified = verify_findings(result)
        assert verified is result

    def test_severity_auto_upgrade_on_confirmed_active(self) -> None:
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
        )
        finding.severity = Severity.HIGH
        result = ScanResult(findings=[finding])

        mock_verifier = lambda key: "CONFIRMED ACTIVE"
        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-001": mock_verifier}):
            verified = verify_findings(result)

        assert verified.findings[0].severity == Severity.CRITICAL

    def test_severity_not_upgraded_on_inactive(self) -> None:
        finding = _make_secret_finding(
            "AAK-SECRET-001",
            "Found Anthropic API key: sk-ant-api03-abc123def456",
        )
        finding.severity = Severity.HIGH
        result = ScanResult(findings=[finding])

        mock_verifier = lambda key: "INACTIVE/ROTATED"
        with patch.dict("agent_audit_kit.verification._VERIFIERS", {"AAK-SECRET-001": mock_verifier}):
            verified = verify_findings(result)

        assert verified.findings[0].severity == Severity.HIGH

    def test_no_verifier_for_rule_annotates_evidence(self) -> None:
        # AAK-SECRET-008 is verifiable but has no entry in _VERIFIERS.
        # Since there is also no _KEY_PATTERNS entry for AAK-SECRET-008, the
        # code path hits "could not extract key" before reaching "no verifier".
        finding = _make_secret_finding(
            "AAK-SECRET-008",
            "Found GitHub token: ghp_ABCDEFGHIJ1234567890",
        )
        result = ScanResult(findings=[finding])
        verified = verify_findings(result)
        assert "could not extract key" in verified.findings[0].evidence

    def test_no_verifier_available_path(self) -> None:
        """When a key IS extractable but no verifier exists, evidence gets
        'no verifier available' annotation."""
        import re

        finding = _make_secret_finding(
            "AAK-SECRET-008",
            "Found GitHub token: ghp_ABC123test1234567890",
        )
        result = ScanResult(findings=[finding])

        # Patch _KEY_PATTERNS so AAK-SECRET-008 has an extractable pattern
        # but leave _VERIFIERS without an entry for AAK-SECRET-008
        fake_patterns = {"AAK-SECRET-008": re.compile(r"(ghp_\S+)")}
        with patch.dict("agent_audit_kit.verification._KEY_PATTERNS", fake_patterns):
            verified = verify_findings(result)

        assert "no verifier available" in verified.findings[0].evidence


# ---------------------------------------------------------------------------
# _verify_anthropic
# ---------------------------------------------------------------------------


class TestVerifyAnthropic:
    def test_returns_confirmed_active_on_200(self) -> None:
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.verification.urllib.request.urlopen", return_value=mock_resp):
            result = _verify_anthropic("sk-ant-api03-test")
        assert result == "CONFIRMED ACTIVE"

    def test_returns_inactive_on_401(self) -> None:
        import urllib.error

        exc = urllib.error.HTTPError(
            url="https://api.anthropic.com/v1/models",
            code=401,
            msg="Unauthorized",
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )
        with patch("agent_audit_kit.verification.urllib.request.urlopen", side_effect=exc):
            result = _verify_anthropic("sk-ant-api03-test")
        assert result == "INACTIVE/ROTATED"

    def test_returns_inactive_on_403(self) -> None:
        import urllib.error

        exc = urllib.error.HTTPError(
            url="https://api.anthropic.com/v1/models",
            code=403,
            msg="Forbidden",
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )
        with patch("agent_audit_kit.verification.urllib.request.urlopen", side_effect=exc):
            result = _verify_anthropic("sk-ant-api03-test")
        assert result == "INACTIVE/ROTATED"

    def test_returns_failed_on_500(self) -> None:
        import urllib.error

        exc = urllib.error.HTTPError(
            url="https://api.anthropic.com/v1/models",
            code=500,
            msg="Server Error",
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )
        with patch("agent_audit_kit.verification.urllib.request.urlopen", side_effect=exc):
            result = _verify_anthropic("sk-ant-api03-test")
        assert "VERIFICATION FAILED" in result
        assert "500" in result

    def test_returns_failed_on_url_error(self) -> None:
        import urllib.error

        with patch(
            "agent_audit_kit.verification.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            result = _verify_anthropic("sk-ant-api03-test")
        assert result == "VERIFICATION FAILED"

    def test_returns_inactive_on_non_200_success(self) -> None:
        """Non-200 status (e.g., 204) should return INACTIVE/ROTATED."""
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.verification.urllib.request.urlopen", return_value=mock_resp):
            result = _verify_anthropic("sk-ant-api03-test")
        assert result == "INACTIVE/ROTATED"


# ---------------------------------------------------------------------------
# _verify_openai
# ---------------------------------------------------------------------------


class TestVerifyOpenai:
    def test_returns_confirmed_active_on_200(self) -> None:
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.verification.urllib.request.urlopen", return_value=mock_resp):
            result = _verify_openai("sk-TestKey12345678901234")
        assert result == "CONFIRMED ACTIVE"

    def test_returns_inactive_on_401(self) -> None:
        import urllib.error

        exc = urllib.error.HTTPError(
            url="https://api.openai.com/v1/models",
            code=401,
            msg="Unauthorized",
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )
        with patch("agent_audit_kit.verification.urllib.request.urlopen", side_effect=exc):
            result = _verify_openai("sk-TestKey12345678901234")
        assert result == "INACTIVE/ROTATED"

    def test_returns_failed_on_network_error(self) -> None:
        with patch(
            "agent_audit_kit.verification.urllib.request.urlopen",
            side_effect=OSError("network error"),
        ):
            result = _verify_openai("sk-TestKey12345678901234")
        assert result == "VERIFICATION FAILED"

    def test_returns_failed_on_500(self) -> None:
        import urllib.error

        exc = urllib.error.HTTPError(
            url="https://api.openai.com/v1/models",
            code=500,
            msg="Server Error",
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )
        with patch("agent_audit_kit.verification.urllib.request.urlopen", side_effect=exc):
            result = _verify_openai("sk-TestKey12345678901234")
        assert "VERIFICATION FAILED" in result

    def test_returns_inactive_on_non_200_success(self) -> None:
        """Non-200 status (e.g., 204) should return INACTIVE/ROTATED."""
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.verification.urllib.request.urlopen", return_value=mock_resp):
            result = _verify_openai("sk-TestKey12345678901234")
        assert result == "INACTIVE/ROTATED"


# ---------------------------------------------------------------------------
# _verify_gcp
# ---------------------------------------------------------------------------


class TestVerifyGcp:
    def test_returns_confirmed_active_on_200(self) -> None:
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.verification.urllib.request.urlopen", return_value=mock_resp):
            result = _verify_gcp('{"type": "service_account"}')
        assert result == "CONFIRMED ACTIVE"

    def test_returns_inactive_on_401(self) -> None:
        import urllib.error

        exc = urllib.error.HTTPError(
            url="https://oauth2.googleapis.com/tokeninfo",
            code=401,
            msg="Unauthorized",
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )
        with patch("agent_audit_kit.verification.urllib.request.urlopen", side_effect=exc):
            result = _verify_gcp('{"type": "service_account"}')
        assert result == "INACTIVE/ROTATED"

    def test_returns_inactive_on_400(self) -> None:
        import urllib.error

        exc = urllib.error.HTTPError(
            url="https://oauth2.googleapis.com/tokeninfo",
            code=400,
            msg="Bad Request",
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )
        with patch("agent_audit_kit.verification.urllib.request.urlopen", side_effect=exc):
            result = _verify_gcp('{"type": "service_account"}')
        assert result == "INACTIVE/ROTATED"

    def test_returns_failed_on_network_error(self) -> None:
        with patch(
            "agent_audit_kit.verification.urllib.request.urlopen",
            side_effect=OSError("network error"),
        ):
            result = _verify_gcp('{"type": "service_account"}')
        assert result == "VERIFICATION FAILED"

    def test_returns_inactive_on_non_200_success(self) -> None:
        """Non-200 status (e.g., 204) should return INACTIVE/ROTATED."""
        mock_resp = unittest.mock.MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("agent_audit_kit.verification.urllib.request.urlopen", return_value=mock_resp):
            result = _verify_gcp('{"type": "service_account"}')
        assert result == "INACTIVE/ROTATED"

    def test_returns_failed_on_500(self) -> None:
        import urllib.error

        exc = urllib.error.HTTPError(
            url="https://oauth2.googleapis.com/tokeninfo",
            code=500,
            msg="Server Error",
            hdrs={},  # type: ignore[arg-type]
            fp=None,
        )
        with patch("agent_audit_kit.verification.urllib.request.urlopen", side_effect=exc):
            result = _verify_gcp('{"type": "service_account"}')
        assert "VERIFICATION FAILED" in result
        assert "500" in result
