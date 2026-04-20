"""Detached-mode SARIF guarantee + fingerprint-strategy regression test.

The marketplace use-case: users upload SARIF from a runner that scanned
a container where source is NOT co-located with the repo root. GitHub
Code Scanning only computes partialFingerprints server-side when source
IS co-located, per:
https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

This test exercises the detached path (no source file present on disk
at the reported `file_path`) and asserts we still emit valid SARIF 2.1
with the fingerprints the server expects.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.models import Category, Finding, ScanResult, Severity
from agent_audit_kit.output.sarif import FINGERPRINT_STRATEGIES, format_results


def _finding(path: str = "missing/src.py", line: int = 42) -> Finding:
    return Finding(
        rule_id="AAK-MCPWN-001",
        title="test",
        description="test",
        severity=Severity.CRITICAL,
        category=Category.MCP_CONFIG,
        file_path=path,
        line_number=line,
        evidence="example",
        remediation="fix",
    )


def _scan_with_one_finding() -> ScanResult:
    result = ScanResult(rules_evaluated=1, files_scanned=1, scan_duration_ms=1.0)
    result.findings.append(_finding())
    return result


def _validate_sarif(doc: dict) -> None:
    """Minimum SARIF 2.1 shape checks. Not a full JSON-schema validation,
    but close enough — covers everything GitHub Code Scanning's ingestor
    rejects."""
    assert doc.get("$schema", "").endswith("sarif-2.1.0.json")
    assert doc.get("version") == "2.1.0"
    runs = doc.get("runs")
    assert isinstance(runs, list) and runs
    run = runs[0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "AgentAuditKit"
    assert isinstance(driver.get("rules"), list)
    for result in run.get("results", []):
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert isinstance(result.get("locations"), list)


# ---------------------------------------------------------------------------
# Detached mode: SARIF still validates + still emits fingerprints.
# ---------------------------------------------------------------------------


def test_detached_mode_emits_fallback_partial_fingerprint() -> None:
    """No project_root set, source file does not exist on disk."""
    doc = json.loads(format_results(_scan_with_one_finding()))
    _validate_sarif(doc)
    result = doc["runs"][0]["results"][0]
    fp = result["partialFingerprints"]["primaryLocationLineHash"]
    # 64-char hex SHA-256 — the location-based fallback.
    assert len(fp) == 64
    assert result["fingerprints"]["primaryLocationFingerprint"]


def test_detached_mode_auto_equals_detached_line_hash() -> None:
    """When source is not co-located, auto and line-hash both fall back
    to the same location hash — they're functionally identical in this
    scenario."""
    auto_doc = json.loads(format_results(_scan_with_one_finding(), fingerprint_strategy="auto"))
    linehash_doc = json.loads(format_results(_scan_with_one_finding(), fingerprint_strategy="line-hash"))
    assert (
        auto_doc["runs"][0]["results"][0]["partialFingerprints"]
        == linehash_doc["runs"][0]["results"][0]["partialFingerprints"]
    )


def test_disabled_strategy_strips_fingerprints() -> None:
    doc = json.loads(format_results(_scan_with_one_finding(), fingerprint_strategy="disabled"))
    result = doc["runs"][0]["results"][0]
    assert "fingerprints" not in result
    assert "partialFingerprints" not in result


def test_unknown_strategy_rejected() -> None:
    with pytest.raises(ValueError, match="unknown fingerprint_strategy"):
        format_results(_scan_with_one_finding(), fingerprint_strategy="bogus")


def test_fingerprint_strategies_constant_exposed() -> None:
    # Used by the CLI's click.Choice — if this tuple changes, the flag
    # choices must change too.
    assert FINGERPRINT_STRATEGIES == ("auto", "line-hash", "disabled")


# ---------------------------------------------------------------------------
# Co-located-source mode: content hash is used.
# ---------------------------------------------------------------------------


def test_colocated_uses_content_hash(tmp_path: Path) -> None:
    (tmp_path / "src.py").write_text("hello\nworld_is_vulnerable\nfooter\n")
    result = ScanResult(rules_evaluated=1)
    result.findings.append(_finding(path="src.py", line=2))
    doc_a = json.loads(format_results(result, project_root=tmp_path))
    fp_a = doc_a["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]

    # Shift the vulnerable line down by two lines — same content, different
    # line_number. Hash should remain identical.
    (tmp_path / "src.py").write_text(
        "# prelude\n# prelude\nhello\nworld_is_vulnerable\nfooter\n"
    )
    result_b = ScanResult(rules_evaluated=1)
    result_b.findings.append(_finding(path="src.py", line=4))
    doc_b = json.loads(format_results(result_b, project_root=tmp_path))
    fp_b = doc_b["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert fp_a == fp_b


# ---------------------------------------------------------------------------
# action.yml exposes the fingerprint-strategy input.
# ---------------------------------------------------------------------------


def test_action_yml_declares_fingerprint_strategy_input() -> None:
    text = (Path(__file__).resolve().parent.parent / "action.yml").read_text(encoding="utf-8")
    assert "fingerprint-strategy:" in text
    # One of the accepted default values is 'auto'.
    assert "default: 'auto'" in text
