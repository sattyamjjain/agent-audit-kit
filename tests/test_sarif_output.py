from __future__ import annotations

import json

from agent_audit_kit.models import Category, Finding, ScanResult, Severity
from agent_audit_kit.output.sarif import format_results


def _make_test_result() -> ScanResult:
    result = ScanResult(
        files_scanned=5,
        rules_evaluated=35,
        scan_duration_ms=0.42,
    )
    result.findings = [
        Finding(
            rule_id="AAK-MCP-001",
            title="Remote MCP server without authentication",
            description="An MCP server uses HTTP transport without authentication headers.",
            severity=Severity.CRITICAL,
            category=Category.MCP_CONFIG,
            file_path=".mcp.json",
            line_number=5,
            evidence="Server 'remote-no-auth' URL: https://mcp.evil-corp.com/api",
            remediation="Add OAuth 2.1 bearer token or API key header authentication.",
            owasp_mcp_references=["MCP07:2025"],
        ),
        Finding(
            rule_id="AAK-TRUST-001",
            title="enableAllProjectMcpServers is true",
            description="Auto-approves ALL MCP servers.",
            severity=Severity.CRITICAL,
            category=Category.TRUST_BOUNDARY,
            file_path=".claude/settings.json",
            line_number=2,
            evidence="enableAllProjectMcpServers: true",
            remediation="Set to false.",
            cve_references=["CVE-2026-21852"],
        ),
        Finding(
            rule_id="AAK-SECRET-006",
            title=".env file not in .gitignore",
            description="A .env file exists but .gitignore lacks exclusion.",
            severity=Severity.MEDIUM,
            category=Category.SECRET_EXPOSURE,
            file_path=".env",
            remediation="Add .env* to .gitignore.",
        ),
    ]
    return result


def test_sarif_valid_structure() -> None:
    """SARIF output must conform to 2.1.0 schema requirements."""
    result = _make_test_result()
    output = format_results(result)
    sarif = json.loads(output)

    # Required top-level fields
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "runs" in sarif
    assert isinstance(sarif["runs"], list)
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]

    # Tool driver
    assert "tool" in run
    assert "driver" in run["tool"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "AgentAuditKit"
    assert "version" in driver
    assert "rules" in driver
    assert isinstance(driver["rules"], list)

    # Results
    assert "results" in run
    assert isinstance(run["results"], list)
    assert len(run["results"]) == 3

    for result_entry in run["results"]:
        assert "ruleId" in result_entry
        assert "level" in result_entry
        assert "message" in result_entry
        assert "text" in result_entry["message"]
        assert "locations" in result_entry
        assert isinstance(result_entry["locations"], list)


def test_sarif_severity_mapping() -> None:
    """CRITICAL/HIGH maps to error, MEDIUM to warning, LOW/INFO to note."""
    result = _make_test_result()
    output = format_results(result)
    sarif = json.loads(output)

    results = sarif["runs"][0]["results"]
    # First two are CRITICAL -> error
    assert results[0]["level"] == "error"
    assert results[1]["level"] == "error"
    # Third is MEDIUM -> warning
    assert results[2]["level"] == "warning"


def test_sarif_rules_have_security_severity() -> None:
    """Each rule must have a security-severity property."""
    result = _make_test_result()
    output = format_results(result)
    sarif = json.loads(output)

    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert "properties" in rule
        assert "security-severity" in rule["properties"]
        score = float(rule["properties"]["security-severity"])
        assert 0 <= score <= 10


def test_sarif_fingerprints() -> None:
    """Results should have partialFingerprints for deduplication."""
    result = _make_test_result()
    output = format_results(result)
    sarif = json.loads(output)

    for result_entry in sarif["runs"][0]["results"]:
        assert "partialFingerprints" in result_entry
        assert "primaryLocationLineHash" in result_entry["partialFingerprints"]


def test_sarif_empty_results() -> None:
    """Empty scan result should produce valid SARIF with empty results."""
    result = ScanResult(files_scanned=0, rules_evaluated=35)
    output = format_results(result)
    sarif = json.loads(output)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 0


def test_sarif_min_severity_filter() -> None:
    """Severity filter should work in SARIF output."""
    result = _make_test_result()
    output = format_results(result, min_severity=Severity.HIGH)
    sarif = json.loads(output)

    # Only CRITICAL and HIGH should pass (2 CRITICAL findings)
    assert len(sarif["runs"][0]["results"]) == 2
