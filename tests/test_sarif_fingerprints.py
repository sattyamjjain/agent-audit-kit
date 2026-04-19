"""Tests for T6 SARIF upgrades.

- partialFingerprints.primaryLocationLineHash is a SHA256 of (line content +
  rule ID), stable across unrelated line shifts, different when the line
  content changes.
- helpUri per rule points at https://agent-audit-kit.dev/rules/<rule_id>.
- results[].properties.security-severity mirrors the rule's severity score.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_audit_kit.models import Category, Finding, ScanResult, Severity
from agent_audit_kit.output.sarif import format_results


def _make_result(file_rel: str, line: int, rule_id: str = "AAK-MCP-001") -> ScanResult:
    result = ScanResult()
    result.findings.append(
        Finding(
            rule_id=rule_id,
            title="test",
            description="test",
            severity=Severity.CRITICAL,
            category=Category.MCP_CONFIG,
            file_path=file_rel,
            line_number=line,
            evidence="example",
            remediation="fix",
        )
    )
    return result


def test_partial_fingerprint_is_content_hash(tmp_path: Path) -> None:
    code_path = tmp_path / "server.py"
    code_path.write_text(
        "line 1\n"
        "vulnerable_line_content\n"
        "line 3\n"
    )
    sarif = json.loads(
        format_results(_make_result("server.py", 2), project_root=tmp_path)
    )
    fp = sarif["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]

    expected = hashlib.sha256(b"vulnerable_line_content\0AAK-MCP-001").hexdigest()
    assert fp == expected


def test_partial_fingerprint_stable_when_line_shifts(tmp_path: Path) -> None:
    """Same source line, different physical line number -> same hash."""
    (tmp_path / "a.py").write_text("vulnerable_line_content\n")
    (tmp_path / "b.py").write_text(
        "# added comment\n"
        "# another comment\n"
        "vulnerable_line_content\n"
    )
    fp_a = json.loads(
        format_results(_make_result("a.py", 1), project_root=tmp_path)
    )["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    fp_b = json.loads(
        format_results(_make_result("b.py", 3), project_root=tmp_path)
    )["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert fp_a == fp_b


def test_partial_fingerprint_changes_when_line_content_changes(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("vulnerable_old_content\n")
    (tmp_path / "b.py").write_text("vulnerable_new_content\n")
    fp_a = json.loads(
        format_results(_make_result("a.py", 1), project_root=tmp_path)
    )["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    fp_b = json.loads(
        format_results(_make_result("b.py", 1), project_root=tmp_path)
    )["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert fp_a != fp_b


def test_helpuri_per_rule_points_at_rules_subpath(tmp_path: Path) -> None:
    (tmp_path / "s.py").write_text("x\n")
    sarif = json.loads(
        format_results(_make_result("s.py", 1, rule_id="AAK-STDIO-001"), project_root=tmp_path)
    )
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://agent-audit-kit.dev/rules/AAK-STDIO-001"


def test_result_carries_security_severity_score(tmp_path: Path) -> None:
    (tmp_path / "s.py").write_text("x\n")
    sarif = json.loads(
        format_results(_make_result("s.py", 1), project_root=tmp_path)
    )
    result = sarif["runs"][0]["results"][0]
    # CRITICAL -> 9.5
    assert result["properties"]["security-severity"] == "9.5"


def test_fingerprint_falls_back_when_file_missing() -> None:
    """When the source file isn't on disk we still emit a stable (but
    location-based) hash so the SARIF is valid."""
    result = ScanResult()
    result.findings.append(
        Finding(
            rule_id="AAK-MCP-001",
            title="x",
            description="x",
            severity=Severity.HIGH,
            category=Category.MCP_CONFIG,
            file_path="gone.py",
            line_number=7,
        )
    )
    sarif = json.loads(format_results(result))
    fp = sarif["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    # 64 hex chars = full SHA256.
    assert len(fp) == 64


def test_known_rule_fires_twice_fingerprint_is_identical(tmp_path: Path) -> None:
    """Same rule + same line content = same hash. Foundation of GH Code
    Scanning de-dup."""
    (tmp_path / "s.py").write_text("shared_vulnerable_line\n")
    r1 = json.loads(format_results(_make_result("s.py", 1), project_root=tmp_path))
    r2 = json.loads(format_results(_make_result("s.py", 1), project_root=tmp_path))
    fp1 = r1["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    fp2 = r2["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert fp1 == fp2
