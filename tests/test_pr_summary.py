"""Tests for agent_audit_kit.output.pr_summary (T7)."""

from __future__ import annotations

import os
from pathlib import Path

from agent_audit_kit.models import Category, Finding, ScanResult, Severity
from agent_audit_kit.output.pr_summary import (
    PR_COMMENT_MARKER,
    render_markdown,
    write_step_summary,
)


def _finding(rule_id: str, severity: Severity, line: int | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"{rule_id} test",
        description="desc",
        severity=severity,
        category=Category.MCP_CONFIG,
        file_path="server.py",
        line_number=line,
        evidence="evidence",
        remediation="fix it | pipe",
    )


def test_no_findings_emits_clean_body() -> None:
    r = ScanResult(rules_evaluated=138, files_scanned=42, scan_duration_ms=37.4)
    body = render_markdown(r)
    assert PR_COMMENT_MARKER in body
    assert "no security findings" in body
    assert "138" in body and "42" in body


def test_findings_render_markdown_table() -> None:
    r = ScanResult(rules_evaluated=138, files_scanned=1, scan_duration_ms=1.0)
    r.findings.extend([
        _finding("AAK-STDIO-001", Severity.CRITICAL, line=42),
        _finding("AAK-WINDSURF-001", Severity.HIGH, line=7),
        _finding("AAK-MCP-018", Severity.MEDIUM, line=15),
    ])
    body = render_markdown(r)
    assert "| Rule | Severity | Location | Suggestion |" in body
    # Sorted by severity ranking: critical first, then high, then medium.
    assert body.index("AAK-STDIO-001") < body.index("AAK-WINDSURF-001") < body.index("AAK-MCP-018")
    # Pipe characters in remediation are escaped.
    assert r"fix it \| pipe" in body


def test_sticky_marker_is_at_top() -> None:
    r = ScanResult(rules_evaluated=10)
    r.findings.append(_finding("AAK-STDIO-001", Severity.CRITICAL, line=1))
    body = render_markdown(r)
    assert body.startswith(PR_COMMENT_MARKER)


def test_table_truncates_above_max_rows() -> None:
    r = ScanResult(rules_evaluated=10)
    for i in range(60):
        r.findings.append(_finding(f"AAK-MCP-{i:03d}", Severity.LOW, line=i))
    body = render_markdown(r, max_rows=50)
    assert "Table truncated to 50 of 60 findings" in body


def test_write_step_summary_writes_to_target_path(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "summary.md"
    # Preload with existing content to confirm we append, not overwrite.
    target.write_text("existing header\n")
    r = ScanResult(rules_evaluated=10)
    r.findings.append(_finding("AAK-STDIO-001", Severity.CRITICAL, line=1))
    assert write_step_summary(r, target=str(target)) is True
    text = target.read_text()
    assert "existing header" in text
    assert PR_COMMENT_MARKER in text
    assert "AAK-STDIO-001" in text


def test_write_step_summary_noops_without_env(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    r = ScanResult(rules_evaluated=10)
    assert write_step_summary(r) is False


def test_write_step_summary_via_env(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "step.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(target))
    r = ScanResult(rules_evaluated=10)
    r.findings.append(_finding("AAK-STDIO-001", Severity.HIGH, line=5))
    assert write_step_summary(r) is True
    assert "AAK-STDIO-001" in target.read_text()
    # Clean up the env var to avoid leak to other tests (monkeypatch does this but
    # double-check):
    assert os.environ.get("GITHUB_STEP_SUMMARY") == str(target)
