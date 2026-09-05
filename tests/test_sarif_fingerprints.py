"""Tests for T6 SARIF upgrades.

- partialFingerprints.primaryLocationLineHash is a SHA256 of (line content +
  rule ID), stable across unrelated line shifts, different when the line
  content changes.
- helpUri per rule points at a URL that resolves: the rule's own docs page
  when one exists, the published rules index otherwise.
- results[].properties.security-severity mirrors the rule's severity score.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_audit_kit.models import Category, Finding, ScanResult, Severity
from agent_audit_kit.output._rule_doc_pages import RULE_DOC_PAGES
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


def _help_uri_for(tmp_path: Path, rule_id: str) -> str:
    (tmp_path / "s.py").write_text("x\n")
    sarif = json.loads(
        format_results(_make_result("s.py", 1, rule_id=rule_id), project_root=tmp_path)
    )
    return sarif["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"]


def test_helpuri_deep_links_a_rule_that_has_a_docs_page(tmp_path: Path) -> None:
    """AAK-TOXICFLOW-001 has docs/rules/AAK-TOXICFLOW-001.md, so it earns a
    per-rule URL. The trailing slash is the canonical MkDocs directory URL."""
    assert _help_uri_for(tmp_path, "AAK-TOXICFLOW-001") == (
        "https://sattyamjjain.github.io/agent-audit-kit/docs/rules/AAK-TOXICFLOW-001/"
    )


def test_helpuri_falls_back_to_the_index_for_a_rule_with_no_page(tmp_path: Path) -> None:
    """The other 319. Deep-linking these would produce a 404 per finding --
    a link that fails 96% of the time is harder to notice than one that always
    does, which is the failure this replaced."""
    assert "AAK-STDIO-001" not in RULE_DOC_PAGES
    assert _help_uri_for(tmp_path, "AAK-STDIO-001") == (
        "https://sattyamjjain.github.io/agent-audit-kit/docs/rules/"
    )


def test_helpuri_never_points_at_an_unregistered_domain(tmp_path: Path) -> None:
    """agent-audit-kit.dev is NXDOMAIN and was the helpUri base until 2026-09-05.

    Pinned as a string rather than a network check: the test must fail if the
    constant comes back, and must not depend on DNS to say so."""
    for rule_id in ("AAK-TOXICFLOW-001", "AAK-STDIO-001"):
        assert "agent-audit-kit.dev" not in _help_uri_for(tmp_path, rule_id)


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
