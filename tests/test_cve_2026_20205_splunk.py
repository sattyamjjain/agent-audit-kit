"""CVE-2026-20205 — Splunk MCP Server token cleartext in logs.

AAK-SPLUNK-TOKLOG-001 fires on (a) token-shaped values in log sinks, and
(b) `splunk-mcp-server<1.0.3` pinned in a manifest.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.log_token_leak import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-20205"


def test_vulnerable_token_log_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-token-log")
    assert any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_redacted_token_log_passes() -> None:
    findings, _ = scan(FIXTURES / "redacted-token-log")
    assert not any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_vulnerable_splunk_pin_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-splunk-pin")
    assert any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_patched_splunk_pin_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-splunk-pin")
    assert not any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_jwt_in_log_fires(tmp_path: Path) -> None:
    (tmp_path / "leak.py").write_text(
        'import logging\nlogging.info("token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.XX.YY")\n',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_ts_console_log_bearer_fires(tmp_path: Path) -> None:
    (tmp_path / "leak.ts").write_text(
        'console.log(`Bearer ${authToken}`);\n',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)


def test_unrelated_log_call_passes(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text(
        'import logging\nlogging.info("user %s logged in", username)\n',
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-SPLUNK-TOKLOG-001" for f in findings)
