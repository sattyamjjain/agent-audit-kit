"""CVE-2025-66414 / CVE-2025-66416 — Python MCP SDK DNS rebinding.

`mcp` Python SDK < 1.23.0 shipped a StreamableHTTP transport that trusted
the browser-supplied Host header. AAK-DNS-REBIND-002 is the pin check;
AAK-DNS-REBIND-001 is the pattern check for downstream servers embedding
StreamableHTTP without a Host allow-list.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.dns_rebind import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "dns-rebind-sdk-class"


def test_python_sdk_vulnerable_pin_fires() -> None:
    findings, _ = scan(FIXTURES / "python-vulnerable")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-002" in rule_ids


def test_python_sdk_patched_pin_passes() -> None:
    findings, _ = scan(FIXTURES / "python-patched")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-002" not in rule_ids


def test_python_streamable_unguarded_pattern_fires() -> None:
    findings, _ = scan(FIXTURES / "python-pattern-unguarded")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-001" in rule_ids


def test_python_streamable_guarded_pattern_passes() -> None:
    findings, _ = scan(FIXTURES / "python-pattern-guarded")
    rule_ids = {f.rule_id for f in findings}
    # Pattern rule should not fire when TrustedHostMiddleware present.
    assert "AAK-DNS-REBIND-001" not in rule_ids
