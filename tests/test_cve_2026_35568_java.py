"""CVE-2026-35568 — Java MCP SDK DNS rebinding.

`io.modelcontextprotocol.sdk:mcp-core` pre-0.11.0 shipped a
StreamableHTTP transport with no Host-header allow-list.
"""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.dns_rebind import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "dns-rebind-sdk-class"


def test_java_vulnerable_pom_fires() -> None:
    findings, _ = scan(FIXTURES / "java-vulnerable")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-002" in rule_ids


def test_java_patched_pom_passes() -> None:
    findings, _ = scan(FIXTURES / "java-patched")
    rule_ids = {f.rule_id for f in findings}
    assert "AAK-DNS-REBIND-002" not in rule_ids


def test_java_gradle_vulnerable_pin_fires(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation 'io.modelcontextprotocol.sdk:mcp-core:0.9.5'\n"
        "}\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-DNS-REBIND-002" for f in findings)


def test_java_gradle_patched_pin_passes(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text(
        "dependencies {\n"
        "    implementation 'io.modelcontextprotocol.sdk:mcp-core:0.11.0'\n"
        "}\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-DNS-REBIND-002" for f in findings)
