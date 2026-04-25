"""CVE-2026-41488 — langchain-openai TOCTOU / DNS rebinding."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.ssrf_toctou import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-41488"


def test_vulnerable_toctou_pattern_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-toctou")
    assert any(f.rule_id == "AAK-SSRF-TOCTOU-001" for f in findings)


def test_pinned_ip_pattern_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-pinned")
    assert not any(f.rule_id == "AAK-SSRF-TOCTOU-001" for f in findings)


def test_vulnerable_pin_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-pin")
    assert any(f.rule_id == "AAK-SSRF-TOCTOU-001" for f in findings)


def test_patched_pin_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-pin")
    assert not any(f.rule_id == "AAK-SSRF-TOCTOU-001" for f in findings)


def test_unrelated_get_passes(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(
        "import requests\nrequests.get('https://example.com')\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-SSRF-TOCTOU-001" for f in findings)
