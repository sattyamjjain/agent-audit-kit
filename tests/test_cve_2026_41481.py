"""CVE-2026-41481 — langchain-text-splitters SSRF redirect bypass."""

from __future__ import annotations

from pathlib import Path

from agent_audit_kit.scanners.ssrf_redirect import scan

FIXTURES = Path(__file__).parent / "fixtures" / "cves" / "cve-2026-41481"


def test_vulnerable_redirect_pattern_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-redirect")
    assert any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_patched_no_redirect_pattern_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-no-redirect")
    assert not any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_vulnerable_pin_fires() -> None:
    findings, _ = scan(FIXTURES / "vulnerable-pin")
    assert any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_patched_pin_passes() -> None:
    findings, _ = scan(FIXTURES / "patched-pin")
    assert not any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_ts_fetch_without_redirect_off_fires(tmp_path: Path) -> None:
    (tmp_path / "tool.ts").write_text(
        """
async function fetchDoc(url: string) {
  if (!validateSafeUrl(url)) throw new Error("unsafe");
  const r = await fetch(url);
  return r.text();
}
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_ts_fetch_redirect_manual_passes(tmp_path: Path) -> None:
    (tmp_path / "tool.ts").write_text(
        """
async function fetchDoc(url: string) {
  if (!validateSafeUrl(url)) throw new Error("unsafe");
  const r = await fetch(url, { redirect: 'manual' });
  return r.text();
}
""",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)


def test_unrelated_get_without_validator_passes(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(
        "import requests\nrequests.get('https://example.com')\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert not any(f.rule_id == "AAK-LANGCHAIN-SSRF-REDIR-001" for f in findings)
