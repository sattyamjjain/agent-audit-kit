"""CVE-2026-41488 — langchain-openai TOCTOU / DNS rebinding."""

from __future__ import annotations

from pathlib import Path

import pytest

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


# The pin took the first number after the name, so `langchain-openai<1.1.14`, which
# admits only affected releases, read as the fix and was silent, and the extras in
# `langchain-openai[x]==1.1.14` read as a name with no version and fired. Manifests
# are now read as the CVE pin table reads them.


@pytest.mark.parametrize(("manifest", "text", "fires"), [
    ("requirements.txt", "langchain-openai<1.1.14\n", True),
    ("requirements.txt", "langchain-openai<2.0.0,>=1.0.0\n", True),
    ("requirements.txt", "langchain-openai[x]==1.1.14\n", False),
    ("requirements.txt", "langchain-openai[x]==1.1.13\n", True),
    ("requirements.txt", "langchain-openai\n", True),   # no version stated, reported as before
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["langchain-openai<1.1.14"]\n', True),
    ("pyproject.toml", '[project]\nname = "d"\ndependencies = ["langchain-openai"]\n', True),
    ("pyproject.toml", '[tool.poetry.dependencies]\nlangchain-openai = "^1.1.14"\n', False),
])
def test_pin_reads_ranges_extras_and_pyproject(tmp_path: Path, manifest: str, text: str, fires: bool) -> None:
    (tmp_path / manifest).write_text(text, encoding="utf-8")
    findings, _ = scan(tmp_path)
    assert any(f.rule_id == "AAK-SSRF-TOCTOU-001" for f in findings) is fires
