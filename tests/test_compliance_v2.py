"""Tests for the new compliance frameworks added in v0.3.x."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.pdf_report import _FRAMEWORK_TITLES, _text_report


def test_all_frameworks_have_titles() -> None:
    for fw in [
        "eu-ai-act",
        "eu-ai-act-art55",
        "soc2",
        "iso27001",
        "iso42001",
        "hipaa",
        "nist-ai-rmf",
        "singapore-agentic",
        "india-dpdp",
    ]:
        assert fw in _FRAMEWORK_TITLES
        assert _FRAMEWORK_TITLES[fw]


def test_singapore_framework_emits_pillar_controls(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-liveKey12345")
    result = run_scan(tmp_path)
    text = _text_report(result, "singapore-agentic")
    assert "Singapore Agentic AI" in text
    assert "Pillar" in text


def test_india_dpdp_framework_emits_sections(tmp_path: Path) -> None:
    (tmp_path / "data.txt").write_text("pan: ABCDE1234F")
    result = run_scan(tmp_path)
    text = _text_report(result, "india-dpdp")
    assert "DPDP" in text or "Digital Personal Data Protection" in text
    assert "s.8" in text  # section reference


def test_iso42001_framework_emits_annex_controls(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("API_KEY=secret12345")
    result = run_scan(tmp_path)
    text = _text_report(result, "iso42001")
    assert "ISO/IEC 42001" in text
    assert "A.6" in text or "A.7" in text or "A.10" in text


def test_eu_ai_act_article_55(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-liveKey12345")
    result = run_scan(tmp_path)
    text = _text_report(result, "eu-ai-act-art55")
    assert "Article 55" in text  # title
    # If no findings fired, control rows are absent; if any did, expect Art. 55 in them.
    if result.findings:
        assert "Art. 55" in text


def test_report_cli_accepts_all_new_frameworks(tmp_path: Path) -> None:
    runner = CliRunner()
    for fw in ("singapore-agentic", "india-dpdp", "iso42001", "eu-ai-act-art55"):
        out = tmp_path / f"report-{fw}.txt"
        r = runner.invoke(
            cli,
            ["report", str(tmp_path), "--framework", fw, "--format", "text", "--output", str(out)],
        )
        assert r.exit_code == 0, (fw, r.output)
        assert out.is_file()


def test_report_cli_rejects_unknown_framework(tmp_path: Path) -> None:
    runner = CliRunner()
    r = runner.invoke(
        cli,
        ["report", str(tmp_path), "--framework", "gdpr", "--format", "text"],
    )
    assert r.exit_code != 0
