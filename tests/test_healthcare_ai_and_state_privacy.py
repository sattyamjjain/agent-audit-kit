"""Tests for AAK-HEALTHCARE-AI-001..005 (Tennessee SB 1580 family) and
AAK-STATE-PRIVACY-001..003 (Alabama DPPA + CCPA-lineage disclosures).

Apr-2026 regulatory wave per:
- https://www.troutmanprivacy.com/2026/04/tennessee-enacts-health-care-ai-bill-with-private-right-of-action/
- https://iapp.org/news/a/alabama-set-to-add-variation-to-us-state-privacy-patchwork
"""

from __future__ import annotations

import shutil
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.pdf_report import _FRAMEWORK_TITLES, _text_report
from agent_audit_kit.scanners import healthcare_ai, state_privacy

FIX = Path(__file__).parent / "fixtures" / "cves"


# ---------------------------------------------------------------------------
# Healthcare AI
# ---------------------------------------------------------------------------


def test_healthcare_vulnerable_fires_multiple_rules(tmp_path: Path) -> None:
    shutil.copy(FIX / "healthcare_ai" / "vulnerable_skill.md", tmp_path / "SKILL.md")
    findings, _ = healthcare_ai.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-HEALTHCARE-AI-001" in ids  # TN SB 1580 trigger
    assert "AAK-HEALTHCARE-AI-002" in ids  # prior-auth solo
    assert "AAK-HEALTHCARE-AI-003" in ids  # insurance solo
    assert "AAK-HEALTHCARE-AI-005" in ids  # suicide keyword w/o escalation


def test_healthcare_safe_is_quiet(tmp_path: Path) -> None:
    shutil.copy(FIX / "healthcare_ai" / "safe_skill.md", tmp_path / "SKILL.md")
    findings, _ = healthcare_ai.scan(tmp_path)
    # No HEALTHCARE-AI rules should fire; the safe fixture has disclosure, disclaimer, 988 escalation.
    ids = {f.rule_id for f in findings}
    for rid in (
        "AAK-HEALTHCARE-AI-001",
        "AAK-HEALTHCARE-AI-002",
        "AAK-HEALTHCARE-AI-003",
        "AAK-HEALTHCARE-AI-005",
    ):
        assert rid not in ids


def test_healthcare_mcp_json_with_mental_health_claim(tmp_path: Path) -> None:
    # Embed claim inside MCP tool description — should still fire via JSON-aware path.
    import json

    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wellness": {
                        "command": "node",
                        "tools": [
                            {
                                "name": "therapy_session",
                                "description": "I am your licensed therapist and can run therapy sessions.",
                            }
                        ],
                    }
                }
            }
        )
    )
    findings, _ = healthcare_ai.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AAK-HEALTHCARE-AI-001" in ids


# ---------------------------------------------------------------------------
# State privacy
# ---------------------------------------------------------------------------


def test_state_privacy_vulnerable_fires_all_three(tmp_path: Path) -> None:
    shutil.copy(FIX / "state_privacy" / "vulnerable_privacy.md", tmp_path / "privacy.md")
    findings, _ = state_privacy.scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert ids == {
        "AAK-STATE-PRIVACY-001",
        "AAK-STATE-PRIVACY-002",
        "AAK-STATE-PRIVACY-003",
    }


def test_state_privacy_safe_is_quiet(tmp_path: Path) -> None:
    shutil.copy(FIX / "state_privacy" / "safe_privacy.md", tmp_path / "privacy.md")
    findings, _ = state_privacy.scan(tmp_path)
    assert findings == []


def test_state_privacy_ignores_non_policy_files(tmp_path: Path) -> None:
    # README.md is not a privacy policy even if it mentions "personal data".
    (tmp_path / "README.md").write_text(
        "# My project\n\nWe handle personal data carefully."
    )
    findings, _ = state_privacy.scan(tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# Compliance frameworks for the new laws
# ---------------------------------------------------------------------------


def test_alabama_and_tennessee_framework_titles_registered() -> None:
    for fw in ("alabama-dppa", "tennessee-sb1580"):
        assert fw in _FRAMEWORK_TITLES
        assert _FRAMEWORK_TITLES[fw]


def test_tennessee_report_mentions_pra(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: x\n---\nI am your licensed therapist\n"
    )
    result = run_scan(tmp_path)
    text = _text_report(result, "tennessee-sb1580")
    assert "Tennessee SB 1580" in text
    # The framework maps every category to prohibition / TCPA citation.
    assert "Prohibition" in text or "TCPA" in text


def test_alabama_report_mentions_hb351(tmp_path: Path) -> None:
    (tmp_path / "privacy.md").write_text(
        "# Privacy Policy\n\nWe process personal data.\n"
    )
    result = run_scan(tmp_path)
    text = _text_report(result, "alabama-dppa")
    assert "Alabama Personal Data Protection Act" in text


def test_report_cli_accepts_new_frameworks(tmp_path: Path) -> None:
    runner = CliRunner()
    for fw in ("alabama-dppa", "tennessee-sb1580"):
        out = tmp_path / f"r-{fw}.txt"
        r = runner.invoke(
            cli,
            ["report", str(tmp_path), "--framework", fw, "--format", "text", "--output", str(out)],
        )
        assert r.exit_code == 0, (fw, r.output)
