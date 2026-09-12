"""EU AI Act Article 50 transparency evidence (AAK-AIACT50-001..003).

Article 50 has applied since 2026-08-02. Two properties matter more than
coverage: the scanner must stay silent unless a project actually declares the
surface, and the pack must never print a conformity conclusion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.pdf_report import (
    _CATEGORY_TO_CONTROL,
    _FRAMEWORK_TITLES,
    _text_report,
)
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import eu_ai_act_art50 as art50

FIXTURES = Path(__file__).parent / "fixtures" / "aiact50"
EXAMPLES = Path(__file__).parent.parent / "examples" / "vulnerable-configs"
ART50_RULES = ("AAK-AIACT50-001", "AAK-AIACT50-002", "AAK-AIACT50-003")
_CONCLUSION_WORDS = ("compliant", "conforms", "certified")


def _ids(project: Path) -> set[str]:
    findings, _ = art50.scan(project)
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------
# Each duty fires
# --------------------------------------------------------------------------


def test_art50_1_fires_on_a_conversational_surface_without_disclosure() -> None:
    assert _ids(FIXTURES / "no_disclosure") == {"AAK-AIACT50-001"}


def test_art50_1_silent_when_the_surface_says_it_is_an_ai() -> None:
    assert _ids(FIXTURES / "disclosed") == set()


def test_art50_2_fires_on_generation_without_provenance_marking() -> None:
    assert _ids(FIXTURES / "synthetic_unmarked") == {"AAK-AIACT50-002"}


def test_art50_2_silent_when_c2pa_content_credentials_are_declared() -> None:
    assert _ids(FIXTURES / "synthetic_marked") == set()


def test_art50_4_fires_on_an_undisclosed_deepfake_surface() -> None:
    assert "AAK-AIACT50-003" in _ids(FIXTURES / "deepfake_undisclosed")


def test_all_three_duties_fire_on_the_example_project() -> None:
    assert _ids(EXAMPLES / "13-eu-ai-act-art50") == set(ART50_RULES)


# --------------------------------------------------------------------------
# Silence, which is the property that matters
# --------------------------------------------------------------------------


def test_the_statutory_exemptions_suppress_the_finding() -> None:
    """50(4) exempts artistic, satirical and fictional work.

    Deliberately generous: the failure mode of the opposite bias is accusing a
    satirist of a transparency offence.
    """
    assert _ids(FIXTURES / "exempt_satire") == set()


def test_a_project_with_no_declared_surface_emits_nothing() -> None:
    assert _ids(FIXTURES / "neutral") == set()


def test_scanner_is_silent_on_this_repository() -> None:
    """The first draft produced 83 findings here.

    It read every text file and gated Art. 50(1) on the conversational-surface
    pattern alone, so this scanner's own rule catalogue, tests and launch notes
    -- which discuss personas and system prompts constantly -- all read as agent
    surfaces. Describing an agent surface is not being one.
    """
    repo = Path(__file__).parent.parent
    findings, _ = art50.scan(repo)
    offenders = [
        f for f in findings
        if not f.file_path.startswith(("tests/fixtures", "examples/"))
    ]
    assert offenders == [], [f"{f.rule_id} {f.file_path}" for f in offenders]


def test_declarations_come_only_from_product_intent_surfaces() -> None:
    """A bare function is not a declaration; a tool-decorated one is."""
    assert art50._SURFACE_FILENAME_RE.match("SKILL.md")
    assert art50._SURFACE_FILENAME_RE.match("agent-card.json")
    assert not art50._SURFACE_FILENAME_RE.match("README.md")
    assert not art50._SURFACE_FILENAME_RE.match("CHANGELOG.md")


def test_the_licence_and_colorado_fixtures_stay_clean() -> None:
    assert _ids(EXAMPLES / "11-legal-compliance") == set()
    assert _ids(EXAMPLES / "12-colorado-admt") == set()


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "project", [FIXTURES / "no_disclosure", EXAMPLES / "13-eu-ai-act-art50"]
)
def test_two_scans_are_identical(project: Path) -> None:
    first, first_files = art50.scan(project)
    second, second_files = art50.scan(project)
    assert [f.rule_id for f in first] == [f.rule_id for f in second]
    assert [f.file_path for f in first] == [f.file_path for f in second]
    assert first_files == second_files


# --------------------------------------------------------------------------
# Evidence, never a conclusion
# --------------------------------------------------------------------------


def test_rendered_report_prints_no_conformity_conclusion() -> None:
    result = run_scan(EXAMPLES / "13-eu-ai-act-art50")
    text = _text_report(result, "eu-ai-act-art50").lower()
    for word in _CONCLUSION_WORDS:
        assert word not in text, f"report claims conformity: {word!r}"


def test_rule_text_states_evidence_not_determination() -> None:
    for rule_id in ART50_RULES:
        rule = RULES[rule_id]
        blob = f"{rule.description} {rule.remediation}".lower()
        for word in _CONCLUSION_WORDS:
            assert word not in blob, (rule_id, word)
        assert "determination" in rule.description.lower()


def test_every_rule_declares_its_blind_spot() -> None:
    for rule_id in ART50_RULES:
        assert RULES[rule_id].limitations.strip(), rule_id


# --------------------------------------------------------------------------
# Registry and framework wiring
# --------------------------------------------------------------------------


def test_rules_are_registered_under_legal_compliance() -> None:
    for rule_id in ART50_RULES:
        assert RULES[rule_id].category.value == "legal-compliance"
        assert RULES[rule_id].severity.value == "medium"
        assert RULES[rule_id].sarif_name


def test_framework_title_states_it_is_already_in_force() -> None:
    title = _FRAMEWORK_TITLES["eu-ai-act-art50"]
    assert "Article 50" in title
    assert "2026-08-02" in title


def test_arm_covers_the_same_categories_as_its_peers() -> None:
    assert set(_CATEGORY_TO_CONTROL["eu-ai-act-art50"]) == set(
        _CATEGORY_TO_CONTROL["eu-ai-act"]
    )


def test_rows_that_cannot_be_evidenced_cite_no_paragraph() -> None:
    """transport-security has no Art. 50 paragraph behind it, and 50(3) has no
    rule. Both say so rather than printing a citation they cannot support."""
    arm = _CATEGORY_TO_CONTROL["eu-ai-act-art50"]
    assert "Art. 50(" not in arm["transport-security"]
    assert "Supporting evidence only" in arm["transport-security"]
    assert "50(3)" in arm["legal-compliance"]
    assert "not evidenced" in arm["legal-compliance"]


def test_cited_paragraphs_exist_in_article_50() -> None:
    # Article 50 runs (1) through (7). This scanner evidences 1, 2, 4 and 5.
    real = {"50(1)", "50(2)", "50(3)", "50(4)", "50(5)"}
    for category, row in _CATEGORY_TO_CONTROL["eu-ai-act-art50"].items():
        if "50(" not in row:
            continue
        assert any(tok in row for tok in real), (category, row)


def test_scan_surfaces_art50_findings_end_to_end() -> None:
    result = run_scan(EXAMPLES / "13-eu-ai-act-art50")
    fired = {f.rule_id for f in result.findings if f.rule_id.startswith("AAK-AIACT50")}
    assert fired == set(ART50_RULES)


def test_example_fixture_matches_its_expected_findings_file() -> None:
    expected = json.loads(
        (EXAMPLES / "13-eu-ai-act-art50" / "expected-findings.json").read_text(encoding="utf-8")
    )
    assert set(expected["expectedRules"]) == _ids(EXAMPLES / "13-eu-ai-act-art50")


def test_report_cli_renders_the_art50_pack(tmp_path: Path) -> None:
    out = tmp_path / "art50.txt"
    res = CliRunner().invoke(
        cli,
        ["report", str(EXAMPLES / "13-eu-ai-act-art50"), "--framework",
         "eu-ai-act-art50", "--format", "text", "--output", str(out)],
    )
    assert res.exit_code == 0, res.output
    text = out.read_text(encoding="utf-8")
    assert "Article 50" in text
    for word in _CONCLUSION_WORDS:
        assert word not in text.lower()
