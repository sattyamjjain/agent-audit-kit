"""Colorado SB 26-189 developer-documentation evidence (AAK-ADMT-001..004).

The statute is C.R.S. 6-1-1702, read from the signed act on 2026-09-12
(https://leg.colorado.gov/bill_files/116489/download). Two properties matter
more than coverage here:

1. The scanner is silent unless the project's own declarations name both an
   inference and a 6-1-1701(6) covered domain. A false positive is an
   accusation of breaking a consumer-protection statute.
2. The pack never prints a conformity conclusion. Producing evidence toward a
   duty and determining that the duty is satisfied are different acts, and only
   the first is available to a static scan.
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
from agent_audit_kit.scanners import admt_documentation

FIXTURES = Path(__file__).parent / "fixtures" / "admt"
EXAMPLES = Path(__file__).parent.parent / "examples" / "vulnerable-configs"

ADMT_RULES = ("AAK-ADMT-001", "AAK-ADMT-002", "AAK-ADMT-003", "AAK-ADMT-004")


def _ids(project: Path) -> list[str]:
    findings, _ = admt_documentation.scan(project)
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# Each rule fires on its fixture
# ---------------------------------------------------------------------------


def test_admt_001_fires_when_no_documentation_exists() -> None:
    assert _ids(FIXTURES / "no_documentation") == ["AAK-ADMT-001"]


def test_admt_001_fires_on_a_tool_decorated_declaration() -> None:
    """The declaration surface includes a tool docstring, not only MCP config."""
    assert _ids(FIXTURES / "tool_decorator") == ["AAK-ADMT-001"]


def test_admt_002_003_004_fire_on_a_thin_model_card() -> None:
    fired = set(_ids(EXAMPLES / "12-colorado-admt"))
    assert fired == {"AAK-ADMT-002", "AAK-ADMT-003", "AAK-ADMT-004"}


def test_admt_001_does_not_fire_when_documentation_exists() -> None:
    """001 is 'no documentation at all'. It must not double-report with 002-004."""
    assert "AAK-ADMT-001" not in _ids(EXAMPLES / "12-colorado-admt")


def test_complete_card_answers_every_documentation_duty() -> None:
    assert _ids(FIXTURES / "complete_card") == []


# ---------------------------------------------------------------------------
# Silence where nothing declares a covered-domain decision
# ---------------------------------------------------------------------------


def test_no_declared_surface_emits_nothing() -> None:
    assert _ids(FIXTURES / "no_declaration") == []


def test_carved_out_surface_emits_nothing() -> None:
    """6-1-1701(3)(b)(I) excludes routine scheduling and customer-service triage."""
    assert _ids(FIXTURES / "excluded_surface") == []


def test_covered_domain_without_an_inference_emits_nothing() -> None:
    """6-1-1701(3)(b)(IV) excludes presenting information without producing a
    score, ranking, recommendation, classification or prediction."""
    assert _ids(FIXTURES / "domain_without_inference") == []


def test_a_declaration_in_a_subdirectory_is_found() -> None:
    """MCP configs are read recursively, like tool declarations already were.

    Reading them only at the project root made the same project answer
    differently depending on which surface carried the declaration. The 0.5.0
    smoke test scanned examples/vulnerable-configs and saw nothing, because the
    declaration sat one directory down.
    """
    assert _ids(FIXTURES / "nested_declaration") == ["AAK-ADMT-001"]


def test_scanning_the_examples_root_reaches_the_colorado_fixture() -> None:
    fired = {r for r in _ids(EXAMPLES) if r.startswith("AAK-ADMT")}
    assert fired == {"AAK-ADMT-002", "AAK-ADMT-003", "AAK-ADMT-004"}


def test_licence_fixture_stays_clean() -> None:
    """11-legal-compliance is a licence fixture and must not gain ADMT findings."""
    assert _ids(EXAMPLES / "11-legal-compliance") == []


def test_an_undecorated_helper_is_not_a_declaration() -> None:
    """`helper_not_a_tool` in the fixture names rental applicants and eligibility.

    It is not tool-decorated, so it is not a declaration. Describing a decision
    is not declaring one.
    """
    source = (FIXTURES / "tool_decorator" / "server.py").read_text(encoding="utf-8")
    assert "helper_not_a_tool" in source
    assert "rental applicants" in source
    declaration = admt_documentation._find_declaration(FIXTURES / "tool_decorator")
    assert declaration is not None
    assert "helper_not_a_tool" not in declaration[1]


def test_scanner_is_silent_on_this_repository() -> None:
    """A security scanner describing prior-authorization denials in its own rule
    catalog is not an ADMT. An earlier draft read whole files and picked exactly
    that up.
    """
    repo = Path(__file__).parent.parent
    findings, _ = admt_documentation.scan(repo)
    offenders = [f for f in findings if not f.file_path.startswith("tests/fixtures")]
    assert offenders == [], offenders


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "project",
    [FIXTURES / "no_documentation", EXAMPLES / "12-colorado-admt"],
)
def test_two_scans_are_identical_in_order_and_content(project: Path) -> None:
    first, first_files = admt_documentation.scan(project)
    second, second_files = admt_documentation.scan(project)
    assert [f.rule_id for f in first] == [f.rule_id for f in second]
    assert [f.file_path for f in first] == [f.file_path for f in second]
    assert [f.evidence for f in first] == [f.evidence for f in second]
    assert first_files == second_files


# ---------------------------------------------------------------------------
# The pack states evidence, never a conclusion
# ---------------------------------------------------------------------------

_CONCLUSION_WORDS = ("compliant", "conforms", "certified")


def test_rendered_report_prints_no_conformity_conclusion(tmp_path: Path) -> None:
    result = run_scan(EXAMPLES / "12-colorado-admt")
    text = _text_report(result, "colorado-admt").lower()
    for word in _CONCLUSION_WORDS:
        assert word not in text, f"report claims conformity: {word!r}"


def test_rule_text_states_evidence_not_determination() -> None:
    for rule_id in ADMT_RULES:
        rule = RULES[rule_id]
        blob = f"{rule.description} {rule.remediation}".lower()
        for word in _CONCLUSION_WORDS:
            assert word not in blob, (rule_id, word)
    # Each rule says out loud that it is not a determination.
    for rule_id in ADMT_RULES:
        assert "determination" in RULES[rule_id].description.lower()


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


def test_all_four_rules_are_registered_under_legal_compliance() -> None:
    for rule_id in ADMT_RULES:
        assert rule_id in RULES
        assert RULES[rule_id].category.value == "legal-compliance"
        assert RULES[rule_id].severity.value == "medium"
        assert RULES[rule_id].sarif_name


def test_framework_arm_covers_the_same_categories_as_its_peers() -> None:
    assert set(_CATEGORY_TO_CONTROL["colorado-admt"]) == set(
        _CATEGORY_TO_CONTROL["alabama-dppa"]
    )
    assert "2027-01-01" in _FRAMEWORK_TITLES["colorado-admt"]


def test_rows_that_cannot_be_evidenced_carry_no_subsection() -> None:
    """a2a-protocol has no developer duty in 6-1-1702 behind it.

    The row says so instead of printing a control number, which is the whole
    reason the arm is hand-written rather than filled in for symmetry.
    """
    row = _CATEGORY_TO_CONTROL["colorado-admt"]["a2a-protocol"]
    assert "6-1-1702(" not in row
    assert "no developer subsection" in row


def test_every_other_row_cites_a_subsection_that_exists_in_the_act() -> None:
    # Subsections read from the signed act on 2026-09-12. 6-1-1702 runs (1)(a)
    # through (1)(e), (2)(a), (2)(b), (3), (4) and (5).
    real = {
        "6-1-1702(1)(a)", "6-1-1702(1)(b)", "6-1-1702(1)(c)", "6-1-1702(1)(d)",
        "6-1-1702(1)(e)", "6-1-1702(2)(a)", "6-1-1702(4)",
        "6-1-1702(1)(a)-(d)",
    }
    for category, row in _CATEGORY_TO_CONTROL["colorado-admt"].items():
        if "6-1-1702(" not in row:
            continue
        cited = [token for token in real if token in row]
        assert cited, (category, row)


def test_scan_surfaces_admt_findings_end_to_end() -> None:
    result = run_scan(EXAMPLES / "12-colorado-admt")
    assert {f.rule_id for f in result.findings if f.rule_id.startswith("AAK-ADMT")} == {
        "AAK-ADMT-002", "AAK-ADMT-003", "AAK-ADMT-004",
    }


def test_example_fixture_matches_its_expected_findings_file() -> None:
    expected = json.loads(
        (EXAMPLES / "12-colorado-admt" / "expected-findings.json").read_text(encoding="utf-8")
    )
    fired = set(_ids(EXAMPLES / "12-colorado-admt"))
    assert set(expected["expectedRules"]) == fired
    assert len(fired) >= expected["expectedMinFindings"]


def test_report_cli_renders_the_colorado_pack(tmp_path: Path) -> None:
    out = tmp_path / "colorado.txt"
    res = CliRunner().invoke(
        cli,
        ["report", str(EXAMPLES / "12-colorado-admt"), "--framework", "colorado-admt",
         "--format", "text", "--output", str(out)],
    )
    assert res.exit_code == 0, res.output
    text = out.read_text(encoding="utf-8")
    assert "Colorado SB 26-189" in text
    for word in _CONCLUSION_WORDS:
        assert word not in text.lower()
