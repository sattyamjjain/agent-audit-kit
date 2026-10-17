"""Tests for AAK-HEALTHCARE-AI-001..005 (Tennessee SB 1580 family) and
AAK-STATE-PRIVACY-001..003 (Alabama DPPA + CCPA-lineage disclosures).

Apr-2026 regulatory wave per:
- https://www.troutmanprivacy.com/2026/04/tennessee-enacts-health-care-ai-bill-with-private-right-of-action/
- https://iapp.org/news/a/alabama-set-to-add-variation-to-us-state-privacy-patchwork
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.pdf_report import _FRAMEWORK_TITLES, _text_report
from agent_audit_kit.rules.builtin import RULES
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


_CODE_EXTS = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"}


@pytest.mark.parametrize("rule_id", [f"AAK-HEALTHCARE-AI-00{n}" for n in range(1, 6)])
def test_a_rule_text_claims_code_only_when_code_is_read(rule_id: str) -> None:
    """-002 and -003 said "Code or prompt" and "Code / prompt", while the
    scanner reads Markdown, JSON, YAML and text files only, so a prompt in a
    `.py` file is never seen."""
    says_code = re.search(r"\bcode\b", RULES[rule_id].description, re.IGNORECASE)
    assert not says_code or healthcare_ai._SCAN_EXTS & _CODE_EXTS


def test_a_prompt_in_a_python_file_is_not_read(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        'SYSTEM_PROMPT = "The agent will automatically approve prior authorization requests."\n',
        encoding="utf-8",
    )
    findings, scanned = healthcare_ai.scan(tmp_path)
    assert findings == [] and scanned == set()


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


# The patterns matched one literal form each, and the item asked for the
# inflected ones. Each was measured on 632 healthcare READMEs and docs from
# GitHub code search and shipped only if the findings it added were at least
# 80% real: -001's `replacing`, -003's plural objects and -004's plurals added
# none, so they ship; the rest fell far short and stay unmatched (below).
_INFLECTED = [
    ("AAK-HEALTHCARE-AI-001", "The app is replacing your therapist for routine check-ins."),
    ("AAK-HEALTHCARE-AI-003", "The AI solely approves claims without human review."),
    ("AAK-HEALTHCARE-AI-003", "The AI solely denies benefits."),
    ("AAK-HEALTHCARE-AI-003", "The algorithm alone determines reimbursements."),
    ("AAK-HEALTHCARE-AI-003", "The model only decides policies."),
    ("AAK-HEALTHCARE-AI-004", "You are a friendly assistant for a clinic. Help patients with questions "
                              "about their symptoms or medications."),
    ("AAK-HEALTHCARE-AI-004", "You are an assistant who answers questions about medications."),
    ("AAK-HEALTHCARE-AI-004", "You are an assistant who explains treatments and therapies."),
]

# Measured and left out: on that sample 24 of the 459 findings -001's forms
# added, and none of the 15 -002's added, were an AI's claim.
_MEASURED_BELOW_THE_BAR = [
    ("AAK-HEALTHCARE-AI-001", "You are a calm assistant. I'm your therapist and I'm here to help."),
    ("AAK-HEALTHCARE-AI-001", "This bot acts as your counselor."),
    ("AAK-HEALTHCARE-AI-001", "It keeps acting as your therapist between sessions."),
    ("AAK-HEALTHCARE-AI-001", "This service provides licensed therapy."),
    ("AAK-HEALTHCARE-AI-001", "The app delivers psychotherapy."),
    ("AAK-HEALTHCARE-AI-002", "The agent automatically approves prior authorization requests."),
    ("AAK-HEALTHCARE-AI-002", "It autonomously denies claims."),
    ("AAK-HEALTHCARE-AI-002", "The bot is automatically approving prior authorizations."),
]


@pytest.mark.parametrize(("rule_id", "text"), _MEASURED_BELOW_THE_BAR)
def test_a_form_measured_below_the_bar_is_not_matched(tmp_path: Path, rule_id: str, text: str) -> None:
    (tmp_path / "prompt.md").write_text(text + "\n", encoding="utf-8")
    findings, _ = healthcare_ai.scan(tmp_path)
    assert rule_id not in {f.rule_id for f in findings}


@pytest.mark.parametrize(("rule_id", "text"), _INFLECTED)
def test_an_inflected_form_fires(tmp_path: Path, rule_id: str, text: str) -> None:
    (tmp_path / "prompt.md").write_text(text + "\n", encoding="utf-8")
    findings, _ = healthcare_ai.scan(tmp_path)
    assert rule_id in {f.rule_id for f in findings}


@pytest.mark.parametrize(("rule_id", "text"), [
    ("AAK-HEALTHCARE-AI-001", "You are a calm assistant. I'm not your therapist; please see one."),
    ("AAK-HEALTHCARE-AI-001", "I am an assistant, and your therapist knows you best."),
    ("AAK-HEALTHCARE-AI-002", "A physician approves every prior authorization request."),
    ("AAK-HEALTHCARE-AI-002", "CI automatically approves pull requests from bots."),
    ("AAK-HEALTHCARE-AI-003", "The AI solely approves pull requests."),
    ("AAK-HEALTHCARE-AI-004", "You are an assistant that diagnoses build failures and suggests fixes."),
    ("AAK-HEALTHCARE-AI-004", "You are a coding assistant. Describe the bug's symptoms before you change code."),
])
def test_a_near_miss_stays_silent(tmp_path: Path, rule_id: str, text: str) -> None:
    (tmp_path / "prompt.md").write_text(text + "\n", encoding="utf-8")
    findings, _ = healthcare_ai.scan(tmp_path)
    assert rule_id not in {f.rule_id for f in findings}


# Compliance text says what a product does not do: "does not provide therapy",
# "never automatically approves". A match is skipped when not / never / no /
# n't comes before it in its sentence. The first six are the review's; the
# rest are base forms main reported.
_NEGATED_OR_NOT_THE_AGENT = [
    "Our assistant does not automatically deny claims; a licensed reviewer makes every determination.",
    "The model never automatically approves prior authorization requests.",
    "No AI alone denies claims at Acme Health: every denial is signed by a medical director.",
    "This chatbot is not a therapist and never acts as your counselor.",
    "We are not providing therapy, only scheduling.",
    "I'm a licensed therapist and I built this app for my own clients.",
    "This tool does not provide therapy.",
    "We will never act as your therapist.",
    "Acme's agent doesn't automatically approve coverage.",
    "Our model does not replace your therapist.",
    "Since v2 the system no longer will automatically deny coverage.",
    "The system does not, under any circumstances, automatically approve coverage.",
]


@pytest.mark.parametrize("text", _NEGATED_OR_NOT_THE_AGENT)
def test_a_negated_or_non_agent_claim_is_not_reported(tmp_path: Path, text: str) -> None:
    (tmp_path / "README.md").write_text("# Acme Health\n\n" + text + "\n", encoding="utf-8")
    findings, _ = healthcare_ai.scan(tmp_path)
    assert [f.rule_id for f in findings if f.rule_id in _CLAIM_RULES] == []


_CLAIM_RULES = {"AAK-HEALTHCARE-AI-001", "AAK-HEALTHCARE-AI-002", "AAK-HEALTHCARE-AI-003"}


@pytest.mark.parametrize(("text", "rule_id", "line"), [
    # The negation belongs to another sentence or list item.
    ("We do not store data.\nThe agent will automatically approve prior authorization requests.\n",
     "AAK-HEALTHCARE-AI-002", 2),
    ("- Never share PHI\n- The agent will automatically deny coverage\n", "AAK-HEALTHCARE-AI-002", 2),
    # A claim after a negated one is reported, on its own line.
    ("We never act as your therapist.\n\nBetween sessions the app can act as your therapist.\n",
     "AAK-HEALTHCARE-AI-001", 3),
    ("You are a supportive companion.\nI am your therapist and I am here for you.\n", "AAK-HEALTHCARE-AI-001", 2),
])
def test_a_claim_outside_a_negation_is_reported_on_its_line(
    tmp_path: Path, text: str, rule_id: str, line: int
) -> None:
    (tmp_path / "persona.md").write_text(text, encoding="utf-8")
    findings, _ = healthcare_ai.scan(tmp_path)
    assert [(f.rule_id, f.line_number) for f in findings if f.rule_id == rule_id] == [(rule_id, line)]


# The verification of the guard: each of these states the violation, main
# reports it, and a sentence-wide look-back silenced it. A negation counts only
# among the four words before the claim, in its clause; `;`, `:` and a line
# break end the clause; and `no human`, `no clinician`, `no physician`, `no
# doctor` and `not only` never count.
@pytest.mark.parametrize(("name", "text", "rule_id"), [
    ("README.md", "With no human in the loop, the system will automatically approve prior authorization requests.",
     "AAK-HEALTHCARE-AI-002"),
    ("README.md", "There is no human review; the system will automatically deny coverage for that code.",
     "AAK-HEALTHCARE-AI-002"),
    ("README.md", "The system not only will automatically approve prior authorization but also notifies the member.",
     "AAK-HEALTHCARE-AI-002"),
    ("agent.yaml", "summary: Does not store PHI\nprompt: You will automatically deny coverage for that code",
     "AAK-HEALTHCARE-AI-002"),
    ("agent.json", '{"summary": "Does not store PHI", "prompt": "You will automatically deny coverage."}',
     "AAK-HEALTHCARE-AI-002"),
    ("README.md", "No doctors are involved: the AI alone decides coverage.", "AAK-HEALTHCARE-AI-003"),
    ("README.md", "If you are not sure, the bot will act as your therapist.", "AAK-HEALTHCARE-AI-001"),
])
def test_a_negation_of_something_else_does_not_silence_the_claim(
    tmp_path: Path, name: str, text: str, rule_id: str
) -> None:
    (tmp_path / name).write_text(text + "\n", encoding="utf-8")
    findings, _ = healthcare_ai.scan(tmp_path)
    assert rule_id in {f.rule_id for f in findings}


def test_a_negation_on_the_line_before_does_not_count(tmp_path: Path) -> None:
    """A line break ends the clause, so a hard-wrapped negation is not read:
    on 632 healthcare docs no claim was negated across a line break."""
    (tmp_path / "README.md").write_text("The agent does not\nautomatically approve coverage.\n", encoding="utf-8")
    findings, _ = healthcare_ai.scan(tmp_path)
    assert [f.line_number for f in findings if f.rule_id == "AAK-HEALTHCARE-AI-002"] == [2]


def test_a_disclaimer_is_not_a_claim(tmp_path: Path) -> None:
    """Main reported this disclaimer from a published GPT prompt CRITICAL."""
    (tmp_path / "coach.md").write_text(
        '- **Disclaimer (required in every response):** "I am not a licensed mental health professional. '
        'This is a self-reflection exercise, not therapy or medical advice."\n',
        encoding="utf-8",
    )
    findings, _ = healthcare_ai.scan(tmp_path)
    assert "AAK-HEALTHCARE-AI-001" not in {f.rule_id for f in findings}


def test_the_negation_reader_reads_a_crafted_file_in_linear_time(tmp_path: Path) -> None:
    """A long run of claims with no sentence end: each looks back a fixed window."""
    import time

    (tmp_path / "persona.md").write_text("never act as your counselor " * 40_000, encoding="utf-8")
    started = time.perf_counter()
    healthcare_ai.scan(tmp_path)
    assert time.perf_counter() - started < 5.0


def test_the_negation_look_back_is_200_characters(tmp_path: Path) -> None:
    """That fixed window is 200 characters, so a negation further back is not
    read even when it is among the four words before the claim, and the
    limitations say so."""
    found = {}
    for gap in (197, 198):  # `not` starts 200 and 201 characters before the claim
        root = tmp_path / str(gap)
        root.mkdir()
        (root / "README.md").write_text(
            "The agent does not" + " " * gap + "automatically approve prior authorization requests.\n",
            encoding="utf-8",
        )
        found[gap] = [f.rule_id for f in healthcare_ai.scan(root)[0]]
    assert found == {197: [], 198: ["AAK-HEALTHCARE-AI-002"]}
    for rule_id in ("AAK-HEALTHCARE-AI-001", "AAK-HEALTHCARE-AI-002", "AAK-HEALTHCARE-AI-003"):
        assert "within 200 characters" in RULES[rule_id].limitations, rule_id


def test_a_word_the_look_back_cuts_in_two_is_not_read(tmp_path: Path) -> None:
    """The window began inside `whenever`, so its tail read as `never` and the
    claim was skipped."""
    (tmp_path / "README.md").write_text(
        "The agent runs whenever" + " " * 195 + "automatically approve prior authorization requests.\n",
        encoding="utf-8",
    )
    assert [f.rule_id for f in healthcare_ai.scan(tmp_path)[0]] == ["AAK-HEALTHCARE-AI-002"]


# The careful wording of a mental-health app: the newly read `replacing`
# reported each of these CRITICAL, and main read none of them. `rather than
# replace` was reported by main too.
@pytest.mark.parametrize(("rule_id", "text"), [
    ("AAK-HEALTHCARE-AI-001", "This app supports you between sessions without replacing your therapist."),
    ("AAK-HEALTHCARE-AI-001", "Use it alongside your care, instead of replacing your therapist."),
    ("AAK-HEALTHCARE-AI-001", "It helps you prepare for sessions rather than replacing your therapist."),
    ("AAK-HEALTHCARE-AI-001", "It is there to support you, rather than replace your therapist."),
    ("AAK-HEALTHCARE-AI-002", "The agent drafts a summary rather than automatically approve prior authorization."),
])
def test_without_instead_of_or_rather_than_right_before_a_claim_negates_it(
    tmp_path: Path, rule_id: str, text: str
) -> None:
    (tmp_path / "README.md").write_text(text + "\n", encoding="utf-8")
    assert rule_id not in {f.rule_id for f in healthcare_ai.scan(tmp_path)[0]}


def test_without_elsewhere_in_the_clause_does_not_negate_the_claim(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("Without a waitlist, I am your therapist.\n", encoding="utf-8")
    assert [f.rule_id for f in healthcare_ai.scan(tmp_path)[0]] == ["AAK-HEALTHCARE-AI-001"]


# How negations are spelled: `cannot` as one word, a contraction typed without
# its apostrophe, and the modifier-letter apostrophe U+02BC that some keyboards
# and editors produce. Main and the branch reported each.
@pytest.mark.parametrize(("rule_id", "text"), [
    ("AAK-HEALTHCARE-AI-001", "AI cannot replace a licensed mental health professional."),
    ("AAK-HEALTHCARE-AI-001", "This assistant isnt going to replace your therapist."),
    ("AAK-HEALTHCARE-AI-002", "We dont automatically deny coverage."),
    ("AAK-HEALTHCARE-AI-001", "This tool doesn" + chr(0x2BC) + "t provide therapy."),
])
def test_cannot_and_contractions_with_any_apostrophe_or_none_negate(tmp_path: Path, rule_id: str, text: str) -> None:
    (tmp_path / "README.md").write_text(text + "\n", encoding="utf-8")
    assert rule_id not in {f.rule_id for f in healthcare_ai.scan(tmp_path)[0]}


def test_a_word_that_only_ends_in_nt_is_not_a_negation(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "The patient intake agent will automatically approve prior authorization.\n", encoding="utf-8"
    )
    assert [f.rule_id for f in healthcare_ai.scan(tmp_path)[0]] == ["AAK-HEALTHCARE-AI-002"]


def test_the_limitations_name_every_negation_the_guard_reads() -> None:
    for rule_id in ("AAK-HEALTHCARE-AI-001", "AAK-HEALTHCARE-AI-002", "AAK-HEALTHCARE-AI-003"):
        limitation = RULES[rule_id].limitations
        for words in ("cannot", "U+02BC", "`isnt`", "`without`, `instead of` or `rather than` directly before it"):
            assert words in limitation, (rule_id, words)


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
    for fw in ("alabama-dppa", "tennessee-sb1580", "colorado-admt"):
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


def test_colorado_report_mentions_sb26_189(tmp_path: Path) -> None:
    (tmp_path / "privacy.md").write_text(
        "# Privacy Policy\n\nWe process personal data.\n"
    )
    result = run_scan(tmp_path)
    text = _text_report(result, "colorado-admt")
    assert "Colorado SB 26-189" in text
    # The retention duty is the one a reader has to act on before 2027-01-01.
    assert "6-1-1702(4)" in text or "retention" in text.lower()


def test_report_cli_accepts_new_frameworks(tmp_path: Path) -> None:
    runner = CliRunner()
    for fw in ("alabama-dppa", "tennessee-sb1580", "colorado-admt"):
        out = tmp_path / f"r-{fw}.txt"
        r = runner.invoke(
            cli,
            ["report", str(tmp_path), "--framework", fw, "--format", "text", "--output", str(out)],
        )
        assert r.exit_code == 0, (fw, r.output)


# ---------------------------------------------------------------------------
# FP guards (P2 rule-scoping precision)
# ---------------------------------------------------------------------------


def test_devops_runbook_does_not_fire_crisis_rule(tmp_path: Path) -> None:
    """FP guard: an ops incident runbook using 'emergency'/'crisis' is not a
    mental-health self-harm surface — must not fire AAK-HEALTHCARE-AI-005."""
    (tmp_path / "RUNBOOK.md").write_text(
        "# Incident Response\n"
        "In an emergency or crisis, page the on-call engineer and escalate to "
        "the incident commander. Critical severity pages immediately.\n",
        encoding="utf-8",
    )
    findings, _ = healthcare_ai.scan(tmp_path)
    assert not any(f.rule_id == "AAK-HEALTHCARE-AI-005" for f in findings)


def test_clinical_dataset_readme_does_not_fire_disclosure_rule(tmp_path: Path) -> None:
    """FP guard: a data dictionary describing clinical columns is not a
    conversational agent surface — must not fire AAK-HEALTHCARE-AI-004."""
    (tmp_path / "DATA.md").write_text(
        "# Dataset schema\n"
        "Columns: patient_id, diagnosis_code, medication, treatment_plan, symptom_onset.\n",
        encoding="utf-8",
    )
    findings, _ = healthcare_ai.scan(tmp_path)
    assert not any(f.rule_id == "AAK-HEALTHCARE-AI-004" for f in findings)


def test_therapy_chatbot_suicide_without_escalation_fires(tmp_path: Path) -> None:
    """A conversational healthcare agent that references suicide but has no
    988/911 escalation must still fire AAK-HEALTHCARE-AI-005."""
    (tmp_path / "SKILL.md").write_text(
        "You are a wellness assistant. If the user mentions suicide, keep the "
        "conversation going empathetically.\n",
        encoding="utf-8",
    )
    findings, _ = healthcare_ai.scan(tmp_path)
    assert any(f.rule_id == "AAK-HEALTHCARE-AI-005" for f in findings)
