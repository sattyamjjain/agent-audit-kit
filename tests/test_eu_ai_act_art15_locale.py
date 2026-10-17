"""AAK-EU-AI-ACT-ART15-LOCALE-001 — multilingual-eval coverage tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from agent_audit_kit.models import Finding, ScanResult, Severity, Category
from agent_audit_kit.output import compliance
from agent_audit_kit.rules.builtin import get_rule
from agent_audit_kit.scanners import eu_ai_act_art15_locale

FIXTURES = Path(__file__).parent / "fixtures" / "eu_ai_act_art15_locale"
RULE_ID = "AAK-EU-AI-ACT-ART15-LOCALE-001"


def _copy(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        target = dst / entry.name
        if entry.is_dir():
            _copy(entry, target)
        else:
            shutil.copy2(entry, target)


# --------------------------------------------------------------------------
# Rule registration sanity
# --------------------------------------------------------------------------

def test_rule_registered_and_advisory() -> None:
    rule = get_rule(RULE_ID)
    assert rule.severity == Severity.INFO, "must be advisory severity"
    assert rule.category == Category.LEGAL_COMPLIANCE
    # No ASI tag — drives the Art. 15 subsection directly, not the OWASP
    # ASI-driven PASS/FAIL summary. If we tag with ASI codes the Art. 15
    # control would FAIL on a single coverage gap, which contradicts the
    # advisory intent of the rule.
    assert rule.owasp_agentic_references == [], \
        "rule must NOT carry ASI tags — surfaces as evidence, not control failure"


def test_scanner_registered_in_engine() -> None:
    from agent_audit_kit.engine import _OPTIONAL_SCANNERS
    names = {name for name, _, _ in _OPTIONAL_SCANNERS}
    assert "eu_ai_act_art15_locale" in names


# --------------------------------------------------------------------------
# Positive: multilingual user-facing config + English-only eval → fires
# --------------------------------------------------------------------------

def test_multilingual_en_only_fires(tmp_path: Path) -> None:
    _copy(FIXTURES / "multilingual_en_only", tmp_path)
    findings, _ = eu_ai_act_art15_locale.scan(tmp_path)
    matches = [f for f in findings if f.rule_id == RULE_ID]
    assert matches, "must fire on multilingual user-facing config with en-only eval"
    f = matches[0]
    assert f.severity == Severity.INFO
    assert "locales=[de, en, es, fr]" in f.evidence
    assert "fixtures cover locales=[en]" in f.evidence
    assert "2027-12-02" in f.evidence
    # The AI Omnibus (OJ L_202601744) superseded the old 2 Aug 2026 date; it must
    # not silently reappear in the evidence. The literal is built from parts so
    # this guard file itself stays clean under the acceptance grep for the old
    # superseded ISO date — the stale-date fence must not be what trips the fence.
    assert ("2026-08-" + "02") not in f.evidence
    assert f.file_path.endswith("agent.yaml")


# --------------------------------------------------------------------------
# Negative cases
# --------------------------------------------------------------------------

def test_multilingual_with_coverage_silent(tmp_path: Path) -> None:
    """When eval fixtures cover ≥2 of the declared locales, rule stays silent."""
    _copy(FIXTURES / "multilingual_with_coverage", tmp_path)
    findings, _ = eu_ai_act_art15_locale.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        "evidenced coverage must suppress AAK-EU-AI-ACT-ART15-LOCALE-001"


def test_single_locale_silent(tmp_path: Path) -> None:
    _copy(FIXTURES / "single_locale", tmp_path)
    findings, _ = eu_ai_act_art15_locale.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        "single-locale agent must not be flagged for cross-lingual gap"


def test_multilingual_internal_only_silent(tmp_path: Path) -> None:
    _copy(FIXTURES / "multilingual_internal_only", tmp_path)
    findings, _ = eu_ai_act_art15_locale.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        "non-user-facing multilingual agent must not fire (Art. 15 narrows to user-facing)"


def test_documented_risk_suppresses(tmp_path: Path) -> None:
    _copy(FIXTURES / "documented_risk", tmp_path)
    findings, _ = eu_ai_act_art15_locale.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings), \
        "accepts_locale_coverage_gap opt-out must suppress the finding"


def test_no_config_no_finding(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# unrelated repo\n", encoding="utf-8")
    findings, _ = eu_ai_act_art15_locale.scan(tmp_path)
    assert not any(f.rule_id == RULE_ID for f in findings)


# --------------------------------------------------------------------------
# Compliance report subsection
# --------------------------------------------------------------------------

def _make_result_with_finding() -> ScanResult:
    result = ScanResult()
    result.findings.append(Finding(
        rule_id=RULE_ID,
        title="Multilingual user-facing agent lacks per-locale eval coverage",
        description="…",
        severity=Severity.INFO,
        category=Category.LEGAL_COMPLIANCE,
        file_path="agent.yaml",
        line_number=1,
        evidence=(
            "Agent declares locales=[de, en, fr] for a user-facing surface; "
            "eval/test fixtures cover locales=[en]. EU AI Act Article 15 "
            "(Annex III high-risk: binding 2027-12-02; Annex I: 2028-08-02) "
            "requires per-language robustness evidence."
        ),
        remediation="…",
    ))
    return result


def test_report_subsection_renders_when_no_finding() -> None:
    """Default Art. 15 subsection lines must be present even on a clean scan
    so the report shape stays stable for auditors."""
    out = compliance.format_results(ScanResult(), "eu-ai-act")
    assert "Article 15 — Accuracy, Robustness & Cybersecurity (evidence)" in out
    assert "multilingual-locale-declared: n/a" in out
    assert "multilingual-eval-coverage: evidenced or not applicable" in out


def test_report_subsection_renders_when_finding_present() -> None:
    out = compliance.format_results(_make_result_with_finding(), "eu-ai-act")
    assert "Article 15 — Accuracy, Robustness & Cybersecurity (evidence)" in out
    assert "multilingual-locale-declared: 3 locale(s) (de, en, fr)" in out
    assert "multilingual-eval-coverage: not evidenced" in out
    assert "AAK-EU-AI-ACT-ART15-LOCALE-001" in out


def test_art15_control_not_failed_by_advisory_finding() -> None:
    """The advisory locale-coverage rule must NOT flip the Art. 15 control to
    FAIL — it has no ASI tags, so the OWASP-Agentic PASS/FAIL path ignores
    it. This is the critical invariant that lets evidence and control
    status coexist."""
    out = compliance.format_results(_make_result_with_finding(), "eu-ai-act")
    # Find the Art. 15 control block and assert Status: PASS sits above
    # the subsection.
    idx = out.find("Art. 15 - Robustness & Security")
    assert idx != -1
    block = out[idx:idx + 800]
    assert "Status: ✅ PASS" in block, \
        "Art. 15 must stay PASS even with the advisory finding present"


def test_subsection_only_under_eu_ai_act() -> None:
    """Other frameworks must NOT print the Art. 15 subsection — it's
    eu-ai-act-only."""
    for fw in ["soc2", "iso27001", "hipaa", "nist-ai-rmf"]:
        out = compliance.format_results(_make_result_with_finding(), fw)
        assert "Article 15 — Accuracy, Robustness & Cybersecurity" not in out, \
            f"framework {fw} must not emit the Art. 15 subsection"


# --------------------------------------------------------------------------
# `multilingual: true`. The rule text and the docstring promised it, but the
# key was never read, and a config naming fewer than two locales was skipped.
# --------------------------------------------------------------------------

_MULTILINGUAL = "name: support-bot\nrole: assistant\nuser_facing: true\nmultilingual: true\n"


def _locale_project(root: Path, config: str, evals: tuple[str, ...]) -> list[Finding]:
    (root / "crew.yaml").write_text(config, encoding="utf-8")
    for name in evals:
        (root / "evals").mkdir(exist_ok=True)
        (root / "evals" / name).write_text("prompt: hello\n", encoding="utf-8")
    findings, _ = eu_ai_act_art15_locale.scan(root)
    return [f for f in findings if f.rule_id == RULE_ID]


def test_multilingual_with_a_default_locale_and_one_eval_language_fires(tmp_path: Path) -> None:
    found = _locale_project(tmp_path, _MULTILINGUAL + "default_locale: en\n", ("welcome.en.yaml",))
    assert len(found) == 1
    assert "multilingual: true" in found[0].evidence
    assert "named locales=[en]" in found[0].evidence
    assert "fixtures cover locales=[en]" in found[0].evidence


def test_multilingual_naming_no_locale_fires(tmp_path: Path) -> None:
    found = _locale_project(tmp_path, _MULTILINGUAL, ())
    assert len(found) == 1
    assert "named locales=[]" in found[0].evidence
    assert "fixtures cover locales=[none]" in found[0].evidence


def test_multilingual_with_two_eval_languages_is_silent(tmp_path: Path) -> None:
    """The flag names no locale set, so any two languages the evals cover evidence it."""
    assert _locale_project(tmp_path, _MULTILINGUAL + "default_locale: en\n", ("welcome.en.yaml", "welcome.de.yaml")) == []


def test_multilingual_false_is_a_single_locale_agent(tmp_path: Path) -> None:
    config = _MULTILINGUAL.replace("multilingual: true", "multilingual: false") + "default_locale: en\n"
    assert _locale_project(tmp_path, config, ("welcome.en.yaml",)) == []


def test_multilingual_internal_agent_is_silent(tmp_path: Path) -> None:
    config = _MULTILINGUAL.replace("user_facing: true", "user_facing: false").replace("role: assistant", "role: pipeline")
    assert _locale_project(tmp_path, config, ("welcome.en.yaml",)) == []


def test_named_locales_are_judged_as_before_when_the_flag_is_set(tmp_path: Path) -> None:
    """Two or more named locales keep the named set, so the flag cannot widen
    what counts as covered: fr is declared, es is not."""
    config = _MULTILINGUAL + "locales: [en, fr, de]\n"
    found = _locale_project(tmp_path, config, ("welcome.en.yaml", "welcome.es.yaml"))
    assert len(found) == 1
    assert "locales=[de, en, fr]" in found[0].evidence


def test_the_report_reads_a_multilingual_finding(tmp_path: Path) -> None:
    """The line read "1 locale(s) (en)" for an agent that declared itself multilingual."""
    result = ScanResult()
    result.findings.extend(_locale_project(tmp_path, _MULTILINGUAL + "default_locale: en\n", ("welcome.en.yaml",)))
    out = compliance.format_results(result, "eu-ai-act")
    assert "multilingual-locale-declared: multilingual: true, 1 named locale(s) (en)" in out
    assert "multilingual-eval-coverage: not evidenced — covered=[en]" in out


def test_a_tools_multilingual_flag_is_not_the_agents(tmp_path: Path) -> None:
    """Read anywhere, a tool's own `multilingual: true` counted as the agent's."""
    config = (
        "name: support-bot\nrole: assistant\nuser_facing: true\ndefault_locale: en\n"
        "tools:\n  - name: translate\n    multilingual: true\n"
    )
    assert _locale_project(tmp_path, config, ("welcome.en.yaml",)) == []


def test_an_agent_entrys_multilingual_flag_counts(tmp_path: Path) -> None:
    """A CrewAI-style entry: the flag sits beside the agent's own role."""
    config = "support:\n  role: assistant\n  goal: help customers\n  multilingual: true\n"
    assert len(_locale_project(tmp_path, config, ("welcome.en.yaml",))) == 1
