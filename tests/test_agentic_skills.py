"""OWASP Agentic Skills Top 10 (AST10) — the statically decidable subset.

Three rules, not ten. The count is the point: AST10 names ten risks and only some
of them are a static question, so this family ships the ones where a check over a
skill bundle gives a deterministic answer and the README says plainly which seven
it does not cover.

Three categories were already covered before the family existed and are
deliberately not re-implemented — AST01 and the semantic half of AST04 by
``AAK-SKILL-*`` and ``AAK-POISON-*``, AST03 by ``AAK-COMPOSE-003``. The tests
below hold that, because the obvious way to "complete" this family later is to
add rules that report a second time what another rule already found.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_audit_kit.models import Category
from agent_audit_kit.output.owasp_report import OWASP_AST
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import agentic_skills
from agent_audit_kit.scanners.agentic_skills import COVERED_AST_CATEGORIES, scan

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "agentic_skills"

PROVENANCE = "AAK-AST02-001"
METADATA = "AAK-AST04-001"
CROSS_PLATFORM = "AAK-AST10-001"
FAMILY = (PROVENANCE, METADATA, CROSS_PLATFORM)


def _ids(arm: str) -> set[str]:
    findings, _ = scan(FIXTURES / arm)
    return {f.rule_id for f in findings}


def _evidence(arm: str, rule_id: str) -> str:
    findings, _ = scan(FIXTURES / arm)
    return next(f.evidence for f in findings if f.rule_id == rule_id)


# ---------------------------------------------------------------------------
# The malicious bundle: every rule fires
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", FAMILY)
def test_malicious_bundle_fires_every_rule(rule_id: str) -> None:
    assert rule_id in _ids("malicious")


def test_provenance_names_the_unpinned_resource() -> None:
    """A finding that says "something is unpinned" is not actionable."""
    evidence = _evidence("malicious", PROVENANCE)
    assert "git ref that moves" in evidence
    assert "github.com/acme/invoice-fmt" in evidence


def test_metadata_names_the_deserialization_tag() -> None:
    evidence = _evidence("malicious", METADATA)
    assert "!!python/object" in evidence


def test_cross_platform_reports_ast10s_own_headline_scenario() -> None:
    """AST10's first attack scenario, in the fixture and in the evidence.

    "A skill with ``risk_tier: L3`` is ported to a platform that doesn't support
    ``risk_tier``; the warning is silently dropped." If the fixture stops
    demonstrating that, the rule is only being tested on the weaker-value arm.
    """
    evidence = _evidence("malicious", CROSS_PLATFORM)
    assert "risk tier declared in skill.json" in evidence
    assert "absent from manifest.json" in evidence
    assert "weaker in manifest.json" in evidence


# ---------------------------------------------------------------------------
# The clean bundle: nothing fires. A family with no true negative is untested.
# ---------------------------------------------------------------------------


def test_clean_bundle_is_silent() -> None:
    ids = _ids("clean")
    assert not (ids & set(FAMILY)), f"clean bundle reported {sorted(ids)}"


def test_the_clean_bundle_is_actually_exercising_all_three_manifests() -> None:
    """Guard the guard.

    A clean result proves nothing if the bundle never parsed. The malicious
    fixture's frontmatter is rejected by safe parsing (it carries a
    deserialization tag), so if the clean one silently failed to parse too, the
    cross-platform negative would pass for the wrong reason.
    """
    bundles = agentic_skills._bundles(FIXTURES / "clean")
    assert len(bundles) == 1
    assert sorted(bundles[0].manifests) == ["SKILL.md", "manifest.json", "skill.json"]


def test_malicious_frontmatter_does_not_parse_and_that_is_recorded() -> None:
    """The interaction between AST04 and AST10, asserted rather than assumed.

    Frontmatter carrying a deserialization tag is rejected by safe parsing, so
    that manifest drops out of the cross-platform comparison. That is correct —
    the scanner must not use an unsafe loader to read it — but it means AST10
    silently sees one fewer manifest, which AST10's `limitations` has to say.
    """
    bundles = agentic_skills._bundles(FIXTURES / "malicious")
    assert "SKILL.md" not in bundles[0].manifests
    assert "does not parse" in RULES[CROSS_PLATFORM].limitations
    assert METADATA in RULES[CROSS_PLATFORM].limitations


def test_pinned_bundle_clears_provenance(tmp_path: Path) -> None:
    """The rule is about pinning, not about mentioning a URL."""
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: s\ndescription: d\n---\n\n"
        "Install: `npm install invoice-fmt@2.4.1`\n"
        "Docs: https://github.com/acme/invoice-fmt/blob/main/README.md\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert PROVENANCE not in {f.rule_id for f in findings}


def test_single_manifest_bundle_is_out_of_scope_for_cross_platform(tmp_path: Path) -> None:
    """Nothing to disagree with. Reporting here would be a rule with no predicate."""
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: s\ndescription: d\nrisk_tier: L1\n---\n\nBody.\n", encoding="utf-8"
    )
    findings, _ = scan(tmp_path)
    assert CROSS_PLATFORM not in {f.rule_id for f in findings}


def test_differing_permission_lists_are_left_alone(tmp_path: Path) -> None:
    """Two non-empty lists that differ need a judgement this rule will not make.

    Deciding which of ``["read"]`` and ``["write"]`` is weaker is exactly the
    guessing the family exists to avoid, so only the unambiguous directions are
    reported.
    """
    skill_dir = tmp_path / "skills" / "s"
    skill_dir.mkdir(parents=True)
    (skill_dir / "skill.json").write_text(
        json.dumps({"name": "s", "permissions": ["read"]}), encoding="utf-8"
    )
    (skill_dir / "manifest.json").write_text(
        json.dumps({"name": "s", "permissions": ["write"]}), encoding="utf-8"
    )
    (skill_dir / "SKILL.md").write_text(
        "---\nname: s\ndescription: d\npermissions: [read]\n---\n\nBody.\n",
        encoding="utf-8",
    )
    findings, _ = scan(tmp_path)
    assert CROSS_PLATFORM not in {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# Registry contract and honest coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", FAMILY)
def test_rule_is_registered_in_the_agentic_skill_category(rule_id: str) -> None:
    assert rule_id in RULES
    assert RULES[rule_id].category is Category.AGENTIC_SKILL


@pytest.mark.parametrize("rule_id", FAMILY)
def test_rule_carries_its_ast_category(rule_id: str) -> None:
    refs = RULES[rule_id].owasp_ast_references
    assert refs, f"{rule_id} must record which AST10 category it covers"
    for ref in refs:
        assert ref in OWASP_AST, f"{ref} is not an AST10 category"


@pytest.mark.parametrize("rule_id", FAMILY)
def test_rule_states_its_limitations(rule_id: str) -> None:
    limitations = RULES[rule_id].limitations
    assert limitations
    assert "static" in limitations.lower()


def test_ast_taxonomy_has_exactly_the_ten_categories_owasp_publishes() -> None:
    """Read from the OWASP repo's own ast01.md..ast10.md, not paraphrased."""
    assert list(OWASP_AST) == [f"AST{i:02d}" for i in range(1, 11)]
    assert OWASP_AST["AST02"] == "Supply Chain Compromise"
    assert OWASP_AST["AST10"] == "Cross-Platform Reuse"


def test_covered_categories_match_what_the_rules_actually_claim() -> None:
    """The README's coverage table is only honest if this holds.

    ``COVERED_AST_CATEGORIES`` is what the module advertises; the union of the
    rules' own references is what it delivers. If they drift, the README states a
    coverage number no rule backs.
    """
    claimed = {ref for rid in FAMILY for ref in RULES[rid].owasp_ast_references}
    assert claimed == set(COVERED_AST_CATEGORIES)


def test_coverage_is_partial_and_not_padded() -> None:
    """Three deterministic rules, not ten that guess.

    If someone later adds seven rules to "complete" the table, this fails and
    they have to justify each one against the deterministic bar rather than the
    count.
    """
    assert len(FAMILY) == 3
    assert len(set(COVERED_AST_CATEGORIES)) < len(OWASP_AST)


def test_the_family_does_not_duplicate_rules_that_already_cover_a_category() -> None:
    """AST01, AST03 and the semantic half of AST04 were already covered.

    ``AAK-COMPOSE-003`` is declared-vs-actual capability mismatch and
    ``AAK-SKILL-005`` reads frontmatter values for injection triggers. Neither is
    re-implemented here, and both must still exist for the README's "covered
    elsewhere" column to be true.
    """
    assert "AAK-COMPOSE-003" in RULES
    assert "AAK-SKILL-005" in RULES
    for rule_id in FAMILY:
        assert "AST01" not in RULES[rule_id].owasp_ast_references
        assert "AST03" not in RULES[rule_id].owasp_ast_references


@pytest.mark.parametrize(("text", "found"), [
    ("npm install left-pad\n", "npm install left-pad\n"),
    ("pip install requests==2.32.0\n", None),
    ("npm install --save-dev\n", "npm install --save-dev\n"),     # the flag reads as the target
    ("npm i --a\n--b ==1\n", "npm i --a\n"),                     # a marker on a later line
    ("cargo install --locked ripgrep\n", "cargo install --locked ripgrep\n"),
])
def test_install_arm_finds_what_it_did(text: str, found: str | None) -> None:
    assert agentic_skills._unpinned_install(text) == found


@pytest.mark.parametrize("text", [
    # `-{1,2}[\w-]+` split each `--a` two ways, and a marker after the flags made
    # the search try every combination: 22 flags took 0.74 seconds.
    "npm install " + "--a " * 40 + "==1\n",
    # A marker at the end of a 1 MB line of flags: every flag given back re-read the line.
    "npm install " + "--a " * 250_000 + "==1\n",
])
def test_install_arm_reads_a_crafted_line_in_linear_time(text: str) -> None:
    import time

    started = time.perf_counter()
    agentic_skills._unpinned_install(text)
    assert time.perf_counter() - started < 5.0
