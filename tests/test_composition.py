"""The capability-graph composition pass (AAK-COMPOSE-001/002/003).

These rules exist because every other rule in the registry answers a question
about one artifact. `AAK-AGENT-COMPOSE-001` is the one prior exception and it is
a *set* predicate: an unordered capability union over the `SKILL.md` files in one
container, from declared frontmatter only. It has no notion of direction, of one
component's output being another's input, of hop count, or of anything that is
not a skill. This module tests the graph that adds those.

The load-bearing test here is `test_already_reported_*`: a composition pass that
double-reports is worse than no composition pass, because it turns one problem
into two entries pointing at the same files and trains people to skim.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from agent_audit_kit.engine import run_scan
from agent_audit_kit.models import Category
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners import composition
from agent_audit_kit.scanners.composition import MAX_PATH_NODES, scan

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "composition"
CORPUS = REPO_ROOT / "benchmarks" / "data"

CHAIN = "AAK-COMPOSE-001"
SHARED_STATE = "AAK-COMPOSE-002"
UNDERDECLARED = "AAK-COMPOSE-003"


def _scanner_ids(fixture: str) -> list[str]:
    findings, _ = scan(FIXTURES / fixture)
    return [f.rule_id for f in findings]


def _engine_ids(fixture: str) -> list[str]:
    return [f.rule_id for f in run_scan(FIXTURES / fixture).findings]


# ---------------------------------------------------------------------------
# True positives
# ---------------------------------------------------------------------------


def test_two_node_chain_fires() -> None:
    """A skill that reads untrusted mail and local files, feeding a remote server.

    Neither component trips a single-artifact rule: the skill has no egress, the
    server reads nothing local. The exposure is only in the pair.
    """
    assert CHAIN in _scanner_ids("chain_2node")


def test_three_node_chain_fires() -> None:
    """Untrusted source -> credential reader -> egress, none of them complete."""
    assert CHAIN in _scanner_ids("chain_3node")


def test_chain_finding_names_every_component() -> None:
    """The finding has to be actionable, which means naming the whole path."""
    findings, _ = scan(FIXTURES / "chain_3node")
    chain = next(f for f in findings if f.rule_id == CHAIN)
    assert len(chain.related_locations) >= 3, (
        "a 3-node chain must carry all three components as related locations"
    )
    for name in ("ticket-reader", "config-loader", "metrics-sink"):
        assert name in chain.evidence, f"{name} missing from the evidence"


def test_shared_undeclared_state_fires() -> None:
    """ColluSkill's channel: one writable path, two skills, nobody declaring it."""
    assert SHARED_STATE in _scanner_ids("collusion_channel")


def test_underdeclared_capability_fires() -> None:
    """The manifest says Read; the body opens a file for writing."""
    assert UNDERDECLARED in _scanner_ids("collusion_channel")


# ---------------------------------------------------------------------------
# True negatives
# ---------------------------------------------------------------------------


def test_the_cap_is_three_components() -> None:
    """Pinned, because it is a claim about CompoSkill's result, not a tuning knob.

    Raising it changes what the rule asserts about the literature and multiplies
    the path search by the node count, so it should be a deliberate edit here.
    """
    assert MAX_PATH_NODES == 3


def test_four_node_chain_does_not_fire() -> None:
    """Capped at 3 components, per CompoSkill's own falloff past three skills."""
    assert CHAIN not in _scanner_ids("chain_4node_capped")


def test_four_node_chain_would_fire_if_the_cap_were_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guard the guard.

    Without this, `chain_4node_capped` passing proves nothing: a fixture that is
    silently malformed, or a predicate that rejects it for some unrelated reason,
    looks identical to the cap doing its job. Raising the cap has to turn the
    finding on, which is what shows the cap is the only thing suppressing it.
    """
    assert CHAIN not in _scanner_ids("chain_4node_capped")
    monkeypatch.setattr(composition, "MAX_PATH_NODES", 4)
    assert CHAIN in _scanner_ids("chain_4node_capped"), (
        "raising the cap to 4 should expose the chain; if it does not, the fixture "
        "is not testing the cap"
    )


def test_benign_read_only_shared_path_does_not_fire() -> None:
    """Two skills reading one config file are sharing settings, not a channel.

    AAK-COMPOSE-002 requires evidence somebody actually writes the path. Without
    that, every project whose skills read a common config would be reported.
    """
    ids = _scanner_ids("benign_readonly")
    assert SHARED_STATE not in ids
    assert CHAIN not in ids
    assert ids == [], f"benign fixture should be silent, got {ids}"


def test_no_component_holding_the_whole_chain_is_reported() -> None:
    """A component with all three roles is a single-artifact finding.

    Reporting it here as well would be the double-report this pass must not do.
    """
    for fixture in ("chain_2node", "chain_3node", "chain_4node_capped"):
        root = FIXTURES / fixture
        nodes = composition._skill_nodes(root) + composition._mcp_nodes(root)
        assert nodes, f"{fixture} produced no components"
        complete = [n.name for n in nodes if n.caps.holds_whole_chain]
        assert not complete, (
            f"{fixture} invalidated: {complete} span the whole chain alone, so the "
            "fixture no longer tests composition -- it tests a single artifact"
        )

    # And the predicate itself refuses such a component, not just these fixtures.
    solo = composition._Node(
        kind="skill",
        name="does-everything",
        rel="skills/x/SKILL.md",
        line=1,
        caps=composition._Caps(
            reads_untrusted_input=True,
            reads_local_secrets=True,
            performs_network_egress=True,
        ),
        container="skills",
    )
    sink = composition._Node(
        kind="mcp-server",
        name="sink",
        rel=".mcp.json",
        line=3,
        caps=composition._Caps(performs_network_egress=True),
        container=".mcp.json",
    )
    assert composition._chain_findings([solo, sink]) == [], (
        "a component holding untrusted-input + secrets + egress is a single-artifact "
        "finding; the chain rule must not also claim it"
    )


# ---------------------------------------------------------------------------
# Deduplication — the property that decides whether this pass is worth having
# ---------------------------------------------------------------------------


def test_already_reported_component_suppresses_the_chain() -> None:
    """One node fires AAK-MCP-001 (CRITICAL). Report it once, not twice.

    The chain is identical to `chain_2node` except the remote server declares no
    auth. That makes the server a CRITICAL finding on its own, so the chain is no
    longer something only this pass can see, and adding a second HIGH entry about
    the same two files is noise.
    """
    ids = _engine_ids("already_reported")
    assert "AAK-MCP-001" in ids, "fixture should still trip the single-artifact rule"
    assert CHAIN not in ids, (
        "AAK-COMPOSE-001 duplicated a chain whose component is already reported"
    )


def test_the_same_chain_is_reported_when_no_component_is_covered() -> None:
    """The other half of the previous test.

    `chain_2node` differs from `already_reported` only by the server declaring
    auth. If both were silent, the suppression test above would pass for the
    wrong reason -- a chain that never fires at all.
    """
    assert CHAIN in _engine_ids("chain_2node")


def test_suppression_is_by_severity_not_by_presence() -> None:
    """Presence-suppression is the tempting rule and it is wrong.

    AAK-MCP-ATTEST-001 (MEDIUM) fires on virtually every MCP config. If any
    finding on a component stood the chain down, every MCP composition would be
    permanently unreportable while the guard still looked correct -- a rule that
    ships and never fires. `chain_2node` carries ATTEST-001 and still reports.
    """
    ids = _engine_ids("chain_2node")
    assert "AAK-MCP-ATTEST-001" in ids, "fixture no longer carries a MEDIUM finding"
    assert CHAIN in ids, "a MEDIUM hygiene finding must not stand down a HIGH chain"


def test_skill_and_server_components_use_different_identity_granularity() -> None:
    """A SKILL.md is one artifact; an MCP config holds many servers.

    Keying both on the file would let one unrelated finding anywhere in a shared
    `.mcp.json` suppress every chain through it. Keying both on an exact line
    would miss AAK-MCP-001, which reports on the `url` line rather than the line
    naming the server.
    """
    findings, _ = scan(FIXTURES / "chain_2node")
    keys = composition.suppression_keys(next(f for f in findings if f.rule_id == CHAIN))
    assert any(k.startswith("file:") and k.endswith("SKILL.md") for k in keys)
    assert any(k.startswith("node:.mcp.json:") for k in keys)
    # The server block spans more than its name line, so more than one line key.
    server_keys = {k for k in keys if k.startswith("node:.mcp.json:")}
    assert len(server_keys) > 1, (
        "an MCP component must claim its whole block, or a finding one line below "
        "the server name will not be recognised as covering it"
    )


# ---------------------------------------------------------------------------
# Registry contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", [CHAIN, SHARED_STATE, UNDERDECLARED])
def test_rule_is_registered_in_the_composition_category(rule_id: str) -> None:
    assert rule_id in RULES
    assert RULES[rule_id].category is Category.COMPOSITION


@pytest.mark.parametrize("rule_id", [CHAIN, SHARED_STATE, UNDERDECLARED])
def test_rule_states_its_limitations(rule_id: str) -> None:
    """A static pass that implies it sees runtime composition is worse than none.

    Every one of these builds its graph from declared configuration, so each has
    to say that a chain assembled at runtime from a registry fetched at start-up
    is invisible to it.
    """
    limitations = RULES[rule_id].limitations
    assert limitations, f"{rule_id} must state what it cannot see"
    assert "runtime" in limitations.lower()
    assert "static" in limitations.lower()


@pytest.mark.parametrize(
    "rule_id,expected",
    [
        (CHAIN, {"ARXIV-2608.16246", "ARXIV-2608.09732"}),
        (SHARED_STATE, {"ARXIV-2608.09732"}),
        (UNDERDECLARED, {"ARXIV-2608.16246"}),
    ],
)
def test_rule_cites_its_source_paper(rule_id: str, expected: set[str]) -> None:
    assert set(RULES[rule_id].incident_references or []) == expected


def test_chain_rule_distinguishes_itself_from_the_existing_union_rule() -> None:
    """AAK-AGENT-COMPOSE-001 already exists and is not this.

    If the description stops saying how they differ, the next person will read
    two overlapping composition rules and delete one.
    """
    description = RULES[CHAIN].description
    assert "AAK-AGENT-COMPOSE-001" in description
    assert "unordered" in description


# ---------------------------------------------------------------------------
# Corpus behaviour
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not CORPUS.is_dir(), reason="benchmark corpus not present")
def test_firing_rate_on_the_public_corpus_stays_low() -> None:
    """A composition rule that fires on a third of real projects is a broken one.

    Measured on the 748 public MCP configs in `benchmarks/data`. The first draft
    of this predicate treated any remote server as a source of untrusted input,
    which reported 253 chains across 33.8% of the corpus. Requiring the source to
    actually look like untrusted content -- a browser, a mail or issue reader --
    took it to 2 findings across 2 configs. This holds that line: if a change
    pushes it back over 5%, the predicate has loosened.
    """
    configs = sorted(CORPUS.glob("*.mcp.json"))
    assert configs, "corpus is empty"
    hit = 0
    tmp = Path(tempfile.mkdtemp())
    try:
        for i, src in enumerate(configs):
            root = tmp / f"p{i}"
            root.mkdir()
            shutil.copyfile(src, root / ".mcp.json")
            findings, _ = scan(root)
            if any(f.rule_id == CHAIN for f in findings):
                hit += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    rate = hit / len(configs)
    assert rate <= 0.05, (
        f"AAK-COMPOSE-001 fires on {hit}/{len(configs)} = {rate:.1%} of the public "
        "corpus. Above ~5% the predicate is too loose to ship."
    )


# ---------------------------------------------------------------------------
# Downstream surfaces — a rule nothing renders is a rule nobody sees
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", [CHAIN, SHARED_STATE, UNDERDECLARED])
def test_rule_reaches_the_sarif_surface(rule_id: str) -> None:
    """SARIF needs a stable `name`, or a code-scanning UI shows a bare ID."""
    assert RULES[rule_id].sarif_name, f"{rule_id} has no sarif_name"
    assert RULES[rule_id].sarif_name[0].isupper()


def test_chain_finding_renders_related_locations_in_sarif() -> None:
    """The whole point is the path, so every component must survive into SARIF."""
    import json

    from agent_audit_kit.output.sarif import format_results

    doc = json.loads(format_results(run_scan(FIXTURES / "chain_3node")))
    results = [
        r for r in doc["runs"][0]["results"] if r["ruleId"] == CHAIN
    ]
    assert results, "no composition result in the SARIF document"
    assert len(results[0].get("relatedLocations", [])) >= 3, (
        "a 3-node chain must render all three components as SARIF relatedLocations"
    )


def test_composition_category_has_a_readme_row() -> None:
    """`sync_rule_count.py` updates existing anchors; it does not add rows.

    So a new category is silently absent from the README table until someone adds
    it by hand, and the per-category anchor sum test only catches that because the
    totals stop adding up.
    """
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "<!-- category-count:COMPOSITION -->" in readme


def test_composition_rules_map_into_the_owasp_agentic_coverage_page() -> None:
    page = (REPO_ROOT / "docs" / "coverage" / "owasp-agentic-top10.md").read_text(
        encoding="utf-8"
    )
    for rule_id in (CHAIN, SHARED_STATE, UNDERDECLARED):
        assert rule_id in page, f"{rule_id} missing from the OWASP Agentic coverage page"


def test_composition_finding_drives_a_compliance_control() -> None:
    """The rules carry ASI references, and those are what compliance maps on.

    Asserted through the rendered report rather than the mapping table, so this
    fails if the wiring between them breaks rather than only if the table changes.
    """
    from agent_audit_kit.output.compliance import format_results

    result = run_scan(FIXTURES / "chain_2node")
    highs = [f.rule_id for f in result.findings if f.severity.value == "high"]
    assert highs == [CHAIN], f"fixture should have exactly one HIGH finding, got {highs}"
    report = format_results(result, "eu-ai-act")
    assert "highest: high" in report, (
        "the composition finding did not reach any EU AI Act control, so the ASI "
        "mapping is not wired through"
    )


def test_crosswalk_cites_both_papers() -> None:
    """The crosswalk is where the standards claim lives, so the sources belong there."""
    page = (REPO_ROOT / "docs" / "crosswalk" / "nsa-csi-owasp-agentic.md").read_text(
        encoding="utf-8"
    )
    assert "2608.16246" in page, "CompoSkill not cited in the crosswalk"
    assert "2608.09732" in page, "ColluSkill not cited in the crosswalk"


def test_category_count_is_guarded() -> None:
    """The 0.3.81 lesson, applied to the number this release changed.

    `check_counts.py` matches phrases, so a count written in an uncovered phrasing
    is never looked at and rots while `make count-check` reports clean. The
    category count was in exactly that position until this release.
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from check_counts import PATTERNS, canonical_counts

    assert "categories" in canonical_counts()
    assert any(kind == "categories" for _, kind in PATTERNS), (
        "no PATTERNS entry claims the category count, so it is unguarded"
    )


def test_category_pattern_does_not_match_the_owasp_taxonomy_size() -> None:
    """Guard the guard: a bare `N categories` pattern was wrong.

    The OWASP coverage pages say "AAK covers 10/10 categories", where 10 is the
    size of the OWASP taxonomy, not AAK's category count. A broad pattern matched
    those and would have "corrected" a true statement into a false one.
    """
    import sys

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from check_counts import PATTERNS

    category_patterns = [rx for rx, kind in PATTERNS if kind == "categories"]
    for text in (
        "**AAK covers 10/10 categories** with at least one deterministic rule.",
        "11 intentionally vulnerable configurations covering 10 of the 13 categories.",
        "detects vulnerabilities across **7 of 13 security categories** in these configs",
    ):
        for rx in category_patterns:
            assert not rx.search(text), (
                f"category pattern {rx.pattern!r} matches a non-AAK category count: {text!r}"
            )
    # ...and still matches the headline form it exists for.
    assert any(
        rx.search("- **313 rules** across 13 security categories")
        for rx in category_patterns
    )


def test_the_graph_size_bound_is_pinned_and_its_silence_is_documented() -> None:
    """A bound that produces silence reads exactly like a clean result.

    Path enumeration is O(n**depth) so some bound is required, but an undocumented
    one means a large project gets no composition findings and no way to know the
    rule never ran. The number is pinned here and its consequence is stated in the
    rule's own `limitations`, so both move together or the test fails.
    """
    assert composition._MAX_GRAPH_NODES == 200
    limitations = RULES[CHAIN].limitations
    assert "200" in limitations, (
        "the graph-size bound must be stated in AAK-COMPOSE-001's limitations, or a "
        "project above it gets silence indistinguishable from a clean scan"
    )


def test_exceeding_the_graph_bound_yields_silence_not_a_crash() -> None:
    """Known behaviour, asserted, rather than an accident nobody has hit."""
    import json
    import tempfile
    from pathlib import Path as _Path

    with tempfile.TemporaryDirectory() as td:
        root = _Path(td)
        servers = {"browsermcp": {"url": "https://b.example/mcp"}}
        for i in range(composition._MAX_GRAPH_NODES + 5):
            servers[f"srv{i}"] = {
                "url": f"https://s{i}.example/mcp",
                "env": {"API_KEY": "x"},
            }
        (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
        findings, _ = scan(root)
        assert not [f for f in findings if f.rule_id == CHAIN]
