"""Dispositions for the 2026-08-19/20 CVE pair, pinned so they are not re-litigated.

Two advisories, and both name something that *looks* pinnable. Only one of them is,
and the difference is not severity: the CRITICAL one is out of scope and the HIGH one
ships a rule.

* CVE-2026-75149 (marimo, 8.8) is in scope. A notebook embeds an MCP server entry whose
  ``command`` marimo launches on open, before any cell runs. That is AAK's own
  stdio-launcher shape arriving through a ``.py`` notebook, which no config scanner
  opens, so a pin is the right instrument rather than a pattern rule.
* CVE-2026-76404 (Splunk MCP Server app, 9.1) is out of scope. The artifact is a
  Splunkbase ``.spl`` app, an ecosystem ``_CANDIDATE_NAMES`` does not cover.

Both carry a name collision, and the collisions are the reason this file exists.
``marimo`` on npm is an unrelated test runner; ``mcp-server-splunk`` on PyPI is an
unrelated third-party server. In one case the collision is tolerable and in the other
it is disqualifying, and the test that keeps those straight is the one that stops a
future contributor "fixing" the gap by adding the pin that looked obvious.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS, scan

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "CHANGELOG.cves.md"

MARIMO_RULE = "AAK-MCP-MARIMO-CVE-2026-75149-001"
N8N_RULE = "AAK-MCP-N8N-CVE-2026-72768-001"
NEOMJS_RULE = "AAK-MCP-NEOMJS-CVE-2026-18482-001"
LANGBOT_RULE = "AAK-MCP-LANGBOT-CVE-2026-54449-001"

IN_SCOPE = {
    "CVE-2026-75149": MARIMO_RULE,
    "CVE-2026-77068": N8N_RULE,
    "CVE-2026-77073": N8N_RULE,
    "CVE-2026-18482": NEOMJS_RULE,
    "CVE-2026-54449": LANGBOT_RULE,
}
OUT_OF_SCOPE = {
    "CVE-2026-76404": "Splunk MCP Server app - a Splunkbase .spl bundle, not a "
                      "PyPI/npm manifest the pin detector reads",
    "CVE-2026-72846": "Lightdash backend - container-deployed, publishes no npm "
                      "distribution; the name that is on npm belongs to someone else",
    "CVE-2026-59279": "Spring AI - Maven Central only; third advisory on that "
                      "boundary after ArcadeDB and the Splunk app",
}

# Names a pin must never be keyed on for this batch. `mcp-server-splunk` is a real,
# unrelated PyPI package, so a pin there is a false positive on someone else's
# dependency and never a true positive on the vulnerable Splunk app.
COLLIDING_NAMES = (
    "mcp-server-splunk", "splunk-mcp-server", "splunk",
    # npm `lightdash` is an unrelated lodash-style utility, and `@lightdash/cli`
    # versions in lockstep with the monorepo so it *looks* pinnable -- but the CLI
    # is not the component that runs the vulnerable sendWebhook path.
    "lightdash", "@lightdash/cli",
    # Spring AI is org.springframework.ai on Maven; neither spelling resolves
    # on PyPI or npm, so a pin on either would key on nothing.
    "spring-ai", "springai",
)


def _ids(tmp_path: Path, name: str, content: str) -> set[str]:
    (tmp_path / name).write_text(content, encoding="utf-8")
    findings, _ = scan(tmp_path)
    return {f.rule_id for f in findings}


def _row_for(cve: str) -> str:
    """The 2026-08-21 ledger row for ``cve``, scoped to this batch's section."""
    text = LEDGER.read_text(encoding="utf-8")
    # Anchored on the full heading, not the date: a later same-day section
    # ("## 2026-08-21 (later): ...") is inserted above this one, and a prefix
    # split silently started returning that section instead.
    section = text.split("## 2026-08-21: seven advisories", 1)[1].split("\n## ", 1)[0]
    rows = [ln for ln in section.splitlines() if ln.startswith("|") and cve in ln]
    assert rows, f"{cve} has no row in the 2026-08-21 ledger section"
    return rows[0]


# ---------------------------------------------------------------------------
# In scope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cve,rule_id", sorted(IN_SCOPE.items()))
def test_in_scope_cve_is_carried_by_its_rule(cve: str, rule_id: str) -> None:
    assert rule_id in RULES
    assert cve in (RULES[rule_id].cve_references or [])


def test_marimo_below_floor_fires(tmp_path: Path) -> None:
    assert MARIMO_RULE in _ids(tmp_path, "requirements.txt", "marimo==0.23.10\n")


def test_marimo_at_floor_is_quiet(tmp_path: Path) -> None:
    assert MARIMO_RULE not in _ids(tmp_path, "requirements.txt", "marimo==0.23.15\n")


def test_marimo_pin_has_no_lower_bound() -> None:
    """Checked, not assumed.

    NVD gives no start version. Rather than invent one, the floor covers everything
    below it, which the advisory database supports: two further pip marimo advisories
    record ``< 0.23.0`` and ``< 0.23.9``. An ``introduced`` bound added later would
    silently stop reporting versions that are still exposed.
    """
    pin = next(p for p in _PINS if p.rule_id == MARIMO_RULE)
    assert pin.floor == (0, 23, 15)
    assert pin.introduced is None


def test_marimo_regex_is_bounded_and_stays_off_lookalikes(tmp_path: Path) -> None:
    """The 0.3.82 ``cline`` regression, held for this name."""
    pin = next(p for p in _PINS if p.rule_id == MARIMO_RULE)
    assert pin.regexes, "marimo must carry an explicit bounded regex"
    assert MARIMO_RULE not in _ids(
        tmp_path, "requirements.txt", "marimo-extras==0.1.0\nsubmarimo==0.2.0\n"
    )
    patterns = list(pin.compiled())
    assert not any(rx.search("see marimo-team/marimo for details") for rx in patterns)


def test_marimo_remediation_says_do_not_open_untrusted_notebooks() -> None:
    """The upgrade is not the whole mitigation and the remediation must say so.

    The subprocess launches before any cell executes, so "review the cells first" is
    advice that does nothing. A remediation that only said "upgrade" would leave a
    reader on an unpatched version with no usable interim step.
    """
    remediation = RULES[MARIMO_RULE].remediation.lower()
    assert "upgrade" in remediation
    assert "edit mode" in remediation or "before any cell" in remediation


# ---------------------------------------------------------------------------
# Out of scope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_no_rule_claims_an_out_of_scope_cve(cve: str) -> None:
    claiming = sorted(
        rid for rid, rule in RULES.items() if cve in (rule.cve_references or [])
    )
    assert not claiming, (
        f"{cve} is recorded out of scope in CHANGELOG.cves.md but rule(s) {claiming} "
        "reference it. Reconcile the ledger and the registry."
    )


@pytest.mark.parametrize("name", COLLIDING_NAMES)
def test_no_pin_is_keyed_on_a_splunk_name(name: str) -> None:
    """`mcp-server-splunk` is a real PyPI package belonging to someone else.

    Its line is 0.1.0/0.2.0 and never reaches the 1.2.x the advisory names, which is
    what proves it is a different project. A pin there reports a CVE against an
    innocent dependency and never fires on the vulnerable Splunk app.
    """
    hits = sorted(p.rule_id for p in _PINS if any(n.lower() == name for n in p.names))
    assert not hits, (
        f"pin(s) {hits} are keyed on {name!r}, which is not the vulnerable artifact"
    )


@pytest.mark.parametrize("cve", sorted({**IN_SCOPE, **OUT_OF_SCOPE}))
def test_disposition_is_recorded_in_the_ledger(cve: str) -> None:
    assert cve in LEDGER.read_text(encoding="utf-8")


def test_splunk_row_names_the_scanner_boundary_it_falls_outside() -> None:
    """An out-of-scope row has to say which boundary, not just that there is one."""
    row = _row_for("CVE-2026-76404")
    assert "Out of scope" in row
    assert "_CANDIDATE_NAMES" in row or "candidate" in row
    assert "Splunkbase" in row or ".spl" in row


def test_splunk_row_does_not_reduce_the_fix_to_an_upgrade() -> None:
    """The vendor's own remediation leads with removing the app.

    A ledger row that said only "upgrade to >= 1.2.1" would be a quieter version of
    the advisory than the advisory itself.
    """
    row = _row_for("CVE-2026-76404")
    assert "Turn off or remove" in row


def test_splunk_row_names_what_does_cover_the_posture() -> None:
    assert "AAK-MCP-001" in _row_for("CVE-2026-76404")


def test_the_covering_rule_still_exists_and_is_critical() -> None:
    rule = RULES["AAK-MCP-001"]
    assert rule.severity.name == "CRITICAL"
    assert "auth" in rule.title.lower()


# ---------------------------------------------------------------------------
# The 2026-08-20 wave, cleared in the same pass
# ---------------------------------------------------------------------------


def test_n8n_floor_moved_rather_than_gaining_a_fifth_pin(tmp_path: Path) -> None:
    """One package, one authoritative floor.

    AAK already carried four n8n pin entries across three rules. A fifth would
    report the same dependency five times, so the highest floor moved instead.
    2.33.5 is the band that proves the move: it cleared the old 2.32.1 floor and is
    still exposed.

    Updated 2026-09-04: the claim under test is "no new *rule id* for n8n", not "no
    second arm". CVE-2026-85166 fixes on two lines (< 2.35.4, and 2.36.x < 2.36.2),
    so this rule now carries two arms the way AAK-MCP-N8N-CVE-2026-65594-001
    already did. That is still one finding per dependency, which is what the test
    was defending; asserting the arm *count* conflated the two.
    """
    n8n_rule_ids = {p.rule_id for p in _PINS if p.display == "n8n"}
    assert n8n_rule_ids == {
        "AAK-MCP-N8N-CVE-2026-59207-001",
        "AAK-MCP-N8N-CVE-2026-65594-001",
        N8N_RULE,
    }, "a fourth n8n rule id would report the same dependency one more time"
    floors = {p.floor for p in _PINS if p.rule_id == N8N_RULE}
    assert floors == {(2, 35, 4), (2, 36, 2)}
    assert N8N_RULE in _ids(tmp_path, "package.json", '{"dependencies":{"n8n":"2.33.5"}}')
    assert N8N_RULE not in _ids(
        tmp_path, "package.json", '{"dependencies":{"n8n":"2.35.4"}}'
    )


@pytest.mark.parametrize("rule_id", [NEOMJS_RULE, LANGBOT_RULE])
def test_presence_only_pin_has_no_floor(rule_id: str) -> None:
    """Both were checked, not assumed.

    neo.mjs names a fix *commit* dated after the newest published release, so the fix
    has never shipped. LangBot's GHSA records ``patched: null`` and the release that
    landed 31 minutes after the advisory claims no security fix. A version floor in
    either case would be invented.
    """
    pin = next(p for p in _PINS if p.rule_id == rule_id)
    assert pin.floor is None


@pytest.mark.parametrize("rule_id", [NEOMJS_RULE, LANGBOT_RULE])
def test_presence_only_remediation_does_not_promise_an_upgrade(rule_id: str) -> None:
    """No fix exists, so "upgrade" would be the do-nothing advice.

    Each has to name the control that actually helps: dropping the file-system MCP
    server for neo.mjs, closing the account boundary for LangBot.
    """
    remediation = RULES[rule_id].remediation.lower()
    assert "no fixed release" in remediation or "no upgrade" in remediation
    assert not remediation.startswith("upgrade")


def test_neomjs_newer_version_still_fires(tmp_path: Path) -> None:
    """Presence-only means the newest published release is still reported.

    13.1.0 is the latest on npm and predates the fix commit, so a user on latest is
    exposed. A floor-based pin would have gone quiet exactly there.
    """
    assert NEOMJS_RULE in _ids(
        tmp_path, "package.json", '{"dependencies":{"neo.mjs":"13.1.0"}}'
    )


def test_langbot_newer_version_still_fires(tmp_path: Path) -> None:
    """4.10.8 exists and does not claim to fix this, so it must still fire."""
    assert LANGBOT_RULE in _ids(tmp_path, "requirements.txt", "langbot==4.10.8\n")


def test_neomjs_pin_is_marked_a_placeholder_not_a_permanent_state() -> None:
    """The distinction from mcp-florence2 matters and must survive edits.

    florence2 is presence-only because the vendor ruled out a source fix. neo.mjs is
    presence-only because a written fix has not been released. One should never
    become a floor; the other should, the moment upstream publishes.
    """
    text = RULES[NEOMJS_RULE].description.lower()
    assert "placeholder" in text
    assert "88c77fc" in RULES[NEOMJS_RULE].description


def test_lightdash_row_names_both_near_misses() -> None:
    """Two separate traps, and a future reader needs both.

    npm `lightdash` is an unrelated utility library, and `@lightdash/cli` publishes a
    matching 1.146.4 because the monorepo versions together -- so the CLI looks like
    a valid pin target while not being the component that runs sendWebhook.
    """
    row = _row_for("CVE-2026-72846")
    assert "Out of scope" in row
    assert "@lightdash/cli" in row
    assert "lodash" in row


def test_spring_ai_row_names_the_ecosystem_boundary() -> None:
    """Third advisory on the Maven boundary, written out rather than cross-referenced.

    ArcadeDB (#614) and the Splunk app (#622) came first. Repeating the reason is
    deliberate: a reader who lands on this row should not have to find the
    earlier ones to learn why a CVSS 7.5 is out of scope.
    """
    text = LEDGER.read_text(encoding="utf-8")
    section = text.split("## 2026-08-21 (later)", 1)[1].split("\n## ", 1)[0]
    row = next(ln for ln in section.splitlines() if "CVE-2026-59279" in ln and ln.startswith("|"))
    assert "Out of scope" in row
    assert "Maven" in row
    assert "_CANDIDATE_NAMES" in row
    assert "AAK-MCP-001" in row, (
        "the row must name what does cover the visible half -- an MCP HTTP "
        "surface with no auth is a finding even though session exhaustion is not"
    )
