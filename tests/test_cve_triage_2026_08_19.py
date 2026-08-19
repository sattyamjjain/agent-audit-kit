"""Dispositions for the 2026-08-18 CVE batch, pinned so they are not re-litigated.

Six advisories, and packaging decided every one. Two are in scope and only one needed a
new rule; three went out of scope for three *different* reasons, which is the reason
this file exists. A single "no pinnable artifact" precedent would flatten them, and the
next person reading an open CRITICAL would either re-derive the reasoning or add the pin
that looked obvious.

In scope:

* ``codewhale`` >= 0.8.41 < 0.8.64 (CVE-2026-75858, CVE-2026-75857) is pinned by one
  rule carrying both CVEs, the CKAN precedent, since they share a package and a fix
  version. Its pre-rename name ``deepseek-tui`` is a second pin on the same rule.
* ``@apify/actors-mcp-server`` (CVE-2026-50143) moved an existing pin's floor from
  0.9.21 to 0.10.11, the stata-mcp precedent, rather than adding a rule.

Out of scope, each for its own reason:

* ArcadeDB CVE-2026-75845 names a real artifact, but a **Maven** one, and
  ``_CANDIDATE_NAMES`` holds no ``pom.xml`` or ``build.gradle``.
* Apache SkyWalking MCP CVE-2026-34884 is **Go**, released as a tarball and an image;
  ``go.mod`` is not in the candidate set either. Same basis as Grafana MCP.
* Context7 CVE-2026-75130 has **no client version boundary at all**: Custom AI
  Instructions live in the hosted service, so no published version of the npm client
  separates vulnerable from fixed.

That last one is the one worth guarding. At CVSS 9 it is the batch's most severe, which
is exactly the pressure that produces a presence-only pin firing on every user for a
defect none of them can fix and none of them still has.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "CHANGELOG.cves.md"

# CVE -> the rule that carries it.
IN_SCOPE = {
    "CVE-2026-75858": "AAK-MCP-CODEWHALE-CVE-2026-75858-001",
    "CVE-2026-75857": "AAK-MCP-CODEWHALE-CVE-2026-75858-001",
    "CVE-2026-50143": "AAK-MCP-APIFY-CVE-2026-46341-001",
}

OUT_OF_SCOPE = {
    "CVE-2026-75845": "ArcadeDB - Maven coordinate, an ecosystem the pin detector does not read",
    "CVE-2026-34884": "Apache SkyWalking MCP - Go, released as a tarball and an image",
    "CVE-2026-75130": "Context7 - hosted-service defect, no client version boundary exists",
}

# Bare product names a pin must never be keyed on for this batch. `arcadedb` and
# `skywalking` publish nothing the detector reads; `context7` on npm is a *different*
# project (a CLI for the Context7 API) from `@upstash/context7-mcp`, so it is the same
# collision shape as `onyx` in the 08-17 batch.
COLLIDING_NAMES = ("arcadedb", "skywalking", "context7", "pycharm-community")


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_no_rule_claims_an_out_of_scope_cve(cve: str) -> None:
    """Out of scope means no rule references it.

    If a rule later cites one of these the disposition changed, and that should be a
    deliberate edit here rather than the ledger quietly disagreeing with the registry.
    """
    claiming = sorted(
        rid for rid, rule in RULES.items() if cve in (rule.cve_references or [])
    )
    assert not claiming, (
        f"{cve} is recorded out of scope in CHANGELOG.cves.md but rule(s) {claiming} "
        "reference it. Reconcile the ledger and the registry."
    )


@pytest.mark.parametrize("cve,rule_id", sorted(IN_SCOPE.items()))
def test_in_scope_cve_is_carried_by_its_rule(cve: str, rule_id: str) -> None:
    """In scope means a rule actually cites it, not that a row says so."""
    assert rule_id in RULES, f"{rule_id} is missing from the registry"
    assert cve in (RULES[rule_id].cve_references or []), (
        f"{rule_id} should carry {cve} in cve_references"
    )


@pytest.mark.parametrize("name", COLLIDING_NAMES)
def test_no_pin_is_keyed_on_a_bare_product_name(name: str) -> None:
    """The mistake this triage avoided, twice over.

    None of these names is a distribution the vulnerable project publishes, and
    ``context7`` on npm belongs to someone else entirely. A pin on any of them reports a
    CVE for a package the project does not have: the failure mode the ``cline`` pin had
    in 0.3.82 and the transport-flip keys had in 0.3.78.
    """
    hits = sorted(p.rule_id for p in _PINS if any(n.lower() == name for n in p.names))
    assert not hits, (
        f"pin(s) {hits} are keyed on the bare name {name!r}, which the vulnerable "
        "project does not publish. Key on a real distribution, or leave it out of scope."
    )


@pytest.mark.parametrize("cve", sorted({**IN_SCOPE, **OUT_OF_SCOPE}))
def test_disposition_is_recorded_in_the_ledger(cve: str) -> None:
    """A decision that is not written down is not a decision."""
    text = LEDGER.read_text(encoding="utf-8")
    assert cve in text, f"{cve} has no row in CHANGELOG.cves.md"


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_out_of_scope_rows_state_the_disposition(cve: str) -> None:
    text = LEDGER.read_text(encoding="utf-8")
    row = _row_for(text, cve)
    assert "Out of scope" in row, f"{cve} row does not state the disposition"


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_out_of_scope_rows_name_what_does_cover_it(cve: str) -> None:
    """An out-of-scope row must not read as "nothing covers this"."""
    text = LEDGER.read_text(encoding="utf-8")
    row = _row_for(text, cve)
    assert "AAK-MCP-001" in row, (
        f"{cve} row should name AAK-MCP-001 as the rule covering the reachable posture"
    )


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_out_of_scope_rows_do_not_imply_a_version_aak_cannot_see(cve: str) -> None:
    """No row may leave a reader believing AAK detects the version.

    Every one of these three names an upgrade path, and the honest statement is that
    nothing in the scanned tree carries the version. A row that implied otherwise would
    be the do-nothing advice the remediation-key guard exists to stop, relocated from a
    remediation into the ledger.
    """
    text = LEDGER.read_text(encoding="utf-8")
    row = _row_for(text, cve)
    assert re.search(
        r"not one this scanner reads|not in the pin detector|no client version|"
        r"candidate set|does not read",
        row,
    ), f"{cve} row should state plainly why there is nothing to pin"


def test_the_three_out_of_scope_reasons_are_actually_distinct() -> None:
    """Guard against the reasons collapsing into one copied sentence.

    The value of these rows is that they are three different facts. If a later edit
    rewrites them to share wording, the ledger stops explaining why ArcadeDB and
    Context7 are not the same call.
    """
    text = LEDGER.read_text(encoding="utf-8")
    markers = {
        "CVE-2026-75845": "Maven",
        "CVE-2026-34884": "Go",
        "CVE-2026-75130": "hosted",
    }
    for cve, marker in markers.items():
        row = _row_for(text, cve)
        assert marker in row, f"{cve} row no longer names its distinguishing reason ({marker})"


def test_context7_is_not_pinned_presence_only() -> None:
    """The specific wrong answer for the batch's most severe advisory.

    Presence-only (``floor=None``) is the right shape when upstream ships no fix, which
    is why ``mcp-florence2`` uses it. It is the wrong shape here: the Context7 defect is
    in the hosted service, so a presence-only pin would fire on every user of every
    client version, for something none of them runs and none of them can patch.
    """
    context7_pins = [
        p for p in _PINS if any("context7" in n.lower() for n in p.names)
    ]
    assert not context7_pins, (
        "Context7 must not carry a pin of any shape: no published client version "
        f"separates vulnerable from fixed. Found {[p.rule_id for p in context7_pins]}."
    )


def test_apify_floor_moved_rather_than_gaining_a_second_pin() -> None:
    """One package, one pin. A second would report one dependency twice."""
    apify = [p for p in _PINS if any(n == "@apify/actors-mcp-server" for n in p.names)]
    assert len(apify) == 1, (
        f"expected exactly one @apify/actors-mcp-server pin, found {len(apify)}: "
        f"{[p.rule_id for p in apify]}"
    )
    assert apify[0].floor == (0, 10, 11), (
        f"floor should be 0.10.11 for CVE-2026-50143, found {apify[0].floor}"
    )


def test_codewhale_pins_cover_both_names_under_one_rule() -> None:
    """Two pins, one rule: the agenticmail shape, so the two names cannot drift apart."""
    pins = [p for p in _PINS if p.rule_id == "AAK-MCP-CODEWHALE-CVE-2026-75858-001"]
    assert {n for p in pins for n in p.names} == {"codewhale", "deepseek-tui"}
    floors = {p.display: p.floor for p in pins}
    assert floors["codewhale"] == (0, 8, 64)
    assert floors["deepseek-tui"] == (0, 8, 41)


def test_codewhale_pins_are_bounded_and_do_not_match_prose() -> None:
    """The 0.3.82 ``cline`` regression, held for the names added here.

    ``codewhale`` must also stay off ``codewhale-tui``: that crate has the same defect
    but lives in an ecosystem the detector does not read, so matching it from a JS
    manifest would report something the scanner cannot actually establish.
    """
    pins = [p for p in _PINS if p.rule_id == "AAK-MCP-CODEWHALE-CVE-2026-75858-001"]
    for pin in pins:
        assert pin.regexes, f"{pin.display} must carry an explicit bounded regex"
    patterns = [rx for p in pins for rx in p.compiled()]
    must_not_match = (
        "the codewhale-tui crate is out of reach",
        "see github.com/Hmbown/CodeWhale for details",
        "deepseek-tui-legacy is a different package",
        "a codewhaler is not a package",
    )
    for line in must_not_match:
        hits = [rx.pattern for rx in patterns if rx.search(line)]
        assert not hits, f"{hits} matched prose: {line!r}"
    for line in ('"codewhale": "^0.8.50"', '"deepseek-tui": "0.8.39"'):
        assert any(rx.search(line) for rx in patterns), f"no pin matched {line!r}"


def test_deepseek_tui_remediation_says_migrate_not_upgrade_in_place() -> None:
    """Its line ends before the fix, so "upgrade" would be advice that does nothing."""
    pin = next(p for p in _PINS if p.display == "deepseek-tui")
    assert "migrate" in pin.fix_label.lower(), (
        "deepseek-tui is deprecated and has no fixed release of its own; the label must "
        f"point at codewhale rather than an in-place upgrade. Got: {pin.fix_label!r}"
    )


def test_the_covering_rule_still_exists_and_is_critical() -> None:
    """Guard the guard: the out-of-scope rows are only true while this rule is."""
    rule = RULES["AAK-MCP-001"]
    assert rule.severity.name == "CRITICAL"
    assert "auth" in rule.title.lower()


def _row_for(text: str, cve: str) -> str:
    """The 2026-08-19 ledger row mentioning ``cve``.

    Scoped to this batch's section so a later row for the same CVE in a different
    section cannot satisfy these assertions by accident.
    """
    section = text.split("## 2026-08-19", 1)[1].split("\n## ", 1)[0]
    rows = [ln for ln in section.splitlines() if ln.startswith("|") and cve in ln]
    assert rows, f"{cve} has no row in the 2026-08-19 ledger section"
    return rows[0]
