"""Dispositions for the 2026-08-17 CVE pair, pinned so they are not re-litigated.

Both went out of scope. An out-of-scope call leaves no rule behind, so without a test
there is nothing in the tree holding the decision, and the next person seeing an open
CRITICAL either re-derives the reasoning or, worse, adds the pin that looked obvious.

CVE-2026-71424 (Onyx, 9.6) is the one worth guarding. It names fix versions, so it
reads as pinnable. It is not: the Onyx AI platform publishes no PyPI or npm
distribution, and both names a pin would key on are taken by unrelated projects -
``onyx`` on PyPI is a trading framework, ``onyx`` on npm is a static file server, and
neither shares the 3.1.x / 3.2.x / 4.0 version lines the CVE names. A pin on that name
would fire on innocent packages and never on the vulnerable platform, which is the
collision the ``@adenot/mcp-google-search`` pin comment already documents for the
unscoped name.

CVE-2026-75060 (JetBrains PyCharm, 8.4) is the settled desktop-app shape: SiYuan
CVE-2026-66012 (#499), ArcadeDB CVE-2026-68578 (#528), SiYuan CVE-2026-74798 in 0.3.81.

Both are covered for exposure by AAK-MCP-001, which is the finding that matters since
each CVE's precondition is a reachable MCP surface without authentication.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "CHANGELOG.cves.md"

OUT_OF_SCOPE = {
    "CVE-2026-71424": "Onyx - no pinnable artifact; the PyPI/npm name belongs to other projects",
    "CVE-2026-75060": "JetBrains PyCharm - desktop IDE, no pinnable artifact",
}

# Names a pin must never be keyed on for these advisories. Each is a real, unrelated
# package, so a pin here is a false positive on someone else's dependency.
COLLIDING_NAMES = ("onyx", "pycharm")


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_no_rule_claims_these_cves(cve: str) -> None:
    """Out of scope means no rule references it.

    If a rule later cites one of these, the disposition changed and this test should be
    updated deliberately rather than the ledger quietly disagreeing with the registry.
    """
    claiming = sorted(
        rid for rid, rule in RULES.items() if cve in (rule.cve_references or [])
    )
    assert not claiming, (
        f"{cve} is recorded out of scope in CHANGELOG.cves.md but rule(s) {claiming} "
        "reference it. Reconcile the ledger and the registry."
    )


@pytest.mark.parametrize("name", COLLIDING_NAMES)
def test_no_pin_is_keyed_on_a_colliding_bare_name(name: str) -> None:
    """The specific mistake this triage avoided.

    ``onyx`` resolves to a trading framework on PyPI and a static file server on npm;
    ``pycharm`` is not a distribution at all. A pin on either would report a CVE for a
    package the project does not have, which is the failure mode the cline pin had in
    0.3.82 and the transport-flip keys had in 0.3.78: advice about something that is
    not there.
    """
    hits = sorted(
        p.rule_id for p in _PINS if any(n.lower() == name for n in p.names)
    )
    assert not hits, (
        f"pin(s) {hits} are keyed on the bare name {name!r}, which belongs to an "
        "unrelated published package. Key on a distribution the vulnerable project "
        "actually publishes, or leave the advisory out of scope."
    )


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_disposition_is_recorded_in_the_ledger(cve: str) -> None:
    """A decision that is not written down is not a decision."""
    text = LEDGER.read_text(encoding="utf-8")
    assert cve in text, f"{cve} has no row in CHANGELOG.cves.md"
    row = next(line for line in text.splitlines() if cve in line and line.startswith("|"))
    assert "Out of scope" in row, f"{cve} row does not state the disposition"


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_out_of_scope_rows_name_what_does_cover_it(cve: str) -> None:
    """An out-of-scope row must not read as "nothing covers this".

    Both CVEs need a reachable, unauthenticated MCP surface, which AAK-MCP-001 reports.
    Saying so is the difference between a disposition and a shrug.
    """
    text = LEDGER.read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if cve in line and line.startswith("|"))
    assert "AAK-MCP-001" in row, (
        f"{cve} row should name AAK-MCP-001 as the rule covering the reachable posture"
    )


def test_the_covering_rule_still_exists_and_is_critical() -> None:
    """Guard the guard: the rows above are only true while this rule is."""
    rule = RULES["AAK-MCP-001"]
    assert rule.severity.name == "CRITICAL"
    assert "auth" in rule.title.lower()


@pytest.mark.parametrize("cve", sorted(OUT_OF_SCOPE))
def test_out_of_scope_rows_do_not_promise_a_pin(cve: str) -> None:
    """Neither row may tell a reader AAK detects the version.

    Both advisories name a fixed version, and the honest statement is that AAK cannot
    see it. A row implying otherwise would be the do-nothing advice the
    remediation-key guard exists to stop, in the ledger instead of a remediation.
    """
    text = LEDGER.read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if cve in line and line.startswith("|"))
    assert re.search(r"pinnable|pin detector|static config scan cannot see|no PyPI or npm", row), (
        f"{cve} row should state plainly why there is nothing to pin"
    )
