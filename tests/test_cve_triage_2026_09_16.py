"""Dispositions for the ten-CVE queue cleared on 2026-09-16 (#732-#741).

The watcher opened ten `cve-response` issues over two days. Six were in scope
and four were not, and the four are the more interesting half.

**Four Apache Storm advisories, out of scope (#733-#736).** CVE-2026-82439,
-82428, -82427 and -82429 are a DRPC memory-exhaustion, a blob-key collision,
a `topology.blobstore.map` path traversal and a setuid worker-launcher TOCTOU.
Apache Storm is a distributed stream processor; none of this is MCP or an
agent pipeline. They matched because each advisory's credit line reads "found
using Claude agents to study the security of open-source projects". The
watcher matched the word "agents" in an acknowledgement, which is the same
failure as CVE-2026-89622, where "MCP2221" (a Microchip USB-to-I2C bridge)
collided with Model Context Protocol. That is the right bias for a watcher and
the wrong answer for a rule.

**Two already covered (#732, #737+#740).** PraisonAI's CVE-2026-57124 is this
project's own favourite shape - unauthenticated `POST /api/mcp/connect`,
caller-controlled `command`/`args` into `StdioMCPClient`, UI bound to 0.0.0.0 -
and is fixed in 4.6.59, below the existing 4.6.78 floor, so every version it
affects already fires. Both mcp-atlassian advisories ship in 0.22.0, which is
the existing floor exactly. All three are recorded in `cve_references` and
given no pin of their own: two pins on one package report one dependency twice.

**One floor raised (#739).** dbt-mcp's CVE-2026-55837 is fixed in 1.20.0, and
the rule's floor was 1.17.1. That gap is the case a `cve_references` line
cannot cover: 1.17.1 through 1.19.x were vulnerable and silent.

**Three new pins (#738, #741).** CVE-2026-55253 is the LangGraph MongoDB NoSQL
injection again, but in the PyPI distributions rather than the npm one the
existing pin names, so the existing rule gains two pins it could not see
before. `langgraph-api` had no rule at all and gets one.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import scan

PRAISON = "AAK-MCP-PRAISONAI-CVE-2026-61427-001"
ATLASSIAN = "AAK-MCP-ATLASSIAN-CVE-2026-73498-001"
DBT = "AAK-MCP-DBTMCP-CVE-2026-44968-001"
MONGO = "AAK-MCP-LANGGRAPH-MONGO-CVE-2026-48121-001"
LGAPI = "AAK-MCP-LANGGRAPH-API-CVE-2026-55235-001"


def _pins(requirements: str) -> set[str]:
    d = Path(tempfile.mkdtemp())
    (d / "requirements.txt").write_text(requirements, encoding="utf-8")
    return {f.rule_id for f in scan(d)[0]}


# ---------------------------------------------------------------------------
# Already covered: recorded, not re-pinned
# ---------------------------------------------------------------------------


def test_praisonai_cve_is_recorded_against_the_existing_floor() -> None:
    assert "CVE-2026-57124" in RULES[PRAISON].cve_references


def test_praisonai_floor_already_fires_on_every_affected_version() -> None:
    """Fixed in 4.6.59; the floor is 4.6.78."""
    assert PRAISON in _pins("praisonai==4.6.58\n")
    assert PRAISON in _pins("praisonai==4.6.70\n")


def test_both_atlassian_cves_are_recorded() -> None:
    refs = RULES[ATLASSIAN].cve_references
    assert "CVE-2026-73496" in refs and "CVE-2026-73497" in refs


def test_no_second_pin_was_added_for_an_already_covered_package() -> None:
    """Two pins on one package report one dependency twice."""
    from agent_audit_kit.scanners.mcp_cve_pins_2026_07 import _PINS

    for pkg in ("praisonai", "mcp-atlassian"):
        assert sum(1 for p in _PINS if pkg in p.names) == 1, pkg


# ---------------------------------------------------------------------------
# Floor raised: the case a cve_references line cannot cover
# ---------------------------------------------------------------------------


def test_dbt_mcp_floor_now_covers_the_gap_between_1_17_1_and_1_20_0() -> None:
    assert DBT in _pins("dbt-mcp==1.18.0\n"), "1.18.0 was vulnerable and silent"
    assert DBT in _pins("dbt-mcp==1.19.9\n")
    assert DBT not in _pins("dbt-mcp==1.20.0\n")


def test_dbt_mcp_cve_is_recorded() -> None:
    assert "CVE-2026-55837" in RULES[DBT].cve_references


# ---------------------------------------------------------------------------
# New pins
# ---------------------------------------------------------------------------


def test_pypi_langgraph_mongo_packages_are_pinned() -> None:
    """The existing pin named the npm package and could not see these."""
    assert MONGO in _pins("langgraph-checkpoint-mongodb==0.2.9\n")
    assert MONGO not in _pins("langgraph-checkpoint-mongodb==0.3.0\n")
    assert MONGO in _pins("langgraph-store-mongodb==0.3.9\n")
    assert MONGO not in _pins("langgraph-store-mongodb==0.4.0\n")


def test_mongo_cve_is_recorded_on_the_existing_rule() -> None:
    assert "CVE-2026-55253" in RULES[MONGO].cve_references


def test_langgraph_api_is_pinned_at_0_10_0() -> None:
    assert LGAPI in _pins("langgraph-api==0.9.0\n")
    assert LGAPI not in _pins("langgraph-api==0.10.0\n")


def test_langgraph_api_rule_is_registered() -> None:
    rule = RULES[LGAPI]
    assert rule.severity.value == "medium"
    assert rule.cve_references == ["CVE-2026-55235"]


# ---------------------------------------------------------------------------
# Out of scope: no rule may claim the Storm advisories
# ---------------------------------------------------------------------------


def test_no_rule_claims_the_apache_storm_advisories() -> None:
    """They matched the watcher on the word "agents" in a credit line.

    Recording them against any rule would be a false coverage claim, which in a
    scanner is worse than recording nothing.
    """
    storm = {"CVE-2026-82439", "CVE-2026-82428", "CVE-2026-82427", "CVE-2026-82429"}
    claimed = {c for r in RULES.values() for c in r.cve_references} & storm
    assert claimed == set(), f"out-of-scope CVEs claimed by a rule: {sorted(claimed)}"
