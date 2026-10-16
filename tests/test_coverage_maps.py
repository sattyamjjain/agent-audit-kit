"""The coverage maps behind `aak coverage` name real rules, and only real rules count.

`aak coverage --source ox` and `--source prisma-airs`, the OX badge and the coverage
page report how much of two outside catalogues AAK covers: OX Security's MCP
disclosures (`data/ox-cve-manifest.json`) and Palo Alto's Prisma AIRS attack catalogue
(`data/prisma-airs-aak-map.json`). Both maps were written by hand in April 2026, and
between them they cited six ids that no rule ever had, each a wrong name for a rule
that did exist: `AAK-MCP-STDIO-PARAMS-001` for the four `AAK-MCP-STDIO-CMD-INJ` rules
that `mcp_stdio_params` emits, `AAK-MCP-MARKETPLACE-FETCH-001` for
`AAK-MCP-MARKETPLACE-CONFIG-FETCH-001`, `AAK-LOG-TOKEN-LEAK-001` for
`AAK-SPLUNK-MCP-TOKEN-LEAK-001`, `AAK-MCP-SERVER-AUTH-001` for
`AAK-AZURE-MCP-NOAUTH-001`, `AAK-LANGCHAIN-SSRF-TOCTOU-001` for `AAK-SSRF-TOCTOU-001`
and `AAK-OAUTH-3P-BROAD-001` for `AAK-OAUTH-SCOPE-001`. Four entries rested on those
names alone and were counted as covered anyway, because both summaries counted a
listed id without asking whether it was a rule.

So both halves are checked here: the maps cite registered rules, and an id that is not
a registered rule covers nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_audit_kit import coverage
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.translators import prisma_airs

DATA = Path(__file__).resolve().parent.parent / "agent_audit_kit" / "data"

#: Not a rule, and never one: what a typo in a map looks like to the summaries.
_NOT_A_RULE = "AAK-NOT-A-RULE-001"


def _ox_entries() -> list[dict]:
    return json.loads((DATA / "ox-cve-manifest.json").read_text(encoding="utf-8"))["entries"]


def _airs_map() -> list[dict]:
    return json.loads((DATA / "prisma-airs-aak-map.json").read_text(encoding="utf-8"))["map"]


def test_the_ox_manifest_cites_only_registered_rules() -> None:
    unknown = sorted({rule for entry in _ox_entries() for rule in entry.get("rules", []) if rule not in RULES})
    assert not unknown, f"ox-cve-manifest.json cites ids that are not rules: {unknown}"


def test_the_prisma_airs_map_cites_only_registered_rules() -> None:
    unknown = sorted({rule for entry in _airs_map() for rule in entry.get("aak_rule_ids", []) if rule not in RULES})
    assert not unknown, f"prisma-airs-aak-map.json cites ids that are not rules: {unknown}"


def test_every_ox_entry_is_covered_by_a_rule_that_cites_it() -> None:
    """A covering rule names the disclosure itself, as a CVE or an incident reference.

    This is what pins the renamed ids to the right rules, not just to some rule: the
    entry for CVE-2026-41488 must be covered by a rule whose `cve_references` holds
    CVE-2026-41488, and OX-MCP-2026-04-25 by rules that carry that incident.
    """
    unbacked = {}
    for entry in _ox_entries():
        citing = [
            rule
            for rule in entry.get("rules", [])
            if rule in RULES
            and (entry["cve"] in RULES[rule].cve_references or entry["cve"] in RULES[rule].incident_references)
        ]
        if not citing:
            unbacked[entry["cve"]] = entry.get("rules", [])
    assert not unbacked, f"entries no listed rule cites: {unbacked}"


def test_an_ox_entry_backed_only_by_an_unregistered_id_is_uncovered() -> None:
    summary = coverage.summarize([
        {"cve": "CVE-2026-0001", "title": "only a typo", "covered": True, "rules": [_NOT_A_RULE]},
        {"cve": "CVE-2026-0002", "title": "a rule and a typo", "covered": True, "rules": ["AAK-MCP-001", _NOT_A_RULE]},
        {"cve": "CVE-2026-0003", "title": "the manifest says no", "covered": False, "rules": ["AAK-MCP-001"]},
    ])
    assert (summary["total"], summary["covered"], summary["coverage_pct"]) == (3, 1, 33.3)
    by_cve = {entry["cve"]: entry for entry in summary["entries"]}
    assert by_cve["CVE-2026-0001"] == {"cve": "CVE-2026-0001", "title": "only a typo", "covered": False, "rules": []}
    assert by_cve["CVE-2026-0002"]["covered"] is True
    assert by_cve["CVE-2026-0002"]["rules"] == ["AAK-MCP-001"]
    assert by_cve["CVE-2026-0003"]["covered"] is False


def test_an_airs_attack_backed_only_by_an_unregistered_id_is_uncovered() -> None:
    catalog = [
        {"airs_attack_id": "PA-T-1", "title": "only a typo", "category": "x"},
        {"airs_attack_id": "PA-T-2", "title": "a rule and a typo", "category": "x"},
        {"airs_attack_id": "PA-T-3", "title": "runtime", "category": "x"},
    ]
    mapping = [
        {"airs_attack_id": "PA-T-1", "aak_rule_ids": [_NOT_A_RULE], "status": "covered"},
        {"airs_attack_id": "PA-T-2", "aak_rule_ids": ["AAK-MCP-001", _NOT_A_RULE], "status": "covered"},
        {"airs_attack_id": "PA-T-3", "aak_rule_ids": [], "status": "runtime-only"},
    ]
    summary = prisma_airs.summarize(catalog=catalog, mapping=mapping)
    assert (summary["total_static"], summary["covered"], summary["coverage_pct"]) == (2, 1, 50.0)
    rows = {row["airs_attack_id"]: row for row in summary["entries"]}
    assert (rows["PA-T-1"]["status"], rows["PA-T-1"]["aak_rule_ids"]) == ("uncovered", [])
    assert (rows["PA-T-2"]["status"], rows["PA-T-2"]["aak_rule_ids"]) == ("covered", ["AAK-MCP-001"])
    assert rows["PA-T-3"]["status"] == "runtime-only"
    assert prisma_airs.map_airs_attack_to_rule({"airs_attack_id": "PA-T-2"}, mapping) == ["AAK-MCP-001"]


def test_every_entry_the_maps_mark_covered_is_counted_as_covered() -> None:
    """What the maps claim and what the summaries count agree, entry by entry.

    An entry can still be honestly uncovered (`covered: false`, or no `status: covered`);
    what may not happen again is a claim of coverage that no registered rule backs.
    """
    ox = coverage.summarize(coverage.load_manifest("ox"))
    claimed = {entry["cve"] for entry in _ox_entries() if entry.get("covered")}
    assert {entry["cve"] for entry in ox["entries"] if entry["covered"]} == claimed
    airs = prisma_airs.summarize()
    claimed = {entry["airs_attack_id"] for entry in _airs_map() if entry.get("status") == "covered"}
    assert {row["airs_attack_id"] for row in airs["entries"] if row["status"] == "covered"} == claimed
