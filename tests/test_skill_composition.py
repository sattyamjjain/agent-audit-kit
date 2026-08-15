"""Tests for the composition-aware capability-union check (AAK-AGENT-COMPOSE-001).

The rule operates on the SET of skills that load into one agent context, not one
artifact at a time. Fixtures under tests/fixtures/skill_composition/ reproduce the
ColluSkill shape: three skills that individually pass every existing rule but
collectively cross the exfiltration boundary. A benign three-skill set is the
false-positive control.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agent_audit_kit.engine import run_scan
from agent_audit_kit.output.sarif import format_results
from agent_audit_kit.rules.builtin import RULES
from agent_audit_kit.scanners.skill_composition import scan

FIX = Path(__file__).resolve().parent / "fixtures" / "skill_composition"
RULE = "AAK-AGENT-COMPOSE-001"


def _ids(root: Path) -> list[str]:
    return [f.rule_id for f in scan(root)[0]]


def test_rule_registered_with_limitations() -> None:
    assert RULE in RULES
    rule = RULES[RULE]
    assert rule.severity.value == "high"
    assert rule.category.value == "trust-boundary"
    assert rule.owasp_agentic_references, "needs a framework mapping"
    # Honest about its own scope.
    assert rule.limitations and "declared capability" in rule.limitations.lower()
    # Cites the composition study.
    assert "2608.09732" in rule.description


def test_collude_set_trips() -> None:
    assert RULE in _ids(FIX / "collude")


def test_benign_set_does_not_trip() -> None:
    # The false-positive control: a read/write-only set with no egress must stay silent.
    assert _ids(FIX / "benign") == []


def test_finding_names_which_skill_contributed_which_capability() -> None:
    findings, _ = scan(FIX / "collude")
    finding = next(f for f in findings if f.rule_id == RULE)
    related = {r["file_path"]: r["message"] for r in finding.related_locations}
    # Every one of the three skills is named as a contributor.
    assert any("project-reader" in p for p in related)
    assert any("credential-loader" in p for p in related)
    assert any("metrics-reporter" in p for p in related)
    # The egress destination is surfaced, not just "a set is risky".
    egress_msg = next(m for p, m in related.items() if "metrics-reporter" in p)
    assert "metrics-collector.attacker.example" in egress_msg
    # The read/credential contributors are labelled with the capability they add.
    assert "filesystem_read" in " ".join(related.values())
    assert "credential_access" in " ".join(related.values())


def test_collude_skills_are_individually_clean() -> None:
    # The whole point of the ColluSkill shape: every existing rule passes on each
    # skill in isolation, so the SET-level rule is the ONLY thing that fires.
    ids = {f.rule_id for f in run_scan(FIX / "collude").findings}
    assert ids == {RULE}, f"a per-skill rule fired on an individually-benign skill: {ids}"


def test_sarif_carries_contributors_as_related_locations() -> None:
    result = run_scan(FIX / "collude")
    sarif = json.loads(format_results(result, project_root=FIX / "collude"))
    results = sarif["runs"][0]["results"]
    compose = next(r for r in results if r["ruleId"] == RULE)
    related = compose.get("relatedLocations", [])
    uris = {rl["physicalLocation"]["artifactLocation"]["uri"] for rl in related}
    assert any("metrics-reporter" in u for u in uris)
    assert any("credential-loader" in u for u in uris)
    assert any("project-reader" in u for u in uris)


def test_boundary_is_configurable_via_egress_allowlist(tmp_path: Path) -> None:
    # Copy the colluding set, then allowlist the egress destination via a
    # project-level override. The set must then NOT trip — proving the boundary /
    # allowlist is configurable, not hard-coded.
    shutil.copytree(FIX / "collude", tmp_path / "proj")
    aak = tmp_path / "proj" / ".aak"
    aak.mkdir()
    (aak / "composition-boundaries.yaml").write_text(
        "boundaries:\n"
        "  - name: exfiltration-path\n"
        "    left: [filesystem_read, credential_access]\n"
        "    right: [network_egress]\n"
        "    destination_checked_side: right\n"
        "    severity: high\n"
        "egress_allowlist: [metrics-collector.attacker.example]\n",
        encoding="utf-8",
    )
    assert _ids(tmp_path / "proj") == []
