"""Coverage crosswalk emitter + count/staleness guards.

Guards `--emit-coverage`, `docs/coverage.json`, and the count-consistency rule:
the committed artifact is regenerated from the registry, so `total_rules` is
always `len(RULES)` and the committed file can never go stale silently.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_audit_kit.cli import cli
from agent_audit_kit.output import coverage_map
from agent_audit_kit.rules.builtin import RULES

REPO = Path(__file__).resolve().parent.parent
COVERAGE_JSON = REPO / "docs" / "coverage.json"
# Reduced from a competing "report seed" to a coverage & crosswalk pointer
# page on 2026-09-06; it still carries the generated rule-count anchor.
COVERAGE_DOC = REPO / "docs" / "STATE-OF-MCP-SECURITY-2026.md"


# ---------------------------------------------------------------------------
# Builder + counts
# ---------------------------------------------------------------------------


def test_coverage_covers_every_rule() -> None:
    data = coverage_map.build_coverage()
    assert data["summary"]["total_rules"] == len(RULES)
    assert len(data["rules"]) == len(RULES)
    assert [r["rule_id"] for r in data["rules"]] == sorted(RULES)


def test_every_row_has_all_framework_fields() -> None:
    for row in coverage_map.build_coverage()["rules"]:
        assert set(row) >= {
            "rule_id", "title", "severity", "category",
            "cve_references", "owasp_mcp", "owasp_agentic", "nsa_mcp_csi", "eu_ai_act",
        }


def test_framework_rollups_present() -> None:
    s = coverage_map.build_coverage()["summary"]
    for key in ("by_severity", "by_owasp_agentic", "by_owasp_mcp", "by_nsa_mcp_csi", "by_eu_ai_act"):
        assert s[key], key
    assert s["total_cves_covered"] > 0


def test_known_rule_mappings() -> None:
    rows = {r["rule_id"]: r for r in coverage_map.build_coverage()["rules"]}
    # A rule with a CVE surfaces it.
    assert any("CVE-" in c for c in rows["AAK-MCP-STATA-CVE-2026-47708-001"]["cve_references"])
    # NSA CSI + EU AI Act derive from the rule's ASI tokens.
    apps = rows["AAK-MCP-APPS-001"]
    assert any("Constrain and sandbox" in c for c in apps["nsa_mcp_csi"])
    assert any("Art. 15" in a for a in apps["eu_ai_act"])


# ---------------------------------------------------------------------------
# 2026-07-28 reserved surfaces (do not invent rules)
# ---------------------------------------------------------------------------


def test_reserved_surfaces_status() -> None:
    reserved = {r["surface"]: r for r in coverage_map.build_coverage()["reserved_surfaces_2026_07_28"]}
    # SEP-1865 / SEP-2663 already have rules -> covered.
    assert reserved["MCP Apps sandboxed iframes"]["status"] == "covered"
    assert "AAK-MCP-APPS-001" in reserved["MCP Apps sandboxed iframes"]["rule_ids"]
    assert reserved["Tasks handles"]["status"] == "covered"
    # The two genuinely-new surfaces are reserved (no rule invented).
    assert reserved["Stateless _meta-per-request"]["status"] == "reserved"
    assert reserved["Stateless _meta-per-request"]["rule_ids"] == []
    assert reserved["JSON-Schema-2020-12 tool schemas"]["status"] == "reserved"
    assert reserved["JSON-Schema-2020-12 tool schemas"]["rule_ids"] == []


# ---------------------------------------------------------------------------
# Determinism + staleness (the "counts can't drift" guard)
# ---------------------------------------------------------------------------


def test_render_json_is_deterministic() -> None:
    assert coverage_map.render_json() == coverage_map.render_json()


def test_committed_coverage_json_not_stale() -> None:
    """docs/coverage.json must equal a fresh render — CI fails if it drifted."""
    assert COVERAGE_JSON.read_text(encoding="utf-8") == coverage_map.render_json(), (
        "docs/coverage.json is stale — regenerate: "
        "python -c \"from agent_audit_kit.output.coverage_map import render_json; "
        "open('docs/coverage.json','w').write(render_json())\""
    )


def test_committed_coverage_json_count_matches_registry() -> None:
    data = json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))
    assert data["summary"]["total_rules"] == len(RULES)
    assert len(data["rules"]) == len(RULES)


def test_report_seed_rule_count_anchor_matches_registry() -> None:
    import re

    text = COVERAGE_DOC.read_text(encoding="utf-8")
    anchors = re.findall(r"<!--\s*rule-count:total\s*-->(\d+)<!--\s*/rule-count\s*-->", text)
    assert anchors, "the coverage reference lost its rule-count anchor"
    assert all(int(a) == len(RULES) for a in anchors)


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_emit_coverage_json_nonempty() -> None:
    res = CliRunner().invoke(cli, ["--emit-coverage", "--format", "json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert data["summary"]["total_rules"] == len(RULES)
    assert data["rules"]


def test_cli_emit_coverage_md_nonempty() -> None:
    res = CliRunner().invoke(cli, ["--emit-coverage", "--format", "md"])
    assert res.exit_code == 0, res.output
    assert "coverage, mapped to frameworks" in res.output.lower()
    assert "AAK-MCP-APPS-001" in res.output
