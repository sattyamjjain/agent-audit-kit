"""Per-rule framework coverage crosswalk — the source of truth for
``agent-audit-kit --emit-coverage``, ``docs/coverage.json`` and the coverage &
crosswalk reference at ``docs/STATE-OF-MCP-SECURITY-2026.md``.

For every rule in the built-in registry this emits: id, title, severity,
category, the CVE(s) it covers, its OWASP MCP Top-10 slot, its OWASP Agentic
Top-10 (2026) slot, the NSA MCP CSI control it evidences, and the EU AI Act
article it maps to — then groups and counts by framework. Every mapping is
derived from the committed registry and the existing compliance / OWASP tables
(``compliance.FRAMEWORKS``, ``owasp_report.OWASP_*``); nothing is hand-typed, so
the artifact cannot drift from the code, and ``total_rules`` is always
``len(RULES)``.

Deterministic: rules are sorted by id, keys are sorted, so two runs produce
byte-identical output (guarded by ``tests/test_coverage_map.py``).
"""

from __future__ import annotations

import json
from typing import Any, cast

from agent_audit_kit.output.compliance import FRAMEWORKS
from agent_audit_kit.output.owasp_report import OWASP_AGENTIC, OWASP_MCP
from agent_audit_kit.rules.builtin import RULES

_CSI = cast("dict[str, Any]", FRAMEWORKS["nsa-mcp-csi-2026"])
_EU = cast("dict[str, Any]", FRAMEWORKS["eu-ai-act"])

# 2026-07-28 MCP-final surfaces. The crosswalk reserves a slot for each so a
# future rule slots in without a schema change. SEP-1865 / SEP-2663 already have
# rules (added in the spec-ahead pack); the other two are reserved — NO rule is
# invented here.
_RESERVED_2026_07_28: tuple[dict[str, Any], ...] = (
    {
        "surface": "Stateless _meta-per-request",
        "reference": "MCP final 2026-07-28 (per-request _meta; stateless servers)",
        "rule_id_prefix": "AAK-MCP-META",
    },
    {
        "surface": "MCP Apps sandboxed iframes",
        "reference": "SEP-1865",
        "rule_id_prefix": "AAK-MCP-APPS",
    },
    {
        "surface": "Tasks handles",
        "reference": "SEP-2663",
        "rule_id_prefix": "AAK-TASKS",
    },
    {
        "surface": "JSON-Schema-2020-12 tool schemas",
        "reference": "MCP final 2026-07-28 (JSON Schema 2020-12 tool input/output schemas)",
        "rule_id_prefix": "AAK-MCP-SCHEMA",
    },
)


def _csi_controls_for(rule_id: str, asi: set[str]) -> list[str]:
    out: list[str] = []
    for name, spec in _CSI["controls"].items():
        if not isinstance(spec, dict):
            continue
        if rule_id in spec.get("rule_ids", []) or (asi & set(spec.get("also_covers_asi", []))):
            out.append(name)
    return out


def _eu_articles_for(asi: set[str]) -> list[str]:
    return [art for art, tokens in _EU["controls"].items() if asi & set(tokens)]


def _labelled(codes: list[str], titles: dict[str, str]) -> list[str]:
    return [f"{c} {titles[c]}" if c in titles else c for c in codes]


def build_coverage() -> dict[str, Any]:
    """The full crosswalk: per-rule rows + framework roll-ups + reserved slots."""
    rows: list[dict[str, Any]] = []
    cve_set: set[str] = set()
    by_sev: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    by_agentic: dict[str, int] = {}
    by_mcp: dict[str, int] = {}
    by_csi: dict[str, int] = {}
    by_eu: dict[str, int] = {}

    for rid in sorted(RULES):
        rule = RULES[rid]
        asi = set(rule.owasp_agentic_references)
        csi = _csi_controls_for(rid, asi)
        eu = _eu_articles_for(asi)
        row = {
            "rule_id": rid,
            "title": rule.title,
            "severity": rule.severity.value,
            "category": rule.category.value,
            "cve_references": sorted(rule.cve_references),
            "owasp_mcp": _labelled(sorted(rule.owasp_mcp_references), OWASP_MCP),
            "owasp_agentic": _labelled(sorted(rule.owasp_agentic_references), OWASP_AGENTIC),
            "nsa_mcp_csi": csi,
            "eu_ai_act": eu,
        }
        rows.append(row)

        cve_set.update(rule.cve_references)
        by_sev[rule.severity.value] = by_sev.get(rule.severity.value, 0) + 1
        by_cat[rule.category.value] = by_cat.get(rule.category.value, 0) + 1
        for a in rule.owasp_agentic_references:
            by_agentic[a] = by_agentic.get(a, 0) + 1
        for m in rule.owasp_mcp_references:
            by_mcp[m] = by_mcp.get(m, 0) + 1
        for c in csi:
            by_csi[c] = by_csi.get(c, 0) + 1
        for e in eu:
            by_eu[e] = by_eu.get(e, 0) + 1

    reserved = []
    for spec in _RESERVED_2026_07_28:
        matched = sorted(r for r in RULES if r.startswith(spec["rule_id_prefix"]))
        reserved.append({
            "surface": spec["surface"],
            "reference": spec["reference"],
            "status": "covered" if matched else "reserved",
            "rule_ids": matched,
        })

    return {
        "tool": "agent-audit-kit",
        "schema_version": "1",
        "summary": {
            "total_rules": len(RULES),
            "total_cves_covered": len(cve_set),
            "by_severity": dict(sorted(by_sev.items())),
            "by_category": dict(sorted(by_cat.items())),
            "by_owasp_agentic": dict(sorted(by_agentic.items())),
            "by_owasp_mcp": dict(sorted(by_mcp.items())),
            "by_nsa_mcp_csi": dict(sorted(by_csi.items())),
            "by_eu_ai_act": dict(sorted(by_eu.items())),
        },
        "frameworks": {
            "owasp_agentic_top10_2026": OWASP_AGENTIC,
            "owasp_mcp_top10_2025": OWASP_MCP,
            "nsa_mcp_csi_2026": _CSI["source"],
            "eu_ai_act": {"name": _EU["name"], "articles": sorted(_EU["controls"])},
        },
        "reserved_surfaces_2026_07_28": reserved,
        "rules": rows,
    }


def render_json() -> str:
    """Byte-deterministic machine-readable coverage (docs/coverage.json)."""
    return json.dumps(build_coverage(), indent=2, sort_keys=True) + "\n"


def render_markdown() -> str:
    data = build_coverage()
    s = data["summary"]
    src = data["frameworks"]["nsa_mcp_csi_2026"]
    out: list[str] = [
        "# AgentAuditKit — coverage, mapped to frameworks",
        "",
        f"**{s['total_rules']} rules** covering **{s['total_cves_covered']} CVEs**, "
        "each mapped to its OWASP MCP Top-10 slot, OWASP Agentic Top-10 (2026) slot, "
        "NSA MCP Security CSI control, and EU AI Act article. Generated from the "
        "committed rule registry — the counts here are always `len(RULES)`.",
        "",
        "## Counts by framework",
        "",
        "| Framework | Slots covered |",
        "|-----------|---------------|",
        f"| Severity | {_fmt_counts(s['by_severity'])} |",
        f"| OWASP Agentic Top-10 (2026) | {_fmt_counts(s['by_owasp_agentic'])} |",
        f"| OWASP MCP Top-10 (2025) | {_fmt_counts(s['by_owasp_mcp'])} |",
        f"| NSA MCP CSI ({src['doc_id']}) | {len(s['by_nsa_mcp_csi'])} / 9 controls |",
        f"| EU AI Act | {len(s['by_eu_ai_act'])} / {len(data['frameworks']['eu_ai_act']['articles'])} articles |",
        "",
        "## 2026-07-28 MCP-final surfaces (crosswalk slots)",
        "",
        "| Surface | Reference | Status | Rules |",
        "|---------|-----------|--------|-------|",
    ]
    for r in data["reserved_surfaces_2026_07_28"]:
        rules = ", ".join(f"`{x}`" for x in r["rule_ids"]) or "—"
        out.append(f"| {r['surface']} | {r['reference']} | {r['status']} | {rules} |")
    out += [
        "",
        "## Per-rule crosswalk",
        "",
        "| Rule | Sev | CVE(s) | OWASP MCP | OWASP Agentic | NSA MCP CSI | EU AI Act |",
        "|------|-----|--------|-----------|---------------|-------------|-----------|",
    ]
    for row in data["rules"]:
        cves = ", ".join(row["cve_references"]) or "—"
        mcp = "; ".join(m.split(" ")[0] for m in row["owasp_mcp"]) or "—"
        asi = "; ".join(a.split(" ")[0] for a in row["owasp_agentic"]) or "—"
        csi = "; ".join(c.split(" (p.")[0] for c in row["nsa_mcp_csi"]) or "—"
        eu = "; ".join(e.split(" - ")[0] for e in row["eu_ai_act"]) or "—"
        out.append(
            f"| `{row['rule_id']}` | {row['severity']} | {cves} | {mcp} | {asi} | {csi} | {eu} |"
        )
    out.append("")
    return "\n".join(out)


def _fmt_counts(d: dict[str, int]) -> str:
    return ", ".join(f"{k}={v}" for k, v in d.items()) or "—"
