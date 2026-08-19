"""Standards crosswalk: every AAK rule → NSA MCP CSI control + OWASP Agentic Top-10.

A static, deterministic mapping artifact (no scan required) that positions the
AgentAuditKit rule set against two agentic-security standards:

  - **NSA MCP Security CSI** (U/OO/6030316-26, May 2026) — 9 recommendation
    sections. A rule maps to a section if it is explicitly listed there, or if
    one of its OWASP-Agentic tokens fans out to it (the same `also_covers_asi`
    logic the compliance report uses).
  - **OWASP Agentic Top-10 (2026)** — ASI01–ASI10, from each rule's
    `owasp_agentic_references`.

This is provenance evidence: it shows, rule by rule, which recognized control a
finding satisfies. Reuses the committed mappings in
`agent_audit_kit.output.compliance` and `.owasp_report` — no mapping is invented
here, so the crosswalk cannot drift from the compliance reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

from agent_audit_kit.output.compliance import FRAMEWORKS
from agent_audit_kit.output.owasp_report import OWASP_AGENTIC
from agent_audit_kit.rules.builtin import RULES

# FRAMEWORKS values are heterogeneous (str name + nested control/source dicts);
# the NSA CSI entry is a mapping — narrow it once so field access is typed.
_CSI: dict[str, Any] = cast("dict[str, Any]", FRAMEWORKS["nsa-mcp-csi-2026"])


@dataclass(frozen=True)
class CrosswalkRow:
    rule_id: str
    category: str
    severity: str
    nsa_csi_controls: list[str] = field(default_factory=list)
    owasp_agentic: list[str] = field(default_factory=list)


def _csi_controls_for(rule_id: str, asi_tokens: list[str]) -> list[str]:
    """CSI recommendation sections a rule evidences — explicit listing OR ASI
    fan-out (`also_covers_asi`), mirroring the compliance report's own logic."""
    out: list[str] = []
    asi = set(asi_tokens)
    for control_name, spec in _CSI["controls"].items():
        if not isinstance(spec, dict):
            continue
        if rule_id in spec.get("rule_ids", []) or (asi & set(spec.get("also_covers_asi", []))):
            out.append(control_name)
    return out


def build_crosswalk() -> list[CrosswalkRow]:
    """One row per rule (sorted by rule_id) with its CSI + OWASP-Agentic mapping."""
    rows: list[CrosswalkRow] = []
    for rid in sorted(RULES):
        rule = RULES[rid]
        asi = list(rule.owasp_agentic_references)
        rows.append(CrosswalkRow(
            rule_id=rid,
            category=rule.category.value,
            severity=rule.severity.value,
            nsa_csi_controls=_csi_controls_for(rid, asi),
            owasp_agentic=[f"{a} {OWASP_AGENTIC.get(a, a)}" for a in asi],
        ))
    return rows


def _short_csi(name: str) -> str:
    """'Design for boundaries (p.10)' → 'Design for boundaries'."""
    return name.split(" (p.")[0]


def render_markdown() -> str:
    rows = build_crosswalk()
    src = _CSI["source"]
    mapped = sum(1 for r in rows if r.nsa_csi_controls or r.owasp_agentic)
    out: list[str] = [
        "# AgentAuditKit standards crosswalk",
        "",
        f"Every AgentAuditKit rule ({len(rows)} total; {mapped} mapped) against two "
        "agentic-security standards. Static and deterministic — generated from the "
        "committed rule registry and compliance mappings, no scan required.",
        "",
        "**Standards**",
        "",
        f"- **NSA MCP Security CSI** — {src['title']} "
        f"({src['doc_id']}, {src['publisher']}, {src['published']}).",
        "- **OWASP Agentic Top-10 (2026)** — ASI01–ASI10.",
        "",
        "**Composition** — three rules in this table (`AAK-COMPOSE-001/002/003`) hold "
        "over a *graph* of components rather than one artifact, because a chain can "
        "cross a control boundary while every component on it satisfies the control "
        "individually. Source results: CompoSkill "
        "([arXiv:2608.16246](https://arxiv.org/abs/2608.16246)), which assembles a risk "
        "chain from skills that each pass an individual scanner and reports attack "
        "success falling off past three skills, and ColluSkill "
        "([arXiv:2608.09732](https://arxiv.org/abs/2608.09732)), whose skills cooperate "
        "through a medium neither declares. Read the CSI controls below as per-component "
        "requirements; these three are what checks the joins between them.",
        "",
        "**Evidence** — for how often these controls actually fail in the wild, see "
        "*The State of MCP Security, 2026* (v1.0): a scan of 2,303 distinct public "
        "MCP configs. "
        "[Report](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md)"
        " · this crosswalk says what the controls are; the report says how often they "
        "are met.",
        "",
        "| AAK rule | Severity | Category | NSA MCP CSI control(s) | OWASP Agentic Top-10 (2026) |",
        "|----------|----------|----------|------------------------|------------------------------|",
    ]
    for r in rows:
        csi = "; ".join(_short_csi(c) for c in r.nsa_csi_controls) or "—"
        asi = "; ".join(r.owasp_agentic) or "—"
        out.append(f"| `{r.rule_id}` | {r.severity} | {r.category} | {csi} | {asi} |")
    out.append("")
    return "\n".join(out)


def render_text() -> str:
    """Plain-text variant for `report --framework standards-crosswalk --format text`."""
    rows = build_crosswalk()
    src = _CSI["source"]
    out: list[str] = [
        "AgentAuditKit standards crosswalk",
        "=" * 34,
        f"NSA MCP Security CSI: {src['doc_id']} ({src['published']})",
        "OWASP Agentic Top-10 (2026): ASI01-ASI10",
        f"{len(rows)} rules",
        "",
    ]
    for r in rows:
        csi = "; ".join(_short_csi(c) for c in r.nsa_csi_controls) or "-"
        asi = "; ".join(r.owasp_agentic) or "-"
        out.append(f"{r.rule_id}  [{r.severity}/{r.category}]")
        out.append(f"    NSA MCP CSI : {csi}")
        out.append(f"    OWASP ASI   : {asi}")
    return "\n".join(out)
