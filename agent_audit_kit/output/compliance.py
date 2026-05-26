from __future__ import annotations

import re

from agent_audit_kit.models import ScanResult, Severity
from agent_audit_kit.rules.builtin import RULES

FRAMEWORKS = {
    "eu-ai-act": {
        "name": "EU AI Act",
        "controls": {
            "Art. 9 - Risk Management": ["ASI01", "ASI02", "ASI05", "ASI10"],
            "Art. 10 - Data Governance": ["ASI06", "ASI04"],
            "Art. 13 - Transparency": ["ASI09", "ASI01"],
            "Art. 14 - Human Oversight": ["ASI09", "ASI10"],
            "Art. 15 - Robustness & Security": ["ASI03", "ASI04", "ASI05", "ASI08"],
        },
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "controls": {
            "CC6.1 - Access Control": ["ASI03", "ASI06"],
            "CC6.3 - Role-Based Access": ["ASI03"],
            "CC6.6 - System Boundaries": ["ASI05", "ASI02"],
            "CC6.7 - Data Transmission": ["ASI03"],
            "CC7.1 - Vulnerability Management": ["ASI04"],
            "CC7.2 - Incident Detection": ["ASI08", "ASI10"],
            "CC8.1 - Change Management": ["ASI04", "ASI06"],
        },
    },
    "iso27001": {
        "name": "ISO 27001:2022",
        "controls": {
            "A.8.9 - Configuration Management": ["ASI02", "ASI05"],
            "A.8.24 - Cryptography": ["ASI03"],
            "A.8.25 - Secure Development": ["ASI05", "ASI04"],
            "A.8.28 - Secure Coding": ["ASI05", "ASI02"],
            "A.5.23 - Cloud Security": ["ASI03", "ASI04"],
            "A.8.12 - Data Classification": ["ASI06"],
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "controls": {
            "164.312(a) - Access Control": ["ASI03", "ASI06"],
            "164.312(c) - Integrity": ["ASI04", "ASI06"],
            "164.312(d) - Authentication": ["ASI03"],
            "164.312(e) - Transmission Security": ["ASI03"],
            "164.308(a)(1) - Security Management": ["ASI01", "ASI10"],
        },
    },
    "nist-ai-rmf": {
        "name": "NIST AI RMF 1.0",
        "controls": {
            "GOVERN 1.1 - AI Policies": ["ASI01", "ASI09"],
            "MAP 1.5 - Risk Identification": ["ASI02", "ASI05", "ASI08"],
            "MEASURE 2.6 - Safety Metrics": ["ASI05", "ASI08"],
            "MANAGE 2.2 - Risk Treatment": ["ASI04", "ASI10"],
            "MANAGE 4.1 - Incident Response": ["ASI08", "ASI10"],
        },
    },
    "mcp-2026-roadmap": {
        # MCP 2026 Roadmap (May 2026) — adds transport-hardening +
        # signed-tools requirements that are stricter than the live
        # MCP spec our existing 4 STDIO rules assume. Lite scope: maps
        # the Roadmap's named requirements onto the AAK rules that
        # already cover them, so consumers can run
        # `aak scan --compliance mcp-2026-roadmap` and see whether they
        # would pass the Roadmap conformance bar today. AISI Cyber
        # Eval 2026-05-01 cites MCP transport hardening as an axis;
        # this surface seeds the data-shape for the v0.3.16 CSA
        # Agentic Trust full-conformance work.
        "name": "MCP 2026 Roadmap",
        "controls": {
            # Transport-flip resistance — the central hardening item.
            "Transport Hardening (no stdio override)": ["ASI02", "ASI05", "ASI10"],
            # Tool provenance / signed-tools checks.
            "Tool Provenance / Signed Tools": ["ASI04", "ASI05"],
            # Protocol-version pinning (manifest discipline).
            "Protocol Version Pinning": ["ASI03", "ASI04"],
            # Authenticated MCP endpoints, deprecate unauth STDIO.
            "Authenticated Endpoints (STDIO deprecation)": ["ASI03", "ASI05", "ASI10"],
            # Marketplace/source provenance for installed servers.
            "Marketplace Source Provenance": ["ASI04", "ASI06"],
        },
    },
}


def _get_rules_for_asi(asi_code: str) -> list[str]:
    return [
        rule_id for rule_id, rule in RULES.items()
        if asi_code in rule.owasp_agentic_references
    ]


# ---------------------------------------------------------------------------
# EU AI Act Article 15 evidence subsection
#
# Article 15 of Regulation (EU) 2024/1689 (binding for high-risk AI systems
# on 2026-08-02) requires "an appropriate level of accuracy, robustness and
# cybersecurity throughout the lifecycle". The default control row above
# only summarises PASS/FAIL via OWASP-Agentic ASI mapping; this subsection
# adds itemised evidence lines that auditors expect to see in an Article-15
# evidence pack — currently:
#
#   - multilingual-locale-declared: which locales an agent claims to serve
#   - multilingual-eval-coverage:   whether per-locale eval fixtures exist
#
# Driven directly off `AAK-EU-AI-ACT-ART15-LOCALE-001` findings (advisory /
# INFO severity, no ASI tag) so a single coverage gap does NOT flip the
# Art. 15 control to FAIL through the OWASP-Agentic mapping.
# ---------------------------------------------------------------------------

_ART15_LOCALE_RULE = "AAK-EU-AI-ACT-ART15-LOCALE-001"
_DECLARED_RE = re.compile(r"locales=\[([^\]]*)\]")
_COVERED_RE = re.compile(r"fixtures cover locales=\[([^\]]*)\]")


def _art15_locale_subsection(result: ScanResult) -> list[str]:
    """Emit Article-15 evidence sub-items beneath the Art. 15 control row.

    Two stable line items are emitted on every eu-ai-act report (so the
    evidence shape stays deterministic for auditors), with the values
    derived from `AAK-EU-AI-ACT-ART15-LOCALE-001` findings when present.
    """
    findings = [f for f in result.findings if f.rule_id == _ART15_LOCALE_RULE]
    lines: list[str] = []
    lines.append("    Article 15 — Accuracy, Robustness & Cybersecurity (evidence)")

    if findings:
        # Aggregate across every agent config that fired.
        all_declared: set[str] = set()
        all_covered: set[str] = set()
        for f in findings:
            md = _DECLARED_RE.search(f.evidence or "")
            mc = _COVERED_RE.search(f.evidence or "")
            if md:
                all_declared.update(
                    t.strip() for t in md.group(1).split(",") if t.strip()
                )
            if mc:
                covered_raw = mc.group(1).strip()
                if covered_raw and covered_raw != "none":
                    all_covered.update(
                        t.strip() for t in covered_raw.split(",") if t.strip()
                    )
        declared_str = ", ".join(sorted(all_declared)) or "n/a"
        covered_str = ", ".join(sorted(all_covered)) if all_covered else "none"
        lines.append(
            f"      multilingual-locale-declared: "
            f"{len(all_declared)} locale(s) ({declared_str})"
        )
        lines.append(
            f"      multilingual-eval-coverage: not evidenced — "
            f"covered=[{covered_str}], "
            f"{len(findings)} finding(s) ({_ART15_LOCALE_RULE})"
        )
    else:
        lines.append(
            "      multilingual-locale-declared: n/a "
            "(no multilingual user-facing agent config detected)"
        )
        lines.append(
            "      multilingual-eval-coverage: evidenced "
            "or not applicable (no Art. 15 locale-coverage finding)"
        )
    return lines


def format_results(result: ScanResult, framework_key: str) -> str:
    framework = FRAMEWORKS.get(framework_key)
    if not framework:
        available = ", ".join(FRAMEWORKS.keys())
        return f"Unknown compliance framework: {framework_key}\nAvailable: {available}"

    lines: list[str] = []
    lines.append(f"\n\u2501\u2501\u2501 {framework['name']} Compliance Report \u2501\u2501\u2501\n")

    finding_rules = {f.rule_id for f in result.findings}
    controls_met = 0
    controls_total = len(framework["controls"])

    controls = framework["controls"]
    assert isinstance(controls, dict)
    for control, asi_codes in controls.items():
        mapped_rules: list[str] = []
        for asi in asi_codes:
            mapped_rules.extend(_get_rules_for_asi(asi))
        mapped_rules = list(set(mapped_rules))

        triggered = [r for r in mapped_rules if r in finding_rules]
        if not triggered:
            status = "\u2705 PASS"
            controls_met += 1
        else:
            sev = max(
                (f.severity for f in result.findings if f.rule_id in triggered),
                key=lambda s: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO].index(s),
            )
            status = f"\u274c FAIL ({len(triggered)} finding(s), highest: {sev.value})"

        lines.append(f"  {control}")
        lines.append(f"    Status: {status}")
        lines.append(f"    Mapped rules: {len(mapped_rules)} ({', '.join(mapped_rules[:4])}{'...' if len(mapped_rules) > 4 else ''})")
        if framework_key == "eu-ai-act" and control.startswith("Art. 15"):
            lines.extend(_art15_locale_subsection(result))
        lines.append("")

    pct = 100 * controls_met // controls_total if controls_total else 0
    lines.append(f"Controls met: {controls_met}/{controls_total} ({pct}%)")

    if result.score is not None:
        lines.append(f"Security Score: {result.score}/100  Grade: {result.grade}")

    lines.append("")
    return "\n".join(lines)
