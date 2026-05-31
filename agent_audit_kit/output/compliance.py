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
    "iso42001": {
        # ISO/IEC 42001:2023 — Information technology — Artificial intelligence
        # — Management system. Closes the gap between the `--framework
        # iso42001` choice already exposed in cli.py / pdf_report.py and the
        # runtime FRAMEWORKS table that drives the text/console compliance
        # report. Controls are taken from Annex A (normative) and clauses
        # 6/8 of the body. ASI-token mapping mirrors what pdf_report.py uses
        # at the category level: A.6.2.x covers MCP / trust-boundary
        # operational surface, A.8.x covers data quality + AI inputs, A.10
        # covers third-party/supply-chain, A.5 covers leadership.
        "name": "ISO/IEC 42001:2023 — AI Management System",
        "controls": {
            "Clause 6.1.2 — AI risk assessment": ["ASI01", "ASI02", "ASI05", "ASI08"],
            "Clause 6.1.3 — AI risk treatment": ["ASI04", "ASI10"],
            "Clause 8.2 — AI system risk assessment": ["ASI02", "ASI05", "ASI08"],
            "Clause 8.3 — AI system impact assessment": ["ASI05", "ASI09"],
            "A.5.1 — Leadership & governance": ["ASI01", "ASI09"],
            "A.6.2.3 — AI system operational controls": ["ASI02", "ASI05"],
            "A.6.2.4 — AI system boundaries": ["ASI02", "ASI05"],
            "A.6.2.6 — AI verification": ["ASI04", "ASI05"],
            "A.7.4 — Data handling": ["ASI06"],
            "A.8.2 — Data for AI": ["ASI02", "ASI06"],
            "A.8.3 — Data quality & integrity": ["ASI04", "ASI06"],
            "A.10.1 — Supplier AI agreements": ["ASI03", "ASI04"],
        },
    },
    "nsa-mcp-csi-2026": {
        # NSA AISC Cybersecurity Information Sheet:
        # "Model Context Protocol (MCP): Security Design Considerations for
        # AI-Driven Automation" — U/OO/6030316-26 / PP-26-1834, May 2026
        # Ver. 1.0, published 2026-05-20.
        #
        # The CSI body is prose (not numbered controls). Section 2,
        # "Recommendations" (pp.10-14), lists 9 named recommendation
        # sections; each is mapped here to the exact AAK rule IDs that
        # evidence it AND the OWASP-Agentic ASI tokens that fan-out to
        # related rules (so future rule additions auto-light the relevant
        # NSA control without a code change here).
        #
        # Source citation lands in the report header (see format_results)
        # and is the primary evidence handle for auditors — control names
        # are reproduced verbatim from the CSI with their page number for
        # traceability.
        "name": "NSA MCP Security CSI (U/OO/6030316-26, May 2026)",
        "source": {
            "doc_id": "U/OO/6030316-26 | PP-26-1834",
            "title": (
                "Model Context Protocol (MCP): Security Design "
                "Considerations for AI-Driven Automation"
            ),
            "publisher": "NSA Artificial Intelligence Security Center (AISC)",
            "published": "May 2026 Ver. 1.0",
            "url": "https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf",
        },
        "controls": {
            "Choose supported MCP projects when possible (p.10)": {
                "rule_ids": [
                    "AAK-RUGPULL-001", "AAK-RUGPULL-002", "AAK-RUGPULL-003",
                    "AAK-SUPPLY-001", "AAK-SUPPLY-002", "AAK-SUPPLY-003",
                    "AAK-SUPPLY-004", "AAK-SUPPLY-005", "AAK-SUPPLY-006",
                    "AAK-MARKETPLACE-001", "AAK-MARKETPLACE-002",
                    "AAK-MARKETPLACE-003", "AAK-MARKETPLACE-004",
                    "AAK-MCP-LINEAGE-STAINLESS-001",
                    "AAK-MCP-INSPECTOR-CVE-2026-23744-001",
                    "AAK-DNS-REBIND-002",
                ],
                "also_covers_asi": ["ASI04"],
            },
            "Design for boundaries (p.10)": {
                "rule_ids": [
                    "AAK-TRUST-001", "AAK-TRUST-002", "AAK-TRUST-003",
                    "AAK-TRUST-004", "AAK-TRUST-005", "AAK-TRUST-006",
                    "AAK-TRUST-007",
                    "AAK-A2A-001", "AAK-A2A-002", "AAK-A2A-008", "AAK-A2A-010",
                    "AAK-MCP-ATTEST-001", "AAK-MCP-TUNNEL-001",
                    "AAK-MCP-TUNNEL-002", "AAK-MCP-010",
                ],
                "also_covers_asi": ["ASI02", "ASI03", "ASI05"],
            },
            "Validate parameters (p.11)": {
                "rule_ids": [
                    "AAK-POISON-002", "AAK-MCP-FHI-001",
                    "AAK-IPI-WILD-CORPUS-001", "AAK-PRTITLE-IPI-001",
                    "AAK-LANGCHAIN-PROMPT-LOADER-PATH-001",
                    "AAK-A2A-003", "AAK-DEEPSEEK-V4-MOE-TOOL-INJ-001",
                ],
                "also_covers_asi": ["ASI02", "ASI05"],
            },
            "Constrain and sandbox tool execution (p.11)": {
                "rule_ids": [
                    "AAK-MCP-002", "AAK-MCP-006",
                    "AAK-MCP-STDIO-CMD-INJ-001", "AAK-MCP-STDIO-CMD-INJ-002",
                    "AAK-MCP-STDIO-CMD-INJ-003", "AAK-MCP-STDIO-CMD-INJ-004",
                    "AAK-MCP-TOOL-UNSAFE-EVAL-001", "AAK-MCP-010",
                    "AAK-HOOK-RCE-001",
                ],
                "also_covers_asi": ["ASI02", "ASI05"],
            },
            "Sign and verify MCP messages (p.12)": {
                "rule_ids": [
                    "AAK-MCP-ATTEST-001",
                    "AAK-A2A-005", "AAK-A2A-006", "AAK-A2A-011",
                    "AAK-WINDSURF-001", "AAK-MCP-LINEAGE-STAINLESS-001",
                    "AAK-MCP-TUNNEL-003",
                ],
                "also_covers_asi": ["ASI03", "ASI04"],
            },
            "Filter and monitor output pipelines and chained execution (p.12)": {
                "rule_ids": [
                    "AAK-POISON-001", "AAK-POISON-002", "AAK-POISON-003",
                    "AAK-POISON-004", "AAK-POISON-005", "AAK-POISON-006",
                    "AAK-RUGPULL-001", "AAK-RUGPULL-002", "AAK-RUGPULL-003",
                    "AAK-MCP-FHI-001",
                    "AAK-MCP-OPENAPI-LAZY-DESCRIPTION-001",
                    "AAK-MCP-OPENAPI-BLOATED-PARAMS-001",
                    "AAK-MCP-OPENAPI-TANGLED-METHODS-001",
                    "AAK-SKILL-001", "AAK-SKILL-002", "AAK-SKILL-003",
                    "AAK-SKILL-004", "AAK-SKILL-005",
                    "AAK-METIS-REFUSAL-REFEED-001",
                    "AAK-METIS-SCORING-SINK-001",
                ],
                "also_covers_asi": ["ASI05"],
            },
            "Instrument for logging and detection (p.13)": {
                "rule_ids": [
                    "AAK-LOGINJ-001",
                    "AAK-SPLUNK-TOKLOG-001",
                    "AAK-SPLUNK-MCP-TOKEN-LEAK-001",
                    "AAK-AGENT-001", "AAK-AGENT-002", "AAK-AGENT-003",
                    "AAK-WINDSURF-001",
                ],
                "also_covers_asi": ["ASI08", "ASI10"],
            },
            "Track and patch MCP related vulnerabilities (p.13)": {
                "rule_ids": [
                    "AAK-MCP-INSPECTOR-CVE-2026-23744-001",
                    "AAK-NEO4J-001",
                    "AAK-CHATGPT-MCP-CVE-2026-7061-PIN-001",
                    "AAK-CREWAI-CVE-2026-2275-001",
                    "AAK-CREWAI-CVE-2026-2285-001",
                    "AAK-CREWAI-CVE-2026-2286-001",
                    "AAK-CREWAI-CVE-2026-2287-001",
                    "AAK-DOCSGPT-MCP-STDIO-MITM-001",
                    "AAK-GPTRESEARCHER-MCP-STDIO-MITM-001",
                    "AAK-LITELLM-CVE-2026-30623-PIN-001",
                    "AAK-DORIS-001", "AAK-EXCEL-MCP-001", "AAK-FLOWISE-001",
                    "AAK-ASTROMCP-SQLI-CVE-2026-7591-001",
                    "AAK-CLAUDECODE-CVE-2026-40068-PIN-001",
                    "AAK-MCP-ATLASSIAN-CVE-2026-27825-001",
                    "AAK-MCP-ATLASSIAN-CVE-2026-27826-001",
                    "AAK-LANGCHAIN-SSRF-REDIR-001",
                    "AAK-LMDEPLOY-VL-SSRF-001",
                ],
                "also_covers_asi": ["ASI04"],
            },
            "Scan local network for open or vulnerable MCP servers (p.14)": {
                "rule_ids": [
                    "AAK-MCP-001",
                    "AAK-AZURE-MCP-NOAUTH-001",
                    "AAK-MCP-009",
                    "AAK-MCPWN-001",
                    "AAK-MCP-INSPECTOR-CVE-2026-23744-001",
                ],
                "also_covers_asi": ["ASI03", "ASI04"],
            },
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


def _resolve_control_rules(
    control_value: list[str] | dict[str, list[str]],
) -> list[str]:
    """Resolve a control value to its set of mapped AAK rule IDs.

    Supports two shapes:

    - **Legacy** (`list[str]`): a list of OWASP-Agentic ASI tokens. Every
      rule whose ``owasp_agentic_references`` includes any of those tokens
      is mapped. This is how the seven pre-2026-05 frameworks declare
      their crosswalk.

    - **New** (``dict``): a curated mapping with two keys:
        - ``rule_ids``: explicit list of AAK rule IDs (the primary
          evidence the auditor will read first).
        - ``also_covers_asi`` (optional): list of ASI tokens whose
          matching rules are added as fan-out coverage. Useful so future
          rule additions auto-light the relevant control without a code
          change here.

    Returns:
        A deduplicated, sorted list of AAK rule IDs. Unknown rule IDs in
        ``rule_ids`` are silently dropped (defensive against typos in the
        crosswalk catching us at audit time).
    """
    out: set[str] = set()
    if isinstance(control_value, list):
        for asi in control_value:
            out.update(_get_rules_for_asi(asi))
    elif isinstance(control_value, dict):
        for rid in control_value.get("rule_ids", []):
            if rid in RULES:
                out.add(rid)
        for asi in control_value.get("also_covers_asi", []):
            out.update(_get_rules_for_asi(asi))
    return sorted(out)


def _source_header_lines(source: dict[str, str]) -> list[str]:
    """Render the framework source-citation header block.

    The header reproduces the document ID, title, publisher, publication
    date, and source URL verbatim \u2014 these are the primary auditor-facing
    citation handles for the report.
    """
    out: list[str] = ["  Source:"]
    if source.get("doc_id"):
        out.append(f"    Document ID: {source['doc_id']}")
    if source.get("title"):
        out.append(f"    Title:       {source['title']}")
    if source.get("publisher"):
        out.append(f"    Publisher:   {source['publisher']}")
    if source.get("published"):
        out.append(f"    Published:   {source['published']}")
    if source.get("url"):
        out.append(f"    URL:         {source['url']}")
    out.append("")
    return out


def format_results(result: ScanResult, framework_key: str) -> str:
    framework = FRAMEWORKS.get(framework_key)
    if not framework:
        available = ", ".join(FRAMEWORKS.keys())
        return f"Unknown compliance framework: {framework_key}\nAvailable: {available}"

    lines: list[str] = []
    lines.append(f"\n\u2501\u2501\u2501 {framework['name']} Compliance Report \u2501\u2501\u2501\n")

    # Optional source-citation block (currently used by nsa-mcp-csi-2026;
    # other frameworks can opt in by adding a `source` dict).
    source = framework.get("source")
    if isinstance(source, dict):
        lines.extend(_source_header_lines(source))

    finding_rules = {f.rule_id for f in result.findings}
    controls_met = 0
    controls_total = len(framework["controls"])

    controls = framework["controls"]
    assert isinstance(controls, dict)
    for control, control_value in controls.items():
        mapped_rules = _resolve_control_rules(control_value)

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
