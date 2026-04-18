"""Auditor-ready PDF compliance report.

When `reportlab` is installed, produces a cleanly-laid-out PDF grouped by
framework (EU AI Act / SOC 2 / ISO 27001 / HIPAA / NIST AI RMF) with a
findings-to-control mapping and severity summary. When `reportlab` is
not available, falls back to a structured plain-text report with the
same layout (so automation can still pipe it to a PDF converter).

Intended primarily for EU AI Act Article 15 evidence packs. Built-in
framework mappings cover: eu-ai-act, soc2, iso27001, hipaa, nist-ai-rmf.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from agent_audit_kit import __version__
from agent_audit_kit.models import ScanResult, Severity


_FRAMEWORK_TITLES = {
    "eu-ai-act": "EU AI Act — Article 15 Cybersecurity & Robustness",
    "eu-ai-act-art55": "EU AI Act — Article 55 GPAI Systemic Risk Obligations",
    "soc2": "SOC 2 — Trust Services Criteria (CC6, CC7, CC8)",
    "iso27001": "ISO/IEC 27001:2022 — Information Security Management",
    "iso42001": "ISO/IEC 42001:2023 — AI Management System",
    "hipaa": "HIPAA Security Rule — Technical Safeguards",
    "nist-ai-rmf": "NIST AI RMF 1.0 — GOVERN, MAP, MEASURE, MANAGE",
    "singapore-agentic": "Singapore Agentic AI Governance Framework (Jan 2026)",
    "india-dpdp": "India Digital Personal Data Protection Act 2023",
}

# Coarse mapping from AAK categories to framework control families.
_CATEGORY_TO_CONTROL = {
    "eu-ai-act": {
        "mcp-config": "Art. 15(1) Accuracy, Robustness, Cybersecurity",
        "hook-injection": "Art. 15(5) Resilience against unauthorized interference",
        "trust-boundary": "Art. 15(4) Adversarial inputs and data poisoning",
        "secret-exposure": "Art. 15(1) Confidentiality controls",
        "supply-chain": "Art. 15(3) Dependency integrity",
        "agent-config": "Art. 15(2) Appropriate technical solutions",
        "tool-poisoning": "Art. 15(5) Adversarial control",
        "taint-analysis": "Art. 15(2) Input validation",
        "transport-security": "Art. 15(1) Cybersecurity",
        "a2a-protocol": "Art. 15(1) Inter-agent security",
        "legal-compliance": "Art. 15(1) Regulatory mapping",
    },
    "soc2": {
        "mcp-config": "CC6.1 Logical Access",
        "hook-injection": "CC7.2 System Monitoring",
        "trust-boundary": "CC6.1 Logical Access",
        "secret-exposure": "CC6.1 Logical Access",
        "supply-chain": "CC8.1 Change Management",
        "agent-config": "CC6.1 Logical Access",
        "tool-poisoning": "CC7.2 System Monitoring",
        "taint-analysis": "CC8.1 Change Management",
        "transport-security": "CC6.7 Transmission",
        "a2a-protocol": "CC6.6 Logical Access Boundaries",
        "legal-compliance": "CC1.3 Governance",
    },
    "iso27001": {
        "mcp-config": "A.5.15 Access control",
        "hook-injection": "A.8.25 Secure development lifecycle",
        "trust-boundary": "A.5.15 Access control",
        "secret-exposure": "A.5.17 Authentication information",
        "supply-chain": "A.5.21 Supply chain",
        "agent-config": "A.8.9 Configuration management",
        "tool-poisoning": "A.8.26 Application security requirements",
        "taint-analysis": "A.8.28 Secure coding",
        "transport-security": "A.8.20 Networks security",
        "a2a-protocol": "A.8.21 Security of network services",
        "legal-compliance": "ISO 42001 clause 9.2 AI audit",
    },
    "hipaa": {
        "mcp-config": "§164.312(a) Access Control",
        "hook-injection": "§164.308(a)(5) Security Awareness",
        "trust-boundary": "§164.312(a) Access Control",
        "secret-exposure": "§164.312(d) Person / Entity Authentication",
        "supply-chain": "§164.308(b) Business Associate Agreements",
        "agent-config": "§164.308(a)(1) Security Management Process",
        "tool-poisoning": "§164.308(a)(1) Security Management",
        "taint-analysis": "§164.312(c) Integrity",
        "transport-security": "§164.312(e) Transmission Security",
        "a2a-protocol": "§164.312(e) Transmission Security",
        "legal-compliance": "§164.316 Documentation",
    },
    "nist-ai-rmf": {
        "mcp-config": "MEASURE 2.6 Security",
        "hook-injection": "MANAGE 2.2 Incident response",
        "trust-boundary": "MAP 3.4 Trust boundary analysis",
        "secret-exposure": "MEASURE 2.6 Security",
        "supply-chain": "MAP 4.1 Third-party risks",
        "agent-config": "GOVERN 1.3 Roles & responsibilities",
        "tool-poisoning": "MANAGE 2.2 Incident response",
        "taint-analysis": "MEASURE 2.8 Validity & Reliability",
        "transport-security": "MEASURE 2.6 Security",
        "a2a-protocol": "MAP 3.4 Trust boundary analysis",
        "legal-compliance": "GOVERN 6.1 Policy alignment",
    },
    "eu-ai-act-art55": {
        "mcp-config": "Art. 55(1)(a) Model evaluation obligation",
        "hook-injection": "Art. 55(1)(b) Systemic-risk mitigation",
        "trust-boundary": "Art. 55(1)(c) Adversarial testing",
        "secret-exposure": "Art. 55(1)(d) Serious incident reporting",
        "supply-chain": "Art. 55(1)(b) Systemic-risk mitigation (supply chain)",
        "agent-config": "Art. 55(1)(a) Model evaluation obligation",
        "tool-poisoning": "Art. 55(1)(b) Systemic-risk mitigation",
        "taint-analysis": "Art. 55(1)(c) Adversarial testing",
        "transport-security": "Art. 55(1)(d) Cybersecurity protection",
        "a2a-protocol": "Art. 55(1)(d) Cybersecurity protection",
        "legal-compliance": "Art. 55(1)(d) Documentation obligation",
    },
    "iso42001": {
        "mcp-config": "A.6.2.3 AI system operational controls",
        "hook-injection": "A.8.3 Data quality and integrity",
        "trust-boundary": "A.6.2.4 AI system boundaries",
        "secret-exposure": "A.7.4 Data handling",
        "supply-chain": "A.10 Third-party relationships",
        "agent-config": "A.6.2.2 AI system resources",
        "tool-poisoning": "A.8.2 Data for AI",
        "taint-analysis": "A.6.2.6 AI verification",
        "transport-security": "A.6.2.3 AI system operational controls",
        "a2a-protocol": "A.10.1 Supplier AI agreements",
        "legal-compliance": "A.5.1 Leadership & governance",
    },
    "singapore-agentic": {
        "mcp-config": "Pillar 3 — Safe & Secure Deployment",
        "hook-injection": "Pillar 3 — Safe & Secure Deployment",
        "trust-boundary": "Pillar 2 — Trustworthy AI Development",
        "secret-exposure": "Pillar 3 — Safe & Secure Deployment",
        "supply-chain": "Pillar 4 — Third-Party Ecosystem",
        "agent-config": "Pillar 1 — Internal Governance",
        "tool-poisoning": "Pillar 3 — Safe & Secure Deployment",
        "taint-analysis": "Pillar 2 — Trustworthy AI Development",
        "transport-security": "Pillar 3 — Safe & Secure Deployment",
        "a2a-protocol": "Pillar 4 — Third-Party Ecosystem",
        "legal-compliance": "Pillar 1 — Internal Governance",
    },
    "india-dpdp": {
        "mcp-config": "s.8(4) Reasonable security safeguards",
        "hook-injection": "s.8(5) Data breach notification",
        "trust-boundary": "s.8(4) Reasonable security safeguards",
        "secret-exposure": "s.8(5) Data breach notification",
        "supply-chain": "s.8(7) Processor obligations",
        "agent-config": "s.6 Notice & consent",
        "tool-poisoning": "s.8(4) Reasonable security safeguards",
        "taint-analysis": "s.8(3) Accuracy of processing",
        "transport-security": "s.8(4) Reasonable security safeguards",
        "a2a-protocol": "s.8(7) Processor obligations",
        "legal-compliance": "s.5 DPDP Rules 2023 alignment",
    },
}


def _group_by_control(result: ScanResult, framework: str) -> dict[str, list]:
    mapping = _CATEGORY_TO_CONTROL.get(framework, {})
    grouped: dict[str, list] = defaultdict(list)
    for finding in result.findings:
        control = mapping.get(finding.category.value, "Unmapped")
        grouped[control].append(finding)
    return grouped


def _severity_summary(findings: Iterable) -> str:
    c = {s: 0 for s in Severity}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return f"CRITICAL={c[Severity.CRITICAL]} HIGH={c[Severity.HIGH]} MEDIUM={c[Severity.MEDIUM]} LOW={c[Severity.LOW]} INFO={c[Severity.INFO]}"


def _text_report(result: ScanResult, framework: str) -> str:
    title = _FRAMEWORK_TITLES.get(framework, framework)
    lines: list[str] = []
    lines.append(f"agent-audit-kit compliance report — {title}")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Scanner: agent-audit-kit {__version__}")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 60)
    lines.append(_severity_summary(result.findings))
    lines.append(f"Findings: {len(result.findings)} across {result.files_scanned} files")
    lines.append("")
    lines.append("Findings by control")
    lines.append("-" * 60)
    for control, fs in sorted(_group_by_control(result, framework).items()):
        lines.append(f"[{control}]  ({len(fs)} finding{'s' if len(fs) != 1 else ''})")
        for f in fs:
            loc = f.file_path
            if f.line_number:
                loc = f"{f.file_path}:{f.line_number}"
            lines.append(f"  - {f.rule_id} [{f.severity.value.upper()}] {f.title}")
            lines.append(f"    {loc}")
            if f.remediation:
                lines.append(f"    fix: {f.remediation}")
        lines.append("")
    return "\n".join(lines)


def emit_pdf(result: ScanResult, framework: str, output_path: Path) -> tuple[bool, str]:
    """Write a PDF report. Returns (ok, message)."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
        )
        from reportlab.lib import colors
    except ImportError:
        # Fallback: write the text report with a .txt extension and inform caller.
        text_path = output_path.with_suffix(".txt")
        text_path.write_text(_text_report(result, framework), encoding="utf-8")
        return False, (
            f"reportlab not installed; wrote plain-text fallback to {text_path}. "
            "Install with `pip install reportlab` to get PDF output."
        )

    doc = SimpleDocTemplate(str(output_path), pagesize=letter, title="AAK Compliance Report")
    story = []
    styles = getSampleStyleSheet()
    body_style = ParagraphStyle(
        "aak-body", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=11
    )
    title = _FRAMEWORK_TITLES.get(framework, framework)
    story.append(Paragraph("<b>agent-audit-kit compliance report</b>", styles["Title"]))
    story.append(Paragraph(title, styles["Heading2"]))
    story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()}", body_style))
    story.append(Paragraph(f"Scanner: agent-audit-kit {__version__}", body_style))
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("<b>Severity summary</b>", styles["Heading3"]))
    story.append(Paragraph(_severity_summary(result.findings), body_style))
    story.append(Paragraph(
        f"{len(result.findings)} findings across {result.files_scanned} files.",
        body_style,
    ))
    story.append(Spacer(1, 0.2 * inch))

    for control, fs in sorted(_group_by_control(result, framework).items()):
        story.append(Paragraph(f"<b>{control}</b> — {len(fs)} finding(s)", styles["Heading3"]))
        rows = [["Rule", "Severity", "Location", "Title"]]
        for f in fs:
            loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
            rows.append([f.rule_id, f.severity.value.upper(), loc, f.title])
        tbl = Table(rows, colWidths=[1.2 * inch, 0.8 * inch, 2.2 * inch, 2.3 * inch])
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
                ]
            )
        )
        story.append(tbl)
        story.append(Spacer(1, 0.15 * inch))

    doc.build(story)
    return True, f"wrote PDF report to {output_path}"
