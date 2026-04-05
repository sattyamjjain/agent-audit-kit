from __future__ import annotations

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
}


def _get_rules_for_asi(asi_code: str) -> list[str]:
    return [
        rule_id for rule_id, rule in RULES.items()
        if asi_code in rule.owasp_agentic_references
    ]


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

    for control, asi_codes in framework["controls"].items():
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
        lines.append("")

    pct = 100 * controls_met // controls_total if controls_total else 0
    lines.append(f"Controls met: {controls_met}/{controls_total} ({pct}%)")

    if result.score is not None:
        lines.append(f"Security Score: {result.score}/100  Grade: {result.grade}")

    lines.append("")
    return "\n".join(lines)
