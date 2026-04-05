from __future__ import annotations

from agent_audit_kit.models import Finding, ScanResult, Severity

BOLD = "\033[1m"
RED = "\033[31m"
BOLD_RED = "\033[1;31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
GRAY = "\033[90m"
GREEN = "\033[32m"
RESET = "\033[0m"
DIM = "\033[2m"

SEVERITY_DISPLAY = {
    Severity.CRITICAL: (f"{BOLD_RED}\u26d4 CRITICAL{RESET}", BOLD_RED),
    Severity.HIGH: (f"{RED}\U0001f534 HIGH{RESET}", RED),
    Severity.MEDIUM: (f"{YELLOW}\U0001f7e1 MEDIUM{RESET}", YELLOW),
    Severity.LOW: (f"{BLUE}\U0001f535 LOW{RESET}", BLUE),
    Severity.INFO: (f"{GRAY}\u2139\ufe0f  INFO{RESET}", GRAY),
}

GRADE_COLORS = {"A": GREEN, "B": GREEN, "C": YELLOW, "D": RED, "F": BOLD_RED}


def _format_finding(finding: Finding, color: str) -> str:
    lines = []
    location = finding.file_path
    if finding.line_number:
        location += f":{finding.line_number}"
    lines.append(f"  {color}{finding.rule_id}{RESET} {BOLD}{finding.title}{RESET}")
    lines.append(f"    {DIM}Location:{RESET} {location}")
    if finding.evidence:
        lines.append(f"    {DIM}Evidence:{RESET} {finding.evidence}")
    lines.append(f"    {DIM}Fix:{RESET} {finding.remediation}")
    if finding.cve_references:
        lines.append(f"    {DIM}CVEs:{RESET} {', '.join(finding.cve_references)}")
    if finding.owasp_mcp_references:
        lines.append(f"    {DIM}OWASP MCP:{RESET} {', '.join(finding.owasp_mcp_references)}")
    if finding.owasp_agentic_references:
        lines.append(f"    {DIM}OWASP Agentic:{RESET} {', '.join(finding.owasp_agentic_references)}")
    if finding.adversa_references:
        lines.append(f"    {DIM}Adversa:{RESET} {', '.join(finding.adversa_references)}")
    lines.append("")
    return "\n".join(lines)


def format_results(
    result: ScanResult,
    min_severity: Severity = Severity.LOW,
    show_score: bool = False,
) -> str:
    filtered = result.findings_at_or_above(min_severity)
    lines: list[str] = []

    lines.append(f"\n{BOLD}\u2501\u2501\u2501 AgentAuditKit Scan Results \u2501\u2501\u2501{RESET}\n")

    if not filtered:
        lines.append(f"  \u2705 No findings at or above {min_severity.value} severity.\n")
    else:
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for severity in severity_order:
            sev_findings = [f for f in filtered if f.severity == severity]
            if not sev_findings:
                continue
            label, color = SEVERITY_DISPLAY[severity]
            lines.append(f"{label} ({len(sev_findings)} finding{'s' if len(sev_findings) != 1 else ''})\n")
            by_file: dict[str, list[Finding]] = {}
            for f in sev_findings:
                by_file.setdefault(f.file_path, []).append(f)
            for file_path, file_findings in by_file.items():
                lines.append(f"  {DIM}{file_path}{RESET}")
                for finding in file_findings:
                    lines.append(_format_finding(finding, color))

    lines.append(f"{BOLD}\u2501\u2501\u2501 Summary \u2501\u2501\u2501{RESET}\n")
    summary_parts = []
    if result.critical_count:
        summary_parts.append(f"{BOLD_RED}\u26d4 CRITICAL  {result.critical_count} finding{'s' if result.critical_count != 1 else ''}{RESET}")
    if result.high_count:
        summary_parts.append(f"{RED}\U0001f534 HIGH      {result.high_count} finding{'s' if result.high_count != 1 else ''}{RESET}")
    if result.medium_count:
        summary_parts.append(f"{YELLOW}\U0001f7e1 MEDIUM    {result.medium_count} finding{'s' if result.medium_count != 1 else ''}{RESET}")
    if result.low_count:
        summary_parts.append(f"{BLUE}\U0001f535 LOW       {result.low_count} finding{'s' if result.low_count != 1 else ''}{RESET}")
    if result.info_count:
        summary_parts.append(f"{GRAY}\u2139\ufe0f  INFO      {result.info_count} finding{'s' if result.info_count != 1 else ''}{RESET}")
    if summary_parts:
        lines.extend(summary_parts)
    else:
        lines.append("  No findings.")

    if show_score and result.score is not None and result.grade is not None:
        gc = GRADE_COLORS.get(result.grade, RESET)
        lines.append(f"\n{BOLD}Security Score:{RESET} {gc}{result.score}/100  Grade: {result.grade}{RESET}")

    lines.append(f"\n{DIM}Files scanned: {result.files_scanned}{RESET}")
    lines.append(f"{DIM}Rules evaluated: {result.rules_evaluated}{RESET}")
    lines.append(f"{DIM}Time: {result.scan_duration_ms:.0f}ms{RESET}")
    lines.append(f"\n{DIM}\U0001f4a1 GitHub Action: uses: sattyamjjain/agent-audit-kit@v1{RESET}\n{DIM}\U0001f4a1 CI mode: agent-audit-kit scan . --ci{RESET}\n")
    return "\n".join(lines)
