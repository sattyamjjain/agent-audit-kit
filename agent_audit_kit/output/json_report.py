from __future__ import annotations

import json

from agent_audit_kit.models import Finding, ScanResult, Severity


def _finding_to_dict(finding: Finding) -> dict:
    d = {
        "ruleId": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "category": finding.category.value,
        "filePath": finding.file_path,
        "lineNumber": finding.line_number,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "cveReferences": finding.cve_references,
        "owaspMcpReferences": finding.owasp_mcp_references,
        "owaspAgenticReferences": finding.owasp_agentic_references,
        "adversaReferences": finding.adversa_references,
    }
    return d


def format_results(result: ScanResult, min_severity: Severity = Severity.LOW) -> str:
    filtered = result.findings_at_or_above(min_severity)
    report: dict = {
        "tool": "AgentAuditKit",
        "version": "0.2.0",
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count,
            "total": len(result.findings),
            "filesScanned": result.files_scanned,
            "rulesEvaluated": result.rules_evaluated,
            "scanDurationMs": round(result.scan_duration_ms, 1),
        },
        "findings": [_finding_to_dict(f) for f in filtered],
    }
    if result.score is not None:
        report["score"] = result.score
        report["grade"] = result.grade
    return json.dumps(report, indent=2)
