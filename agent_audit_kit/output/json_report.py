from __future__ import annotations

import json

from agent_audit_kit import __version__
from agent_audit_kit.models import Finding, ScanResult, Severity


def _finding_to_dict(finding: Finding) -> dict:
    d: dict = {
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
    if finding.related_locations:
        d["relatedLocations"] = finding.related_locations
    return d


def format_results(result: ScanResult, min_severity: Severity = Severity.LOW) -> str:
    """Render a scan result as JSON.

    On the two counts in ``summary``: the severity histogram and ``total`` describe
    everything the scan found, while ``findings`` contains only what cleared
    ``min_severity`` (default LOW, so INFO findings are counted but not listed).
    Those numbers therefore disagree by design, and previously nothing in the
    document said so — a consumer reading ``summary.total`` and then counting
    ``findings`` saw a silent off-by-N, and a histogram claiming ``info: 1`` beside
    an array holding no INFO finding.

    ``reported`` and ``minSeverity`` make the document explain itself:
    ``reported == len(findings)`` always, and ``minSeverity`` names the threshold
    that produced the gap. Existing fields keep their meaning, so consumers reading
    ``total`` are unaffected.
    """
    filtered = result.findings_at_or_above(min_severity)
    report: dict = {
        "tool": "AgentAuditKit",
        "version": __version__,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count,
            # Everything found, at any severity.
            "total": len(result.findings),
            # What `findings` below actually contains, after the threshold.
            "reported": len(filtered),
            "minSeverity": min_severity.value,
            "filesScanned": result.files_scanned,
            "rulesEvaluated": result.rules_evaluated,
            "scanDurationMs": round(result.scan_duration_ms, 1),
            # A machine-readable "do not trust this run" flag. Consumers that
            # gate on `total == 0` were previously told a crashed run was clean
            # (issue #743); `scannerFailures > 0` means the rules those scanners
            # own were never evaluated, so `complete` is false.
            "scannerFailures": len(result.scanner_failures),
            "complete": not result.scanner_failures,
        },
        "findings": [_finding_to_dict(f) for f in filtered],
    }
    failures = result.scanner_failures
    if failures:
        report["scannerFailures"] = [
            {"scanner": _scanner_name(f), "evidence": f.evidence} for f in failures
        ]
    if result.score is not None:
        report["score"] = result.score
        report["grade"] = result.grade
        if failures:
            # The score is derived from findings that exist. When a scanner
            # crashed, the findings it would have produced are absent, so the
            # number is an upper bound rather than a measurement.
            report["scoreReliable"] = False
    return json.dumps(report, indent=2)


def _scanner_name(finding) -> str:
    """Pull the scanner name back out of the failure evidence string."""
    ev = finding.evidence or ""
    if ev.startswith("scanner=") and " error=" in ev:
        return ev[len("scanner="):ev.index(" error=")].strip("'\"")
    return "unknown"
