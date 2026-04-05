from __future__ import annotations

import hashlib
import json

from agent_audit_kit.models import Finding, ScanResult, Severity
from agent_audit_kit.rules.builtin import RULES

SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SEVERITY_TO_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.5",
}


def _rule_to_sarif(rule_id: str) -> dict:
    rule = RULES.get(rule_id)
    if not rule:
        return {"id": rule_id}
    tags = ["security", rule.category.value]
    if rule.cve_references:
        tags.extend(rule.cve_references)
    if rule.owasp_agentic_references:
        tags.extend(f"OWASP-Agentic-{r}" for r in rule.owasp_agentic_references)
    if rule.adversa_references:
        tags.extend(f"Adversa-{r}" for r in rule.adversa_references)
    return {
        "id": rule.rule_id,
        "name": rule.sarif_name or rule.rule_id.replace("-", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "helpUri": "https://owasp.org/www-project-mcp-top-10/",
        "defaultConfiguration": {"level": SEVERITY_TO_LEVEL[rule.severity]},
        "properties": {
            "security-severity": SEVERITY_TO_SCORE[rule.severity],
            "tags": tags,
        },
    }


def _finding_to_result(finding: Finding) -> dict:
    location: dict = {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.file_path},
        }
    }
    if finding.line_number:
        location["physicalLocation"]["region"] = {"startLine": finding.line_number}
    fingerprint_data = f"{finding.rule_id}:{finding.file_path}:{finding.line_number or 0}"
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
    result: dict = {
        "ruleId": finding.rule_id,
        "level": SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": finding.description},
        "locations": [location],
        "partialFingerprints": {"primaryLocationLineHash": fingerprint},
    }
    if finding.evidence:
        result["message"]["text"] += f"\n\nEvidence: {finding.evidence}"
    if finding.remediation:
        result["fixes"] = [{"description": {"text": finding.remediation}}]
    return result


def format_results(result: ScanResult, min_severity: Severity = Severity.LOW) -> str:
    filtered = result.findings_at_or_above(min_severity)
    seen_rules: set[str] = set()
    sarif_rules = []
    for finding in filtered:
        if finding.rule_id not in seen_rules:
            seen_rules.add(finding.rule_id)
            sarif_rules.append(_rule_to_sarif(finding.rule_id))
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AgentAuditKit",
                    "version": "0.2.0",
                    "informationUri": "https://github.com/sattyamjjain/agent-audit-kit",
                    "rules": sarif_rules,
                }
            },
            "results": [_finding_to_result(f) for f in filtered],
        }],
    }
    return json.dumps(sarif, indent=2)
