from __future__ import annotations

import hashlib
import json

from agent_audit_kit import __version__
from agent_audit_kit.models import Finding, ScanResult, Severity
from agent_audit_kit.rules.builtin import RULES

SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SEVERITY_TO_SCORE: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.5",
}


def _build_fingerprint(finding: Finding) -> str:
    """Generate a full SHA-256 fingerprint for a finding."""
    data = f"{finding.rule_id}:{finding.file_path}:{finding.line_number or 0}:{finding.title}"
    return hashlib.sha256(data.encode()).hexdigest()


def _build_partial_fingerprint(finding: Finding) -> str:
    """Generate a partial fingerprint (first 16 hex chars) for location-based dedup."""
    data = f"{finding.rule_id}:{finding.file_path}:{finding.line_number or 0}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def _rule_to_sarif(rule_id: str, index: int) -> dict:
    """Convert a rule definition to a SARIF reportingDescriptor.

    Args:
        rule_id: The rule identifier.
        index: The index of this rule in the rules array.

    Returns:
        SARIF-compliant rule descriptor dictionary.
    """
    rule = RULES.get(rule_id)
    if not rule:
        return {
            "id": rule_id,
            "shortDescription": {"text": rule_id},
            "properties": {"precision": "high"},
        }

    tags = ["security", rule.category.value]
    if rule.cve_references:
        tags.extend(rule.cve_references)
    if rule.owasp_agentic_references:
        tags.extend(f"OWASP-Agentic-{r}" for r in rule.owasp_agentic_references)
    if rule.adversa_references:
        tags.extend(f"Adversa-{r}" for r in rule.adversa_references)

    # Build help text with remediation and references
    help_text = rule.remediation
    help_markdown = f"**Remediation:** {rule.remediation}"

    references: list[str] = []
    if rule.cve_references:
        references.extend(rule.cve_references)
    if rule.owasp_mcp_references:
        references.extend(f"OWASP MCP Top 10: {r}" for r in rule.owasp_mcp_references)
    if rule.owasp_agentic_references:
        references.extend(f"OWASP Agentic: {r}" for r in rule.owasp_agentic_references)
    if rule.adversa_references:
        references.extend(f"Adversa: {r}" for r in rule.adversa_references)

    if references:
        help_text += "\n\nReferences:\n" + "\n".join(f"- {ref}" for ref in references)
        help_markdown += "\n\n**References:**\n" + "\n".join(f"- {ref}" for ref in references)

    return {
        "id": rule.rule_id,
        "name": rule.sarif_name or rule.rule_id.replace("-", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "helpUri": "https://owasp.org/www-project-mcp-top-10/",
        "help": {
            "text": help_text,
            "markdown": help_markdown,
        },
        "defaultConfiguration": {"level": SEVERITY_TO_LEVEL[rule.severity]},
        "properties": {
            "security-severity": SEVERITY_TO_SCORE[rule.severity],
            "precision": "high",
            "tags": tags,
        },
    }


def _finding_to_result(finding: Finding, rule_index_map: dict[str, int]) -> dict:
    """Convert a Finding to a SARIF result object.

    Args:
        finding: The finding to convert.
        rule_index_map: Mapping from rule_id to index in the rules array.

    Returns:
        SARIF-compliant result dictionary.
    """
    location: dict = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": finding.file_path,
                "uriBaseId": "%SRCROOT%",
            },
        }
    }
    if finding.line_number:
        location["physicalLocation"]["region"] = {"startLine": finding.line_number}

    full_fingerprint = _build_fingerprint(finding)
    partial_fingerprint = _build_partial_fingerprint(finding)

    result: dict = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index_map.get(finding.rule_id, 0),
        "level": SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": finding.description},
        "locations": [location],
        "fingerprints": {
            "primaryLocationFingerprint": full_fingerprint,
        },
        "partialFingerprints": {
            "primaryLocationLineHash": partial_fingerprint,
        },
    }

    if finding.evidence:
        result["message"]["text"] += f"\n\nEvidence: {finding.evidence}"

    if finding.remediation:
        result["fixes"] = [{"description": {"text": finding.remediation}}]

    return result


def format_results(result: ScanResult, min_severity: Severity = Severity.LOW) -> str:
    """Format scan results as SARIF 2.1.0 JSON for GitHub Code Scanning.

    Args:
        result: The scan result containing findings.
        min_severity: Minimum severity level to include.

    Returns:
        SARIF JSON string.
    """
    filtered = result.findings_at_or_above(min_severity)

    # Build ordered rules list (preserving first-seen order, deduped)
    seen_rules: list[str] = []
    for finding in filtered:
        if finding.rule_id not in seen_rules:
            seen_rules.append(finding.rule_id)

    sarif_rules = [_rule_to_sarif(rule_id, idx) for idx, rule_id in enumerate(seen_rules)]
    rule_index_map = {rule_id: idx for idx, rule_id in enumerate(seen_rules)}

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentAuditKit",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/sattyamjjain/agent-audit-kit",
                        "rules": sarif_rules,
                    }
                },
                "automationDetails": {
                    "id": "agent-audit-kit/",
                },
                "results": [_finding_to_result(f, rule_index_map) for f in filtered],
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)
