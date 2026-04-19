from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_audit_kit import __version__
from agent_audit_kit.models import Finding, ScanResult, Severity
from agent_audit_kit.rules.builtin import RULES

# Public rule-doc URL per finding. Keep this stable — SARIF ingesters
# cache helpUri and follow it from the GH Security tab.
_HELP_URI_BASE = "https://agent-audit-kit.dev/rules"

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


def _read_finding_line(finding: Finding, project_root: Path | None) -> str | None:
    """Best-effort read of the source line at `finding.line_number`.

    Used to build a *content-aware* partialFingerprint so GitHub Code
    Scanning dedupes the same alert across moves (line shifts) when the
    surrounding code hasn't changed, and flags it as new when the code
    DID change. Returns None if the file can't be read (binary, too
    large, not on disk).
    """
    if not finding.line_number or not finding.file_path:
        return None
    candidates: list[Path] = []
    if project_root:
        candidates.append(project_root / finding.file_path)
    candidates.append(Path(finding.file_path))
    for path in candidates:
        try:
            if not path.is_file():
                continue
            # Cap at 2MB to keep SARIF emission fast.
            if path.stat().st_size > 2_000_000:
                return None
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, start=1):
                    if i == finding.line_number:
                        return line.rstrip("\r\n")
        except OSError:
            continue
    return None


def _build_partial_fingerprint(finding: Finding, line_content: str | None) -> str:
    """SHA-256(line content + rule ID). Falls back to location-based hash
    when the line content can't be read so we always emit *something*
    stable for de-dup."""
    if line_content is not None:
        data = f"{line_content}\0{finding.rule_id}"
    else:
        data = f"{finding.rule_id}:{finding.file_path}:{finding.line_number or 0}"
    return hashlib.sha256(data.encode()).hexdigest()


def _rule_to_sarif(rule_id: str, index: int) -> dict:  # noqa: ARG001
    del index  # kept for call-site compat; SARIF rules[] index is positional
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
        "helpUri": f"{_HELP_URI_BASE}/{rule.rule_id}",
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


def _finding_to_result(
    finding: Finding,
    rule_index_map: dict[str, int],
    project_root: Path | None = None,
) -> dict:
    """Convert a Finding to a SARIF result object.

    Args:
        finding: The finding to convert.
        rule_index_map: Mapping from rule_id to index in the rules array.
        project_root: used to resolve relative paths for content-aware
            partial-fingerprint hashing. Falls back to location-based
            hashing when the file can't be read.
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
    line_content = _read_finding_line(finding, project_root)
    partial_fingerprint = _build_partial_fingerprint(finding, line_content)

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
        "properties": {
            "security-severity": SEVERITY_TO_SCORE[finding.severity],
        },
    }

    if finding.evidence:
        result["message"]["text"] += f"\n\nEvidence: {finding.evidence}"

    if finding.remediation:
        result["fixes"] = [{"description": {"text": finding.remediation}}]

    return result


def format_results(
    result: ScanResult,
    min_severity: Severity = Severity.LOW,
    project_root: Path | None = None,
) -> str:
    """Format scan results as SARIF 2.1.0 JSON for GitHub Code Scanning.

    Args:
        result: The scan result containing findings.
        min_severity: Minimum severity level to include.
        project_root: used for content-aware partialFingerprint hashing.
            When omitted, partial fingerprints fall back to
            location-based hashing.
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
                "results": [_finding_to_result(f, rule_index_map, project_root) for f in filtered],
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)
