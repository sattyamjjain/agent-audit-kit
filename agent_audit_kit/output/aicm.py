"""CSA AI Controls Matrix (AICM) CSV formatter.

Emits one row per (control_id, finding) pair so auditors can sort by
control. Rows are ordered by AICM control ID first (lexicographic on the
control-ID string — matches AICM's own `DOMAIN-NN` ordering), then by
rule ID, then by file path.

Findings with no AICM mapping are dropped — use the regular `console`
or `json` format for those.

References:
- CSA AI Controls Matrix: https://cloudsecurityalliance.org/artifacts/ai-controls-matrix
- CSA MCP Security Resource Center (Baseline RC1 pending):
  https://cloudsecurityalliance.org/blog/2025/08/20/securing-the-agentic-ai-control-plane-announcing-the-mcp-security-resource-center
"""

from __future__ import annotations

import csv
import io

from agent_audit_kit.models import ScanResult


_COLUMNS = (
    "aicm_control",
    "rule_id",
    "severity",
    "category",
    "file_path",
    "line_number",
    "title",
    "evidence",
    "remediation",
    "cve_references",
    "incident_references",
)


def format_results(result: ScanResult) -> str:
    rows: list[tuple] = []
    for finding in result.findings:
        if not finding.aicm_references:
            continue
        for control in finding.aicm_references:
            rows.append((
                control,
                finding.rule_id,
                finding.severity.value,
                finding.category.value,
                finding.file_path,
                finding.line_number or "",
                finding.title,
                finding.evidence,
                finding.remediation,
                ";".join(finding.cve_references),
                ";".join(finding.incident_references),
            ))

    rows.sort(key=lambda r: (r[0], r[1], r[4]))

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(_COLUMNS)
    writer.writerows(rows)
    return buf.getvalue()
