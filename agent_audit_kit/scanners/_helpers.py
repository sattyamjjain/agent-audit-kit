from __future__ import annotations

from agent_audit_kit.models import Finding
from agent_audit_kit.rules.builtin import get_rule

SKIP_DIRS = frozenset({
    "node_modules", ".git", "dist", "build", "__pycache__",
    ".next", ".nuxt", "vendor", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "target", "out", ".terraform",
})


def find_line_number(raw: str, key: str) -> int | None:
    for i, line in enumerate(raw.splitlines(), 1):
        if key in line:
            return i
    return None


def make_finding(
    rule_id: str,
    file_path: str,
    evidence: str,
    line_number: int | None = None,
) -> Finding:
    rule = get_rule(rule_id)
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        description=rule.description,
        severity=rule.severity,
        category=rule.category,
        file_path=file_path,
        line_number=line_number,
        evidence=evidence,
        remediation=rule.remediation,
        cve_references=rule.cve_references,
        owasp_mcp_references=rule.owasp_mcp_references,
        owasp_agentic_references=rule.owasp_agentic_references,
        adversa_references=rule.adversa_references,
        incident_references=rule.incident_references,
        aicm_references=rule.aicm_references,
    )
