"""GitHub Security Advisories integration.

Closes B7 from the pending-items audit / ROADMAP §2.3(8).

When a scan finishes and `--advisories` is set, this module turns each
CRITICAL finding into a **private** repository security advisory via
the `gh` CLI (expects the environment to be authenticated — same as
the `cve-watcher.yml` workflow). Each advisory includes the rule
metadata + fix guidance.

Private-first is intentional: an advisory exists only so maintainers
of the scanned project get the drop first, consistent with
`docs/disclosure-policy.md`. Only when the maintainer publishes (or
the 90-day policy window closes) does the advisory become visible.

This module never opens an advisory automatically against a repo you
don't own. The caller must pass `--repo owner/name` and that repo must
match the CI environment or the CLI user's gh auth context.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable

from agent_audit_kit.models import Finding, Severity


@dataclass
class AdvisoryResult:
    rule_id: str
    created: bool
    url: str
    error: str = ""


def _severity_to_ghsa(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.INFO: "low",
    }[severity]


def _build_advisory_body(finding: Finding) -> str:
    lines: list[str] = [
        f"## Rule: {finding.rule_id}",
        "",
        f"**Severity:** {finding.severity.value.upper()}",
        f"**Category:** {finding.category.value}",
        f"**Location:** `{finding.file_path}`"
        + (f":{finding.line_number}" if finding.line_number else ""),
        "",
        "### Description",
        finding.description,
        "",
        "### Evidence",
        f"`{finding.evidence}`" if finding.evidence else "_n/a_",
        "",
        "### Remediation",
        finding.remediation or "_see rule docs_",
    ]
    if finding.cve_references:
        lines += ["", "### CVE references"]
        lines += [f"- https://nvd.nist.gov/vuln/detail/{c}" for c in finding.cve_references]
    if finding.owasp_mcp_references:
        lines += [
            "",
            "### OWASP MCP mapping",
            ", ".join(finding.owasp_mcp_references),
        ]
    lines += [
        "",
        "---",
        "_Advisory drafted automatically by agent-audit-kit. Review the"
        " evidence before publication; remove or rephrase sensitive data"
        " if the rule ID, location, or evidence text would identify a"
        " protected disclosure._",
    ]
    return "\n".join(lines)


def open_advisories(
    findings: Iterable[Finding],
    repo: str,
    min_severity: Severity = Severity.CRITICAL,
    dry_run: bool = False,
) -> list[AdvisoryResult]:
    """Create private GitHub Security Advisories for qualifying findings.

    Requires the `gh` CLI to be installed and authenticated against the
    given repo. In `dry_run=True`, returns the payloads without calling
    `gh`.

    Args:
        findings: iterable of Finding (typically ScanResult.findings).
        repo: "owner/name" of the repo that owns the advisories.
        min_severity: floor; default CRITICAL.
        dry_run: preview without creating.

    Returns:
        One AdvisoryResult per qualifying finding.
    """
    qualifying = [f for f in findings if f.severity >= min_severity]
    results: list[AdvisoryResult] = []
    gh_bin = shutil.which("gh")
    if not gh_bin and not dry_run:
        return [
            AdvisoryResult(
                rule_id="AAK-INTERNAL",
                created=False,
                url="",
                error="gh CLI not found in PATH. Install from https://cli.github.com",
            )
        ]

    for finding in qualifying:
        title = f"[{finding.rule_id}] {finding.title}"
        body = _build_advisory_body(finding)
        payload = {
            "title": title,
            "body": body,
            "severity": _severity_to_ghsa(finding.severity),
        }

        if dry_run:
            results.append(
                AdvisoryResult(
                    rule_id=finding.rule_id,
                    created=False,
                    url=f"(dry-run) advisory for {finding.rule_id} on {repo}",
                    error="",
                )
            )
            continue

        try:
            proc = subprocess.run(
                [
                    gh_bin,  # type: ignore[list-item]
                    "api",
                    "-X",
                    "POST",
                    f"/repos/{repo}/security-advisories",
                    "--input",
                    "-",
                ],
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            results.append(AdvisoryResult(finding.rule_id, False, "", "gh timed out"))
            continue

        if proc.returncode != 0:
            results.append(
                AdvisoryResult(
                    rule_id=finding.rule_id,
                    created=False,
                    url="",
                    error=(proc.stderr or proc.stdout).strip()[:500],
                )
            )
            continue

        try:
            data = json.loads(proc.stdout)
            url = data.get("html_url", "")
        except json.JSONDecodeError:
            url = ""
        results.append(AdvisoryResult(finding.rule_id, True, url, ""))

    return results
