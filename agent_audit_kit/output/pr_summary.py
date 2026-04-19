"""PR-comment + GITHUB_STEP_SUMMARY renderer.

Emits a Markdown table:

    | Rule | Severity | File:Line | Suggestion |

The same renderer is used for two surfaces:
1. `$GITHUB_STEP_SUMMARY` — visible on every Action run.
2. A sticky PR comment created via `peter-evans/create-or-update-comment`
   in the action's composite / docker entrypoint. The comment carries a
   hidden HTML marker so re-runs update-in-place instead of spamming.
"""

from __future__ import annotations

from agent_audit_kit.models import ScanResult, Severity


PR_COMMENT_MARKER = "<!-- agent-audit-kit:pr-summary -->"


_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _severity_rank(sev: Severity) -> int:
    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }[sev]


def render_markdown(result: ScanResult, max_rows: int = 50) -> str:
    """Return the full Markdown payload (header + summary table + table).

    Caller writes this to `$GITHUB_STEP_SUMMARY` (append) and also posts
    as a PR comment when `comment-on-pr=true`.
    """
    total = len(result.findings)
    if total == 0:
        return (
            f"{PR_COMMENT_MARKER}\n"
            "## AgentAuditKit — no security findings ✅\n\n"
            f"Scanner evaluated **{result.rules_evaluated}** rules across "
            f"**{result.files_scanned}** files in "
            f"**{result.scan_duration_ms:.0f} ms**.\n"
        )

    counts = {
        "CRITICAL": result.critical_count,
        "HIGH": result.high_count,
        "MEDIUM": result.medium_count,
        "LOW": result.low_count,
        "INFO": result.info_count,
    }
    summary_line = "  ".join(
        f"{sev}={n}" for sev, n in counts.items() if n > 0
    ) or "no-findings"

    sorted_findings = sorted(
        result.findings,
        key=lambda f: (_severity_rank(f.severity), f.rule_id, f.file_path, f.line_number or 0),
    )
    rows = sorted_findings[:max_rows]

    lines: list[str] = [
        PR_COMMENT_MARKER,
        f"## AgentAuditKit — {total} finding{'s' if total != 1 else ''}",
        "",
        f"**Summary:** {summary_line}",
        f"**Rules evaluated:** {result.rules_evaluated}  "
        f"**Files scanned:** {result.files_scanned}  "
        f"**Duration:** {result.scan_duration_ms:.0f} ms",
    ]
    if result.grade and result.score is not None:
        lines.append(f"**Score:** {result.score}/100 ({result.grade})")
    lines += [
        "",
        "| Rule | Severity | Location | Suggestion |",
        "| --- | --- | --- | --- |",
    ]
    for f in rows:
        location = f.file_path + (f":{f.line_number}" if f.line_number else "")
        emoji = _SEVERITY_EMOJI.get(f.severity, "")
        suggestion = (f.remediation or f.title).replace("|", r"\|").splitlines()[0][:120]
        lines.append(
            f"| `{f.rule_id}` | {emoji} {f.severity.value.upper()} | `{location}` | {suggestion} |"
        )
    if total > max_rows:
        lines.append("")
        lines.append(
            f"_Table truncated to {max_rows} of {total} findings. "
            "Full SARIF is uploaded to the Security tab._"
        )
    return "\n".join(lines) + "\n"


def write_step_summary(result: ScanResult, target: "str | None" = None) -> bool:
    """Append the summary to $GITHUB_STEP_SUMMARY (no-op outside Actions).

    `target` overrides the env lookup — primarily for tests.
    Returns True if anything was written.
    """
    import os

    path = target or os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return False
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(render_markdown(result))
        fh.write("\n")
    return True
