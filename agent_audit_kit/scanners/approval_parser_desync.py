"""Command-safety parser that does not read the shell's own syntax — CVE-2026-19591.

An agent decides whether a command needs human approval by parsing it. Then it
hands the command to a shell. If the two disagree about what a byte means, the
thing that was approved is not the thing that runs.

Codex CLI is the disclosed instance: PowerShell's stop-parsing token ``--%``
makes ``pwsh`` re-read the rest of the line verbatim, and Codex's safety parser
did not implement it. A command classified as safe therefore ran a different
command, writing a file with no approval prompt — and what it could write was
Codex's own configuration, loaded on the next start.

This is a near neighbour of two existing rules and is neither of them.
``AAK-POLICY-TRUNCATION-001`` is specific about *how* the two views diverge: the
policy is evaluated on a copy **cut to a fixed length**. ``AAK-MCP-ARGV-TOCTOU-001``
needs the argv to be **rebuilt after** the check. Here the string is neither cut
nor rebuilt. The checker and the shell read the same bytes and disagree, which
is a third way to arrive at the same place. Scanned against the whole engine
before writing this: nothing fired.

**Scope, stated rather than implied.** This detects the PowerShell stop-parsing
token specifically. It does not enumerate every shell's escaping quirks, and a
file that gates commands for ``bash`` is not flagged by it. A rule that claimed
to know every shell's grammar would be claiming something no regex can do; this
one claims to know one token that one very common interpreter treats as "stop
reading", and that the approval path has to know about before it approves.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import SKIP_DIRS, find_line_number, make_finding

_RULE_ID = "AAK-APPROVAL-PARSER-DESYNC-001"

_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".rs", ".go")

_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

# An approval / safety decision is being made about a command.
_APPROVAL_RE = re.compile(
    r"\bis\w*Safe\w*\s*\(|\bisAllowed\w*\s*\(|\bis_safe\w*\s*\("
    r"|\bcheck\w*Command\w*\s*\(|\brequire\w*Approval\w*\s*\(|\brequest_approval\s*\("
    r"|\bapproval[-_]?polic\w*|\bneedsApproval\b|\bauto[-_]?approve\b"
    r"|\bSAFE_[A-Z_]+\b|\ballow(?:ed)?[-_]?list\b|\bcommand[-_]?safety\b",
    re.IGNORECASE,
)

# A PowerShell-family interpreter is actually invoked with the command.
_POWERSHELL_RE = re.compile(
    r"['\"`]pwsh['\"`]|['\"`]powershell(?:\.exe)?['\"`]"
    r"|\bpwsh\b\s*,|\bPowerShell\s*Core\b",
    re.IGNORECASE,
)

# The token that changes what the rest of the line means. Knowing about it at
# all is the thing being checked -- rejecting it, stripping it, or refusing to
# classify a command containing it all count.
_STOP_PARSING_RE = re.compile(
    r"--%"
    r"|stop[-_]?parsing"
    r"|STOP_PARSING",
    re.IGNORECASE,
)

# A spawn sink, so this is a gate in front of execution rather than a linter.
_SPAWN_RE = re.compile(
    r"\bspawn\w*\s*\(|\bexec\w*\s*\(|subprocess\s*\.\s*(?:run|Popen|call)\s*\("
    r"|\bCommand\s*::\s*new\s*\(|exec\.Command\s*\(",
)


def _strip_comments(text: str, path: Path) -> str:
    if path.suffix in (".py",):
        return text
    return _TS_LINE_COMMENT_RE.sub(" ", _TS_BLOCK_COMMENT_RE.sub(" ", text))


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for approval gates that classify commands a PowerShell will re-parse.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for path in project_root.rglob("*"):
        if path.suffix not in _SUFFIXES:
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        text = _strip_comments(raw, path)
        if not (
            _APPROVAL_RE.search(text)
            and _POWERSHELL_RE.search(text)
            and _SPAWN_RE.search(text)
        ):
            continue
        # Knowing the token exists is the whole mitigation.
        if _STOP_PARSING_RE.search(text):
            continue

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                "A command-safety check classifies a command and a PowerShell-family "
                "interpreter then executes it, with no handling of the stop-parsing "
                "token `--%`. pwsh re-reads everything after `--%` verbatim, so the "
                "command that was approved is not the command that runs and an "
                "approval prompt is skipped entirely (CVE-2026-19591 class, "
                "CWE-150). Reject `--%` before classifying, or hand the argv to the "
                "interpreter without a shell-parsed command string."
            ),
            find_line_number(raw, "pwsh") or find_line_number(raw, "powershell"),
        ))

    return findings, scanned_files
