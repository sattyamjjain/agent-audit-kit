"""MCP Tasks primitive (SEP-1686) leakage scanner (AAK-TASKS-001..003).

Inspects source files for the three shapes flagged in ROADMAP §2.2:
- 001 task read endpoint with no owner/tenant check
- 002 credentials retained in a task row past terminal state
- 003 task has no TTL / cancellation endpoint
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_SCAN_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs"}
_MAX_FILE_BYTES = 512_000

_TASK_HINT = re.compile(
    r"\b(?:Task|task)\s*(?:Manager|Store|Queue|Runner|Primitive|SEP[_-]?1686)\b|"
    r"class\s+\w*Task\w*\b|"
    r"/tasks/[{:<]|task_id",
)

_TASK_GET_RE = re.compile(
    r"""(?:def|async\s+def)\s+(?:get_task|read_task|task_read|get_by_id|findTask)\s*\([^)]*\)[^:]*:""",
    re.DOTALL,
)

_OWNER_CHECK_RE = re.compile(
    r"\b(?:owner|requesting_user|current_user|authenticated_user|principal|tenant_id|caller_id)\b",
    re.IGNORECASE,
)

_CREDENTIAL_FIELD_RE = re.compile(
    r"""\bself\.(?:credentials?|api_key|token|secret|password)\s*=""",
    re.IGNORECASE,
)

_TERMINAL_STATE_RE = re.compile(
    r"(?:completed|failed|cancelled|done|finished|terminal)",
    re.IGNORECASE,
)

_ZEROIZE_RE = re.compile(
    r"""(?:\bself\.(?:credentials?|api_key|token|secret|password)\s*=\s*None\b|"""
    r"""\bdel\s+self\.(?:credentials?|api_key|token|secret|password)\b|"""
    r"""\bclear_secret\s*\(|"""
    r"""\bzero_?ize\s*\()""",
)

_TTL_RE = re.compile(
    r"""\b(?:ttl|expires_at|expiry|deadline)\s*[:=]""",
    re.IGNORECASE,
)
_CANCEL_RE = re.compile(
    r"""\bdef\s+cancel_?\w*\s*\(|\bdef\s+abort_?\w*\s*\(|\bdef\s+terminate_?\w*\s*\(""",
)


def _iter_source(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SCAN_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        out.append(path)
    return out


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    if not _TASK_HINT.search(text):
        return findings
    rel = str(path.relative_to(project_root))

    m_get = _TASK_GET_RE.search(text)
    if m_get:
        window = text[m_get.start() : m_get.start() + 1200]
        if not _OWNER_CHECK_RE.search(window):
            findings.append(
                make_finding(
                    "AAK-TASKS-001",
                    rel,
                    f"Task read function {m_get.group(0)!r} has no owner/tenant check in the first 1200 chars",
                    line_number=find_line_number(text, m_get.group(0)),
                )
            )

    if _CREDENTIAL_FIELD_RE.search(text) and _TERMINAL_STATE_RE.search(text):
        if not _ZEROIZE_RE.search(text):
            m_cred = _CREDENTIAL_FIELD_RE.search(text)
            findings.append(
                make_finding(
                    "AAK-TASKS-002",
                    rel,
                    "Task object stores credential fields but never zeroizes on terminal state",
                    line_number=find_line_number(text, m_cred.group(0)) if m_cred else None,
                )
            )

    if _TASK_HINT.search(text) and not _TTL_RE.search(text) and not _CANCEL_RE.search(text):
        findings.append(
            make_finding(
                "AAK-TASKS-003",
                rel,
                "Task module references tasks but has no TTL or cancellation keyword",
            )
        )

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_source(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
