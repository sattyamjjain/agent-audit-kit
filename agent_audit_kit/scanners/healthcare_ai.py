"""Healthcare-AI regulation trigger detection.

Fires AAK-HEALTHCARE-AI-001..005 — rules driven by the 2026 wave of US
state healthcare-AI legislation.

References:
- Tennessee SB 1580 (signed 2026-04-01, effective 2026-07-01): an AI
  system cannot "advertise or represent to the public that [it] is or
  is able to act as a qualified mental health professional."
  Enforceable under the Tennessee Consumer Protection Act 1977, with
  a **private right of action** and $5,000/violation civil penalty.
  https://www.troutmanprivacy.com/2026/04/tennessee-enacts-health-care-ai-bill-with-private-right-of-action/
- Kansas / Washington / Utah: AI prior-authorization must be reviewed
  by a licensed physician; transparency required.
- Georgia / Iowa: AI-only insurance coverage decisions restricted.

These patterns fire on MCP tool descriptions, SKILL.md bodies, agent
card JSON, and similar user-facing strings that would expose a
deployment to state-level enforcement.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_SCAN_EXTS = {".md", ".json", ".yaml", ".yml", ".txt"}
_MAX_FILE_BYTES = 512_000


# AAK-HEALTHCARE-AI-001: explicit mental-health-professional claim (TN SB 1580).
# Intentionally strict: the TN bill targets explicit claims, not generic wellness help.
_MENTAL_HEALTH_CLAIM_RE = re.compile(
    r"""\b(?:
        I\s+am\s+(?:a|your)\s+(?:licensed\s+)?(?:therapist|counsel(?:or|lor)|psychologist|psychiatrist|mental[- ]health\s+professional)|
        act\s+as\s+(?:a|your)\s+(?:licensed\s+)?(?:therapist|counsel(?:or|lor)|psychologist|psychiatrist|mental[- ]health\s+professional)|
        (?:qualified|licensed)\s+mental[- ]health\s+professional|
        replace[sd]?\s+(?:a|your)\s+(?:therapist|counsel(?:or|lor)|psychologist|psychiatrist)|
        provide\s+(?:licensed\s+)?therapy|
        deliver\s+(?:licensed\s+)?psychotherapy
    )\b""",
    re.IGNORECASE | re.VERBOSE,
)

# AAK-HEALTHCARE-AI-002: AI makes prior-auth / medical-necessity decisions
_PRIOR_AUTH_AI_RE = re.compile(
    r"\b(?:automatically|autonomously|without\s+physician|no\s+(?:human|clinician|physician))\s+(?:approve|deny|determine|decide|issue)\s+(?:prior[- ]authorization|medical[- ]necessity|coverage|claim)\b",
    re.IGNORECASE,
)

# AAK-HEALTHCARE-AI-003: AI-only insurance coverage decision
_INSURANCE_AI_RE = re.compile(
    r"\b(?:AI|algorithm|model)\s+(?:only|solely|alone)\s+(?:determines?|decides?|approves?|denies?)\s+(?:coverage|claim|benefit|policy|reimbursement)\b",
    re.IGNORECASE,
)

# AAK-HEALTHCARE-AI-004: missing disclosure that user is talking to AI (in healthcare context)
_HEALTHCARE_CONTEXT_RE = re.compile(
    r"\b(?:patient|clinical|medical|mental[- ]?health|therapy|diagnosis|symptom|treatment|medication)\b",
    re.IGNORECASE,
)
_AI_DISCLOSURE_RE = re.compile(
    r"\b(?:you\s+are\s+(?:interacting|talking|chatting)\s+with\s+(?:an\s+)?AI|AI[- ]generated\s+response|I\s+am\s+(?:an\s+)?AI|non[- ]human)\b",
    re.IGNORECASE,
)

# AAK-HEALTHCARE-AI-005: emergency / suicide-risk escalation missing
_CRISIS_KEYWORDS_RE = re.compile(
    r"\b(?:suicide|self[- ]harm|crisis|emergency|overdose|harm\s+(?:myself|yourself))\b",
    re.IGNORECASE,
)
_CRISIS_RESPONSE_RE = re.compile(
    r"\b(?:988|911|crisis\s+line|emergency\s+services|call\s+(?:911|112|999))\b",
    re.IGNORECASE,
)


def _iter_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in _SCAN_EXTS:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _collect_text_from_json(obj: object) -> str:
    """Pull description-like text values out of a loaded MCP/agent-card config."""
    out: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str) and key.lower() in {
                "description", "system_prompt", "systemprompt", "persona", "prompt",
                "instructions", "tagline", "summary", "greeting",
            }:
                out.append(value)
            out.append(_collect_text_from_json(value))
    elif isinstance(obj, list):
        for item in obj:
            out.append(_collect_text_from_json(item))
    elif isinstance(obj, str):
        return obj
    return "\n".join(s for s in out if s)


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))

    # For JSON files, extract string fields that carry user-facing meaning.
    scan_body = raw
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(raw)
            extracted = _collect_text_from_json(data)
            if extracted:
                scan_body = raw + "\n" + extracted
        except json.JSONDecodeError:
            pass

    m = _MENTAL_HEALTH_CLAIM_RE.search(scan_body)
    if m:
        findings.append(
            make_finding(
                "AAK-HEALTHCARE-AI-001",
                rel,
                f"Tennessee SB 1580 trigger: AI described as a mental-health professional ({m.group(0)!r})",
                line_number=find_line_number(raw, m.group(0)),
            )
        )

    m = _PRIOR_AUTH_AI_RE.search(scan_body)
    if m:
        findings.append(
            make_finding(
                "AAK-HEALTHCARE-AI-002",
                rel,
                f"AI decides prior-auth / medical necessity without licensed physician: {m.group(0)!r}",
                line_number=find_line_number(raw, m.group(0)),
            )
        )

    m = _INSURANCE_AI_RE.search(scan_body)
    if m:
        findings.append(
            make_finding(
                "AAK-HEALTHCARE-AI-003",
                rel,
                f"AI-only insurance coverage decision (Georgia/Iowa pattern): {m.group(0)!r}",
                line_number=find_line_number(raw, m.group(0)),
            )
        )

    if _HEALTHCARE_CONTEXT_RE.search(scan_body) and not _AI_DISCLOSURE_RE.search(scan_body):
        findings.append(
            make_finding(
                "AAK-HEALTHCARE-AI-004",
                rel,
                "Healthcare context without explicit AI-disclosure string",
            )
        )

    if _CRISIS_KEYWORDS_RE.search(scan_body) and not _CRISIS_RESPONSE_RE.search(scan_body):
        crisis_match = _CRISIS_KEYWORDS_RE.search(scan_body)
        findings.append(
            make_finding(
                "AAK-HEALTHCARE-AI-005",
                rel,
                f"Crisis keyword {crisis_match.group(0)!r} appears without a crisis-line escalation (988 / 911 / 112 / 999)" if crisis_match else "",
                line_number=find_line_number(raw, crisis_match.group(0)) if crisis_match else None,
            )
        )

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
