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
from agent_audit_kit.scanners._helpers import find_line_number, in_skip_dir, loads_json, make_finding, read_text_capped


_SCAN_EXTS = {".md", ".json", ".yaml", ".yml", ".txt"}
_MAX_FILE_BYTES = 512_000


# The item asked for the inflected forms of each rule's words. Each was measured
# on 632 healthcare READMEs and docs from GitHub code search (pinned, every
# finding read) and kept only if the findings it added were at least 80% real.
# With the negation guard below, -001's contraction (`I'm your therapist`),
# `acts as` / `acting as`, `provides` / `providing therapy` and `delivers` /
# `delivering psychotherapy` added 459 findings, 24 of them an AI's claim: they
# were mostly people describing themselves or their work. -002's -s and -ing
# verbs and plural objects added 15, none an AI deciding medical necessity.
# Those stay unmatched. `replacing`, -003's plural objects and -004's plurals
# added none, and ship.

# AAK-HEALTHCARE-AI-001: explicit mental-health-professional claim (TN SB 1580).
# Intentionally strict: the TN bill targets explicit claims, not generic wellness help.
_MENTAL_HEALTH_CLAIM_RE = re.compile(
    r"""\b(?:
        I\s+am\s+(?:a|your)\s+(?:licensed\s+)?(?:therapist|counsel(?:or|lor)|psychologist|psychiatrist|mental[- ]health\s+professional)|
        act\s+as\s+(?:a|your)\s+(?:licensed\s+)?(?:therapist|counsel(?:or|lor)|psychologist|psychiatrist|mental[- ]health\s+professional)|
        (?:qualified|licensed)\s+mental[- ]health\s+professional|
        replac(?:e[sd]?|ing)\s+(?:a|your)\s+(?:therapist|counsel(?:or|lor)|psychologist|psychiatrist)|
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
    r"\b(?:AI|algorithm|model)\s+(?:only|solely|alone)\s+(?:determines?|decides?|approves?|denies?)\s+"
    r"(?:coverage|claims?|benefits?|polic(?:y|ies)|reimbursements?)\b",
    re.IGNORECASE,
)

# AAK-HEALTHCARE-AI-004: missing disclosure that user is talking to AI (in healthcare context).
# Not `diagnoses`, which is also a verb ("an assistant that diagnoses build
# failures"), and not `symptoms`: on the 892-repo instruction-file benchmark slice
# its only match was engineering prose ("bugs whose symptoms only surface in the
# rendered DOM"), so it did not clear the precision bar a widening needs.
_HEALTHCARE_CONTEXT_RE = re.compile(
    r"\b(?:patients?|clinical|medical|mental[- ]?health|therap(?:y|ies)|diagnosis|symptom|treatments?|medications?)\b",
    re.IGNORECASE,
)
_AI_DISCLOSURE_RE = re.compile(
    r"\b(?:you\s+are\s+(?:interacting|talking|chatting)\s+with\s+(?:an\s+)?AI|AI[- ]generated\s+response|I\s+am\s+(?:an\s+)?AI|non[- ]human)\b",
    re.IGNORECASE,
)

# Rules 004/005 only make sense for a *conversational agent surface* — a
# persona / chatbot / assistant prompt or agent card, not an arbitrary
# markdown file that happens to use clinical words (a dataset README, an ops
# runbook, a data dictionary). This gate keeps them from firing on documents
# that describe healthcare rather than converse about it.
_AGENT_SURFACE_RE = re.compile(
    r"\b(?:you\s+are\s+(?:a|an|your)\b|I\s+am\s+(?:a|an|your)\b|"
    r"system\s*prompt|persona|chat\s*bot|assistant|companion|conversational|"
    r"virtual\s+(?:agent|assistant|nurse|therapist)|talk\s+to\s+me|"
    r"how\s+are\s+you\s+feeling|I['’]?m\s+here\s+(?:to\s+help|for\s+you))\b",
    re.IGNORECASE,
)

# AAK-HEALTHCARE-AI-005: suicide / self-harm escalation missing. Restricted to
# unambiguous self-harm terms — bare "crisis"/"emergency" fired on DevOps
# incident runbooks ("in an emergency, page on-call") that have nothing to do
# with mental-health risk.
_CRISIS_KEYWORDS_RE = re.compile(
    r"\bsuicid\w*|\bself[- ]harm|\boverdose|\bharm\s+(?:myself|yourself)|"
    r"\bkill\s+(?:myself|yourself)|\bend\s+(?:my|your)\s+life\b",
    re.IGNORECASE,
)
_CRISIS_RESPONSE_RE = re.compile(
    r"\b(?:988|911|crisis\s+line|emergency\s+services|call\s+(?:911|112|999))\b",
    re.IGNORECASE,
)


# Compliance text says what a product does not do: "does not automatically deny
# claims", "No AI alone denies claims". A claim is skipped when not, never, no
# or n't stands among the four words before it, in its clause: the negation of
# the claim sits right before it. Read across a whole sentence, the guard also
# silenced claims a sentence states while negating something else: "With no
# human in the loop, the system will automatically approve ...", "There is no
# human review; the system will automatically deny coverage", "not only will
# automatically approve", and a YAML `summary: Does not store PHI` above
# `prompt: You will automatically deny coverage`. So the clause ends at a
# sentence end, `;`, `:` or a line break (each YAML or JSON key is its own
# statement; on 632 healthcare docs a line break never separated a claim from
# the negation of it), and `no human`, `no clinician`, `no physician`, `no
# doctor` and `not only` never count. A mental-health app writes "supports you
# without replacing your therapist", "rather than replacing your therapist":
# `without`, `instead of` and `rather than` negate a claim too, but only right
# before it, since "Without a waitlist, I am your therapist" still claims it.
# A negation is spelled `cannot`, or with the apostrophe curly, U+02BC or left
# out of a common contraction (`isnt`); a word that merely ends in nt, such as
# `patient`, is not one.
_CLAUSE_END_RE = re.compile(r"[.!?;:](?=\s)|\n")
_NOT_A_NEGATION_RE = re.compile(r"\bno\s+(?:human|clinician|physician|doctor)s?\b|\bnot\s+only\b", re.IGNORECASE)
_WORD_RE = re.compile(r"[A-Za-z]+(?:['\u2019\u02bc][A-Za-z]+)*")
_NEGATION_WORD_RE = re.compile(
    r"not|never|no|cannot|[A-Za-z]+n['\u2019\u02bc]t"
    r"|(?:is|are|was|were|ai|do|does|did|has|have|had|ca|could|wo|would|sha|should|might|must|need|ought|dare)nt",
    re.IGNORECASE,
)
_GOVERNED_RE = re.compile(r"\b(?:without|instead\s+of|rather\s+than)\s*\Z", re.IGNORECASE)
_NEGATION_WORDS = 4
_LOOK_BACK = 200


def _negated(text: str, start: int) -> bool:
    """Whether a negation stands among the four words before `start`, in its
    clause, or `without`, `instead of` or `rather than` right before it.

    It reads at most `_LOOK_BACK` characters back, so a crafted run of claims
    stays linear. A word the window cuts in two is dropped: the tail of
    `whenever` read as `never`, and the claim after it was skipped.
    """
    low = max(0, start - _LOOK_BACK)
    window = text[low:start]
    cut = _WORD_RE.match(window) if low and text[low - 1].isascii() and text[low - 1].isalpha() else None
    if cut:
        window = window[cut.end():]
    last = None
    for last in _CLAUSE_END_RE.finditer(window):
        pass
    clause = window[last.end():] if last else window
    if _GOVERNED_RE.search(clause):
        return True
    words = _WORD_RE.findall(_NOT_A_NEGATION_RE.sub(" ", clause))
    return any(_NEGATION_WORD_RE.fullmatch(w) for w in words[-_NEGATION_WORDS:])


def _first_claim(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    """The first match of ``pattern`` that is not negated."""
    for m in pattern.finditer(text):
        if not _negated(text, m.start()):
            return m
    return None


def _line_of(raw: str, m: re.Match[str]) -> int | None:
    """The match's own line; a match in the text pulled out of JSON falls back to the first line holding it."""
    if m.end() <= len(raw):
        return raw.count("\n", 0, m.start()) + 1
    return find_line_number(raw, m.group(0))


def _iter_files(project_root: Path) -> Iterable[Path]:
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if in_skip_dir(path, project_root):
            continue
        if path.suffix.lower() not in _SCAN_EXTS:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


_TEXT_KEYS = frozenset({
    "description", "system_prompt", "systemprompt", "persona", "prompt",
    "instructions", "tagline", "summary", "greeting",
})


def _collect_text_from_json(obj: object) -> str:
    """Pull description-like text values out of a loaded MCP/agent-card config.

    Every string in it, in document order, with a description-like value
    twice. Iterative: `json.loads` accepts nesting thousands of levels deeper
    than Python's recursion limit, and the recursive walk this was took the
    scanner down on one such file, with its findings on every other.
    """
    out: list[str] = []
    stack: list[object] = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if node:
                out.append(node)
        elif isinstance(node, dict):
            parts: list[object] = []
            for key, value in node.items():
                if isinstance(value, str) and key.lower() in _TEXT_KEYS:
                    parts.append(value)
                parts.append(value)
            stack.extend(reversed(parts))
        elif isinstance(node, list):
            stack.extend(reversed(node))
    return "\n".join(out)


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    try:
        raw = read_text_capped(path, _MAX_FILE_BYTES, errors="replace")
    except OSError:
        return []
    findings: list[Finding] = []
    rel = str(path.relative_to(project_root))

    # For JSON files, extract string fields that carry user-facing meaning.
    scan_body = raw
    if path.suffix.lower() == ".json":
        try:
            data = loads_json(raw, path)
            extracted = _collect_text_from_json(data)
            if extracted:
                scan_body = raw + "\n" + extracted
        except json.JSONDecodeError:
            pass

    m = _first_claim(_MENTAL_HEALTH_CLAIM_RE, scan_body)
    if m:
        findings.append(
            make_finding(
                "AAK-HEALTHCARE-AI-001",
                rel,
                f"Tennessee SB 1580 trigger: AI described as a mental-health professional ({m.group(0)!r})",
                line_number=_line_of(raw, m),
            )
        )

    m = _first_claim(_PRIOR_AUTH_AI_RE, scan_body)
    if m:
        findings.append(
            make_finding(
                "AAK-HEALTHCARE-AI-002",
                rel,
                f"AI decides prior-auth / medical necessity without licensed physician: {m.group(0)!r}",
                line_number=_line_of(raw, m),
            )
        )

    m = _first_claim(_INSURANCE_AI_RE, scan_body)
    if m:
        findings.append(
            make_finding(
                "AAK-HEALTHCARE-AI-003",
                rel,
                f"AI-only insurance coverage decision (Georgia/Iowa pattern): {m.group(0)!r}",
                line_number=_line_of(raw, m),
            )
        )

    if (
        _HEALTHCARE_CONTEXT_RE.search(scan_body)
        and _AGENT_SURFACE_RE.search(scan_body)
        and not _AI_DISCLOSURE_RE.search(scan_body)
    ):
        findings.append(
            make_finding(
                "AAK-HEALTHCARE-AI-004",
                rel,
                "Conversational healthcare agent surface without explicit AI-disclosure string",
            )
        )

    if (
        _CRISIS_KEYWORDS_RE.search(scan_body)
        and _AGENT_SURFACE_RE.search(scan_body)
        and not _CRISIS_RESPONSE_RE.search(scan_body)
    ):
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
