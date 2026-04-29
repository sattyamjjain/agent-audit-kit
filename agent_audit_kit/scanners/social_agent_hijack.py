"""AAK-TIKTOK-AGENT-HIJACK-001 — social-agent auto-reply hijack.

Jiacheng Zhong's BlackHat Asia 2026 (2026-04-24) talk demonstrates
hijack of TikTok-style agents that auto-reply to comments. The class
generalises: any agent that ingests user-generated short-form content
into a tool-use loop. LLM08 / Excessive Agency.

Fires on `tiktok_api.reply(...)`, `instagrapi.direct.send(...)`,
`tweepy.API.update_status(...)`, `discord.Message.reply(...)` whose
argument transitively depends on `comments.fetch(...)` /
`webhook.payload[...]['text']` without an `aak.review.human_in_loop()`
gate.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding


_REPLY_SINK_RE = re.compile(
    r"""
    (?:
        tiktok_api\s*\.\s*reply\s*\(
      | tiktok\s*\.\s*comment\s*\.\s*reply\s*\(
      | instagrapi\s*\.\s*direct\s*\.\s*send\s*\(
      | instagrapi\s*\.\s*\w+\s*\.\s*comment_reply\s*\(
      | tweepy\s*\.\s*API\s*\(\s*\)\s*\.\s*update_status\s*\(
      | tweepy\s*\.\s*Client\s*\(\s*\)\s*\.\s*create_tweet\s*\(
      | discord\s*\.\s*Message\s*\.\s*reply\s*\(
      | discord\s*\.\s*Channel\s*\.\s*send\s*\(
    )
    """,
    re.VERBOSE,
)
_USER_INPUT_RE = re.compile(
    r"""
    (?:
        comments\.fetch\s*\(
      | webhook\.payload\[\s*['"]text['"]\s*\]
      | event\[\s*['"]comment['"]\s*\]
      | tiktok_api\.comments
      | instagrapi\.\w+\.comments
      | media\.comments
    )
    """,
    re.VERBOSE,
)
_HUMAN_GATE_RE = re.compile(
    r"""
    (?:
        aak\.review\.human_in_loop\s*\(
      | human_in_the_loop\s*\(
      | require_approval\s*\(
      | needs_review\s*\(
    )
    """,
    re.VERBOSE,
)


def _walk_python(text: str, path: Path, project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    if not _REPLY_SINK_RE.search(text) or not _USER_INPUT_RE.search(text):
        return findings
    if _HUMAN_GATE_RE.search(text):
        return findings
    rel = str(path.relative_to(project_root))
    scanned.add(rel)
    sink_m = _REPLY_SINK_RE.search(text)
    line = (text.count("\n", 0, sink_m.start()) + 1) if sink_m else 1
    findings.append(make_finding(
        "AAK-TIKTOK-AGENT-HIJACK-001",
        rel,
        "Social-agent auto-reply sink reachable from user-generated "
        "comment / webhook content without a human-in-loop gate. "
        "BlackHat Asia 2026 hijack class (LLM08).",
        line_number=line,
    ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    for path in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_walk_python(text, path, project_root, scanned))
    return findings, scanned
