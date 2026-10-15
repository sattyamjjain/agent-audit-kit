"""Scanner for poisoned Claude Code / Claude Agent SDK `SKILL.md` files.

Fires AAK-SKILL-001..006:
- 001 post-install / side-effect command embedded in SKILL.md
- 002 unicode steganography (bidi, zero-width, tag-unicode)
- 003 data-exfiltration primitive (outbound HTTP + local-data reference)
- 004 description hijacks a trusted first-party skill name
- 005 prompt-injection trigger in frontmatter
- 006 hidden instruction in a body HTML comment

Patterns are based on the Snyk ToxicSkills dataset (1,467 malicious
payloads, 2026) and the Anthropic first-party skill directory.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, in_skip_dir, finditer_up_to_last
from agent_audit_kit.scanners.agent_config import (
    _downloaded_code_runs,
    _line_at,
    _prohibited_lines,
)


_TRUSTED_NAMES = frozenset(
    {
        "pdf",
        "docx",
        "pptx",
        "xlsx",
        "frontend-design",
        "canvas-design",
        "brand-guidelines",
        "algorithmic-art",
        "theme-factory",
        "web-artifacts-builder",
        "webapp-testing",
        "slack-gif-creator",
        "doc-coauthoring",
        "mcp-builder",
        "skill-creator",
        "internal-comms",
    }
)

# ---- AAK-SKILL-001: post-install / side-effect command ----
#
# The rule promises bash, curl, pipe-to-sh and wget. It used to match
# `curl|wget ... | sh` only, and only when the command opened a line, so
# `| bash`, `| zsh`, `| sudo sh`, a list item, a `$ ` prompt and the usual
# "run `curl ... | bash` once" sentence all scanned clean. Two arms now:
#
# - A download run as code is the shape AAK-AGENT-001 already reads in agent
#   instruction files, and `agent_config._downloaded_code_runs` is reused rather
#   than copied: it matches anywhere on a line, wants a remote target (a
#   deny-list quoting `curl | sh` names none), and skips a guardrail ("never run
#   ..."), so one command is judged the same way in an AGENTS.md and a SKILL.md.
# - The other commands keep their spelling but count only where a command
#   starts: a line, optionally after blockquote markers, a list marker, a `$ `
#   prompt or opening backticks. `eval(` and `npm install -g` are ordinary words
#   in prose about code; a review skill that tells the model to flag `eval(` is
#   not running it.
_SIDE_EFFECT_RE = re.compile(
    r"[ \t]*(?:>[ \t]*)*(?:(?:[-*+]|\d+[.)])[ \t]+)?(?:\$[ \t]+)?`*"
    r"(?P<command>npm\s+install\s+-g|pip\s+install\s+--user|bash\s+-c|sh\s+-c|eval\s*\()",
    re.IGNORECASE,
)

# zero-width, bidi, tag-unicode ranges
_INVISIBLE_RE = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]|"
    r"[\U000E0000-\U000E007F]"
)

_EXFIL_SINK_RE = re.compile(
    r"\b(?:fetch|axios\.(?:get|post|put)|requests\.(?:get|post|put)|"
    r"urllib\.request\.urlopen|http\.client\.HTTP(?:S)?Connection|"
    r"curl\b|wget\b)",
    re.IGNORECASE,
)
# ---- AAK-SKILL-003 / -006: a local secret ----
#
# The whole alternation used to sit inside `\b(?:...)\b`. `\b` needs a word
# character on one side, so in front of a `~`, `.` or `$` it held only after a
# word character: `~/.ssh`, `.aws/credentials` and `.netrc` never matched after
# a space, a slash or a quote (`curl -T ~/.aws/credentials ...` scanned clean),
# while `config.netrc` did. Word-led tokens keep `\b`; each symbol-led path gets
# a lookbehind that refuses a word character or another path character before
# it, which is the boundary it was meant to have. `$HOME/.ssh` and
# `${HOME}/.ssh` are spelled out beside `~/.ssh`.
#
# `$HOME` and a bare `~/` were in the list too, and dead for the same reason.
# They are not brought back: a home directory on its own is not local data.
# Every install line names one (`~/.local/bin`, `$HOME/.bun`), and
# AAK-SKILL-003 pairs this pattern with any `curl` anywhere in the file, so
# restoring them would report most skills that document an install. The
# credential files under the home directory are what both rules mean.
_LOCAL_DATA_RE = re.compile(
    r"\b(?:process\.env|os\.environ|id_rsa|id_ed25519|read(?:Text|File))\b"
    r"|(?<![\w.-])\.(?:aws/credentials|netrc)\b"
    r"|(?<![\w~/.$-])(?:~|\$HOME|\$\{HOME\})/\.ssh\b",
    re.IGNORECASE,
)

_INJECTION_TRIGGERS = (
    "ignore previous",
    "ignore above",
    "you are now",
    "you are a",
    "system:",
    "disregard prior",
    "forget all prior",
    "jailbreak",
    "developer mode",
    "DAN mode",
)

#: The triggers as case-insensitive matches that start at a word. Both callers
#: used to lower-case the text and test each trigger as a plain substring, so
#: "DAN mode", the one trigger with capitals, could never match. A
#: case-insensitive substring would find it inside "Jordan mode" instead, and
#: the same word start is why "filesystem:" no longer reads as "system:".
_TRIGGER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (trigger, re.compile(r"\b" + re.escape(trigger), re.IGNORECASE))
    for trigger in _INJECTION_TRIGGERS
)


def _first_trigger(text: str) -> tuple[str, int] | None:
    """The first trigger, in list order, that ``text`` holds, with its offset."""
    for trigger, pattern in _TRIGGER_PATTERNS:
        match = pattern.search(text)
        if match:
            return trigger, match.start()
    return None


# ---- AAK-SKILL-006: hidden instruction in a body HTML comment ----
#
# An HTML comment in a skill body is invisible in every rendered view a human
# reviews and fully visible to the model, which gets the raw file. Bare comments
# are ordinary in markdown, so the comment has to read as an *instruction*
# before this fires: either an injection trigger, or a local-secret reference
# with somewhere to send it. TODO/FIXME/NOTE housekeeping and licence headers
# carry neither and stay quiet.
_HTML_COMMENT_RE = re.compile(r"<!--([\s\S]*?)-->")
_DESTINATION_RE = re.compile(r"https?://|\b(?:webhook|endpoint|collect|drop|exfil)\b", re.IGNORECASE)
_IMPERATIVE_EXFIL_RE = re.compile(
    r"\b(?:exfiltrate|leak|steal|smuggle|siphon|upload|post|send|forward|copy)\b",
    re.IGNORECASE,
)


def _hidden_instruction_hits(body: str) -> list[tuple[str, str]]:
    """Return (comment_text, why) for each body comment that reads as an order."""
    hits: list[tuple[str, str]] = []
    for match in finditer_up_to_last(_HTML_COMMENT_RE, body, "-->"):
        inner = match.group(1).strip()
        if not inner:
            continue
        trigger = _first_trigger(inner)
        if trigger:
            hits.append((inner, f"injection trigger {trigger[0]!r}"))
            continue
        # Exfiltration shape: a local secret, an imperative, and a destination.
        if (
            _LOCAL_DATA_RE.search(inner)
            and _IMPERATIVE_EXFIL_RE.search(inner)
            and _DESTINATION_RE.search(inner)
        ):
            hits.append((inner, "local-secret reference with an outbound destination"))
    return hits


def _post_install_command(raw: str) -> tuple[int, str] | None:
    """``(line, command)`` for the first post-install command in ``raw``, or None.

    One finding per file at the first command, as the rule has always reported,
    with the line taken from where the command is rather than from a search for
    its text. A line that a prohibition heading or lead-in governs ("## Never",
    "Do not run any of these:") is skipped, the guardrail AAK-AGENT-001 honours.
    """
    lines = raw.splitlines()
    prohibited = _prohibited_lines(lines)
    for number, line in enumerate(lines, 1):
        if number in prohibited:
            continue
        hits = _downloaded_code_runs(line)
        side_effect = _SIDE_EFFECT_RE.match(line)
        if side_effect:
            hits.append((side_effect.start("command"), side_effect.group("command")))
        if hits:
            return number, min(hits)[1]
    return None


def _iter_skill_files(project_root: Path) -> list[Path]:
    results: list[Path] = []
    for path in project_root.rglob("SKILL.md"):
        if in_skip_dir(path, project_root):
            continue
        if path.is_file():
            results.append(path)
    return results


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---"):
        return {}, text
    try:
        _, fm, body = text.split("---", 2)
    except ValueError:
        return {}, text
    meta: dict[str, str] = {}
    for line in fm.strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip().lower()] = value.strip()
    return meta, body


def _check_skill(path: Path, project_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    rel = str(path.relative_to(project_root))
    meta, _ = _parse_frontmatter(raw)

    post_install = _post_install_command(raw)
    if post_install:
        line_number, command = post_install
        findings.append(
            make_finding(
                "AAK-SKILL-001",
                rel,
                f"Post-install command detected: {command!r}",
                line_number=line_number,
            )
        )

    invis = _INVISIBLE_RE.search(raw)
    if invis:
        offset = invis.start()
        line = raw[:offset].count("\n") + 1
        findings.append(
            make_finding(
                "AAK-SKILL-002",
                rel,
                f"Invisible/bidi unicode character U+{ord(invis.group()[0]):04X} at line {line}",
                line_number=line,
            )
        )

    if _EXFIL_SINK_RE.search(raw) and _LOCAL_DATA_RE.search(raw):
        findings.append(
            make_finding(
                "AAK-SKILL-003",
                rel,
                "Outbound HTTP sink combined with local-data reference (exfil shape)",
            )
        )

    name = meta.get("name", "").strip().strip("\"'")
    if name and name not in _TRUSTED_NAMES:
        for trusted in _TRUSTED_NAMES:
            if _looks_like(name.lower(), trusted):
                findings.append(
                    make_finding(
                        "AAK-SKILL-004",
                        rel,
                        f"Skill name {name!r} hijacks trusted skill {trusted!r}",
                        line_number=find_line_number(raw, name),
                    )
                )
                break

    # AAK-SKILL-006: hidden instruction in the body (not the frontmatter).
    _, body = _parse_frontmatter(raw)
    for inner, why in _hidden_instruction_hits(body):
        findings.append(
            make_finding(
                "AAK-SKILL-006",
                rel,
                f"HTML comment in the skill body reads as an instruction "
                f"({why}): {inner[:100]!r}",
                line_number=find_line_number(raw, inner.splitlines()[0][:60]),
            )
        )

    fm_boundary = raw.find("---", 3)
    trigger = _first_trigger(raw[: fm_boundary if fm_boundary > 0 else 500])
    if trigger:
        findings.append(
            make_finding(
                "AAK-SKILL-005",
                rel,
                f"Prompt-injection trigger in frontmatter: {trigger[0]!r}",
                line_number=_line_at(raw, trigger[1]),
            )
        )

    return findings


def _looks_like(candidate: str, target: str) -> bool:
    if candidate == target:
        return False
    if abs(len(candidate) - len(target)) > 2:
        return False
    if target in candidate or candidate in target:
        return True
    shared = sum(1 for a, b in zip(candidate, target) if a == b)
    return shared >= min(len(candidate), len(target)) - 1


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_skill_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_skill(path, project_root))
    return findings, scanned
