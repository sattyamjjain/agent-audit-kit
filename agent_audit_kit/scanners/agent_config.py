from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import make_finding

# ---- Target files to scan (relative to project root) ----
_AGENT_CONFIG_FILES: list[str] = [
    "AGENTS.md",
    ".cursorrules",
    "CLAUDE.md",
    ".claude/CLAUDE.md",
    ".github/copilot-instructions.md",
    ".windsurfrules",
    ".roo/rules",
    ".kiro/rules",
]

# ---- AAK-AGENT-001: Shell command directives ----
# NOTE: no bare `` `...` `` inline-code arm — it matched *every* backtick span
# in an agent-instruction file (`` `cargo build` ``, `` `make` ``, `` `npx tsc` ``),
# producing dozens of false positives per CLAUDE.md. A genuinely dangerous
# backtick-wrapped command (`` `rm -rf /` ``, `` `sh -c ...` ``) still matches
# through the specific arms below. The `curl|wget ... | sh` arm preserves
# detection of pipe-to-shell that the catch-all used to cover.
_SHELL_DIRECTIVE_RE = re.compile(
    r"\bsh\s+-c\s|\bbash\s+-c\s|"
    r"\bos\.system\s*\(|"
    r"\bsubprocess\b|"
    r"\bexec\s*\(|"
    r"\beval\s*\(|"
    r"\brm\s+-rf\b|"
    r"(?:curl|wget)\b[^\n`]*\|\s*(?:sh|bash|zsh)\b",
    re.IGNORECASE,
)

# ---- AAK-AGENT-002 / -006: links in instruction files ----
#
# AAK-AGENT-002 used to be HIGH for *any* link outside a prefix allowlist, which
# reads the wrong risk in both directions. Reported in #771 against 930 public
# repositories shipping AGENTS.md / CLAUDE.md: it fired on 303 of them, so a
# third of that sample failed `--ci` for carrying a documentation link. A link
# on its own is not an attack, and calling it HIGH trains people to pass
# `--fail-on critical`, which then hides the findings that are.
#
# What is worth HIGH is the directive, not the host: text that tells the agent to
# fetch a URL and follow, execute, obey or load what comes back, or to send data
# to one. AAK-AGENT-006 matches that, deterministically and with no allowlist at
# all — the reporter's own point, that an attacker can host on github.com too.
_URL_RE = re.compile(r"https?://[^\s\)>\]\"']+", re.IGNORECASE)

#: Hosts whose links are ordinary documentation. Compared as HOSTS, never as a
#: prefix of the URL string. The prefix form let `github.com.evil.example` pass
#: as `github.com`, so the one shape an allowlist has to get right — a lookalike
#: registered under somebody else's name — was the shape it waved through.
#: Verified against the published 0.6.7 wheel before this change: a
#: fetch-and-follow directive pointing at that host produced no finding at all.
#:
#: The bare `docs.` and `developer.` arms are gone with it. They matched any host
#: beginning with those labels — `docs.attacker.example` included — which is a
#: statement about a subdomain label, not about who controls the domain.
_SAFE_URL_HOSTS = frozenset({
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "npmjs.com",
    "registry.npmjs.org",
    "pypi.org",
    # `python.org` replaces what the bare `docs.` arm used to cover for
    # `docs.python.org`. Naming the domain is the whole change: it admits any
    # subdomain of python.org and nothing that merely begins with `docs.`. Any
    # other documentation host wanted here has to be named the same way.
    "python.org",
    "crates.io",
    "gitlab.com",
    "bitbucket.org",
    "readthedocs.io",
    "readthedocs.org",
    "shields.io",
    "badge.fury.io",
    "travis-ci.org",
    "circleci.com",
    "codecov.io",
    "coveralls.io",
    "mozilla.org",
    "w3.org",
    "json-schema.org",
    "schema.org",
    "creativecommons.org",
    "opensource.org",
    "spdx.org",
    "example.com",
})


def _is_safe_host(url: str) -> bool:
    """True when `url`'s host is an allowlisted domain or a subdomain of one.

    Dot-bounded suffix match on the parsed hostname: `gist.github.com` is inside
    `github.com`, and `github.com.evil.example` is not, because the allowlisted
    name has to end the host rather than merely start it.
    """
    try:
        host = urlsplit(url).hostname
    except ValueError:  # malformed authority — not something to call safe
        return False
    if not host:
        return False
    host = host.rstrip(".").lower()
    return any(
        host == safe or host.endswith("." + safe) for safe in _SAFE_URL_HOSTS
    )


#: A verb that makes a URL an instruction rather than a reference. Three
#: patterns, because there are three shapes and lumping them made the rule too
#: loose: an act verb plus any URL later on the line matched "Run the tests, then
#: see <docs link>", which is exactly the false positive this rule exists to
#: avoid becoming.
_FETCH_VERB = (
    r"(?:fetch|download|curl|wget|retrieve|read|load|import|pull|GET|"
    r"open|visit|go\s+to)"
)
_ACT_VERB = r"(?:follow|execute|run|obey|apply|comply|eval|source|adhere\s+to)"
_SEND_VERB = r"(?:send|post|POST|upload|exfiltrate|report|submit|transmit|push)"
_URL_FRAG = r"https?://[^\s\)>\]\"']+"

#: Fetch it, then act on it: "download <url> and run it".
_FETCH_THEN_ACT_RE = re.compile(
    r"\b" + _FETCH_VERB + r"\b[^\n]{0,120}?" + _URL_FRAG
    + r"[^\n]{0,120}?\b" + _ACT_VERB + r"\b",
    re.IGNORECASE,
)

#: Act on what is at it: "follow the instructions at <url>". The preposition is
#: required, and is what keeps the act verb bound to the URL rather than merely
#: sharing a line with it.
_ACT_AT_URL_RE = re.compile(
    r"\b" + _ACT_VERB + r"\b[^\n]{0,100}?\b(?:at|from|in|on|via|per)\s+"
    r"(?:the\s+|this\s+)?(?:\S+\s+){0,3}?" + _URL_FRAG,
    re.IGNORECASE,
)

#: Send something to it: "upload the results to <url>".
_SEND_TO_URL_RE = re.compile(
    r"\b" + _SEND_VERB + r"\b[^\n]{0,140}?" + _URL_FRAG,
    re.IGNORECASE,
)

_DIRECTIVE_PATTERNS = (_FETCH_THEN_ACT_RE, _ACT_AT_URL_RE, _SEND_TO_URL_RE)


def _directive_links(content: str) -> list[tuple[int, str, str]]:
    """``(line, evidence, url)`` for each line whose text acts on a URL.

    Scoped to one line, which is what "the same sentence or list item" means in
    a markdown instruction file: a URL three paragraphs below an unrelated
    "follow" is not a directive about that URL, and matching across the gap is
    how a context rule turns into the blunt one it replaced.
    """
    out: list[tuple[int, str, str]] = []
    for line_num, line in enumerate(content.splitlines(), 1):
        if "://" not in line:
            continue
        for pattern in _DIRECTIVE_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            url = _URL_RE.search(match.group())
            if url is None:
                continue
            out.append((line_num, match.group().strip(), url.group()))
            break
    return out


# ---- AAK-AGENT-003: Security override patterns ----
_SECURITY_OVERRIDE_RE = re.compile(
    r"ignore\s+security|"
    r"skip\s+verification|"
    r"disable\s+auth|"
    r"allow\s+all|"
    r"bypass|"
    r"ignore\s+previous\s+instructions|"
    r"you\s+are\s+now|"
    r"new\s+system\s+prompt",
    re.IGNORECASE,
)

# ---- AAK-AGENT-004: Credential patterns ----
_CREDENTIAL_RE = re.compile(
    r"\$API_KEY|\$SECRET|\$TOKEN|\$PASSWORD|"
    r"\$\{?[A-Z_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*\}?|"
    r"\benv\s*\[\s*['\"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*['\"]\s*\]|"
    r"\bos\.environ\s*\[\s*['\"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*['\"]\s*\]|"
    r"\bprocess\.env\.[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*\b",
    re.IGNORECASE,
)

# ---- AAK-AGENT-005: Hidden content ----
_HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")

# Comments that are a tool's own bookkeeping, matched against that tool's whole
# syntax. The Claude Code auto-memory plugin writes sixteen section markers into
# a root CLAUDE.md, and once each comment reached code scanning as its own alert
# they buried the comments this rule exists for.
#
# The exemption is a grammar, not a prefix: fixed keywords, a known section name,
# `MDnnn` rule ids, and nowhere to put a sentence. A keyword followed by free
# text is free text, an unknown section name is a free-form phrase, and
# markdownlint's rule aliases are words rather than ids, so all of those still
# report. Length is no test: a short comment hides a command as well as a long one.
# A link reference definition is never rendered, and one whose destination is `#`
# or `<>` exists only to carry its title: `[//]: # (text)` is how Markdown writes a
# comment, and the HTML-comment pattern never saw it. Up to three spaces of indent
# (four is a code block), one line, a title in (), "" or ''. A definition that
# points somewhere is a link, and one with no title carries no text, so neither is
# reported.
_REFDEF_COMMENT_RE = re.compile(
    r"""^[ ]{0,3}\[[^\]\n]+\]:[ \t]*(?:\#|<>)[ \t]+"""
    r"""(?:\((?P<p>[^)\n]*)\)|"(?P<d>[^"\n]*)"|'(?P<s>[^'\n]*)')[ \t]*$""",
    re.MULTILINE,
)

_AUTO_MEMORY_SECTIONS = (
    "project-description", "build-commands", "architecture", "conventions",
    "patterns", "git-insights", "best-practices", "module-description",
    "dependencies",
)
_TOOL_MARKER_RE = re.compile(
    r"<!--\s*(?:"
    r"AUTO-MANAGED:\s*(?:" + "|".join(_AUTO_MEMORY_SECTIONS) + r")"
    r"|END AUTO-MANAGED|MANUAL|END MANUAL"
    r"|markdownlint-(?:disable|enable)(?:-next-line|-line|-file)?(?:\s+[Mm][Dd]\d{3})*"
    r"|markdownlint-(?:capture|restore)"
    r"|prettier-ignore(?:-start|-end)?"
    r")\s*-->"
)
_ZERO_WIDTH_CHARS = frozenset({
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # byte order mark / zero-width no-break space
    "\u2060",  # word joiner
    "\u202e",  # right-to-left override
})

# Three of those characters do ordinary work in ordinary text, and reporting
# them as "hidden content" told writers of several scripts that their language
# is suspicious. Raised in #771 alongside the AAK-AGENT-002 severity: emoji ZWJ
# sequences, a leading BOM, and Hindi and Persian joiners were all reported at
# MEDIUM.
#
# What stays reportable is placement, not identity. U+200C and U+200D between
# letters of one script are spelling: Devanagari needs U+200D for a conjunct and
# U+200C to break one, Persian needs U+200C for a word like "می‌رود". U+200D
# between two emoji is how a single glyph is composed. A BOM at offset 0 is a
# file-encoding marker every editor writes.
#
# The same characters anywhere else still fire, because that is where they hide
# text: a joiner between a letter and a space, between two scripts, or inside a
# run of ASCII is doing nothing a reader can see. U+200B, U+2060 and U+202E are
# never exempt -- none of them is required to spell anything, and U+202E
# reverses display order, which is the trick itself.
_CONTEXTUAL_ZERO_WIDTH = frozenset({"\u200c", "\u200d"})

#: Scripts whose orthography uses U+200C / U+200D between letters. Read off
#: `unicodedata.name`, which prefixes every letter with its script, so this is
#: the script name rather than a hand-kept codepoint range.
_JOINER_SCRIPTS = frozenset({
    "DEVANAGARI", "BENGALI", "GURMUKHI", "GUJARATI", "ORIYA", "TAMIL",
    "TELUGU", "KANNADA", "MALAYALAM", "SINHALA",
    "ARABIC", "SYRIAC", "THAANA", "NKO", "HEBREW",
    "MYANMAR", "KHMER", "TIBETAN", "MONGOLIAN", "JAVANESE", "BALINESE",
})


def _script_of(char: str) -> Optional[str]:
    """The script name `unicodedata` gives a letter, or None if it is not one."""
    if not char.isalpha():
        return None
    try:
        name = unicodedata.name(char)
    except ValueError:
        return None
    return name.split()[0]


def _is_emoji(char: str) -> bool:
    """Close enough for the ZWJ case: a pictographic or regional-indicator code point.

    `unicodedata` exposes no Emoji property, so this is a range test over the
    blocks a ZWJ sequence actually draws from. It decides only whether a joiner
    between two of them is ordinary, never whether anything is a finding.
    """
    cp = ord(char)
    return (
        0x1F300 <= cp <= 0x1FAFF      # pictographs, symbols, emoji extensions
        or 0x1F000 <= cp <= 0x1F0FF   # mahjong/domino/cards
        or 0x2600 <= cp <= 0x27BF     # misc symbols and dingbats
        or 0x1F1E6 <= cp <= 0x1F1FF   # regional indicators (flags)
        or cp in {0x2640, 0x2642, 0x2695, 0x2708, 0x2764, 0xFE0F}
    )


def _zero_width_is_expected(text: str, index: int, at_file_start: bool = False) -> bool:
    """True when the zero-width char at `index` is doing ordinary work.

    Exemptions, and nothing wider:

    * U+FEFF at offset 0 **of the file** — an encoding marker, not content.
      `at_file_start` is passed in rather than derived from `index`, because
      `index` is an offset into one line and a BOM at the start of line five is
      not an encoding marker.
    * U+200C / U+200D between two letters of the SAME joiner-using script.
      Requiring one script is what keeps the exemption from covering a joiner
      spliced between two alphabets, which is a way to hide a word boundary.
    * U+200D between two emoji — one composed glyph.
    """
    char = text[index]
    if char == "\ufeff":
        return at_file_start
    if char not in _CONTEXTUAL_ZERO_WIDTH:
        return False
    if index == 0 or index + 1 >= len(text):
        return False
    before, after = text[index - 1], text[index + 1]

    left, right = _script_of(before), _script_of(after)
    if left is not None and left == right and left in _JOINER_SCRIPTS:
        return True

    if char == "\u200d" and _is_emoji(before) and _is_emoji(after):
        return True
    return False


def _find_agent_config_files(project_root: Path) -> list[Path]:
    """Locate agent configuration / instruction files in the project."""
    found: list[Path] = []
    for rel in _AGENT_CONFIG_FILES:
        p = project_root / rel
        if p.is_file():
            found.append(p)
    return found


def _line_at(content: str, offset: int) -> int:
    """1-based line of the character at ``offset``, counted as ``str.splitlines`` counts.

    Findings used to locate their line by searching the file for their own
    evidence, which always lands on the first occurrence: the second copy of a
    repeated URL or directive pointed at the first, an earlier line that merely
    contained the evidence as a substring took the finding, and every HTML
    comment, searched for as the literal "<!--", carried the first comment's
    line. A regex match already knows where it is.

    Counting as ``splitlines`` does keeps these numbers identical to
    ``find_line_number`` and to the zero-width walk wherever the evidence is not
    repeated. ``"a\\n".splitlines()`` is one line although offset 2 opens line 2,
    so a sentinel character keeps that line counted.
    """
    return len((content[:offset] + "\0").splitlines())


def _check_content(
    content: str,
    rel_path: str,
) -> list[Finding]:
    """Run all six rules against the text content of a single file."""
    findings: list[Finding] = []

    # AAK-AGENT-001: Shell directives
    for match in _SHELL_DIRECTIVE_RE.finditer(content):
        evidence = match.group().strip()
        findings.append(make_finding(
            "AAK-AGENT-001",
            rel_path,
            f"Shell directive: {evidence[:120]}",
            _line_at(content, match.start()),
        ))

    # AAK-AGENT-006: a link the text tells the agent to act on. HIGH, and
    # reported before 002 so the directive is what a reader sees first.
    directive_urls: set[str] = set()
    for line_num, evidence, url in _directive_links(content):
        directive_urls.add(url)
        findings.append(make_finding(
            "AAK-AGENT-006",
            rel_path,
            f"Directive on an external URL: {evidence[:200]}",
            line_num,
        ))

    # AAK-AGENT-002: a link to a host outside the documentation allowlist. LOW —
    # it is something to look at, not something that has happened. A URL already
    # reported by 006 is not repeated here: the directive is the finding, and
    # naming the same link twice at two severities reads as two problems.
    for match in _URL_RE.finditer(content):
        url = match.group()
        if url in directive_urls:
            continue
        if not _is_safe_host(url):
            findings.append(make_finding(
                "AAK-AGENT-002",
                rel_path,
                f"External URL: {url[:200]}",
                _line_at(content, match.start()),
            ))

    # AAK-AGENT-003: Security override patterns
    for match in _SECURITY_OVERRIDE_RE.finditer(content):
        evidence = match.group().strip()
        findings.append(make_finding(
            "AAK-AGENT-003",
            rel_path,
            f"Security override: {evidence}",
            _line_at(content, match.start()),
        ))

    # AAK-AGENT-004: Credential patterns
    for match in _CREDENTIAL_RE.finditer(content):
        evidence = match.group().strip()
        findings.append(make_finding(
            "AAK-AGENT-004",
            rel_path,
            f"Credential reference: {evidence}",
            _line_at(content, match.start()),
        ))

    # AAK-AGENT-005: Hidden content
    # HTML comments
    for match in _HTML_COMMENT_RE.finditer(content):
        comment = match.group()
        if _TOOL_MARKER_RE.fullmatch(comment):
            continue
        findings.append(make_finding(
            "AAK-AGENT-005",
            rel_path,
            f"HTML comment: {comment[:120]}{'...' if len(comment) > 120 else ''}",
            _line_at(content, match.start()),
        ))

    # Link reference definitions used as comments: `[//]: # (text)`.
    for match in _REFDEF_COMMENT_RE.finditer(content):
        title = next(g for g in match.group("p", "d", "s") if g is not None)
        if not title.strip():
            continue
        line = match.group().strip()
        findings.append(make_finding(
            "AAK-AGENT-005",
            rel_path,
            f"Markdown comment: {line[:120]}{'...' if len(line) > 120 else ''}",
            _line_at(content, match.start()),
        ))

    # Zero-width / invisible Unicode characters.
    #
    # Walked per OCCURRENCE rather than per line, because the decision needs the
    # neighbours: the same code point is spelling in one position and concealment
    # in another. The old loop asked only whether the character appeared anywhere
    # on the line, which cannot tell those apart and reported every Devanagari
    # conjunct, every Persian ZWNJ, every emoji ZWJ sequence and every file with
    # a BOM. Still one finding per line, so a paragraph of Hindi with one spliced
    # joiner reports once.
    for line_num, line in enumerate(content.splitlines(), 1):
        for index, char in enumerate(line):
            if char not in _ZERO_WIDTH_CHARS:
                continue
            # Offset 0 of line 1 is the only position that is offset 0 of the file.
            at_file_start = line_num == 1 and index == 0
            if _zero_width_is_expected(line, index, at_file_start):
                continue
            codepoint = f"U+{ord(char):04X}"
            findings.append(make_finding(
                "AAK-AGENT-005",
                rel_path,
                f"Hidden Unicode character {codepoint} found",
                line_num,
            ))
            break  # one finding per line is sufficient

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan agent configuration files for security issues.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for config_path in _find_agent_config_files(project_root):
        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
            if len(content) > 1_000_000:
                continue
        except OSError:
            continue

        rel_path = str(config_path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.extend(_check_content(content, rel_path))

    # AAK-CLAUDE-WIN-001: CVE-2026-35603 Windows ProgramData hijack.
    # Fires when a managed-settings.json lives under a ProgramData path
    # without a sibling setup.ps1 that runs icacls hardening.
    findings.extend(_check_claude_win_programdata(project_root, scanned_files))

    return findings, scanned_files


def _check_claude_win_programdata(
    project_root: Path,
    scanned_files: set[str],
) -> list[Finding]:
    """CVE-2026-35603: managed-settings.json under %ProgramData% needs
    a sibling setup.ps1 that runs `icacls` to harden the ACL. Fires on
    any `managed-settings.json` whose path contains `programdata`
    (case-insensitive) and whose directory lacks the hardening script."""
    import re as _re

    findings: list[Finding] = []
    for candidate in project_root.rglob("managed-settings.json"):
        path_lower = str(candidate).lower()
        if "programdata" not in path_lower:
            continue
        rel = str(candidate.relative_to(project_root))
        scanned_files.add(rel)
        sibling = candidate.parent / "setup.ps1"
        if not sibling.is_file():
            findings.append(make_finding(
                "AAK-CLAUDE-WIN-001",
                rel,
                "managed-settings.json under ProgramData without sibling setup.ps1 ACL hardener",
            ))
            continue
        try:
            ps1_text = sibling.read_text(encoding="utf-8", errors="replace")
        except OSError:
            ps1_text = ""
        if not _re.search(r"\bicacls\b", ps1_text, _re.IGNORECASE):
            findings.append(make_finding(
                "AAK-CLAUDE-WIN-001",
                rel,
                f"setup.ps1 next to {rel} does not run icacls to restrict ACLs",
            ))
    return findings
