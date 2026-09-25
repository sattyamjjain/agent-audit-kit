from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Optional

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding

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

# ---- AAK-AGENT-002: External URLs (exclude safe domains) ----
_URL_RE = re.compile(r"https?://[^\s\)>\]\"']+", re.IGNORECASE)
_SAFE_URL_DOMAINS = re.compile(
    r"https?://(github\.com|docs\.|"
    r"developer\.|"
    r"stackoverflow\.com|"
    r"wikipedia\.org|"
    r"npmjs\.com|"
    r"pypi\.org|"
    r"crates\.io|"
    r"registry\.npmjs\.org|"
    r"gitlab\.com|"
    r"bitbucket\.org|"
    r"readthedocs\.io|"
    r"readthedocs\.org|"
    r"shields\.io|"
    r"img\.shields\.io|"
    r"badge\.fury\.io|"
    r"travis-ci\.org|"
    r"circleci\.com|"
    r"codecov\.io|"
    r"coveralls\.io|"
    r"mozilla\.org|"
    r"w3\.org|"
    r"json-schema\.org|"
    r"schema\.org|"
    r"creativecommons\.org|"
    r"opensource\.org|"
    r"spdx\.org|"
    r"example\.com)",
    re.IGNORECASE,
)

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


def _check_content(
    content: str,
    rel_path: str,
) -> list[Finding]:
    """Run all five rules against the text content of a single file."""
    findings: list[Finding] = []

    # AAK-AGENT-001: Shell directives
    for match in _SHELL_DIRECTIVE_RE.finditer(content):
        evidence = match.group().strip()
        findings.append(make_finding(
            "AAK-AGENT-001",
            rel_path,
            f"Shell directive: {evidence[:120]}",
            find_line_number(content, evidence[:40]),
        ))

    # AAK-AGENT-002: External URLs (excluding safe domains)
    for match in _URL_RE.finditer(content):
        url = match.group()
        if not _SAFE_URL_DOMAINS.match(url):
            findings.append(make_finding(
                "AAK-AGENT-002",
                rel_path,
                f"External URL: {url[:200]}",
                find_line_number(content, url[:60]),
            ))

    # AAK-AGENT-003: Security override patterns
    for match in _SECURITY_OVERRIDE_RE.finditer(content):
        evidence = match.group().strip()
        findings.append(make_finding(
            "AAK-AGENT-003",
            rel_path,
            f"Security override: {evidence}",
            find_line_number(content, evidence),
        ))

    # AAK-AGENT-004: Credential patterns
    for match in _CREDENTIAL_RE.finditer(content):
        evidence = match.group().strip()
        findings.append(make_finding(
            "AAK-AGENT-004",
            rel_path,
            f"Credential reference: {evidence}",
            find_line_number(content, evidence),
        ))

    # AAK-AGENT-005: Hidden content
    # HTML comments
    for match in _HTML_COMMENT_RE.finditer(content):
        comment = match.group()
        findings.append(make_finding(
            "AAK-AGENT-005",
            rel_path,
            f"HTML comment: {comment[:120]}{'...' if len(comment) > 120 else ''}",
            find_line_number(content, "<!--"),
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
