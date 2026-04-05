from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

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
_SHELL_DIRECTIVE_RE = re.compile(
    r"sh\s+-c\s|bash\s+-c\s|"
    r"`[^`]+`|"
    r"\bos\.system\s*\(|"
    r"\bsubprocess\b|"
    r"\bexec\s*\(|"
    r"\beval\s*\(|"
    r"\brm\s+-rf\b",
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

    # Zero-width / invisible Unicode characters
    for line_num, line in enumerate(content.splitlines(), 1):
        for char in _ZERO_WIDTH_CHARS:
            if char in line:
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

    return findings, scanned_files
