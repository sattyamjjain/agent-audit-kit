"""Scanner for poisoned Claude Code / Claude Agent SDK `SKILL.md` files.

Fires AAK-SKILL-001..005:
- 001 post-install / side-effect command embedded in SKILL.md
- 002 unicode steganography (bidi, zero-width, tag-unicode)
- 003 data-exfiltration primitive (outbound HTTP + local-data reference)
- 004 description hijacks a trusted first-party skill name
- 005 prompt-injection trigger in frontmatter

Patterns are based on the Snyk ToxicSkills dataset (1,467 malicious
payloads, 2026) and the Anthropic first-party skill directory.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


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

_POST_INSTALL_RE = re.compile(
    r"(?:^|\n)\s*(?:curl\s+[^\n]*\|\s*sh|wget\s+[^\n]*\|\s*sh|"
    r"npm\s+install\s+-g|pip\s+install\s+--user|"
    r"bash\s+-c|sh\s+-c|eval\s*\()",
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
_LOCAL_DATA_RE = re.compile(
    r"\b(?:process\.env|os\.environ|~/\.ssh|\.aws/credentials|\.netrc|"
    r"id_rsa|id_ed25519|\$HOME|~\/|read(?:Text|File))\b",
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


def _iter_skill_files(project_root: Path) -> list[Path]:
    results: list[Path] = []
    for path in project_root.rglob("SKILL.md"):
        if any(part in SKIP_DIRS for part in path.parts):
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

    m = _POST_INSTALL_RE.search(raw)
    if m:
        findings.append(
            make_finding(
                "AAK-SKILL-001",
                rel,
                f"Post-install command detected: {m.group(0).strip()!r}",
                line_number=find_line_number(raw, m.group(0).strip().splitlines()[0]),
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

    lowered = raw.lower()
    fm_boundary = raw.find("---", 3)
    fm_slice = lowered[: fm_boundary if fm_boundary > 0 else 500]
    for trigger in _INJECTION_TRIGGERS:
        if trigger in fm_slice:
            findings.append(
                make_finding(
                    "AAK-SKILL-005",
                    rel,
                    f"Prompt-injection trigger in frontmatter: {trigger!r}",
                    line_number=find_line_number(raw, trigger),
                )
            )
            break

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
