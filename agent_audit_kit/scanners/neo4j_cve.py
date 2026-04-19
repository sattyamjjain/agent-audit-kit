"""Neo4j Cypher MCP read-only bypass scanner (AAK-NEO4J-001).

Two detections:
    1. Version-pin check — mcp-neo4j-cypher < 0.6.0 in requirements.txt
       / pyproject.toml / package.json.
    2. Code pattern — `read_only=True` combined with any `CALL apoc.*`
       or `db.cypher.runWrite` reference in the same file.

References:
- CVE-2026-35402: https://nvd.nist.gov/vuln/detail/CVE-2026-35402
- Fix: upgrade to 0.6.0+.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_REQ_PIN_RE = re.compile(
    r"""^\s*(mcp-neo4j-cypher)\s*(?:==|>=|<=|<|>|~=|!=)?\s*([0-9][0-9a-zA-Z.\-_]*)""",
    re.MULTILINE,
)

_PACKAGE_LOCKFILE_NAMES = ("requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "dev-requirements.txt")

_APOC_CALL_RE = re.compile(r"CALL\s+apoc\.", re.IGNORECASE)
_RUNWRITE_RE = re.compile(r"\bdb\.cypher\.runWrite\b|\brun_write\b")
_READ_ONLY_RE = re.compile(r"read_only\s*=\s*True")


def _parse_version(spec: str) -> tuple[int, int, int] | None:
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", spec)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _check_requirements_file(path: Path, text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _REQ_PIN_RE.finditer(text):
        version = _parse_version(match.group(2))
        if version is None:
            continue
        if version < (0, 6, 0):
            findings.append(
                make_finding(
                    "AAK-NEO4J-001",
                    rel,
                    f"mcp-neo4j-cypher pinned at {match.group(2)} — CVE-2026-35402 patched in 0.6.0",
                    line_number=find_line_number(text, match.group(0)),
                )
            )
    return findings


def _check_python_source(text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    if _READ_ONLY_RE.search(text) and (_APOC_CALL_RE.search(text) or _RUNWRITE_RE.search(text)):
        hit = _APOC_CALL_RE.search(text) or _RUNWRITE_RE.search(text)
        findings.append(
            make_finding(
                "AAK-NEO4J-001",
                rel,
                "read_only=True combined with APOC / runWrite call — CVE-2026-35402 bypass class",
                line_number=find_line_number(text, hit.group(0)) if hit else None,
            )
        )
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()

    # Requirements files + pyproject + package.json
    for name in _PACKAGE_LOCKFILE_NAMES:
        p = project_root / name
        if p.is_file():
            rel = str(p.relative_to(project_root))
            scanned.add(rel)
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(_check_requirements_file(p, text, rel))

    # Python source: read_only=True + apoc. patterns
    for py in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in py.parts):
            continue
        try:
            if py.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        rel = str(py.relative_to(project_root))
        scanned.add(rel)
        try:
            text = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "neo4j" in text.lower() or "apoc" in text.lower():
            findings.extend(_check_python_source(text, rel))

    return findings, scanned
