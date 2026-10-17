"""Neo4j Cypher MCP read-only bypass scanner (AAK-NEO4J-001).

Two detections:
    1. Version-pin check — mcp-neo4j-cypher < 0.6.0 in the root
       requirements files and pyproject.toml. The server is a PyPI package,
       so package.json is not read.
    2. Code pattern — `read_only=True` combined with any `CALL apoc.*`
       or `db.cypher.runWrite` reference in the same file.

The pin used to take the first number after the name, from a pattern with no
place for extras, and this docstring promised pyproject.toml while only four
requirements files were opened, so `mcp-neo4j-cypher<0.6.0`, which admits only
affected releases, `mcp-neo4j-cypher[all]==0.5.0` and any pyproject.toml were
silent. A manifest is now read as the CVE pin table reads it
(`_dependency_pins`), and a range is reported when it admits an affected
release.

References:
- CVE-2026-35402: https://nvd.nist.gov/vuln/detail/CVE-2026-35402
- Fix: upgrade to 0.6.0+.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._dependency_pins import (
    DependencyPin,
    Manifest,
    pinned_dependency,
    read_manifest,
    read_text,
)
from agent_audit_kit.scanners._helpers import (
    find_line_number,
    in_skip_dir,
    make_finding,
)


# A stated version only: the old pattern needed one, so an unpinned line was
# never reported.
_PIN = DependencyPin(("mcp-neo4j-cypher",), (0, 6, 0), ecosystem="py")

_MANIFEST_NAMES = (
    "requirements.txt", "requirements-dev.txt", "requirements-prod.txt", "dev-requirements.txt",
    "pyproject.toml",
)

_APOC_CALL_RE = re.compile(r"CALL\s+apoc\.", re.IGNORECASE)
_RUNWRITE_RE = re.compile(r"\bdb\.cypher\.runWrite\b|\brun_write\b")
_READ_ONLY_RE = re.compile(r"read_only\s*=\s*True")


def _check_manifest(manifest: Manifest, rel: str) -> list[Finding]:
    hit = pinned_dependency(manifest, _PIN)
    if hit is None:
        return []
    return [make_finding(
        "AAK-NEO4J-001",
        rel,
        f"mcp-neo4j-cypher referenced as {hit.quoted} — CVE-2026-35402 patched in 0.6.0",
        line_number=hit.line,
    )]


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

    # The root requirements files and pyproject.toml
    for name in _MANIFEST_NAMES:
        p = project_root / name
        if p.is_file():
            rel = str(p.relative_to(project_root))
            scanned.add(rel)
            manifest = read_manifest(p)
            if manifest is not None:
                findings.extend(_check_manifest(manifest, rel))

    # Python source: read_only=True + apoc. patterns
    for py in project_root.rglob("*.py"):
        if in_skip_dir(py, project_root):
            continue
        try:
            if py.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        rel = str(py.relative_to(project_root))
        scanned.add(rel)
        text = read_text(py, 512_000)
        if text is None:
            continue
        if "neo4j" in text.lower() or "apoc" in text.lower():
            findings.extend(_check_python_source(text, rel))

    return findings, scanned
