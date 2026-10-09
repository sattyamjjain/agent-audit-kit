"""LangChain-specific vulnerability scanner.

Fires AAK-LANGCHAIN-001..003. AAK-LANGCHAIN-001 and -003 are version pins on
`langchain-core`, the PyPI distribution both advisories name: CVE-2026-34070
(load_prompt path traversal, fixed in 1.2.22) and CVE-2025-68664
(serialization injection). They read Python manifests only, the requirements
files below and pyproject.toml, and match that one distribution name in any
PEP 503 spelling. AAK-LANGCHAIN-002 pattern-matches load_prompt() calls with
user-controlled paths in source code.

Both pins used to read package.json as well, and compared any npm dependency
whose name contained "langchain" against these Python floors. Neither advisory
names an npm package, and npm's `@langchain/*` integrations have version lines
of their own, so `@langchain/redis` 1.1.1, a fixed release, got a HIGH that no
upgrade could clear (found while measuring #918). The umbrella `langchain` and
`langchain-community` distributions were compared with langchain-core's floors
the same way, and are not read either: their version numbers are not
langchain-core's.

References:
- https://nvd.nist.gov/vuln/detail/CVE-2026-34070
- https://nvd.nist.gov/vuln/detail/CVE-2025-68664
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_REQUIREMENTS_NAMES = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "dev-requirements.txt",
)

_LANGCHAIN_PATH_TRAVERSAL_PATCHED = (1, 2, 22)
_LANGCHAIN_DESERIALIZE_PATCHED = (0, 3, 14)


def _parse_version(spec: str) -> tuple[int, int, int] | None:
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", spec)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _version_lt(a: tuple[int, int, int], b: tuple[int, int, int]) -> bool:
    return a < b


# `langchain-core` as PEP 503 normalises it: any run of `-`, `_` or `.` between
# the two words, in any case, and an optional extras bracket. Anchored at the
# start of a requirement line, with the version straight after the name, so
# `langchain-community` or a longer name that starts with `langchain-core` is
# never read as it.
_REQ_PIN_RE = re.compile(
    r"""^\s*(langchain[-_.]+core)\s*(?:\[[^\]\n]*\])?\s*(?:==|>=|<=|<|>|~=|!=)?\s*([0-9][0-9a-zA-Z.\-_]*)""",
    re.MULTILINE | re.IGNORECASE,
)

_LOAD_PROMPT_RE = re.compile(
    r"\bload_prompt(?:_from_config)?\s*\(\s*(?:f?['\"][^'\"]*\{[^}]*\}[^'\"]*['\"]|[a-zA-Z_][\w\.]*)\s*[,)]",
)


def _iter_manifest_files(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for name in _REQUIREMENTS_NAMES:
        p = project_root / name
        if p.is_file():
            out.append(p)
    for toml in project_root.rglob("pyproject.toml"):
        if any(part in SKIP_DIRS for part in toml.parts):
            continue
        out.append(toml)
    return out


def _iter_python_sources(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for py in project_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in py.parts):
            continue
        try:
            if py.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        out.append(py)
    return out


def _check_requirements_text(text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _REQ_PIN_RE.finditer(text):
        name = match.group(1).lower()
        version = _parse_version(match.group(2))
        if version is None:
            continue
        if _version_lt(version, _LANGCHAIN_PATH_TRAVERSAL_PATCHED):
            findings.append(
                make_finding(
                    "AAK-LANGCHAIN-001",
                    rel,
                    f"{name} pinned at {match.group(2)} — CVE-2026-34070 patched in 1.2.22",
                    line_number=find_line_number(text, match.group(0)),
                )
            )
        if _version_lt(version, _LANGCHAIN_DESERIALIZE_PATCHED):
            findings.append(
                make_finding(
                    "AAK-LANGCHAIN-003",
                    rel,
                    f"{name} pinned at {match.group(2)} — CVE-2025-68664 deserialization fix in 0.3.14+",
                    line_number=find_line_number(text, match.group(0)),
                )
            )
    return findings


def _check_python_source(text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    m = _LOAD_PROMPT_RE.search(text)
    if m:
        findings.append(
            make_finding(
                "AAK-LANGCHAIN-002",
                rel,
                f"load_prompt() call with dynamic path: {m.group(0)!r}",
                line_number=find_line_number(text, m.group(0)),
            )
        )
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for manifest in _iter_manifest_files(project_root):
        rel = str(manifest.relative_to(project_root))
        scanned.add(rel)
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_check_requirements_text(text, rel))
    for py in _iter_python_sources(project_root):
        rel = str(py.relative_to(project_root))
        scanned.add(rel)
        try:
            text = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "langchain" in text.lower():
            findings.extend(_check_python_source(text, rel))
    return findings, scanned
