"""LangChain-specific vulnerability scanner.

Fires AAK-LANGCHAIN-001..003. AAK-LANGCHAIN-001 and -003 are version pins on
`langchain-core`, the PyPI distribution both advisories name: CVE-2026-34070
(load_prompt path traversal, fixed in 1.2.22) and CVE-2025-68664
(serialization injection). They read Python manifests only, the requirements
files below and every pyproject.toml, and match that one distribution name in
any PEP 503 spelling. AAK-LANGCHAIN-002 pattern-matches load_prompt() calls with
user-controlled paths in source code.

The pins used to take the first number after the name from a pattern anchored
at the start of a requirement line, so `langchain-core<1.2.22`, which admits
only affected releases, read as the fix and was silent, and no pyproject.toml
ever matched: a TOML string starts with a quote. A manifest is now read as the
CVE pin table reads it (`_dependency_pins`), and a range is reported when it
admits an affected release.

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


_REQUIREMENTS_NAMES = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "dev-requirements.txt",
)

# Both read only a stated version: the old pattern needed one, and an unpinned
# `langchain-core` installs a release above both floors.
_PATH_TRAVERSAL = DependencyPin(("langchain-core",), (1, 2, 22), ecosystem="py")
_DESERIALIZE = DependencyPin(("langchain-core",), (0, 3, 14), ecosystem="py")

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
        if in_skip_dir(toml, project_root):
            continue
        out.append(toml)
    return out


def _iter_python_sources(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for py in project_root.rglob("*.py"):
        if in_skip_dir(py, project_root):
            continue
        try:
            if py.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        out.append(py)
    return out


def _check_manifest(manifest: Manifest, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, pin, tail in (
        ("AAK-LANGCHAIN-001", _PATH_TRAVERSAL, "CVE-2026-34070 patched in 1.2.22"),
        ("AAK-LANGCHAIN-003", _DESERIALIZE, "CVE-2025-68664 deserialization fix in 0.3.14+"),
    ):
        hit = pinned_dependency(manifest, pin)
        if hit is not None:
            findings.append(make_finding(
                rule_id, rel, f"langchain-core referenced as {hit.quoted} — {tail}", line_number=hit.line,
            ))
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
    for path in _iter_manifest_files(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        manifest = read_manifest(path)
        if manifest is not None:
            findings.extend(_check_manifest(manifest, rel))
    for py in _iter_python_sources(project_root):
        rel = str(py.relative_to(project_root))
        scanned.add(rel)
        text = read_text(py, 512_000)
        if text is None:
            continue
        if "langchain" in text.lower():
            findings.extend(_check_python_source(text, rel))
    return findings, scanned
