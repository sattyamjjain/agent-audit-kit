"""JVM MCP SDK version pins — Gradle and Maven manifests.

`mcp_cve_pins_2026_07` is the repository's pin table, and it deliberately cannot
read this ecosystem: its `_CANDIDATE_NAMES` covers Python and npm manifests only,
and its own docstring records the consequence — the crates.io twin of `codewhale`
"has the same defect but Cargo manifests are not in _CANDIDATE_NAMES, so it is
out of this detector's reach", and "ArcadeDB on Maven" is listed among the CVEs
handled elsewhere. Widening that table would put ~60 unrelated package regexes to
work against `pom.xml` and `build.gradle`, which is a lot of new false-positive
surface for one CVE. This module is the narrower answer: JVM manifests only, and
only for MCP SDK coordinates.

First entry: **CVE-2026-53937** (MEDIUM 6.2, CWE-400 + CWE-770). MCP Kotlin SDK
0.7.0–0.12.0 appends every stdio chunk into a `kotlinx.io.Buffer` with no size
cap, and only extracts a frame when it sees `\\n` — so a peer that never sends a
newline grows the buffer until the JVM is OOM-killed. Fixed in 0.13.0.

Version resolution is the actual work here, because a JVM coordinate rarely
carries its version inline any more. Four forms, all seen in the wild:

  * Gradle Groovy   `implementation 'io.modelcontextprotocol:kotlin-sdk:0.12.0'`
  * Gradle KTS      `implementation("io.modelcontextprotocol:kotlin-sdk:$mcpVer")`
                    resolved against `val mcpVer = "0.12.0"` in the same file
  * Version catalog `gradle/libs.versions.toml` — `module = "…:kotlin-sdk"` plus
                    `version.ref = "mcp"`, resolved against `[versions] mcp = …`
  * Maven           `<groupId>/<artifactId>/<version>`, with `${mcp.version}`
                    resolved against `<properties>`

Three artifact names publish the same code — `kotlin-sdk`, `kotlin-sdk-core` and
`kotlin-sdk-jvm` (Gradle resolves the `-jvm` variant from the plain name). All
three are matched and a file reports **once**, because a multiplatform project
that names two of them has one dependency, not two.

Conservative by construction: a finding requires a version that actually resolved
into the affected range. A dynamic version (`0.+`, `latest.release`) or a
`version.ref` pointing at a catalog this scanner cannot see is not reported —
that is a different finding and this rule does not pretend to make it.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, make_finding

RULE_ID = "AAK-MCP-STDIO-UNBOUNDED-BUFFER-001"

_GROUP = "io.modelcontextprotocol"
# `kotlin-sdk-core` is where ReadBuffer.kt lives; `kotlin-sdk` and `kotlin-sdk-jvm`
# pull it in. Matching all three is why a file reports once rather than per-name.
_ARTIFACTS = ("kotlin-sdk-core", "kotlin-sdk-jvm", "kotlin-sdk")

_INTRODUCED = (0, 7, 0)   # first release of kotlin-sdk-core; NVD's range start
_FIXED = (0, 13, 0)       # vendor fix

_GRADLE_FILES = ("build.gradle", "build.gradle.kts")
_CATALOG_REL = ("gradle/libs.versions.toml", "libs.versions.toml")
_MAVEN_FILES = ("pom.xml",)
_MAX_FILE_BYTES = 2_000_000

_VER_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")
# `implementation "io.modelcontextprotocol:kotlin-sdk:0.12.0"` and the $var form.
_COORD_RE = re.compile(
    r"""["']""" + re.escape(_GROUP) + r":(" + "|".join(_ARTIFACTS) + r")"
    r"""(?::\$?\{?([\w.\-]+)\}?)?["']""",
)
# `val mcpVersion = "0.12.0"` / `mcpVersion = '0.12.0'` / `ext.mcp = "0.12.0"`
_ASSIGN_RE = re.compile(r"""(?:val|var|def|ext\.)?\s*([\w.]+)\s*=\s*["']v?([\d][\w.\-]*)["']""")
# Version catalog entries are one line each, so they are parsed per line rather
# than with a single regex. The first attempt used one pattern with an optional
# trailing version group and a lazy `[^\n]*?` between; that matches happily with
# the group empty -- laziness prefers the shortest match -- so every catalog
# resolved to "no version" and the arm silently never fired. Splitting the
# coordinate match from the version match removes the ambiguity.
_CATALOG_COORD_RE = re.compile(
    r"""["']""" + re.escape(_GROUP) + r":(" + "|".join(_ARTIFACTS) + r")[\"']",
)
_CATALOG_NAME_RE = re.compile(
    r"""name\s*=\s*["'](""" + "|".join(_ARTIFACTS) + r""")["']""",
)
_CATALOG_GROUP_RE = re.compile(r"""group\s*=\s*["']""" + re.escape(_GROUP) + r"""["']""")
_VERSION_REF_RE = re.compile(r"""version\.ref\s*=\s*["']([\w.\-]+)["']""")
_VERSION_LIT_RE = re.compile(r"""version\s*=\s*["']v?([\d][\w.\-]*)["']""")
_MAVEN_DEP_RE = re.compile(
    r"<groupId>\s*" + re.escape(_GROUP) + r"\s*</groupId>\s*"
    r"<artifactId>\s*(" + "|".join(_ARTIFACTS) + r")\s*</artifactId>\s*"
    r"(?:<version>\s*\$?\{?([\w.\-]+)\}?\s*</version>)?",
    re.DOTALL,
)
_MAVEN_PROP_RE = re.compile(r"<([\w.\-]+)>\s*v?([\d][\w.\-]*)\s*</\1>")


def _semver(raw: str | None) -> tuple[int, int, int] | None:
    if not raw:
        return None
    m = _VER_RE.match(raw)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _affected(v: tuple[int, int, int] | None) -> bool:
    return v is not None and _INTRODUCED <= v < _FIXED


def _resolve(token: str | None, table: dict[str, str]) -> tuple[int, int, int] | None:
    """A version token is either a literal or a name to look up."""
    if not token:
        return None
    direct = _semver(token)
    if direct is not None:
        return direct
    # `$mcpVersion` / `${mcp.version}` / a catalog version.ref
    for key in (token, token.split(".")[-1]):
        if key in table:
            return _semver(table[key])
    return None


def _versions_table(text: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in _ASSIGN_RE.finditer(text)}


def _maven_props(text: str) -> dict[str, str]:
    block = re.search(r"<properties>(.*?)</properties>", text, re.DOTALL)
    if not block:
        return {}
    return {m.group(1): m.group(2) for m in _MAVEN_PROP_RE.finditer(block.group(1))}


def _line_of(text: str, needle: str) -> int | None:
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return None


def _analyze(text: str, kind: str) -> tuple[str, tuple[int, int, int]] | None:
    """(artifact, resolved version) for the first affected coordinate, else None."""
    if _GROUP not in text:
        return None
    if kind == "maven":
        table = _maven_props(text)
        for m in _MAVEN_DEP_RE.finditer(text):
            v = _resolve(m.group(2), table)
            if v is not None and _affected(v):
                return m.group(1), v
        return None

    table = _versions_table(text)
    if kind == "catalog":
        for line in text.splitlines():
            coord: re.Match[str] | None = _CATALOG_COORD_RE.search(line)
            if coord is None and _CATALOG_GROUP_RE.search(line):
                coord = _CATALOG_NAME_RE.search(line)
            if coord is None:
                continue
            ref = _VERSION_REF_RE.search(line)
            lit = _VERSION_LIT_RE.search(line)
            token = ref.group(1) if ref else (lit.group(1) if lit else None)
            v = _resolve(token, table)
            if v is not None and _affected(v):
                return coord.group(1), v
        return None

    for m in _COORD_RE.finditer(text):
        v = _resolve(m.group(2), table)
        if v is not None and _affected(v):
            return m.group(1), v
    return None


def _candidates(project_root: Path) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for name in _GRADLE_FILES:
        for p in project_root.rglob(name):
            if any(part in SKIP_DIRS for part in p.parts) or p in seen:
                continue
            seen.add(p)
            out.append((p, "gradle"))
    for rel in _CATALOG_REL:
        for p in project_root.rglob(Path(rel).name):
            if any(part in SKIP_DIRS for part in p.parts) or p in seen:
                continue
            seen.add(p)
            out.append((p, "catalog"))
    for name in _MAVEN_FILES:
        for p in project_root.rglob(name):
            if any(part in SKIP_DIRS for part in p.parts) or p in seen:
                continue
            seen.add(p)
            out.append((p, "maven"))
    return out


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path, kind in _candidates(project_root):
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        hit = _analyze(text, kind)
        if hit is None:
            continue
        artifact, version = hit
        shown = ".".join(str(x) for x in version)
        rel = str(path.relative_to(project_root))
        findings.append(make_finding(
            RULE_ID,
            rel,
            f"`{_GROUP}:{artifact}` resolves to {shown} in {path.name} — the MCP "
            f"Kotlin SDK stdio read buffer grows without bound until a newline "
            f"arrives (CVE-2026-53937). Affected 0.7.0–0.12.0; fixed in 0.13.0.",
            _line_of(text, artifact),
        ))
        scanned.add(rel)
    return findings, scanned
