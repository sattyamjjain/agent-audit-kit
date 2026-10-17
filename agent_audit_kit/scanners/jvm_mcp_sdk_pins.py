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

Second entry: **CVE-2026-108714** (HIGH 7.5, CWE-770). From 0.7.3 the server
module adds `Application.mcpWebSocket`, which installs Ktor `WebSockets` with no
`maxFrameSize`, so Ktor's default (`Long.MAX_VALUE`) lets a client declare a frame
near 2 GiB and force the allocation. Checked on Maven Central and in the source:
the extension is absent at 0.7.2 and present from 0.7.3 to 0.15.0, the newest
release, and nothing on `main` sets a limit, so there is no fixed release. It
lives in `kotlin-sdk-server`, which the `kotlin-sdk` umbrella pulls in, so it
matches `kotlin-sdk-server`, `kotlin-sdk` and their `-jvm` variants, and not
`kotlin-sdk-core` or `kotlin-sdk-client`, which do not carry it. Each pin reports
once per file, and the pins report independently.

Third entry, and the first from the Java SDK: **CVE-2026-108395** (HIGH 7.5,
CWE-770). The Servlet SSE, Streamable HTTP and Stateless server transports read a
POST body into a `StringBuilder` with no size limit. The Java SDK publishes under
its own group, `io.modelcontextprotocol.sdk`, so a pin names its group. The code
is in `mcp` from 0.8.0 to 0.12.1 and in `mcp-core` from 0.13.0, and the `mcp`
bundle depends on `mcp-core` at its own version, so both names are matched. The
fix shipped on three lines (0.18.4, 1.1.4, 2.0.1), so a pin holds a range per
line: 0.18.4 does not fix 1.0.0. The SDK's quickstart declares `mcp` with no
version and imports `mcp-bom` instead, so a pin may name a BOM, and a versionless
artifact then takes the BOM's version from the same file. Other BOMs (Spring AI's)
are not read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from agent_audit_kit.models import Finding

from ._helpers import in_skip_dir, make_finding, read_text_capped

_Ver = tuple[int, int, int]

RULE_ID = "AAK-MCP-STDIO-UNBOUNDED-BUFFER-001"
WS_RULE_ID = "AAK-MCP-KOTLINSDK-CVE-2026-108714-001"
JAVA_BODY_RULE_ID = "AAK-MCP-JAVASDK-CVE-2026-108395-001"

# The Kotlin SDK's group, and the prefix every pin's group starts with.
_GROUP = "io.modelcontextprotocol"


@dataclass(frozen=True)
class _JvmPin:
    rule_id: str
    # Longest name first, so an alternation never stops at a prefix.
    artifacts: tuple[str, ...]
    # One [introduced, fixed) range per release line; fixed None: no fixed release yet.
    ranges: tuple[tuple[_Ver, _Ver | None], ...]
    defect: str                # the evidence sentence after the resolved version
    group: str = _GROUP
    # A BOM in the same group: a versionless artifact takes its version.
    bom: str | None = None


_PINS: tuple[_JvmPin, ...] = (
    # `kotlin-sdk-core` is where ReadBuffer.kt lives; `kotlin-sdk` and
    # `kotlin-sdk-jvm` pull it in. Matching all three is why a file reports once
    # rather than per-name. 0.7.0 is the first release of kotlin-sdk-core and
    # NVD's range start; 0.13.0 is the vendor fix.
    _JvmPin(
        RULE_ID, ("kotlin-sdk-core", "kotlin-sdk-jvm", "kotlin-sdk"),
        (((0, 7, 0), (0, 13, 0)),),
        "the MCP Kotlin SDK stdio read buffer grows without bound until a newline "
        "arrives (CVE-2026-53937). Affected 0.7.0–0.12.0; fixed in 0.13.0.",
    ),
    # `Application.mcpWebSocket` is in kotlin-sdk-server from 0.7.3; the umbrella
    # `kotlin-sdk` depends on it. Core and client do not carry the extension.
    _JvmPin(
        WS_RULE_ID,
        ("kotlin-sdk-server-jvm", "kotlin-sdk-server", "kotlin-sdk-jvm", "kotlin-sdk"),
        (((0, 7, 3), None),),
        "`Application.mcpWebSocket` installs Ktor WebSockets with no maxFrameSize, so "
        "a client can declare a frame near 2 GiB and exhaust the heap "
        "(CVE-2026-108714). Affected from 0.7.3; no fixed release yet.",
    ),
    # The three Servlet transports read the body with an unbounded `readLine()`
    # loop: in `mcp` from 0.8.0 (HttpServletSseServerTransportProvider arrives) to
    # 0.12.1, in `mcp-core` from 0.13.0, and `mcp` 0.13.0+ depends on `mcp-core` at
    # its own version. Fixed by a bounded `readBody` in 0.18.4, 1.1.4 and 2.0.1;
    # 1.0.x has no fix. 1.0.0-RC3 and the 2.0.0 milestones read as 1.0.0 and 2.0.0
    # here, and their source has the same loop.
    _JvmPin(
        JAVA_BODY_RULE_ID, ("mcp-core", "mcp"),
        (((0, 8, 0), (0, 18, 4)), ((1, 0, 0), (1, 1, 4)), ((2, 0, 0), (2, 0, 1))),
        "the MCP Java SDK Servlet SSE, Streamable HTTP and Stateless transports read "
        "a request body of any size into memory (CVE-2026-108395). Affected 0.8.0 to "
        "0.18.3, 1.0.0 to 1.1.3 and 2.0.0; fixed in 0.18.4, 1.1.4 and 2.0.1.",
        group="io.modelcontextprotocol.sdk",
        bom="mcp-bom",
    ),
)

_GRADLE_FILES = ("build.gradle", "build.gradle.kts")
_CATALOG_REL = ("gradle/libs.versions.toml", "libs.versions.toml")
_MAVEN_FILES = ("pom.xml",)
_MAX_FILE_BYTES = 2_000_000

_VER_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")
# `val mcpVersion = "0.12.0"` / `mcpVersion = '0.12.0'` / `ext.mcp = "0.12.0"`
# The old `(?:val|var|def|ext\.)?\s*([\w.]+)` let a match start at every
# character of a long word or blank run and read to its end, so a build file of
# either grew with the square of the run. A match now starts only where one
# could first succeed: at the start of a blank run (the name after it is read
# whole), at the start of a `[\w.]` run (a leading `val` / `var` / `def` /
# `ext.` is dropped from the name, as before), or at one of those words that
# ends a run (`myval x = "1"` names `x`). Every other start failed for the same
# reason as one of these, so the table is unchanged.
_ASSIGN_RE = re.compile(
    r"""(?:(?<!\s)\s+|(?<![\w.])(?:(?:val|var|def|ext\.)\s*)?|(?:val|var|def|ext\.)(?![\w.])\s*)"""
    r"""([\w.]+)\s*=\s*["']v?([\d][\w.\-]*)["']"""
)
_VERSION_REF_RE = re.compile(r"""version\.ref\s*=\s*["']([\w.\-]+)["']""")
_VERSION_LIT_RE = re.compile(r"""version\s*=\s*["']v?([\d][\w.\-]*)["']""")
_MAVEN_PROP_RE = re.compile(r"<([\w.\-]+)>\s*v?([\d][\w.\-]*)\s*</\1>")


@dataclass(frozen=True)
class _PinRes:
    """The per-pin patterns: each pin names its own group and artifacts."""
    # `implementation "io.modelcontextprotocol:kotlin-sdk:0.12.0"` and the $var form.
    coord: re.Pattern[str]
    # Version catalog entries are one line each, so they are parsed per line rather
    # than with a single regex. The first attempt used one pattern with an optional
    # trailing version group and a lazy `[^\n]*?` between; that matches happily
    # with the group empty -- laziness prefers the shortest match -- so every
    # catalog resolved to "no version" and the arm silently never fired. Splitting
    # the coordinate match from the version match removes the ambiguity.
    catalog_coord: re.Pattern[str]
    catalog_group: re.Pattern[str]
    catalog_name: re.Pattern[str]
    maven_dep: re.Pattern[str]


def _compile(group: str, names: str) -> _PinRes:
    g = re.escape(group)
    return _PinRes(
        coord=re.compile(
            r"""["']""" + g + r":(" + names + r")"
            r"""(?::\$?\{?([\w.\-]+)\}?)?["']""",
        ),
        catalog_coord=re.compile(r"""["']""" + g + r":(" + names + r")[\"']"),
        # The closing quote keeps `io.modelcontextprotocol` off `....sdk`.
        catalog_group=re.compile(r"""group\s*=\s*["']""" + g + r"""["']"""),
        catalog_name=re.compile(r"""name\s*=\s*["'](""" + names + r""")["']"""),
        maven_dep=re.compile(
            r"<groupId>\s*" + g + r"\s*</groupId>\s*"
            r"<artifactId>\s*(" + names + r")\s*</artifactId>\s*"
            r"(?:<version>\s*\$?\{?([\w.\-]+)\}?\s*</version>)?",
            re.DOTALL,
        ),
    )


_RES = {pin.rule_id: _compile(pin.group, "|".join(pin.artifacts)) for pin in _PINS}
# A BOM is read with the same patterns, as a one-name artifact list.
_BOM_RES = {pin.rule_id: _compile(pin.group, re.escape(pin.bom)) for pin in _PINS if pin.bom}


def _semver(raw: str | None) -> _Ver | None:
    if not raw:
        return None
    m = _VER_RE.match(raw)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _affected(v: _Ver, pin: _JvmPin) -> bool:
    return any(lo <= v and (hi is None or v < hi) for lo, hi in pin.ranges)


def _resolve(token: str | None, table: dict[str, str]) -> str | None:
    """The version a token names, as written: a literal or a name to look up."""
    if not token:
        return None
    if _semver(token) is not None:
        return token
    # `$mcpVersion` / `${mcp.version}` / a catalog version.ref
    for key in (token, token.split(".")[-1]):
        if key in table:
            return table[key] if _semver(table[key]) is not None else None
    return None


def _versions_table(text: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in _ASSIGN_RE.finditer(text)}


def _maven_props(text: str) -> dict[str, str]:
    """The first `<properties>` block, up to the first `</properties>` after it.

    `str.find`, not `<properties>(.*?)</properties>`: with no closer, the lazy
    pattern read from every `<properties>` to the end of the file, so a pom of
    repeated openers grew with the square of its size. A search past the first
    opener could only fail the same way, so the block is the same one.
    """
    start = text.find("<properties>")
    if start < 0:
        return {}
    end = text.find("</properties>", start + len("<properties>"))
    if end < 0:
        return {}
    block = text[start + len("<properties>"):end]
    return {m.group(1): m.group(2) for m in _MAVEN_PROP_RE.finditer(block)}


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _declarations(text: str, kind: str, res: _PinRes) -> list[tuple[str, str | None, int]]:
    """(artifact, version token or None, line) for each coordinate `res` matches."""
    if kind == "maven":
        return [(m.group(1), m.group(2), _line_at(text, m.start(1)))
                for m in res.maven_dep.finditer(text)]
    if kind == "catalog":
        out: list[tuple[str, str | None, int]] = []
        for i, line in enumerate(text.splitlines(), 1):
            coord: re.Match[str] | None = res.catalog_coord.search(line)
            if coord is None and res.catalog_group.search(line):
                coord = res.catalog_name.search(line)
            if coord is None:
                continue
            ref = _VERSION_REF_RE.search(line)
            lit = _VERSION_LIT_RE.search(line)
            out.append((coord.group(1), ref.group(1) if ref else (lit.group(1) if lit else None), i))
        return out
    return [(m.group(1), m.group(2), _line_at(text, m.start(1)))
            for m in res.coord.finditer(text)]


def _analyze(text: str, kind: str, pin: _JvmPin) -> tuple[str, str, int, bool] | None:
    """(artifact, version as written, line, read through the BOM) for the pin's
    first affected coordinate.

    The BOM's version stands in only for a coordinate that states no version at
    all. A version token that does not resolve (`$mcpVersion` set in another file)
    overrides the BOM in the build, so it is not replaced by a guess.
    """
    if pin.group not in text:
        return None
    table = _maven_props(text) if kind == "maven" else _versions_table(text)
    bom: str | None = None
    if pin.rule_id in _BOM_RES:
        for _name, bom_token, _line in _declarations(text, kind, _BOM_RES[pin.rule_id]):
            bom = _resolve(bom_token, table)
            if bom is not None:
                break
    for artifact, token, line in _declarations(text, kind, _RES[pin.rule_id]):
        version = _resolve(token, table) if token else bom
        v = _semver(version)
        if version is not None and v is not None and _affected(v, pin):
            return artifact, version, line, not token
    return None


def _candidates(project_root: Path) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for name in _GRADLE_FILES:
        for p in project_root.rglob(name):
            if in_skip_dir(p, project_root) or p in seen:
                continue
            seen.add(p)
            out.append((p, "gradle"))
    for rel in _CATALOG_REL:
        for p in project_root.rglob(Path(rel).name):
            if in_skip_dir(p, project_root) or p in seen:
                continue
            seen.add(p)
            out.append((p, "catalog"))
    for name in _MAVEN_FILES:
        for p in project_root.rglob(name):
            if in_skip_dir(p, project_root) or p in seen:
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
            text = read_text_capped(path, _MAX_FILE_BYTES, errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(project_root))
        for pin in _PINS:
            hit = _analyze(text, kind, pin)
            if hit is None:
                continue
            artifact, version, line, via_bom = hit
            through = f" through `{pin.bom}`" if via_bom else ""
            findings.append(make_finding(
                pin.rule_id,
                rel,
                f"`{pin.group}:{artifact}` resolves to {version}{through} in "
                f"{path.name} — {pin.defect}",
                line,
            ))
            scanned.add(rel)
    return findings, scanned
