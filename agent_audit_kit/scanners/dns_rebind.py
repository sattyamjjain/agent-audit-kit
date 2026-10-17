"""AAK-DNS-REBIND-001 / -002 — MCP SDK DNS-rebinding class.

April 2026 cluster: CVE-2025-66414, CVE-2025-66416, CVE-2026-35568,
CVE-2026-35577. The upstream Python, Java and Apollo MCP servers shipped
a `StreamableHTTP` transport that trusts the browser-supplied `Host`
header, which lets a malicious web page bounce loopback requests into a
local MCP server via DNS rebinding. Fixed by adding a Host-header
allow-list in the SDK. Patched versions:

- `mcp`                                        >= 1.23.0
- `io.modelcontextprotocol.sdk:mcp-core`       >= 0.11.0
- `@apollo/mcp-server`                         >= 1.7.0
- `@modelcontextprotocol/sdk` (TS)             >= 1.21.1

Two detections:

1. AAK-DNS-REBIND-002 (HIGH) — pin check on manifests. It took the first
   number after the name, from a pattern with no place for extras: in a
   requirements file it acted on `==`, `<` and `<=` only, so `mcp<1.23.0`,
   which admits only affected releases, read as the fix and was silent, and
   `mcp>=1.0` fired in pyproject.toml but not in requirements.txt;
   `mcp[cli]==1.22.0`, the SDK's own install line, and a Poetry table entry
   were never read; and `"@modelcontextprotocol/sdk": "<1.21.1"` read as the
   fix. The Python and npm manifests are now read as the CVE pin table reads
   them (`_dependency_pins`), so a range is reported when it admits a release
   below the fix, and the same line reads alike in every manifest.
2. AAK-DNS-REBIND-001 (CRITICAL) — pattern check for
   `StreamableHTTP*` usage in Python/TS without a Host-header
   allow-list (`TrustedHostMiddleware`, `allowed_hosts=`,
   `validate_host`, `allowedHosts:`).

CVE-2026-81102 (2026-08-27) is the same defect reached through the
Python **FastMCP** wrapper rather than the raw transport class. The Dash
MCP server bound its listener to loopback and never checked the `Host` a
request named, so a rebound name still reached it. Binding to loopback is
not the control here — the Host allow-list is — which is why an explicit
`host="127.0.0.1"` does not clear this rule.

FastMCP names none of the tokens above: it is constructed as
`FastMCP(...)` and selects its transport with `run(transport="streamable-http")`,
where the transport is a **hyphenated string literal** and `streamable_http`
(underscore) never appears. The pattern check therefore read straight past
every FastMCP server. That is a language/framework shape the detector did
not read, not a second defect, so it is folded into this rule rather than
given a new id.

**stdio is deliberately not flagged.** FastMCP defaults to stdio, and a
stdio server has no listener to rebind onto — the advisory says only the
network mode was reachable. A network transport must be selected
explicitly for this to fire.
"""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree

from agent_audit_kit.models import Finding

from ._dependency_pins import DependencyPin, pinned_dependency, read_manifest
from ._helpers import (
    MANIFEST_MAX_BYTES,
    SOURCE_MAX_BYTES,
    find_line_number,
    in_skip_dir,
    make_finding,
    read_text_capped,
    sub_comments,
)

_PY_PATCHED = (1, 23, 0)
_TS_PATCHED = (1, 21, 1)
_APOLLO_PATCHED = (1, 7, 0)
_JAVA_PATCHED = (0, 11, 0)

# A stated version only, as before: an unpinned SDK installs a patched release.
_PY_PIN = DependencyPin(("mcp",), _PY_PATCHED, ecosystem="py")
_NPM_PINS = (
    (DependencyPin(("@apollo/mcp-server",), _APOLLO_PATCHED, ecosystem="js"), "@apollo/mcp-server",
     "DNS-rebinding fixed in 1.7.0 (CVE-2026-35577)."),
    (DependencyPin(("@modelcontextprotocol/sdk",), _TS_PATCHED, ecosystem="js"), "@modelcontextprotocol/sdk",
     "DNS-rebinding fixed in 1.21.1."),
)

_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_PY_EXTS = (".py",)

_SEMVER_RE = re.compile(r"[^\d]*(\d+)\.(\d+)(?:\.(\d+))?")

_PY_STREAMABLE_RE = re.compile(
    r"\b(StreamableHTTPSessionManager|streamable_http|StreamableHTTPServerTransport)\b"
)

# FastMCP (`mcp.server.fastmcp` and the standalone `fastmcp` package) wraps the
# same StreamableHTTP transport, so the defect is identical while none of the
# markers above appear. Construction alone is not enough — see below.
_PY_FASTMCP_RE = re.compile(r"\bFastMCP\s*\(")

# ...it must also select a NETWORK transport. FastMCP defaults to stdio, which
# has no listener to rebind onto, so requiring an explicit network transport is
# what keeps this from firing on every FastMCP server in existence.
# `streamable_http_app` / `sse_app` are the ASGI-app accessors; note
# `streamable_http_app` does NOT match `\bstreamable_http\b` above, because the
# trailing `_app` leaves no word boundary.
_PY_FASTMCP_NET_RE = re.compile(
    r"""
    (?:
        transport\s*=\s*["\'](?:streamable[-_]http|sse|http)["\']
      | \.\s*streamable_http_app\s*\(
      | \.\s*sse_app\s*\(
      | \brun_streamable_http_async\s*\(
      | \brun_sse_async\s*\(
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_TS_STREAMABLE_RE = re.compile(
    r"\b(StreamableHTTPServerTransport|StreamableHTTPTransport|streamableHttp)\b"
)

_HOST_ALLOWLIST_RE = re.compile(
    r"""
    (?:
        TrustedHostMiddleware
      | allowed_hosts\s*=
      | allowedHosts\s*[:=]
      | ALLOWED_HOSTS
      | validate_host
      | validateHost
      | HostHeaderFilter
      | host_allow_list
      | hostAllowList
    )
    """,
    re.VERBOSE,
)

_LINE_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/|\#.*?$", re.MULTILINE | re.DOTALL)
_LINE_ONLY_COMMENT_RE = re.compile(r"//.*?$|\#.*?$", re.MULTILINE | re.DOTALL)


def _parse_semver(spec: str | None) -> tuple[int, int, int] | None:
    if not spec:
        return None
    m = _SEMVER_RE.match(str(spec))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _strip_comments(text: str) -> str:
    return sub_comments(_LINE_COMMENT_RE, _LINE_ONLY_COMMENT_RE, text)


# ---------------------------------------------------------------------------
# Pin-check: AAK-DNS-REBIND-002
# ---------------------------------------------------------------------------


def _check_python_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    manifests = sorted(project_root.glob("requirements*.txt"))
    if (project_root / "pyproject.toml").is_file():
        manifests.append(project_root / "pyproject.toml")
    for path in manifests:
        manifest = read_manifest(path)
        if manifest is None:
            continue
        rel = str(path.relative_to(project_root))
        if path.suffix == ".txt":
            scanned.add(rel)
        hit = pinned_dependency(manifest, _PY_PIN)
        if hit is None:
            continue
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-DNS-REBIND-002",
            rel,
            f"mcp referenced as {hit.quoted} — DNS-rebinding fixed in 1.23.0 "
            "(CVE-2025-66414 / CVE-2025-66416).",
            line_number=hit.line,
        ))
    return findings


def _check_package_json_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    pkg = project_root / "package.json"
    if not pkg.is_file():
        return findings
    rel = str(pkg.relative_to(project_root))
    scanned.add(rel)
    manifest = read_manifest(pkg)
    if manifest is None:
        return findings
    for pin, name, tail in _NPM_PINS:
        hit = pinned_dependency(manifest, pin)
        if hit is not None:
            # No line, as before: giving package.json findings one re-keys
            # their code-scanning alerts.
            findings.append(make_finding(
                "AAK-DNS-REBIND-002",
                rel,
                f"{name} referenced as {hit.quote(f' in {hit.declaration.section}')} — {tail}",
            ))
    return findings


def _check_java_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    pom = project_root / "pom.xml"
    if pom.is_file():
        rel = str(pom.relative_to(project_root))
        scanned.add(rel)
        try:
            tree = ElementTree.parse(pom)
        except ElementTree.ParseError:
            tree = None
        if tree is not None:
            root = tree.getroot()
            ns = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
            dep_xpath = ".//m:dependency" if ns else ".//dependency"
            for dep in root.findall(dep_xpath, ns) if ns else root.findall(dep_xpath):
                def _get(elem: ElementTree.Element, tag: str) -> str:
                    node = elem.find(f"m:{tag}", ns) if ns else elem.find(tag)
                    return (node.text or "").strip() if node is not None and node.text else ""

                group = _get(dep, "groupId")
                artifact = _get(dep, "artifactId")
                version = _get(dep, "version")
                if group == "io.modelcontextprotocol.sdk" and artifact == "mcp-core":
                    parsed = _parse_semver(version)
                    if parsed and parsed < _JAVA_PATCHED:
                        findings.append(make_finding(
                            "AAK-DNS-REBIND-002",
                            rel,
                            f"io.modelcontextprotocol.sdk:mcp-core pinned at {version} — "
                            "DNS-rebinding fixed in 0.11.0 (CVE-2026-35568).",
                        ))

    for gradle in ("build.gradle", "build.gradle.kts"):
        p = project_root / gradle
        if not p.is_file():
            continue
        rel = str(p.relative_to(project_root))
        scanned.add(rel)
        try:
            text = read_text_capped(p, MANIFEST_MAX_BYTES, errors="replace")
        except OSError:
            continue
        for m in re.finditer(
            r"""io\.modelcontextprotocol\.sdk:mcp-core:([0-9][0-9A-Za-z.\-+]*)""",
            text,
        ):
            parsed = _parse_semver(m.group(1))
            if parsed and parsed < _JAVA_PATCHED:
                findings.append(make_finding(
                    "AAK-DNS-REBIND-002",
                    rel,
                    f"mcp-core pinned at {m.group(1)} in {gradle} — "
                    "DNS-rebinding fixed in 0.11.0 (CVE-2026-35568).",
                    line_number=find_line_number(text, m.group(0)),
                ))
    return findings


# ---------------------------------------------------------------------------
# Pattern-check: AAK-DNS-REBIND-001
# ---------------------------------------------------------------------------


def _py_transport_marker(text: str) -> tuple[str, str] | None:
    """``(evidence_label, literal_to_locate)`` for a Python network MCP transport.

    Two shapes reach the same StreamableHTTP transport: the raw SDK classes, and
    a `FastMCP` server told to run over a network transport. Returns ``None`` for
    stdio FastMCP servers and for files that expose no server at all.
    """
    m = _PY_STREAMABLE_RE.search(text)
    if m:
        return m.group(0), m.group(0)
    if _PY_FASTMCP_RE.search(text):
        n = _PY_FASTMCP_NET_RE.search(text)
        if n:
            return f"FastMCP {n.group(0).strip()}", n.group(0)
    return None


def _has_host_allowlist(text: str) -> bool:
    stripped = _strip_comments(text)
    return bool(_HOST_ALLOWLIST_RE.search(stripped))


def _check_streamable_pattern(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    # Collect every file that exposes a StreamableHTTP server. Then check
    # the whole project for a host allow-list — repos often wire the
    # middleware in one place (e.g. `app.py`) while the transport is set
    # up in another. One allow-list anywhere counts as mitigation.
    candidates: list[tuple[Path, str, int | None]] = []
    project_has_allowlist = False

    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _PY_EXTS + _JS_EXTS:
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            text = read_text_capped(path, SOURCE_MAX_BYTES, errors="replace")
        except OSError:
            continue

        if _has_host_allowlist(text):
            project_has_allowlist = True

        if path.suffix in _PY_EXTS:
            hit = _py_transport_marker(text)
            if hit is None:
                continue
            label, literal = hit
        else:
            m = _TS_STREAMABLE_RE.search(text)
            if m is None:
                continue
            label = literal = m.group(0)
        line = find_line_number(text, literal)
        candidates.append((path, label, line))

    if project_has_allowlist or not candidates:
        return findings

    for path, marker, line in candidates:
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding(
            "AAK-DNS-REBIND-001",
            rel,
            f"{marker} transport exposed without a Host-header allow-list — "
            "DNS-rebinding (CVE-2025-66414 / CVE-2025-66416 / CVE-2026-35568 / "
            "CVE-2026-35577 / CVE-2026-81102) lets a malicious browser page "
            "reach a loopback MCP server.",
            line_number=line,
        ))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_python_pin(project_root, scanned))
    findings.extend(_check_package_json_pin(project_root, scanned))
    findings.extend(_check_java_pin(project_root, scanned))
    findings.extend(_check_streamable_pattern(project_root, scanned))
    return findings, scanned
