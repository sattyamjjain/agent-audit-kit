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
request named, so a rebound name still reached it: its uv.lock resolved `mcp`
1.15.0, below the release that changed this.

`mcp` 1.23.0 (CVE-2025-66416, GHSA-9h52-p55h-vw2f) made the SDK's own FastMCP
default to host 127.0.0.1 and turn the protection on for a loopback host when no
`transport_security` is passed, so a request naming another host gets a 421. The
SDK's maintainer gave that as the reason for closing
modelcontextprotocol/python-sdk issue 3562 on 2026-10-06, and it is what 2.x's
`MCPServer` does too. So a loopback host clears this rule for that one shape, when
the project resolves `mcp` to 1.23.0 or later (`_mcp_state`). Without a readable
version it still fires, and the evidence says what would clear it. Three shapes
never get there, because the auto-enable is not on their path:

* Code that builds `StreamableHTTPSessionManager`, `StreamableHTTPServerTransport`
  or `SseServerTransport` directly, which is unprotected even on localhost unless
  it passes `security_settings`.
* A non-loopback or variable `host=`.
* The standalone `fastmcp` package, whose defaults were not read.

Switching `enable_dns_rebinding_protection` off beside a transport fires whatever
else is in the project: the SDK ignores `allowed_hosts` when protection is off. And
an allow-list whose only entry is `*` is not one.

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
from typing import NamedTuple
from xml.etree import ElementTree

from agent_audit_kit.models import Finding

from ._dependency_pins import DependencyPin, pinned_dependency, read_lockfile, read_manifest
from ._helpers import (
    MANIFEST_MAX_BYTES,
    SOURCE_MAX_BYTES,
    find_line_number,
    in_skip_dir,
    make_finding,
    read_text_capped,
    sub_comments,
)
from ._versions import exact_version, parse_range

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
    r"\b(StreamableHTTPSessionManager|streamable_http|StreamableHTTPServerTransport|SseServerTransport)\b"
)
# Building the transport directly never goes through FastMCP's loopback auto-enable.
_PY_DIRECT_RE = re.compile(r"\b(?:StreamableHTTPSessionManager|StreamableHTTPServerTransport|SseServerTransport)\s*\(")

# FastMCP (`mcp.server.fastmcp` and the standalone `fastmcp` package) wraps the
# same StreamableHTTP transport, so the defect is identical while none of the
# markers above appear. Construction alone is not enough — see below.
_PY_FASTMCP_RE = re.compile(r"\bFastMCP\s*\(")
# 2.x's name for it. Other libraries have an `MCPServer` too, so it counts only
# beside an import from the SDK.
_PY_MCPSERVER_RE = re.compile(r"\bMCPServer\s*\(")
_PY_SDK_SERVER_RE = re.compile(
    r"""^[ \t]*(?:
        from[ \t]+mcp\.server(?:\.fastmcp|\.mcpserver)?(?:\.server)?[ \t]+import[ \t]*
            (?:\([^)]{0,400}?|[^\n]{0,400}?)\b(?:FastMCP|MCPServer)\b
      | import[ \t]+mcp\.server\.(?:fastmcp|mcpserver)\b
    )""",
    re.MULTILINE | re.VERBOSE,
)
# Where the listener binds: a keyword argument, an annotated default, or a variable.
_PY_HOST_RE = re.compile(r"""\bhost\s*(?::\s*\w+\s*)?=(?!=)\s*(?:"([^"\n]*)"|'([^'\n]*)')?""")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
# Settings of its own, which the auto-enable leaves alone. `None` is the default.
_PY_TRANSPORT_SECURITY_RE = re.compile(r"\btransport_security\s*=(?!=)\s*(?!None\b)")

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

# Protection switched off. The SDK ignores `allowed_hosts` then, so no allow-list
# beside it counts.
_PROTECTION_OFF_RE = re.compile(r"\benable_dns_rebinding_protection\s*=\s*False\b|\benableDnsRebindingProtection\s*:\s*false\b")
# An allow-list whose only entry is `*`. Starlette's TrustedHostMiddleware reads that
# as every host, and it names none in any SDK.
_WILDCARD_ALLOWLIST_RE = re.compile(
    r"""(?:TrustedHostMiddleware\s*(?:,|\(\s*\w+\s*,)\s*)?(?:allowed_hosts|allowedHosts|ALLOWED_HOSTS)\s*[:=]\s*"""
    r"""[\[(]\s*["']\*["']\s*,?\s*[\])]"""
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
    wrapper = _py_wrapper(text)
    if wrapper:
        n = _PY_FASTMCP_NET_RE.search(text)
        if n:
            return f"{wrapper} {n.group(0).strip()}", n.group(0)
    return None


def _py_wrapper(text: str) -> str | None:
    """The wrapper class a file constructs, if any. `MCPServer` is 2.x's name."""
    if _PY_FASTMCP_RE.search(text):
        return "FastMCP"
    if _PY_MCPSERVER_RE.search(text) and _PY_SDK_SERVER_RE.search(text):
        return "MCPServer"
    return None


def _sdk_server_on_loopback(text: str) -> bool:
    """Is this the SDK's own FastMCP or MCPServer, on the default or a literal
    loopback host, with no settings of its own? That is the one shape `mcp` 1.23.0's
    auto-enable covers. Any `host=` in the file counts, a commented one too, so
    what cannot be told stays reported."""
    if not _PY_SDK_SERVER_RE.search(text) or _py_wrapper(text) is None:
        return False
    if _PY_DIRECT_RE.search(text) or _PY_TRANSPORT_SECURITY_RE.search(text):
        return False
    return all((m.group(1) or m.group(2) or "") in _LOOPBACK_HOSTS for m in _PY_HOST_RE.finditer(text))


_MCP_FIXED, _MCP_BELOW = "fixed", "below"
_MCP_LOCKFILES = ("uv.lock", "poetry.lock", "Pipfile.lock")


def _mcp_in_directory(directory: Path) -> str | None:
    """What one directory says about the `mcp` it resolves: `_MCP_FIXED`, `_MCP_BELOW`
    or None. A lockfile says what is installed, so it is read before a declaration.
    A declaration counts when it pins one release, or when every release it admits
    is at or above the fix (`mcp[cli]>=1.25`)."""
    for name in _MCP_LOCKFILES:
        lockfile = read_lockfile(directory / name)
        versions = lockfile.index.get("mcp") if lockfile is not None else None
        if versions:
            return _MCP_FIXED if min(versions) >= _PY_PATCHED else _MCP_BELOW
    for path in [*sorted(directory.glob("requirements*.txt")), directory / "pyproject.toml"]:
        manifest = read_manifest(path) if path.is_file() else None
        if manifest is None:
            continue
        for declaration in manifest.naming(_PY_PIN.as_table_pin()):
            if declaration.name.lower() != "mcp":
                continue
            spans = parse_range(declaration.version, declaration.dialect)
            if not spans:
                continue
            if all(low >= _PY_PATCHED for low, _ in spans):
                return _MCP_FIXED
            exact = exact_version(spans)
            if exact is not None:
                return _MCP_BELOW
    return None


def _mcp_state(path: Path, project_root: Path, seen: dict[Path, str | None]) -> str | None:
    """What the project resolves `mcp` to for a file: the nearest directory, from the
    file's own up to the root, that says anything. `seen` holds each directory's
    answer, inherited ones too, so thousands of files below one deep directory walk
    the chain once."""
    walked: list[Path] = []
    directory = path.parent
    while directory not in seen:
        walked.append(directory)
        state = _mcp_in_directory(directory)
        if state is not None or directory == project_root:
            break
        directory = directory.parent
    else:
        state = seen[directory]
    for visited in walked:
        seen[visited] = state
    return state


def _has_host_allowlist(text: str) -> bool:
    stripped = _WILDCARD_ALLOWLIST_RE.sub("", _strip_comments(text))
    return bool(_HOST_ALLOWLIST_RE.search(stripped))


class _Candidate(NamedTuple):
    """A file that exposes a network transport."""

    path: Path
    marker: str
    line: int | None
    protection_off: bool
    sdk_on_loopback: bool


_CVES = "CVE-2025-66414 / CVE-2025-66416 / CVE-2026-35568 / CVE-2026-35577 / CVE-2026-81102"


def _candidate(path: Path, text: str) -> _Candidate | None:
    """The file as a candidate, or None when it exposes no network transport."""
    sdk_on_loopback = False
    if path.suffix in _PY_EXTS:
        hit = _py_transport_marker(text)
        if hit is None:
            return None
        label, literal = hit
        sdk_on_loopback = _sdk_server_on_loopback(text)
    else:
        m = _TS_STREAMABLE_RE.search(text)
        if m is None:
            return None
        label = literal = m.group(0)
    off = _PROTECTION_OFF_RE.search(_strip_comments(text))
    if off:
        return _Candidate(path, label, find_line_number(text, off.group(0)), True, False)
    return _Candidate(path, label, find_line_number(text, literal), False, sdk_on_loopback)


def _evidence(candidate: _Candidate, state: str | None) -> str:
    if candidate.protection_off:
        return (f"{candidate.marker} transport runs with DNS-rebinding protection switched off, so the SDK ignores any "
                f"allow-list beside it ({_CVES}): a malicious browser page can reach a loopback MCP server.")
    base = (f"{candidate.marker} transport exposed without a Host-header allow-list — DNS-rebinding ({_CVES}) "
            "lets a malicious browser page reach a loopback MCP server.")
    if not candidate.sdk_on_loopback:
        return base
    if state == _MCP_BELOW:
        return (f"{base} The project resolves `mcp` below 1.23.0, the release that turned the protection on for "
                "this server on a loopback host (CVE-2025-66416).")
    return (f"{base} No `mcp` version could be read from uv.lock, poetry.lock, Pipfile.lock or a pin: from 1.23.0 "
            "the SDK turns the protection on for this server on a loopback host (CVE-2025-66416), so lock or pin "
            "it to clear this finding.")


def _check_streamable_pattern(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    # Collect every file that exposes a StreamableHTTP server. Then check
    # the whole project for a host allow-list — repos often wire the
    # middleware in one place (e.g. `app.py`) while the transport is set
    # up in another. One allow-list anywhere counts as mitigation, except
    # for a transport whose own file switches the protection off.
    candidates: list[_Candidate] = []
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
        candidate = _candidate(path, text)
        if candidate is not None:
            candidates.append(candidate)

    seen: dict[Path, str | None] = {}
    for candidate in candidates:
        if project_has_allowlist and not candidate.protection_off:
            continue
        state = _mcp_state(candidate.path, project_root, seen) if candidate.sdk_on_loopback else None
        if state == _MCP_FIXED:
            continue
        rel = str(candidate.path.relative_to(project_root))
        scanned.add(rel)
        findings.append(make_finding("AAK-DNS-REBIND-001", rel, _evidence(candidate, state),
                                     line_number=candidate.line))
    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    scanned: set[str] = set()
    findings: list[Finding] = []
    findings.extend(_check_python_pin(project_root, scanned))
    findings.extend(_check_package_json_pin(project_root, scanned))
    findings.extend(_check_java_pin(project_root, scanned))
    findings.extend(_check_streamable_pattern(project_root, scanned))
    return findings, scanned
