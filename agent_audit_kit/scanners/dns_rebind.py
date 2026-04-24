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

1. AAK-DNS-REBIND-002 (HIGH) — pin check on manifests.
2. AAK-DNS-REBIND-001 (CRITICAL) — pattern check for
   `StreamableHTTP*` usage in Python/TS without a Host-header
   allow-list (`TrustedHostMiddleware`, `allowed_hosts=`,
   `validate_host`, `allowedHosts:`).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree

from agent_audit_kit.models import Finding

from ._helpers import SKIP_DIRS, find_line_number, make_finding

_PY_PATCHED = (1, 23, 0)
_TS_PATCHED = (1, 21, 1)
_APOLLO_PATCHED = (1, 7, 0)
_JAVA_PATCHED = (0, 11, 0)

_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_PY_EXTS = (".py",)

_SEMVER_RE = re.compile(r"[^\d]*(\d+)\.(\d+)(?:\.(\d+))?")
_REQ_LINE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)\s*(?P<op>==|>=|<=|~=|!=|>|<)?\s*(?P<ver>[0-9][0-9A-Za-z.\-+]*)?"
)

_PY_STREAMABLE_RE = re.compile(
    r"\b(StreamableHTTPSessionManager|streamable_http|StreamableHTTPServerTransport)\b"
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


def _parse_semver(spec: str | None) -> tuple[int, int, int] | None:
    if not spec:
        return None
    m = _SEMVER_RE.match(str(spec))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT_RE.sub("", text)


# ---------------------------------------------------------------------------
# Pin-check: AAK-DNS-REBIND-002
# ---------------------------------------------------------------------------


def _check_python_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for req in project_root.glob("requirements*.txt"):
        try:
            text = req.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(req.relative_to(project_root))
        scanned.add(rel)
        for lineno, line in enumerate(text.splitlines(), 1):
            raw = line.split("#", 1)[0].strip()
            if not raw:
                continue
            m = _REQ_LINE_RE.match(raw)
            if not m:
                continue
            name = (m.group("name") or "").lower()
            op = m.group("op")
            ver = m.group("ver")
            if name != "mcp":
                continue
            if op == "==" and ver:
                parsed = _parse_semver(ver)
                if parsed and parsed < _PY_PATCHED:
                    findings.append(make_finding(
                        "AAK-DNS-REBIND-002",
                        rel,
                        f"mcp pinned at =={ver} — DNS-rebinding fixed in 1.23.0 "
                        "(CVE-2025-66414 / CVE-2025-66416).",
                        line_number=lineno,
                    ))
            elif op in ("<", "<="):
                parsed = _parse_semver(ver or "")
                if parsed and parsed < _PY_PATCHED:
                    findings.append(make_finding(
                        "AAK-DNS-REBIND-002",
                        rel,
                        f"mcp constrained {op}{ver} — allows sub-1.23.0 "
                        "(CVE-2025-66414 / CVE-2025-66416).",
                        line_number=lineno,
                    ))

    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        # Look for "mcp==1.22", 'mcp = "1.22"', "mcp<1.23" — simple regex.
        for m in re.finditer(r"""['"]mcp['"]?\s*[=<>~]=?\s*['"]?([0-9][0-9A-Za-z.\-+]*)['"]?""", text):
            parsed = _parse_semver(m.group(1))
            if parsed and parsed < _PY_PATCHED:
                rel = "pyproject.toml"
                scanned.add(rel)
                findings.append(make_finding(
                    "AAK-DNS-REBIND-002",
                    rel,
                    f"mcp pinned at {m.group(1)} in pyproject.toml — "
                    "DNS-rebinding fixed in 1.23.0 (CVE-2025-66414 / CVE-2025-66416).",
                    line_number=find_line_number(text, m.group(0)),
                ))
    return findings


def _check_package_json_pin(project_root: Path, scanned: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    pkg = project_root / "package.json"
    if not pkg.is_file():
        return findings
    rel = str(pkg.relative_to(project_root))
    scanned.add(rel)
    try:
        data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return findings
    if not isinstance(data, dict):
        return findings
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        apollo_spec = deps.get("@apollo/mcp-server")
        if apollo_spec:
            parsed = _parse_semver(str(apollo_spec))
            if parsed and parsed < _APOLLO_PATCHED:
                findings.append(make_finding(
                    "AAK-DNS-REBIND-002",
                    rel,
                    f"@apollo/mcp-server pinned at {apollo_spec!r} in {section} — "
                    "DNS-rebinding fixed in 1.7.0 (CVE-2026-35577).",
                ))
        ts_spec = deps.get("@modelcontextprotocol/sdk")
        if ts_spec:
            parsed = _parse_semver(str(ts_spec))
            if parsed and parsed < _TS_PATCHED:
                findings.append(make_finding(
                    "AAK-DNS-REBIND-002",
                    rel,
                    f"@modelcontextprotocol/sdk pinned at {ts_spec!r} in {section} — "
                    "DNS-rebinding fixed in 1.21.1.",
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
            text = p.read_text(encoding="utf-8", errors="replace")
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
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if _has_host_allowlist(text):
            project_has_allowlist = True

        marker_re = _PY_STREAMABLE_RE if path.suffix in _PY_EXTS else _TS_STREAMABLE_RE
        m = marker_re.search(text)
        if m is None:
            continue
        line = find_line_number(text, m.group(0))
        candidates.append((path, m.group(0), line))

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
            "CVE-2026-35577) lets a malicious browser page reach a loopback "
            "MCP server.",
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
