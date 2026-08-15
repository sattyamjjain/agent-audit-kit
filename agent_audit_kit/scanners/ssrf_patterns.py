"""SSRF pattern scanner for MCP tool handlers.

Fires AAK-SSRF-001..005. Targets Python + TS/JS files that look like MCP
tool implementations with outbound HTTP calls.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners import _ssrf_reach
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_SCAN_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rs"}
_MAX_FILE_BYTES = 512_000

_MCP_TOOL_HINT = re.compile(
    r"\b(@tool|createTool|McpServer|FastMCP|mcp\.tool|Server\.run_streamable_http)\b"
)

# The outbound-call, user-input and private-address patterns that used to live
# here moved into `_ssrf_reach`, where they are applied to a real call site and
# its URL argument rather than to the whole file. See #593.

_ALLOWLIST_HINT_RE = re.compile(
    r"\b(?:ALLOW(?:ED)?_HOSTS?|URL_ALLOW_LIST)\b|"
    r"\ballowed_hosts\s*=|"
    r"\ballowlist\s*=",
)

_FOLLOW_REDIRECTS_RE = re.compile(
    r"follow_redirects\s*=\s*True|allow_redirects\s*=\s*True|redirect\s*:\s*['\"]?follow",
    re.IGNORECASE,
)

_URL_SCHEME_VALIDATION_RE = re.compile(
    r"urlparse\s*\(|scheme\s*!?=\s*['\"]https|startsWith\(['\"]https",
    re.IGNORECASE,
)


def _iter_source(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SCAN_EXTS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        out.append(path)
    return out


def _check_file(path: Path, project_root: Path) -> list[Finding]:
    """Report only what an actual outbound call site can be shown to reach.

    This used to decide file-wide: `fetch` anywhere plus a user-input marker
    anywhere meant CRITICAL, with no requirement that either be code, be
    related, or be near the other. It reported "loopback address reachable from
    MCP tool" against this scanner's own detection regex, a rule title in
    `builtin.py`, and a scanner description in `engine.py` — three findings, all
    prose (#593).

    Each rule now hangs off a real call site found by `_ssrf_reach`, which walks
    Python via `ast` and TS/JS via comment-stripped def-use. String literals are
    deliberately NOT stripped: a genuine metadata URL lives in one, so blanking
    literals would delete the true positives along with the prose. The
    discrimination comes from reachability instead.
    """
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    if not _MCP_TOOL_HINT.search(text):
        return findings
    rel = str(path.relative_to(project_root))

    is_python = path.suffix.lower() == ".py"
    sites = _ssrf_reach.analyze(text, is_python=is_python)
    if not sites:
        return findings

    has_allowlist = bool(_ALLOWLIST_HINT_RE.search(text))
    has_scheme_check = bool(_URL_SCHEME_VALIDATION_RE.search(text))

    tainted_sites = [s for s in sites if s.tainted]

    if tainted_sites and not has_allowlist and not has_scheme_check:
        site = tainted_sites[0]
        findings.append(make_finding(
            "AAK-SSRF-001",
            rel,
            f"Outbound HTTP call with user input and no scheme/allowlist check: "
            f"{site.callee!r} receives a URL derived from caller-controlled input",
            line_number=site.line or None,
        ))

    for site in sites:
        addr = site.private_addr
        if not addr:
            continue
        if addr in {"169.254.169.254", "metadata.google.internal"}:
            findings.append(make_finding(
                "AAK-SSRF-003",
                rel,
                f"Cloud metadata address reaches an outbound call: {addr} via {site.callee!r}",
                line_number=site.line or None,
            ))
        else:
            findings.append(make_finding(
                "AAK-SSRF-002",
                rel,
                f"Loopback/private address reaches an outbound call: {addr} via {site.callee!r}",
                line_number=site.line or None,
            ))
        break

    if _FOLLOW_REDIRECTS_RE.search(text):
        m = _FOLLOW_REDIRECTS_RE.search(text)
        findings.append(make_finding(
            "AAK-SSRF-004",
            rel,
            f"Redirects followed without re-validation: {m.group(0) if m else ''!r}",
            line_number=find_line_number(text, m.group(0)) if m else None,
        ))

    if tainted_sites and not has_allowlist:
        findings.append(make_finding(
            "AAK-SSRF-005",
            rel,
            f"Outbound HTTP call without allowlist guard: {tainted_sites[0].callee!r} "
            f"receives a URL derived from caller-controlled input",
            line_number=tainted_sites[0].line or None,
        ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_source(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
