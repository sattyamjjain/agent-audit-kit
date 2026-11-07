"""SSRF pattern scanner for MCP tool handlers.

Fires AAK-SSRF-001..005. Targets Python + TS/JS files that look like MCP
tool implementations with outbound HTTP calls.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners import _ssrf_reach
from agent_audit_kit.scanners._helpers import find_line_number, in_skip_dir, make_finding, refusing_overflow


_SCAN_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rs"}
_MAX_FILE_BYTES = 512_000

# `@tool` sits outside the leading `\b`. Inside it, the boundary before `@`
# needed a word character in front, so the alternative matched only glued to a
# word (`x@tool`), never a decorator at the start of a line, and a file whose
# only marker was `@tool` was never read.
_MCP_TOOL_HINT = re.compile(
    r"(?:\b(?:createTool|McpServer|FastMCP|mcp\.tool|Server\.run_streamable_http|BaseTool|StructuredTool)|@tool)\b"
)
# A smolagents tool class carries no marker but the shape smolagents requires. Its VisitWebpageTool
# hands the model's URL to requests.get in a file that says neither MCP nor BaseTool.
_FORWARD_RE = re.compile(r"\bdef forward\b")
_OUTPUT_TYPE_RE = re.compile(r"\boutput_type\b")
_TOOL_CLASS_RE = re.compile(r"^\s*class\s+\w+\s*\([^)\n]*\b(?:Pipeline)?Tool\b", re.M)

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
# TS/JS options are not read call by call, so one of these anywhere in the file counts.
_JS_NO_FOLLOW_RE = re.compile(r"redirect\s*:\s*['\"](?:manual|error)|maxRedirects\s*:\s*0\b|\.redirects\(\s*0\s*\)")

# A comparison of the scheme, not an assignment. `scheme\s*!?=` read
# `scheme = "https://"` as a check and silenced AAK-SSRF-001 for the whole file,
# while the real check `parsed.scheme == "https"` did not match it.
_URL_SCHEME_VALIDATION_RE = re.compile(
    r"urlparse\s*\(|scheme\s*[!=]=\s*['\"]https|startsWith\(['\"]https",
    re.IGNORECASE,
)


def _iter_source(project_root: Path) -> list[Path]:
    out: list[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in _SCAN_EXTS:
            continue
        if in_skip_dir(path, project_root):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        out.append(path)
    return out


def _is_smolagents_shape(text: str) -> bool:
    """`def forward` and `output_type` alone also describe a model file, whose unrelated download
    helper would then be read as a tool's fetch, so a class on a `Tool` base is required too."""
    return bool(_FORWARD_RE.search(text) and _OUTPUT_TYPE_RE.search(text) and _TOOL_CLASS_RE.search(text))


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
    if not (_MCP_TOOL_HINT.search(text) or _is_smolagents_shape(text)):
        return findings
    rel = str(path.relative_to(project_root))

    is_python = path.suffix.lower() == ".py"
    sites: list[_ssrf_reach.Reach] = []
    with refusing_overflow(path):
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

    m = _FOLLOW_REDIRECTS_RE.search(text)
    follower = next((s for s in tainted_sites if s.follows_redirects or not is_python), None)
    if m:
        findings.append(make_finding(
            "AAK-SSRF-004",
            rel,
            f"Redirects followed without re-validation: {m.group(0)!r}",
            line_number=find_line_number(text, m.group(0)),
        ))
    elif follower and (is_python or not _JS_NO_FOLLOW_RE.search(text)):
        findings.append(make_finding(
            "AAK-SSRF-004",
            rel,
            f"Redirects followed without re-validation: {follower.callee!r} follows them by default "
            f"and the caller can set its URL",
            line_number=follower.line or None,
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
