"""SSRF pattern scanner for MCP tool handlers.

Fires AAK-SSRF-001..005. Targets Python + TS/JS files that look like MCP
tool implementations with outbound HTTP calls.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS


_SCAN_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".go", ".rs"}
_MAX_FILE_BYTES = 512_000

_MCP_TOOL_HINT = re.compile(
    r"\b(@tool|createTool|McpServer|FastMCP|mcp\.tool|Server\.run_streamable_http)\b"
)

_URL_FETCH_RE = re.compile(
    r"\b(?:requests\.(?:get|post|put|delete|head)|urllib\.request\.urlopen|"
    r"httpx\.(?:get|post|put|delete)|http\.client\.HTTP(?:S)?Connection|"
    r"fetch|axios\.(?:get|post|put|delete)|got\(|\bnode_fetch\()",
    re.IGNORECASE,
)

_USER_VAR_RE = re.compile(
    r"\b(?:input|args\[|params\[|req\.query|req\.body|request\.json|event\.body|tool_input)\b",
    re.IGNORECASE,
)

_PRIVATE_IP_PATTERN_RE = re.compile(
    r"\b(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1|169\.254\.169\.254|metadata\.google\.internal|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
    re.IGNORECASE,
)

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
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    if not _MCP_TOOL_HINT.search(text):
        return findings
    rel = str(path.relative_to(project_root))

    has_fetch = bool(_URL_FETCH_RE.search(text))
    has_user_var = bool(_USER_VAR_RE.search(text))
    has_allowlist = bool(_ALLOWLIST_HINT_RE.search(text))
    has_scheme_check = bool(_URL_SCHEME_VALIDATION_RE.search(text))

    if has_fetch and has_user_var and not has_allowlist and not has_scheme_check:
        m = _URL_FETCH_RE.search(text)
        findings.append(
            make_finding(
                "AAK-SSRF-001",
                rel,
                f"Outbound HTTP call with user input and no scheme/allowlist check: {m.group(0)!r}" if m else "",
                line_number=find_line_number(text, m.group(0)) if m else None,
            )
        )

    if has_fetch and _PRIVATE_IP_PATTERN_RE.search(text):
        for m in _PRIVATE_IP_PATTERN_RE.finditer(text):
            ip = m.group(0).lower()
            if ip in {"169.254.169.254", "metadata.google.internal"}:
                findings.append(
                    make_finding(
                        "AAK-SSRF-003",
                        rel,
                        f"Cloud metadata address reachable in code path: {ip}",
                        line_number=find_line_number(text, ip),
                    )
                )
            elif ip in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
                findings.append(
                    make_finding(
                        "AAK-SSRF-002",
                        rel,
                        f"Loopback address reachable from MCP tool: {ip}",
                        line_number=find_line_number(text, ip),
                    )
                )
            break

    if has_fetch and _FOLLOW_REDIRECTS_RE.search(text):
        m = _FOLLOW_REDIRECTS_RE.search(text)
        findings.append(
            make_finding(
                "AAK-SSRF-004",
                rel,
                f"Redirects followed without re-validation: {m.group(0) if m else ''!r}",
                line_number=find_line_number(text, m.group(0)) if m else None,
            )
        )

    if has_fetch and has_user_var and not has_allowlist:
        findings.append(
            make_finding(
                "AAK-SSRF-005",
                rel,
                "Outbound HTTP call without allowlist guard",
            )
        )

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    findings: list[Finding] = []
    scanned: set[str] = set()
    for path in _iter_source(project_root):
        rel = str(path.relative_to(project_root))
        scanned.add(rel)
        findings.extend(_check_file(path, project_root))
    return findings, scanned
