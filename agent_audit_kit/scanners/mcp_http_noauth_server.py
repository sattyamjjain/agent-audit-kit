"""Unauthenticated MCP HTTP/SSE server scanner — 2026 no-auth-transport class.

Flags a repository that publishes an MCP server over HTTP / SSE /
Streamable-HTTP with no inbound authentication, while binding to all
interfaces (``0.0.0.0`` / ``::``) or serving a wildcard
``Access-Control-Allow-Origin: *``. The endpoint is then a mutation-capable
RPC surface, backed by the operator's own tokens, reachable without
credentials.

Recurring 2026 CVEs of this exact shape: GitLab MCP Server
(CVE-2026-44895), Nocturne Memory (CVE-2026-44830), AgenticMail
(CVE-2026-50287).

This **generalises** ``AAK-AZURE-MCP-NOAUTH-001`` (which is gated to
Azure-MCP repos). To avoid double-firing, this scanner defers on repos that
declare Azure-MCP identity — the Azure rule owns those.
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

# Reuse the Azure scanner's route + auth-marker + identity patterns so the two
# rules stay consistent.
from agent_audit_kit.scanners.mcp_server_auth import (
    _AUTH_MARKER_RE,
    _PY_MCP_ROUTE_RE,
    _TS_MCP_ROUTE_RE,
    _is_azure_mcp_repo,
)

_RULE_ID = "AAK-MCP-HTTP-NOAUTH-SERVER-001"

# HTTP / SSE / Streamable-HTTP MCP server setup signals (beyond `/mcp` routes).
_HTTP_SERVER_RE = re.compile(
    r"SSEServerTransport"
    r"|StreamableHTTPServerTransport"
    r"|sse_app\s*\("
    r"|transport\s*=\s*['\"](?:sse|streamable-http|http)['\"]"
    r"|\.run\s*\(\s*transport\s*=\s*['\"](?:sse|streamable-http|http)['\"]"
    r"|MCP_HTTP\b"
    r"|--http\b",
    re.IGNORECASE,
)

# Public-exposure signals: bind-all, or wildcard CORS.
_BIND_ALL_RE = re.compile(
    r"['\"]0\.0\.0\.0['\"]"
    r"|['\"]::['\"]"
    r"|host\s*=\s*['\"]0\.0\.0\.0['\"]"
    r"|listen\s*\(\s*[^,)]+,\s*['\"]0\.0\.0\.0['\"]",
)
_WILDCARD_CORS_RE = re.compile(
    r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]"
    r"|allow_origins\s*=\s*\[\s*['\"]\*['\"]"
    r"|origin\s*:\s*['\"]\*['\"]"
    r"|cors\s*\(\s*\)",          # bare cors() defaults to reflect-all
    re.IGNORECASE,
)

# Auth bypass-when-unset smell (Nocturne shape): middleware that skips auth
# when the token env var is empty.
_AUTH_BYPASS_WHEN_UNSET_RE = re.compile(
    r"if\s+not\s+\w*(?:API_)?TOKEN\w*"
    r"|API_TOKEN\s*(?:is\s+None|==\s*['\"]['\"]|or\s+not)"
    r"|!\s*process\.env\.\w*TOKEN\w*",
    re.IGNORECASE,
)

# TS comment stripping so a commented mention can't create a false signal.
_TS_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")


def _strip_ts_comments(text: str) -> str:
    text = _TS_BLOCK_COMMENT_RE.sub(" ", text)
    text = _TS_LINE_COMMENT_RE.sub(" ", text)
    return text


def _is_http_mcp_server(text: str, is_python: bool) -> bool:
    route_re = _PY_MCP_ROUTE_RE if is_python else _TS_MCP_ROUTE_RE
    return bool(route_re.search(text) or _HTTP_SERVER_RE.search(text))


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan for unauthenticated, network-bound MCP HTTP/SSE servers.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    # Azure-MCP repos are owned by AAK-AZURE-MCP-NOAUTH-001 — defer to avoid
    # double-firing the same finding under two rule IDs.
    if _is_azure_mcp_repo(project_root):
        return findings, scanned_files

    for path in project_root.rglob("*"):
        if path.suffix not in _PY_SUFFIXES + _TS_SUFFIXES:
            continue
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        is_python = path.suffix in _PY_SUFFIXES
        text = raw if is_python else _strip_ts_comments(raw)

        if not _is_http_mcp_server(text, is_python):
            continue
        # An auth marker anywhere in the file clears the finding (unless the
        # file also bypasses auth when the token is unset — the Nocturne bug).
        has_auth = bool(_AUTH_MARKER_RE.search(text))
        bypasses_when_unset = bool(_AUTH_BYPASS_WHEN_UNSET_RE.search(text))
        if has_auth and not bypasses_when_unset:
            continue

        exposed = _BIND_ALL_RE.search(text) or _WILDCARD_CORS_RE.search(text)
        if not exposed:
            continue

        why = "no inbound auth" if not has_auth else "auth bypassed when token unset"
        exposure = "binds 0.0.0.0/::" if _BIND_ALL_RE.search(text) else "wildcard CORS"

        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                f"MCP HTTP/SSE server: {why} on a network-exposed transport "
                f"({exposure}) — a mutation-capable, token-backed endpoint is "
                f"reachable without credentials (GitLab/Nocturne/AgenticMail "
                f"no-auth class). Require an inbound credential and bind to "
                f"127.0.0.1."
            ),
            find_line_number(raw, "0.0.0.0") or find_line_number(raw, "mcp"),
        ))

    return findings, scanned_files
