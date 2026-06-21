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

# ---------------------------------------------------------------------------
# Config-file / Docker / inspector-startup surface (CVE-2026-23744 class).
#
# The source-file path above only sees `.py`/`.ts` server code. MCP servers
# and the MCP Inspector are very often *launched* from a config or Dockerfile
# — `claude_desktop_config.json` / `mcp.json` `command`+`args`, a
# `*.mcp.yaml`, `npx @modelcontextprotocol/inspector --host 0.0.0.0`, or a
# Docker `--host 0.0.0.0` / `-p 0.0.0.0:` publish. CVE-2026-23744 (MCP
# Inspector, CVSS 9.8) is the motivating exemplar; Censys counted ~12,520
# MCP services exposed on the public internet in this shape.
# ---------------------------------------------------------------------------

# MCP / inspector / FastMCP context in a config, compose, or Dockerfile.
_CONFIG_MCP_CTX_RE = re.compile(
    r"mcpServers"
    r"|modelcontextprotocol[/-]inspector"
    r"|@modelcontextprotocol/inspector"
    r"|mcpjam"
    r"|fastmcp"
    r"|\bmcp\s+run\b"
    r"|--transport[=\s]+(?:sse|http|streamable-http)"
    r"|SSEServerTransport|StreamableHTTPServerTransport"
    r"|\bmcp\b[^\n]*--host",
    re.IGNORECASE,
)

# Bind-all signals (escaped). The bracketed bridge tolerates JSON `args` arrays
# where the host flag and the value are separate elements (flag, then the
# all-interfaces value in the next array element).
_CONFIG_BIND_ALL_RE = re.compile(
    r"0\.0\.0\.0"
    r"|\[::\]"
    r"|--host[=\s\"',\[\]]+::(?:\b|[\"']|$)"
    r"|[\"']host[\"']\s*:\s*[\"']::[\"']"
    r"|-p\s+0\.0\.0\.0:",
)

# An explicit host assignment to a routable (non-loopback) IPv4 literal.
_CONFIG_ROUTABLE_HOST_RE = re.compile(
    r"(?:--host[=\s\"',\[\]]+|[\"']host[\"']\s*:\s*[\"']|host\s*=\s*[\"'])"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
)

# Config / CLI auth markers (in addition to the source _AUTH_MARKER_RE).
_CONFIG_AUTH_RE = re.compile(
    r"--auth\b"
    r"|--require-auth\b"
    r"|MCP_PROXY_AUTH_TOKEN"
    r"|x-admin-key"
    r"|requireAuth"
    r"|Authorization"
    r"|[Bb]earer"
    r"|--token\b|[\"']token[\"']|api[-_]?key|apiKey",
    re.IGNORECASE,
)

# Inspector's explicit auth kill-switch — overrides any auth marker.
_OMIT_AUTH_RE = re.compile(
    r"DANGEROUSLY_OMIT_AUTH\s*[:=]\s*[\"']?(?:true|1)\b",
    re.IGNORECASE,
)

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_CONFIG_SUFFIXES = (".json", ".yaml", ".yml")


def _strip_ts_comments(text: str) -> str:
    text = _TS_BLOCK_COMMENT_RE.sub(" ", text)
    text = _TS_LINE_COMMENT_RE.sub(" ", text)
    return text


def _is_http_mcp_server(text: str, is_python: bool) -> bool:
    route_re = _PY_MCP_ROUTE_RE if is_python else _TS_MCP_ROUTE_RE
    return bool(route_re.search(text) or _HTTP_SERVER_RE.search(text))


def _is_config_file(path: Path) -> bool:
    """True for MCP config / compose / Dockerfile launch artifacts."""
    if path.suffix.lower() in _CONFIG_SUFFIXES:
        return True
    return path.name.lower().startswith("dockerfile")


def _scan_config(raw: str) -> tuple[str, str] | None:
    """Detect a non-loopback MCP/inspector launch bind with no auth.

    Returns (resolved_bind, route_description) when an MCP/inspector/FastMCP
    config or Dockerfile binds a non-loopback interface with no auth marker
    (or an explicit ``DANGEROUSLY_OMIT_AUTH``), else ``None``.
    """
    if not _CONFIG_MCP_CTX_RE.search(raw):
        return None

    bind: str | None = None
    if _CONFIG_BIND_ALL_RE.search(raw):
        bind = "0.0.0.0/::"
    else:
        m = _CONFIG_ROUTABLE_HOST_RE.search(raw)
        if m and not m.group(1).startswith("127."):
            bind = m.group(1)
    if bind is None:
        return None

    omit_auth = bool(_OMIT_AUTH_RE.search(raw))
    has_auth = bool(_AUTH_MARKER_RE.search(raw) or _CONFIG_AUTH_RE.search(raw))
    if has_auth and not omit_auth:
        return None

    route = (
        "connect/tool-exec route (DANGEROUSLY_OMIT_AUTH set)"
        if omit_auth else
        "connect/tool-exec route (no token / requireAuth)"
    )
    return bind, route


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
        is_source = path.suffix in _PY_SUFFIXES + _TS_SUFFIXES
        is_config = _is_config_file(path)
        if not (is_source or is_config):
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

        # --- Source files: server code binding 0.0.0.0/wildcard-CORS, no auth.
        if is_source:
            is_python = path.suffix in _PY_SUFFIXES
            text = raw if is_python else _strip_ts_comments(raw)

            if not _is_http_mcp_server(text, is_python):
                continue
            # An auth marker anywhere in the file clears the finding (unless the
            # file also bypasses auth when the token is unset — Nocturne bug).
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
            continue

        # --- Config / Docker / inspector launch artifacts (CVE-2026-23744).
        result = _scan_config(raw)
        if result is None:
            continue
        bind, route = result
        rel_path = str(path.relative_to(project_root))
        scanned_files.add(rel_path)
        findings.append(make_finding(
            _RULE_ID,
            rel_path,
            (
                f"MCP server/inspector config binds {bind} on the {route} with "
                f"no authentication — a network-exposed, mutation-capable "
                f"endpoint reachable without credentials (CVE-2026-23744 MCP "
                f"Inspector class; ~12,520 MCP services exposed per Censys). "
                f"Bind 127.0.0.1 or require a bearer token / x-admin-key on the "
                f"connect/exec route."
            ),
            find_line_number(raw, bind.split("/")[0]) or find_line_number(raw, "host"),
        ))

    return findings, scanned_files
