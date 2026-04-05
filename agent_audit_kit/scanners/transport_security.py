from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import find_line_number, make_finding, SKIP_DIRS

# ---- MCP config file discovery (mirrors mcp_config.py) ----
_MCP_CONFIG_FILES: list[str] = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".amazonq/mcp.json",
    "mcp.json",
]

# ---- AAK-TRANSPORT-001: HTTP URLs (excluding localhost / loopback) ----
_HTTP_URL_RE = re.compile(r"^http://", re.IGNORECASE)
_LOCALHOST_RE = re.compile(
    r"^http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(:\d+)?(/|$)",
    re.IGNORECASE,
)

# ---- AAK-TRANSPORT-002: TLS validation disabling ----
_TLS_DISABLE_KEYS = {
    "NODE_TLS_REJECT_UNAUTHORIZED": "0",
}
_SSL_CERT_OVERRIDE_KEY = "SSL_CERT_FILE"

# ---- AAK-TRANSPORT-003: SSE transport indicators ----
_SSE_URL_RE = re.compile(r"/sse\b", re.IGNORECASE)

# ---- AAK-TRANSPORT-004: Token in URL query string ----
_TOKEN_QUERY_RE = re.compile(
    r"[?&](token|key|api_key|apikey|secret|auth|access_token|session_token)=",
    re.IGNORECASE,
)


def _find_mcp_configs(project_root: Path) -> list[Path]:
    """Discover MCP configuration files in the project."""
    found: list[Path] = []
    for name in _MCP_CONFIG_FILES:
        p = project_root / name
        if p.is_file():
            found.append(p)
    for p in project_root.rglob("*mcp*.json"):
        if any(part in SKIP_DIRS for part in p.relative_to(project_root).parts):
            continue
        if p.is_file() and p not in found:
            found.append(p)
    return found


def _check_server(
    server_name: str,
    server_cfg: dict[str, Any],
    rel_path: str,
    raw_text: str,
) -> list[Finding]:
    """Run transport security rules against a single MCP server block."""
    findings: list[Finding] = []

    url: str = server_cfg.get("url", "")
    env: dict[str, Any] = server_cfg.get("env", {})
    transport: str = server_cfg.get("transport", "")

    # AAK-TRANSPORT-001: HTTP (not HTTPS), excluding localhost
    if url and _HTTP_URL_RE.match(url) and not _LOCALHOST_RE.match(url):
        findings.append(make_finding(
            "AAK-TRANSPORT-001",
            rel_path,
            f"Server '{server_name}' URL: {url}",
            find_line_number(raw_text, url),
        ))

    # AAK-TRANSPORT-002: TLS validation disabled
    if isinstance(env, dict):
        for env_key, bad_value in _TLS_DISABLE_KEYS.items():
            val = env.get(env_key)
            if isinstance(val, str) and val == bad_value:
                findings.append(make_finding(
                    "AAK-TRANSPORT-002",
                    rel_path,
                    f"Server '{server_name}' env.{env_key}={val}",
                    find_line_number(raw_text, env_key),
                ))
        # SSL_CERT_FILE override
        if _SSL_CERT_OVERRIDE_KEY in env:
            findings.append(make_finding(
                "AAK-TRANSPORT-002",
                rel_path,
                f"Server '{server_name}' env.{_SSL_CERT_OVERRIDE_KEY}={env[_SSL_CERT_OVERRIDE_KEY]}",
                find_line_number(raw_text, _SSL_CERT_OVERRIDE_KEY),
            ))

    # AAK-TRANSPORT-003: Deprecated SSE transport
    if url and _SSE_URL_RE.search(url):
        findings.append(make_finding(
            "AAK-TRANSPORT-003",
            rel_path,
            f"Server '{server_name}' URL contains /sse: {url}",
            find_line_number(raw_text, url),
        ))
    if isinstance(transport, str) and transport.lower() == "sse":
        findings.append(make_finding(
            "AAK-TRANSPORT-003",
            rel_path,
            f"Server '{server_name}' transport: sse (deprecated)",
            find_line_number(raw_text, "sse"),
        ))

    # AAK-TRANSPORT-004: Token / key / secret in URL query string
    if url and _TOKEN_QUERY_RE.search(url):
        findings.append(make_finding(
            "AAK-TRANSPORT-004",
            rel_path,
            f"Server '{server_name}' URL query contains credential: {url}",
            find_line_number(raw_text, url),
        ))

    return findings


def scan(project_root: Path) -> tuple[list[Finding], set[str]]:
    """Scan MCP config files for transport security issues.

    Args:
        project_root: The root directory of the project to scan.

    Returns:
        A tuple of (list of findings, set of scanned file relative paths).
    """
    findings: list[Finding] = []
    scanned_files: set[str] = set()

    for config_path in _find_mcp_configs(project_root):
        try:
            raw_text = config_path.read_text(encoding="utf-8")
            if len(raw_text) > 1_000_000:
                continue
            data = json.loads(raw_text)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = (
            str(config_path.relative_to(project_root))
            if config_path.is_relative_to(project_root)
            else str(config_path)
        )
        scanned_files.add(rel_path)

        servers = data.get("mcpServers", {})
        if not isinstance(servers, dict):
            continue

        for server_name, server_cfg in servers.items():
            if isinstance(server_cfg, dict):
                findings.extend(
                    _check_server(server_name, server_cfg, rel_path, raw_text)
                )

    return findings, scanned_files
