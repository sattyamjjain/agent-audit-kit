from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent_audit_kit.models import Finding
from agent_audit_kit.scanners._helpers import (
    CONFIG_MAX_BYTES,
    in_skip_dir,
    is_loopback_url,
    iter_mcp_servers,
    loads_jsonc,
    make_finding,
    placed,
    read_text_capped,
    url_readings,
)

# ---- MCP config file discovery (mirrors mcp_config.py) ----
_MCP_CONFIG_FILES: list[str] = [
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".amazonq/mcp.json",
    "mcp.json",
]

# ---- AAK-TRANSPORT-001: cleartext URLs (excluding localhost / loopback) ----
#
# Applies to the two cleartext remote schemes MCP is carried over: `http://`
# and `ws://`. `ws://` is not a lesser case of the same defect -- it is the
# same defect. A WebSocket handshake over `ws://` is an unencrypted HTTP
# upgrade, so credentials in the handshake headers and every frame after it
# are on the wire in clear, exactly as with `http://`. `wss://` is the
# encrypted counterpart and is not flagged, as `https://` is not.
#
# This read `^http://` only until v0.3.93, so a `ws://` MCP server was silently
# exempt from the project's cleartext-transport rule while the byte-identical
# `http://` server was CRITICAL. Found via CVE-2026-37006 (gpt-researcher
# WebSocket endpoint); see tests/test_cve_2026_37006_websocket_transport.py.
#
# stdio has no URL and is out of scope for this rule by construction. A loopback
# host is exempt through `_helpers.is_loopback_url`, the definition AAK-MCP-001
# and AAK-MCP-009 share; it replaced an anchored regex that knew 127.0.0.1 alone
# of the 127.0.0.0/8 block.
_CLEARTEXT_URL_RE = re.compile(r"^(http|ws)://", re.IGNORECASE)


def _cleartext_scheme(url: str) -> str | None:
    """`http` or `ws` when a client would reach `url` in cleartext, else None.

    The anchored regex alone missed every spelling a client accepts that does
    not open with `http://`: a leading space, `http:/host`, `http:\\\\host`, a
    tab inside the scheme. Node strips, removes and skips those as
    `url_readings` describes, so such a server was reached in cleartext with no
    finding. The regex stays as the first test, so a URL it matched still fires.
    """
    match = _CLEARTEXT_URL_RE.match(url)
    if match:
        return match.group(1).lower()
    for reading in url_readings(url):
        if reading.scheme in ("http", "ws"):
            return reading.scheme
    return None

# ---- AAK-TRANSPORT-002: TLS validation disabling ----
_TLS_DISABLE_KEYS = {
    "NODE_TLS_REJECT_UNAUTHORIZED": "0",
}
_SSL_CERT_OVERRIDE_KEY = "SSL_CERT_FILE"

# ---- AAK-TRANSPORT-003: SSE transport indicators ----
_SSE_URL_RE = re.compile(r"/sse\b", re.IGNORECASE)
# The keys a client config declares a server's transport under. `type` is the
# one Claude Code and VS Code write. The rule read `transport` alone, so
# on the State of MCP corpus it missed 11 of the 47 configs that declare SSE:
# each a `"type": "sse"` server at a URL without a whole-word `/sse`.
_TRANSPORT_KEYS = ("transport", "type")

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
        if in_skip_dir(p, project_root):
            continue
        if p.is_file() and p not in found:
            found.append(p)
    return found


def _check_server(
    server_name: str,
    server_cfg: dict[str, Any],
    rel_path: str,
) -> list[tuple[Finding, str]]:
    """Run transport security rules against a single MCP server block; each finding
    comes with the key its line is found by (see `placed`)."""
    findings: list[tuple[Finding, str]] = []

    # A malformed config can put a non-string here; the MCP-config scanner
    # reports that as AAK-MCP-CONFIG-MALFORMED-001. Reading it as "" means the
    # transport rules skip a value they cannot evaluate instead of raising
    # TypeError out of the regex and taking the scanner down (issue #743).
    _raw_url = server_cfg.get("url", "")
    url: str = _raw_url if isinstance(_raw_url, str) else ""
    env: dict[str, Any] = server_cfg.get("env", {})

    # AAK-TRANSPORT-001: cleartext http:// or ws://, excluding loopback
    scheme = _cleartext_scheme(url) if url else None
    if scheme and not is_loopback_url(url):
        secure = "wss" if scheme == "ws" else "https"
        findings.append((make_finding(
            "AAK-TRANSPORT-001",
            rel_path,
            f"Server '{server_name}' URL: {url} — cleartext {scheme}:// "
            f"(use {secure}://)",
        ), url))

    # AAK-TRANSPORT-002: TLS validation disabled
    if isinstance(env, dict):
        for env_key, bad_value in _TLS_DISABLE_KEYS.items():
            val = env.get(env_key)
            if isinstance(val, str) and val == bad_value:
                findings.append((make_finding(
                    "AAK-TRANSPORT-002",
                    rel_path,
                    f"Server '{server_name}' env.{env_key}={val}",
                ), env_key))
        # SSL_CERT_FILE override
        if _SSL_CERT_OVERRIDE_KEY in env:
            findings.append((make_finding(
                "AAK-TRANSPORT-002",
                rel_path,
                f"Server '{server_name}' env.{_SSL_CERT_OVERRIDE_KEY}={env[_SSL_CERT_OVERRIDE_KEY]}",
            ), _SSL_CERT_OVERRIDE_KEY))

    # AAK-TRANSPORT-003: Deprecated SSE transport, reported once per server: by
    # the key that declares it when the server has one, otherwise by its URL.
    # Read as two independent checks, a `type: sse` server at an `/sse` URL, the
    # commonest shape, would be reported twice, as one with `transport: sse`
    # was. The line is the server's own `url` line when it has one: the first
    # "sse" anywhere in the file can sit in another server, or in a name such as
    # `assessment`.
    declared = next(
        (key for key in _TRANSPORT_KEYS
         if isinstance(server_cfg.get(key), str) and server_cfg[key].lower() == "sse"),
        None,
    )
    if declared is not None:
        findings.append((make_finding(
            "AAK-TRANSPORT-003",
            rel_path,
            f"Server '{server_name}' {declared}: sse (deprecated)",
        ), url or "sse"))
    elif url and _SSE_URL_RE.search(url):
        findings.append((make_finding(
            "AAK-TRANSPORT-003",
            rel_path,
            f"Server '{server_name}' URL contains /sse: {url}",
        ), url))

    # AAK-TRANSPORT-004: Token / key / secret in URL query string
    if url and _TOKEN_QUERY_RE.search(url):
        findings.append((make_finding(
            "AAK-TRANSPORT-004",
            rel_path,
            f"Server '{server_name}' URL query contains credential: {url}",
        ), url))

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
            raw_text = read_text_capped(config_path, CONFIG_MAX_BYTES, errors="replace")
            if len(raw_text) > 1_000_000:
                continue
            data = loads_jsonc(raw_text, config_path)
        except (json.JSONDecodeError, OSError):
            continue

        rel_path = (
            str(config_path.relative_to(project_root))
            if config_path.is_relative_to(project_root)
            else str(config_path)
        )
        scanned_files.add(rel_path)

        # `mcpServers`, and VS Code's `servers`, which this read past until
        # mcp_server_maps: a cleartext VS Code server came back clean.
        unplaced: list[tuple[Finding, str]] = []
        for server_name, server_cfg in iter_mcp_servers(data):
            unplaced.extend(_check_server(server_name, server_cfg, rel_path))
        # Every finding's line in one pass over the file, not one search of it per finding.
        findings.extend(placed(raw_text, unplaced))

    return findings, scanned_files
