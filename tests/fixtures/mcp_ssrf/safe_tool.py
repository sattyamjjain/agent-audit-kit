"""Host-allow-listed MCP tool handler — the safe counterpart to CVE-2026-14748.

Same `wiki-summary` tool, but the caller-supplied `url` is parsed and validated
against an explicit host allow-list and an https scheme pin before any fetch, so
a caller cannot steer the outbound request at internal/metadata endpoints. This
must NOT fire AAK-MCP-SSRF-001.
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("wiki")

ALLOWED_HOSTS = {"en.wikipedia.org", "simple.wikipedia.org"}


@mcp.tool()
def wiki_summary(url: str) -> str:
    """Fetch a wiki page summary from an allow-listed host over https only."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("url host is not on the allow-list")
    resp = requests.get(url, timeout=10)
    return resp.text[:500]
