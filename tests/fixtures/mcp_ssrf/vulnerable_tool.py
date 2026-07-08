"""Vulnerable MCP tool handler — CVE-2026-14748 shape.

An MCP `wiki-summary` tool takes a caller-supplied `url` argument and fetches it
server-side with no host/scheme allow-list, so the caller controls the outbound
destination (SSRF, CWE-918). Mirrors mcp-wiki/src/mcp_wiki/server.py.
"""

from __future__ import annotations

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("wiki")


@mcp.tool()
def wiki_summary(url: str) -> str:
    """Fetch and summarize the wiki page at the given URL."""
    resp = requests.get(url, timeout=10)
    return resp.text[:500]
