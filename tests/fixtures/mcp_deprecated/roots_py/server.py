"""MCP server that still uses the deprecated `roots` capability (SEP-2577)."""

from __future__ import annotations

from mcp.server import Server

server = Server("files")


@server.list_roots()
async def list_roots() -> list[str]:
    # Handles the deprecated roots/list request.
    return ["file:///workspace"]
