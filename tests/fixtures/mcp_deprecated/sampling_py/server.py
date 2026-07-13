"""MCP server that still uses the deprecated `sampling` capability (SEP-2577)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.types import CreateMessageRequest

mcp = FastMCP("assistant")


async def summarize(ctx, text: str) -> str:
    # Server-initiated sampling via the deprecated sampling/createMessage flow.
    req = CreateMessageRequest(messages=[{"role": "user", "content": text}])
    return await ctx.session.create_message(req)
