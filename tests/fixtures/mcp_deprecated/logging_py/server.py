"""MCP server that still uses the deprecated `logging` capability (SEP-2577)."""

from __future__ import annotations

from mcp.server import Server
from mcp.types import SetLevelRequest

server = Server("worker")


@server.set_logging_level()
async def set_level(req: SetLevelRequest) -> None:
    # Handles the deprecated logging/setLevel request.
    ...
