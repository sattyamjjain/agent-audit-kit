"""Clean: stateless MCP server, no session-id reliance, no tasks/list,
cached tools list, no shared session store."""
from functools import lru_cache

from mcp.server import Server

server = Server("stateless-clean")


@lru_cache(maxsize=1)
def cached_tools_list():
    return [{"name": "echo"}]


async def handle(request):
    tools = cached_tools_list()
    return {"tools": tools, "method": request["method"]}
