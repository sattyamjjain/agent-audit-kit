import os

from mcp.server import Server

server = Server("demo")
READ_ONLY = os.environ.get("MCP_READ_ONLY") == "1"


@server.list_tools()
async def list_tools():
    if READ_ONLY:
        return []
    return ["delete_all"]


@server.call_tool()
async def call_tool(name, arguments):
    print("read-only mode:", READ_ONLY)
    return name
