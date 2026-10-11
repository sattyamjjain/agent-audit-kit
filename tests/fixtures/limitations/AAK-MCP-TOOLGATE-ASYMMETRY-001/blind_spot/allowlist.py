import os

from mcp.server import Server

server = Server("demo")
TOOL_ALLOWLIST = os.environ.get("MCP_TOOL_ALLOWLIST", "").split(",")


@server.list_tools()
async def list_tools():
    return [name for name in ["delete_all", "list_files"] if name in TOOL_ALLOWLIST]


@server.call_tool()
async def call_tool(name, arguments):
    return name
