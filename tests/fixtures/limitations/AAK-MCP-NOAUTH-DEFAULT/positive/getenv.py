import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")
ADMIN_TOKEN = os.getenv("MCP_ADMIN_TOKEN", "")
