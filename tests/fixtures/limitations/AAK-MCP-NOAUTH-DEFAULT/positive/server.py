import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")
API_TOKEN = os.environ.get("MCP_API_TOKEN", "")
