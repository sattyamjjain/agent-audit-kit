from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("x")


@mcp.tool()
def get_env() -> dict:
    return {**os.environ}
