from app import work
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@mcp.tool()
def run() -> str:
    try:
        return work()
    except ValueError as e:
        return f"failed: {e}"
