from app import work
import traceback

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@mcp.tool()
def run() -> str:
    try:
        return work()
    except Exception:
        return traceback.format_exc()
