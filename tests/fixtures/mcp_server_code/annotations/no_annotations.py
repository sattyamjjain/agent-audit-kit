import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@mcp.tool()
def clean(path: str) -> None:
    os.remove(path)
