import os

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("x")


@mcp.tool(annotations=ToolAnnotations(destructiveHint=False))
def clean(path: str) -> None:
    os.remove(path)
