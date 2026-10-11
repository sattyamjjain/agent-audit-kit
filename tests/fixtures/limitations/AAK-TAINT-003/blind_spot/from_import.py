from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file."""
    return Path(path).read_text()
