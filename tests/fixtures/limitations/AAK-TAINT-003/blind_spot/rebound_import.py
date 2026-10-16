from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def describe(Path: object) -> str:
    """A parameter named like the import: the file binds `Path` twice."""
    return str(Path)


@mcp.tool()
def read_note(path: str) -> str:
    """Read a note."""
    return Path(path).read_text()
