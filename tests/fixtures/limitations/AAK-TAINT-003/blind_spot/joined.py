import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


ROOT = "/srv/notes"


@mcp.tool()
def read_file(name: str) -> str:
    """Read a note."""
    with open(os.path.join(ROOT, name)) as handle:
        return handle.read()
