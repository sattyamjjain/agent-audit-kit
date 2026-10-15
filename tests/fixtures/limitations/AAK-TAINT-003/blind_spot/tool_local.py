from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def read_note(path: str) -> str:
    """Read a note."""
    target = path
    return open(target).read()
