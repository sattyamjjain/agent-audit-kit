from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file."""
    with open(path) as handle:
        return handle.read()
