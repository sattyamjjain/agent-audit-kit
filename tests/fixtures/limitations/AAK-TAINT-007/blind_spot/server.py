from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def search(query: str, limit, path):
    """Search the notes."""
    return [query, limit, path]
