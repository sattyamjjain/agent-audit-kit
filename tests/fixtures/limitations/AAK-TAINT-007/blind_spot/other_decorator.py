from mcp.server.fastmcp import FastMCP

app = FastMCP("demo")


@app.tool()
def search(query, limit, path):
    """Search the notes."""
    return [query, limit, path]
