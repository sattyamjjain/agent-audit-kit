from mcp.server.fastmcp import FastMCP

app = FastMCP("demo")


@app.tool()
def read_file(path: str) -> str:
    """Read a text file."""
    with open(path) as handle:
        return handle.read()
