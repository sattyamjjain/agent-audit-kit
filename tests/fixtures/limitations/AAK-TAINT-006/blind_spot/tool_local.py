import pickle

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def load_state(blob: str) -> object:
    """Restore saved state."""
    data = blob
    return pickle.loads(data)
