import pickle

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def load_state(blob: bytes) -> object:
    """Restore saved state."""
    return pickle.loads(blob)
