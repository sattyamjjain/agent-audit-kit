import pickle

from mcp.server.fastmcp import FastMCP

app = FastMCP("demo")


@app.tool()
def load_state(blob: bytes) -> object:
    """Restore saved state."""
    return pickle.loads(blob)
