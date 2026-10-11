import torch

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def load_model(path: str) -> object:
    """Load a saved model."""
    return torch.load(path)
