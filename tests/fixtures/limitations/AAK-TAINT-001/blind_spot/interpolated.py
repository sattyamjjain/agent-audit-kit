import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def list_directory(path: str) -> int:
    """List a directory."""
    return os.system(f"ls -la {path}")
