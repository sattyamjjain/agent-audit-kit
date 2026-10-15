import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def run_command(command: str) -> int:
    """Run a shell command and return its exit status."""
    cmd = command
    return os.system(cmd)
