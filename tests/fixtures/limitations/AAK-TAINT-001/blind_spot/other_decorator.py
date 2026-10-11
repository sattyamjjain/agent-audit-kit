import os

from mcp.server.fastmcp import FastMCP

app = FastMCP("demo")


@app.tool()
def run_command(command: str) -> int:
    """Run a shell command and return its exit status."""
    return os.system(command)
