import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

sh = subprocess.run


@mcp.tool()
def run_command(command: str) -> int:
    """Run a shell command and return its exit status."""
    return sh(command, shell=True).returncode
