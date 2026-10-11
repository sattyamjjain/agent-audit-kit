from subprocess import run

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def run_command(command: str) -> int:
    """Run a shell command and return its exit status."""
    return run(command, shell=True).returncode
