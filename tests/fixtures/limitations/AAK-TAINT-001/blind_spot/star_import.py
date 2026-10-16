# A star import is what this fixture is about, so ruff's F403/F405 are waived.
from subprocess import *  # noqa: F403

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def run_command(command: str) -> int:
    """Run a shell command and return its exit status."""
    return run(command, shell=True).returncode  # noqa: F405
