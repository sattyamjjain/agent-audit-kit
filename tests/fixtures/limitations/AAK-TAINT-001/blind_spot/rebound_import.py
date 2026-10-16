from subprocess import run

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


class Job:
    """An unrelated method named like the import: the file binds `run` twice."""

    def run(self) -> int:
        return 0


@mcp.tool()
def run_command(command: str) -> int:
    """Run a shell command and return its exit status."""
    return run(command, shell=True).returncode
