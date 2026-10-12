import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def run_python(code: str) -> str:
    """Run a Python snippet and return its output."""
    return subprocess.run(["python3"], input=code, capture_output=True, text=True).stdout
