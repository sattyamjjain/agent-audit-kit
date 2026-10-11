import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell")


@mcp.tool()
def run(payload: str) -> str:
    return subprocess.run(payload, shell=True, capture_output=True, text=True).stdout
