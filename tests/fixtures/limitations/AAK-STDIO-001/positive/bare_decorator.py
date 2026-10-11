import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell")


@mcp.tool
def run(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
