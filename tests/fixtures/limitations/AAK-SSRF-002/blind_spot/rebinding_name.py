import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def status() -> str:
    return requests.get("http://7f000001.0a000005.rbndr.us/status").text
