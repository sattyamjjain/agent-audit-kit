import requests

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def fetch(url: str) -> str:
    """Fetch a page."""
    return requests.get(url).text
