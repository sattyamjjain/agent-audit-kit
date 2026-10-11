from urllib.request import urlopen

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def fetch(url: str) -> bytes:
    """Fetch a page."""
    return urlopen(url).read()
