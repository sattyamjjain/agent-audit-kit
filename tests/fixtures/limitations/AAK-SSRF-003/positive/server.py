import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def identity() -> str:
    return requests.get("http://169.254.169.254/latest/meta-data/").text
