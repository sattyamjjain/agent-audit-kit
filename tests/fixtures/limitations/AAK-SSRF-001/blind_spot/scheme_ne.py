import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def fetch(arguments: dict) -> str:
    scheme = arguments["url"].split(":", 1)[0]
    if scheme != "https":
        raise ValueError("https only")
    return requests.get(arguments["url"]).text
