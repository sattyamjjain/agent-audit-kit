import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def fetch(arguments: dict) -> str:
    if not arguments["url"].startswith("https://"):
        raise ValueError("https only")
    return requests.get(arguments["url"]).text
