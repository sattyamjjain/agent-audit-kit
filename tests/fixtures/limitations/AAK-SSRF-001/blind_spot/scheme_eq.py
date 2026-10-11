import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def fetch(arguments: dict) -> str:
    scheme = "https"
    return requests.get(arguments["url"]).text if scheme else ""
