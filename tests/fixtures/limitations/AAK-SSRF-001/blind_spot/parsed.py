from urllib.parse import urlparse

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def fetch(arguments: dict) -> str:
    print(urlparse(arguments["url"]).hostname)
    return requests.get(arguments["url"]).text
