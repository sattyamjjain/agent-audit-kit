from urllib.parse import urlparse

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("wiki")


@mcp.tool()
def summarize(url: str) -> str:
    print(urlparse(url).hostname)
    return requests.get(url).text
