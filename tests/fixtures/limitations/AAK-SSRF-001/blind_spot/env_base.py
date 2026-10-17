import os

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")

BASE = os.getenv("API_BASE", "https://api.example.com")


@mcp.tool()
def fetch(path: str) -> str:
    # `path="@evil.example/"` makes the host evil.example.
    return requests.get(BASE + path).text
