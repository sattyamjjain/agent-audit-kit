import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


def _download(url: str) -> str:
    return requests.get(url).text


@mcp.tool()
def fetch(url: str) -> str:
    return _download(url)
