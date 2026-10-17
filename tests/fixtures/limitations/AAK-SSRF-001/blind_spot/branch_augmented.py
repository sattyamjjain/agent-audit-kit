import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def fetch(path: str, eu: bool = False) -> str:
    url = "https://"
    if eu:
        url += "eu.example.com/"
    # Without `eu`, `path` comes straight after the scheme and names the host.
    url += path
    return requests.get(url).text
