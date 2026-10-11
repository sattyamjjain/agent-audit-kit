import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


def fetch_page(address):
    return requests.get(address).text


@mcp.tool()
def fetch(arguments: dict) -> str:
    return fetch_page(arguments["url"])
