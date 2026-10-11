import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("wiki")


def fetch_page(address):
    return requests.get(address).text


@mcp.tool()
def summarize(url: str) -> str:
    return fetch_page(url)
