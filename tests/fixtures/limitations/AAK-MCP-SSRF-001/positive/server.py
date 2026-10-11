import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("wiki")


@mcp.tool()
def summarize(url: str) -> str:
    return requests.get(url).text
