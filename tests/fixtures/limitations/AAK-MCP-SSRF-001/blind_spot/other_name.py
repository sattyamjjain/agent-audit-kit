import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("wiki")


@mcp.tool()
def summarize(website: str) -> str:
    return requests.get(website).text
