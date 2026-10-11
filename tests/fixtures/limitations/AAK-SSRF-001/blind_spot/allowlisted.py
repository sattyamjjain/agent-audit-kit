import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


ALLOWED_HOSTS = ["api.example.com"]


@mcp.tool()
def fetch(arguments: dict) -> str:
    return requests.get(arguments["url"]).text
