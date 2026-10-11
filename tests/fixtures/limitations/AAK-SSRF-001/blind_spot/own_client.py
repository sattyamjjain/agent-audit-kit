import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def fetch(arguments: dict) -> str:
    http = requests.Session()
    return http.get(arguments["url"]).text
