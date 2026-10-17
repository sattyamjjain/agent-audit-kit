import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")

HOST = "2130706433"


@mcp.tool()
def status() -> str:
    return requests.get("http://" + HOST + ":9000/admin").text
