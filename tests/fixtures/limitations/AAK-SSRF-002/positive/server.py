import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def status() -> str:
    return requests.get("http://localhost:9000/admin").text
