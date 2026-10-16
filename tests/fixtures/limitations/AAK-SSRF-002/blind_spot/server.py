import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def status() -> str:
    first = requests.get("http://127.0.0.2:9000/admin").text
    second = requests.get("http://[fd12:3456::7]:9000/admin").text
    return first + second
