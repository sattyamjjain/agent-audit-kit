import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


@mcp.tool()
def status() -> str:
    return requests.get("http://10-0-0-5.sslip.io/status").text
