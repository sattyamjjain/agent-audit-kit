import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")


def resolve_base(host: str) -> str:
    return host or "https://api.example.com"


@mcp.tool()
def status(host: str) -> str:
    base = resolve_base(host)
    return requests.get(base + "/status").text
