import requests
from mcp.server.fastmcp import FastMCP

app = FastMCP("fetcher")


@app.tool()
def fetch(url: str) -> str:
    return requests.get(url).text
