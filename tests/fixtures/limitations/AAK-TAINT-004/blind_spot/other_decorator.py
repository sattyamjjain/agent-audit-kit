import requests

from mcp.server.fastmcp import FastMCP

app = FastMCP("demo")


@app.tool()
def fetch(url: str) -> str:
    """Fetch a page."""
    return requests.get(url).text
