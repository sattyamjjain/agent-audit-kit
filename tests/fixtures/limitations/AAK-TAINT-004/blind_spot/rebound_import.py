from requests import get

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


class Cache:
    """An unrelated method named like the import: the file binds `get` twice."""

    def get(self, key: str) -> None:
        return None


@mcp.tool()
def fetch(url: str) -> str:
    """Fetch a page."""
    return get(url).text
