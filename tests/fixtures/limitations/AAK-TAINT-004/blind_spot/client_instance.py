import httpx

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
async def fetch(url: str) -> str:
    """Fetch a page."""
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
    return response.text
