from fastmcp import FastMCP

mcp = FastMCP("plain")


@mcp.tool
def add(a: int, b: int) -> int:
    return a + b
