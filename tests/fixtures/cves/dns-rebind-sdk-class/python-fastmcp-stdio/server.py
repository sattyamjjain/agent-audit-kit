"""Precision guard: a stdio FastMCP server has no listener to rebind onto.

The advisory is explicit that only the network mode was reachable. This must
stay silent, or the rule fires on essentially every FastMCP server written.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("dash")


@mcp.tool()
def company_search(query: str) -> str:
    return f"results for {query}"


if __name__ == "__main__":
    mcp.run()
