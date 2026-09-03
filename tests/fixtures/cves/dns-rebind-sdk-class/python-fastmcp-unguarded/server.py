"""CVE-2026-81102 shape: FastMCP over a network transport, no Host allow-list.

Binding to loopback is not the control. A name pointed at 127.0.0.1 still
reaches this listener while carrying the attacker's Host header.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("dash")


@mcp.tool()
def company_search(query: str) -> str:
    return f"results for {query}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="127.0.0.1", port=8000)
