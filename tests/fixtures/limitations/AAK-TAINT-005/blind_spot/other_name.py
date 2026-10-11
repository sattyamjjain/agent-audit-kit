import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


conn = sqlite3.connect("notes.db")


@mcp.tool()
def run_query(query: str) -> list:
    """Run a query against the notes database."""
    return conn.execute(query).fetchall()
