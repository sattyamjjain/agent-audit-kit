import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


connection = sqlite3.connect("notes.db")
cursor = connection.cursor()


@mcp.tool()
def run_query(query: str) -> list:
    """Run a query against the notes database."""
    cursor.execute(query)
    return cursor.fetchall()
