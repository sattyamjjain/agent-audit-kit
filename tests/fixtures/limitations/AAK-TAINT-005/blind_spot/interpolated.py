import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


connection = sqlite3.connect("notes.db")
cursor = connection.cursor()


@mcp.tool()
def find_note(title: str) -> list:
    """Find notes by title."""
    cursor.execute(f"SELECT * FROM notes WHERE title = '{title}'")
    return cursor.fetchall()
