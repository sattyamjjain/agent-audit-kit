import sqlite3

from mcp.server.fastmcp import FastMCP

app = FastMCP("demo")


connection = sqlite3.connect("notes.db")
cursor = connection.cursor()


@app.tool()
def run_query(query: str) -> list:
    """Run a query against the notes database."""
    cursor.execute(query)
    return cursor.fetchall()
