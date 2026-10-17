import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


connection = sqlite3.connect("notes.db")
cursor = connection.cursor()


@mcp.tool()
def find_by_title(title: str) -> list:
    """Find notes by title."""
    cursor.execute("SELECT * FROM notes WHERE title = '{}'".format(title))
    return cursor.fetchall()


@mcp.tool()
def find_by_author(author: str) -> list:
    """Find notes by author."""
    cursor.execute("SELECT * FROM notes WHERE author = '%s'" % author)
    return cursor.fetchall()


@mcp.tool()
def find_by_tag(tag: str) -> list:
    """Find notes by tag."""
    cursor.execute("SELECT * FROM notes WHERE tag = '" + tag + "'")
    return cursor.fetchall()
