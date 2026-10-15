import sqlite3

from mcp.server.lowlevel import Server

server = Server("demo")
connection = sqlite3.connect("notes.db")
cursor = connection.cursor()


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list:
    sql = arguments["sql"]
    cursor.execute(sql)
    return cursor.fetchall()
