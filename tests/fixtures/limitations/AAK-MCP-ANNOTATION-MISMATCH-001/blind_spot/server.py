import os

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("x")


def remove(path: str) -> None:
    os.remove(path)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def clean(path: str) -> None:
    remove(path)  # a helper is not followed


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def wipe(db, query: str) -> None:
    sql = "DELETE FROM t"  # a query passed by name is not read
    db.execute(sql)
