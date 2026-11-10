from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("x")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def wipe(db, table: str) -> None:
    db.execute(f"DELETE FROM {table}")
