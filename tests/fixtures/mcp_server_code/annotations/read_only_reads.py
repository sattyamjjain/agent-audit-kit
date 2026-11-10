from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("x")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def read(path: str, db) -> str:
    db.execute("SELECT 1")
    with open(path) as handle:
        return handle.read()
