from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("x")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
def note(path: str, text: str, db) -> None:
    db.execute("INSERT INTO notes VALUES (1)")
    with open(path, "a") as handle:
        handle.write(text)
