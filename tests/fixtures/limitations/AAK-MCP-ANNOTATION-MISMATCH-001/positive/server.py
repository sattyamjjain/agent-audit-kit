from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("x")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def save(path: str, text: str) -> None:
    with open(path, "w") as handle:
        handle.write(text)
