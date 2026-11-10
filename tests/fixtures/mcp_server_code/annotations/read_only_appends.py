from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


@mcp.tool(annotations={"readOnlyHint": True})
def note(path: str, text: str) -> None:
    with open(path, "a") as handle:
        handle.write(text)
