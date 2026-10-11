from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def run_snippet(code: str) -> None:
    """Run a snippet."""
    exec("result = " + code)
