from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def calc(expression: str) -> object:
    """Evaluate an expression."""
    return eval(expression.strip())
