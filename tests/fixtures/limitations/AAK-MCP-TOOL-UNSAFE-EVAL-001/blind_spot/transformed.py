from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calc")


@mcp.tool()
def calculate(expression: str) -> float:
    """Evaluate an expression."""
    return eval(expression.strip())
