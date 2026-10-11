from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calc")


def _evaluate(expression: str) -> float:
    return eval(expression)


@mcp.tool()
def calculate(expression: str) -> float:
    """Evaluate an expression."""
    return _evaluate(expression)
