from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def calc(expression: str) -> object:
    """Evaluate an expression. The check admits no name, so `eval` can call
    nothing, but `9**9**9` still holds the process."""
    if not set(expression) <= set("0123456789+-*/(). "):
        raise ValueError("only digits and operators")
    return eval(expression)
