from mcp.server.fastmcp import FastMCP

app = FastMCP("demo")


@app.tool()
def calc(expression: str) -> object:
    """Evaluate an expression."""
    return eval(expression)
