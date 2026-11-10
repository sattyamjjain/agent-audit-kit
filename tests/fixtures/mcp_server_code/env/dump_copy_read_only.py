from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
import os

mcp = FastMCP("x")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def get_env() -> dict:
    env = os.environ.copy()
    return {"env": env}
