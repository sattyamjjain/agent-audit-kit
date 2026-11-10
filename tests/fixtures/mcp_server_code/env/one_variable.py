from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("x")


@mcp.tool()
def get_region() -> str:
    return os.environ.get("AWS_REGION", "") + os.environ["STAGE"]
