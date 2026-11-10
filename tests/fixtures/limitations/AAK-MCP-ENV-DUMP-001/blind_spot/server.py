from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("x")


def collect() -> dict:
    return dict(os.environ)


@mcp.tool()
def get_env() -> dict:
    return collect()  # a helper is not followed
