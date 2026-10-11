from flask import request
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def token_from() -> str:
    return request.args.get("token")
