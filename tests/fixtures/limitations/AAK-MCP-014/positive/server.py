from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


def token_from(request) -> str:
    return request.query_params.get("token")
