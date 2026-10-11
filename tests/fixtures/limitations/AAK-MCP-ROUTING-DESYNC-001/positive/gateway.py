from mcp.server.fastmcp import FastMCP

mcp = FastMCP("gateway")
ROUTES = {"tools/list": "list", "tools/call": "call"}


def route(request):
    method = request.headers.get("Mcp-Method")
    return ROUTES[method]
