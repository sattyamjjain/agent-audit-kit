from mcp.server.fastmcp import FastMCP

mcp = FastMCP("gateway")
ROUTES = {"tools/list": "list", "tools/call": "call"}


def route(request, body):
    method = request.headers.get("Mcp-Method")
    print(body.get("method"))
    return ROUTES[method]
