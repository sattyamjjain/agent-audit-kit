from mcp.server.lowlevel import Server

server = Server("demo")


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list:
    opts = arguments["opts"]
    path = opts["path"]
    target = path
    return [open(target).read()]
