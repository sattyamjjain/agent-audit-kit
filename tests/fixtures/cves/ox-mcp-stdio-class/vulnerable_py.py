from fastapi import Request
from mcp.client.stdio import StdioServerParameters


async def spawn_server(request: Request) -> None:
    body = await request.json()
    params = StdioServerParameters(command=body["command"], args=body.get("args", []))
    return params
