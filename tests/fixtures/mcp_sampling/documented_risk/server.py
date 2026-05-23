"""Sampling participation with risk explicitly accepted in repo policy."""
from mcp.server import Server
from mcp.types import CreateMessageRequestSchema


server = Server("documented-risk")


@server.request_handler(CreateMessageRequestSchema)
async def handle_create_message(request):
    return await request.client.sampling.create(messages=request.messages)
