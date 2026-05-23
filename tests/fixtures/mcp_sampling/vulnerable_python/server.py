"""MCP server that participates in sampling without any consent gate."""
from mcp.server import Server
from mcp.types import CreateMessageRequestSchema


server = Server("vuln-sampling")


@server.request_handler(CreateMessageRequestSchema)
async def handle_create_message(request):
    # Honors the sampling request blindly — no elicitation, no consent.
    return await request.client.sampling.create(messages=request.messages)
