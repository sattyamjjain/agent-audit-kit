"""MCP server with sampling gated behind elicitation/consent."""
from mcp.server import Server
from mcp.types import CreateMessageRequestSchema


server = Server("ok-sampling")


@server.request_handler(CreateMessageRequestSchema)
async def handle_create_message(request):
    # Require human approval before honoring the sampling request.
    consent = await request.client.elicit_input(
        prompt="The server is requesting an LLM completion. Allow?",
    )
    if not consent.granted:
        return None
    return await request.client.sampling.create(messages=request.messages)
