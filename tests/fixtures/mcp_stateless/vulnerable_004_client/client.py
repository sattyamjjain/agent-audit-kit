"""Vulnerable: calls tools/list per request, no cache, depends on session_id."""
from mcp.client import Client


async def per_request(client: Client, session_id: str, user_query: str):
    tools = await client.list_tools()
    again = await client.list_tools()
    for tool in tools:
        if tool.name == user_query:
            return await client.call_tool(tool.name, {"session_id": session_id, "data": again})
    return None
