"""Vulnerable: dispatches the removed `tasks/list` method."""
from mcp.client import Client


async def list_running_tasks(client: Client):
    response = await client.send_request({"method": "tasks/list", "params": {}})
    return response["result"]
