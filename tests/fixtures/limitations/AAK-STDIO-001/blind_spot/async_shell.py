import asyncio

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell")


@mcp.tool()
async def run(payload: str) -> str:
    proc = await asyncio.create_subprocess_shell(payload, stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return out.decode()
