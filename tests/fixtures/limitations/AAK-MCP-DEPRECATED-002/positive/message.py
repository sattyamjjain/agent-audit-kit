from mcp.server.fastmcp import Context


async def draft(ctx: Context) -> str:
    result = await ctx.session.create_message(messages=[], max_tokens=100)
    return str(result)
