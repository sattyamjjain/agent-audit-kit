from mcp.server.fastmcp import Context


async def roots(ctx: Context) -> str:
    return str(await ctx.session.list_roots())
