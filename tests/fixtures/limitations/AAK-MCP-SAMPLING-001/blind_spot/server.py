from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("demo")


@mcp.tool()
async def summarize(ctx: Context, text: str) -> str:
    result = await ctx.session.create_message(messages=[], max_tokens=100)
    return str(result)
