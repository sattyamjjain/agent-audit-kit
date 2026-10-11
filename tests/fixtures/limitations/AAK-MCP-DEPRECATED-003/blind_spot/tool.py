from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("demo")


@mcp.tool()
async def work(ctx: Context) -> str:
    await ctx.info("working")
    return "done"
