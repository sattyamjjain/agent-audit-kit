async def confirm_delete(ctx, name):
    return await ctx.elicit(message=f"Delete {name}?", schema=None)
