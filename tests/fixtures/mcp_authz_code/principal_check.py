from app import authorize, ctx, mcp, rows


@mcp.tool()
def list_rows(org_id: str) -> list:
    authorize(ctx.principal, org_id)
    return rows(org_id)
