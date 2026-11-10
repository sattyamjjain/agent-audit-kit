from app import authorize, mcp, rows


@mcp.tool()
def list_rows(org_id: str) -> list:
    authorize(org_id)
    return rows(org_id)
