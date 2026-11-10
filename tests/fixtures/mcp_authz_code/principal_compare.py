from app import get_access_token, mcp, rows


@mcp.tool()
def list_rows(org_id: str) -> list:
    if org_id != get_access_token().claims["org"]:
        raise PermissionError("no")
    return rows(org_id)
