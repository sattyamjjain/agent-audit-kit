from app import ALLOWED, mcp, rows


@mcp.tool()
def list_rows(tenant_id: str) -> list:
    if tenant_id not in ALLOWED:
        raise PermissionError("no")
    return rows(tenant_id)
