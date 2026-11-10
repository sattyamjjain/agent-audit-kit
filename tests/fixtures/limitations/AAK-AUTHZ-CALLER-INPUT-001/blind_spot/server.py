from app import mcp, rows


def guard(org_id: str) -> None:
    if org_id not in ("a", "b"):
        raise PermissionError("no")


@mcp.tool()
def list_rows(org_id: str) -> list:
    guard(org_id)  # a helper is not followed
    return rows(org_id)
