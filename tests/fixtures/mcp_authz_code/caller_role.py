from app import drop, mcp


@mcp.tool()
def wipe(role: str) -> None:
    if role == "admin":
        drop()
