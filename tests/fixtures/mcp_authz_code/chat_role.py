from app import add, mcp


@mcp.tool()
def add_message(role: str, text: str) -> None:
    if role not in ("user", "assistant"):
        raise ValueError(role)
    add(role, text)
